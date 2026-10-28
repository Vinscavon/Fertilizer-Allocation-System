"""
Fertilizer Slot Allocation & Distribution Tracking System (prototype)

Flow:  allocation per center -> farmer pays -> unique voucher (+OTP by SMS)
       warehouse builds pallets -> waybill -> scan on loading -> seal -> driver confirms
       center scans on unloading -> shortfall = discrepancy alert
       farmer redeems voucher (code + OTP + ID) -> center stock deducted

Run:  python app.py      (http://localhost:5000)
"""
import os
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, g, jsonify, request, session, render_template
from werkzeug.security import generate_password_hash, check_password_hash

DB_PATH = os.environ.get("FERT_DB", os.path.join(os.path.dirname(__file__), "fertilizer.db"))
DEMO_MODE = os.environ.get("DEMO_MODE", "1") == "1"   # returns OTP in API response (turn OFF in production)
VOUCHER_DAYS = int(os.environ.get("VOUCHER_DAYS", "30"))
BAGS_PER_PALLET_DEFAULT = 40

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-me-in-production")

SCHEMA = """
CREATE TABLE IF NOT EXISTS areas(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS centers(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, area_id INTEGER NOT NULL REFERENCES areas(id), external_id TEXT);
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN ('admin','warehouse','driver','center','auditor')),
  full_name TEXT, center_id INTEGER REFERENCES centers(id));
CREATE TABLE IF NOT EXISTS farmers(
  id INTEGER PRIMARY KEY, national_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, phone TEXT NOT NULL,
  area_id INTEGER NOT NULL REFERENCES areas(id), center_id INTEGER NOT NULL REFERENCES centers(id),
  max_bags INTEGER NOT NULL DEFAULT 20, external_id TEXT);
CREATE TABLE IF NOT EXISTS allocations(
  id INTEGER PRIMARY KEY, center_id INTEGER UNIQUE NOT NULL REFERENCES centers(id),
  total_bags INTEGER NOT NULL, price_per_bag REAL NOT NULL, product TEXT NOT NULL DEFAULT 'Fertilizer', external_id TEXT);
CREATE TABLE IF NOT EXISTS vouchers(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, farmer_id INTEGER NOT NULL REFERENCES farmers(id),
  center_id INTEGER NOT NULL REFERENCES centers(id), bags INTEGER NOT NULL, amount REAL NOT NULL,
  otp_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PAID' CHECK(status IN ('PAID','REDEEMED','EXPIRED','CANCELLED')),
  created_at TEXT NOT NULL, expires_at TEXT NOT NULL, redeemed_at TEXT, redeemed_by INTEGER);
CREATE TABLE IF NOT EXISTS payments(
  id INTEGER PRIMARY KEY, voucher_id INTEGER NOT NULL REFERENCES vouchers(id),
  amount REAL NOT NULL, mpesa_ref TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pallets(
  id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, batch_no TEXT, bags INTEGER NOT NULL,
  dest_center_id INTEGER NOT NULL REFERENCES centers(id),
  status TEXT NOT NULL DEFAULT 'BUILT' CHECK(status IN ('BUILT','LOADED','IN_TRANSIT','RECEIVED','MISSING')),
  waybill_id INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS waybills(
  id INTEGER PRIMARY KEY, truck_plate TEXT NOT NULL, driver_name TEXT NOT NULL,
  center_id INTEGER NOT NULL REFERENCES centers(id), seal_no TEXT,
  status TEXT NOT NULL DEFAULT 'LOADING' CHECK(status IN ('LOADING','IN_TRANSIT','COMPLETED','DISCREPANCY')),
  driver_ack INTEGER NOT NULL DEFAULT 0, created_by INTEGER, created_at TEXT NOT NULL,
  dispatched_at TEXT, finalized_at TEXT);
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY, waybill_id INTEGER, pallet_code TEXT NOT NULL,
  scan_type TEXT NOT NULL CHECK(scan_type IN ('LOAD','UNLOAD','REJECTED_LOAD','REJECTED_UNLOAD')),
  user_id INTEGER, device TEXT, lat REAL, lng REAL, note TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS discrepancies(
  id INTEGER PRIMARY KEY, waybill_id INTEGER NOT NULL, kind TEXT NOT NULL, detail TEXT NOT NULL,
  bags_missing INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'OPEN',
  resolution TEXT, created_at TEXT NOT NULL, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, detail TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sms_outbox(
  id INTEGER PRIMARY KEY, phone TEXT NOT NULL, message TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS api_keys(
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, key_hash TEXT UNIQUE NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL, last_used_at TEXT);
CREATE TABLE IF NOT EXISTS outbox(
  id INTEGER PRIMARY KEY, event_type TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING','SENT','FAILED')),
  attempts INTEGER NOT NULL DEFAULT 0, next_try_at TEXT NOT NULL, last_error TEXT,
  created_at TEXT NOT NULL, sent_at TEXT);
"""


# ---------------------------------------------------------------- helpers
def now():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def rows(sql, args=()):
    return [dict(r) for r in db().execute(sql, args).fetchall()]


def one(sql, args=()):
    r = db().execute(sql, args).fetchone()
    return dict(r) if r else None


def audit(action, detail=""):
    db().execute("INSERT INTO audit_log(user_id,action,detail,created_at) VALUES(?,?,?,?)",
                 (session.get("uid"), action, detail, now()))


def sms(phone, message):
    db().execute("INSERT INTO sms_outbox(phone,message,created_at) VALUES(?,?,?)", (phone, message, now()))
    # PRODUCTION: call Africa's Talking / Safaricom SMS API here.


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


class ApiError(Exception):
    def __init__(self, msg, code=400):
        self.msg, self.code = msg, code


@app.errorhandler(ApiError)
def handle_api_error(e):
    return jsonify(error=e.msg), e.code


def current_user():
    uid = session.get("uid")
    return one("SELECT id,username,role,full_name,center_id FROM users WHERE id=?", (uid,)) if uid else None


def require(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                raise ApiError("Login required", 401)
            if roles and u["role"] not in roles:
                raise ApiError("Your role is not allowed to do this", 403)
            g.user = u
            return fn(*a, **kw)
        return wrapper
    return deco


def body():
    return request.get_json(silent=True) or {}


def need(data, *fields):
    for f in fields:
        if data.get(f) in (None, ""):
            raise ApiError(f"Missing field: {f}")


def scan_meta(d):
    return d.get("device") or request.headers.get("User-Agent", "")[:80], d.get("lat"), d.get("lng")


def center_stock(center_id):
    received = one("SELECT COALESCE(SUM(bags),0) n FROM pallets WHERE dest_center_id=? AND status='RECEIVED'", (center_id,))["n"]
    issued = one("SELECT COALESCE(SUM(bags),0) n FROM vouchers WHERE center_id=? AND status='REDEEMED'", (center_id,))["n"]
    return received - issued


def sold_bags(center_id):
    return one("SELECT COALESCE(SUM(bags),0) n FROM vouchers WHERE center_id=? AND status IN ('PAID','REDEEMED')",
               (center_id,))["n"]


def expire_vouchers():
    db().execute("UPDATE vouchers SET status='EXPIRED' WHERE status='PAID' AND expires_at < ?", (now(),))


def new_voucher_code():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I confusion
    return "FV-" + "".join(secrets.choice(alphabet) for _ in range(10))


def next_pallet_code():
    n = one("SELECT COUNT(*) n FROM pallets")["n"] + 1
    return f"PLT-{datetime.utcnow().year}-{n:06d}"


# ---------------------------------------------------------------- auth
@app.post("/api/login")
def login():
    d = body()
    u = one("SELECT * FROM users WHERE username=?", (d.get("username", ""),))
    if not u or not check_password_hash(u["password_hash"], d.get("password", "")):
        raise ApiError("Wrong username or password", 401)
    session["uid"] = u["id"]
    audit("LOGIN", u["username"])
    db().commit()
    return jsonify(current_user())


@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)


@app.get("/api/me")
def me():
    return jsonify(current_user())


# ---------------------------------------------------------------- reference data
@app.get("/api/areas")
@require()
def areas():
    return jsonify(rows("SELECT * FROM areas ORDER BY name"))


@app.get("/api/centers")
@require()
def centers():
    out = rows("""SELECT c.*, a.name area_name FROM centers c JOIN areas a ON a.id=c.area_id ORDER BY c.name""")
    for c in out:
        c["stock"] = center_stock(c["id"])
    return jsonify(out)


@app.post("/api/areas")
@require("admin")
def add_area():
    d = body(); need(d, "name")
    cur = db().execute("INSERT INTO areas(name) VALUES(?)", (d["name"].strip(),))
    audit("AREA_ADD", d["name"]); db().commit()
    return jsonify(id=cur.lastrowid)


@app.post("/api/centers")
@require("admin")
def add_center():
    d = body(); need(d, "name", "area_id")
    cur = db().execute("INSERT INTO centers(name,area_id) VALUES(?,?)", (d["name"].strip(), d["area_id"]))
    audit("CENTER_ADD", d["name"]); db().commit()
    return jsonify(id=cur.lastrowid)


# ---------------------------------------------------------------- allocation (slots)
@app.get("/api/allocations")
@require("admin", "auditor", "center", "warehouse")
def allocations():
    expire_vouchers(); db().commit()
    out = rows("""SELECT al.*, c.name center_name, a.name area_name FROM allocations al
                  JOIN centers c ON c.id=al.center_id JOIN areas a ON a.id=c.area_id ORDER BY a.name""")
    for al in out:
        al["sold"] = sold_bags(al["center_id"])
        al["remaining"] = al["total_bags"] - al["sold"]
        al["in_stock"] = center_stock(al["center_id"])
        al["in_transit"] = one("SELECT COALESCE(SUM(bags),0) n FROM pallets WHERE dest_center_id=? AND status IN ('LOADED','IN_TRANSIT')", (al["center_id"],))["n"]
        al["issued"] = one("SELECT COALESCE(SUM(bags),0) n FROM vouchers WHERE center_id=? AND status='REDEEMED'", (al["center_id"],))["n"]
    return jsonify(out)


@app.post("/api/allocations")
@require("admin")
def set_allocation():
    d = body(); need(d, "center_id", "total_bags", "price_per_bag")
    total = int(d["total_bags"])
    if total < sold_bags(d["center_id"]):
        raise ApiError("Cannot reduce allocation below bags already sold")
    db().execute("""INSERT INTO allocations(center_id,total_bags,price_per_bag,product) VALUES(?,?,?,?)
                    ON CONFLICT(center_id) DO UPDATE SET total_bags=excluded.total_bags,
                    price_per_bag=excluded.price_per_bag, product=excluded.product""",
                 (d["center_id"], total, float(d["price_per_bag"]), d.get("product", "Fertilizer")))
    audit("ALLOCATION_SET", f"center={d['center_id']} bags={total}"); db().commit()
    return jsonify(ok=True)


# ---------------------------------------------------------------- farmers
@app.get("/api/farmers")
@require("admin", "center", "auditor")
def farmers():
    q = "SELECT f.*, a.name area_name, c.name center_name FROM farmers f JOIN areas a ON a.id=f.area_id JOIN centers c ON c.id=f.center_id"
    args = ()
    if g.user["role"] == "center":
        q += " WHERE f.center_id=?"; args = (g.user["center_id"],)
    return jsonify(rows(q + " ORDER BY f.name", args))


@app.post("/api/farmers")
@require("admin", "center")
def add_farmer():
    d = body(); need(d, "national_id", "name", "phone", "center_id")
    center = one("SELECT * FROM centers WHERE id=?", (d["center_id"],))
    if not center:
        raise ApiError("Unknown center")
    if g.user["role"] == "center" and g.user["center_id"] != center["id"]:
        raise ApiError("You can only register farmers for your own center", 403)
    try:
        cur = db().execute("INSERT INTO farmers(national_id,name,phone,area_id,center_id,max_bags) VALUES(?,?,?,?,?,?)",
                           (d["national_id"].strip(), d["name"].strip(), d["phone"].strip(), center["area_id"],
                            center["id"], int(d.get("max_bags", 20))))
    except sqlite3.IntegrityError:
        raise ApiError("A farmer with this national ID is already registered")
    audit("FARMER_ADD", d["national_id"]); db().commit()
    return jsonify(id=cur.lastrowid)


# ---------------------------------------------------------------- payment -> voucher
@app.post("/api/vouchers")
@require("admin", "center")
def create_voucher():
    """Called after payment is confirmed. PRODUCTION: call from the M-Pesa (Daraja) STK callback
    instead of by a clerk, and take mpesa_ref/amount from the callback payload."""
    d = body(); need(d, "farmer_id", "bags", "mpesa_ref")
    bags = int(d["bags"])
    if bags <= 0:
        raise ApiError("Bags must be more than 0")
    f = one("SELECT * FROM farmers WHERE id=?", (d["farmer_id"],))
    if not f:
        raise ApiError("Unknown farmer")
    if g.user["role"] == "center" and g.user["center_id"] != f["center_id"]:
        raise ApiError("This farmer belongs to another center", 403)
    expire_vouchers()
    bought = one("SELECT COALESCE(SUM(bags),0) n FROM vouchers WHERE farmer_id=? AND status IN ('PAID','REDEEMED')", (f["id"],))["n"]
    if bought + bags > f["max_bags"]:
        raise ApiError(f"Farmer cap is {f['max_bags']} bags; already bought {bought}")
    al = one("SELECT * FROM allocations WHERE center_id=?", (f["center_id"],))
    if not al:
        raise ApiError("No allocation set for this center")
    remaining = al["total_bags"] - sold_bags(f["center_id"])
    if bags > remaining:
        raise ApiError(f"Only {remaining} bags left in this center's allocation")
    if one("SELECT 1 FROM payments WHERE mpesa_ref=?", (d["mpesa_ref"].strip(),)):
        raise ApiError("This M-Pesa reference has already been used")
    amount = bags * al["price_per_bag"]
    code = new_voucher_code()
    otp = f"{secrets.randbelow(1000000):06d}"
    expires = (datetime.utcnow() + timedelta(days=VOUCHER_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cur = db().execute("""INSERT INTO vouchers(code,farmer_id,center_id,bags,amount,otp_hash,created_at,expires_at)
                          VALUES(?,?,?,?,?,?,?,?)""", (code, f["id"], f["center_id"], bags, amount, sha(otp), now(), expires))
    db().execute("INSERT INTO payments(voucher_id,amount,mpesa_ref,created_at) VALUES(?,?,?,?)",
                 (cur.lastrowid, amount, d["mpesa_ref"].strip(), now()))
    center = one("SELECT name FROM centers WHERE id=?", (f["center_id"],))
    sms(f["phone"], f"Voucher {code}: {bags} bags at {center['name']}. Pickup OTP {otp}. Valid until {expires[:10]}. Bring ID.")
    audit("VOUCHER_CREATE", f"{code} farmer={f['national_id']} bags={bags}")
    emit("voucher.created", {"code": code, "bags": bags, "amount": amount, "mpesa_ref": d["mpesa_ref"].strip(),
                             "expires_at": expires, "farmer": farmer_ref(f["id"]), "center": center_ref(f["center_id"])})
    db().commit()
    out = {"code": code, "bags": bags, "amount": amount, "expires_at": expires,
           "farmer": f["name"], "center": center["name"]}
    if DEMO_MODE:
        out["otp_demo"] = otp
    return jsonify(out)


@app.get("/api/vouchers")
@require("admin", "center", "auditor")
def vouchers():
    expire_vouchers(); db().commit()
    q = """SELECT v.code,v.bags,v.amount,v.status,v.created_at,v.expires_at,v.redeemed_at,f.name farmer,f.national_id,c.name center
           FROM vouchers v JOIN farmers f ON f.id=v.farmer_id JOIN centers c ON c.id=v.center_id"""
    args = ()
    if g.user["role"] == "center":
        q += " WHERE v.center_id=?"; args = (g.user["center_id"],)
    return jsonify(rows(q + " ORDER BY v.id DESC LIMIT 200", args))


@app.get("/api/vouchers/<code>")
@require("admin", "center", "auditor")
def voucher_lookup(code):
    expire_vouchers(); db().commit()
    v = one("""SELECT v.code,v.bags,v.amount,v.status,v.expires_at,v.center_id,f.name farmer,f.national_id,c.name center
               FROM vouchers v JOIN farmers f ON f.id=v.farmer_id JOIN centers c ON c.id=v.center_id WHERE v.code=?""",
            (code.strip().upper(),))
    if not v:
        raise ApiError("Voucher not found", 404)
    return jsonify(v)


@app.post("/api/redeem")
@require("center")
def redeem():
    d = body(); need(d, "code", "otp", "national_id")
    expire_vouchers()
    v = one("SELECT v.*, f.national_id FROM vouchers v JOIN farmers f ON f.id=v.farmer_id WHERE v.code=?",
            (d["code"].strip().upper(),))
    if not v:
        raise ApiError("Voucher not found", 404)
    if v["center_id"] != g.user["center_id"]:
        audit("REDEEM_WRONG_CENTER", v["code"]); db().commit()
        raise ApiError("This voucher belongs to a different distribution center", 403)
    if v["status"] != "PAID":
        audit("REDEEM_REJECTED", f"{v['code']} status={v['status']}"); db().commit()
        raise ApiError(f"Voucher is {v['status']} and cannot be redeemed")
    if sha(str(d["otp"]).strip()) != v["otp_hash"]:
        audit("REDEEM_BAD_OTP", v["code"]); db().commit()
        raise ApiError("Wrong OTP")
    if str(d["national_id"]).strip() != v["national_id"]:
        audit("REDEEM_ID_MISMATCH", v["code"]); db().commit()
        raise ApiError("National ID does not match the voucher holder")
    if center_stock(v["center_id"]) < v["bags"]:
        raise ApiError("Not enough received stock at this center yet. Ask the farmer to come back later.")
    db().execute("UPDATE vouchers SET status='REDEEMED', redeemed_at=?, redeemed_by=? WHERE id=?",
                 (now(), g.user["id"], v["id"]))
    audit("REDEEM", f"{v['code']} bags={v['bags']}")
    emit("voucher.redeemed", {"code": v["code"], "bags": v["bags"], "redeemed_at": now(),
                              "farmer": farmer_ref(v["farmer_id"]), "center": center_ref(v["center_id"])})
    db().commit()
    return jsonify(ok=True, bags=v["bags"], stock_left=center_stock(v["center_id"]))


# ---------------------------------------------------------------- pallets (warehouse)
@app.post("/api/pallets")
@require("admin", "warehouse")
def build_pallets():
    d = body(); need(d, "center_id", "count")
    if not one("SELECT 1 FROM centers WHERE id=?", (d["center_id"],)):
        raise ApiError("Unknown center")
    per = int(d.get("bags_per_pallet", BAGS_PER_PALLET_DEFAULT))
    count = int(d["count"])
    if not (0 < count <= 200 and 0 < per <= 100):
        raise ApiError("Invalid pallet count or size")
    created = []
    for _ in range(count):
        code = next_pallet_code()
        db().execute("INSERT INTO pallets(code,batch_no,bags,dest_center_id,created_at) VALUES(?,?,?,?,?)",
                     (code, d.get("batch_no", ""), per, d["center_id"], now()))
        created.append(code)
    audit("PALLETS_BUILD", f"{count} x {per} -> center {d['center_id']}")
    db().commit()
    return jsonify(codes=created)


@app.get("/api/pallets")
@require("admin", "warehouse", "auditor", "center")
def pallets():
    q = "SELECT p.*, c.name center_name FROM pallets p JOIN centers c ON c.id=p.dest_center_id"
    args = ()
    if g.user["role"] == "center":
        q += " WHERE p.dest_center_id=?"; args = (g.user["center_id"],)
    return jsonify(rows(q + " ORDER BY p.id DESC LIMIT 300", args))


# ---------------------------------------------------------------- waybills
def waybill_view(wb_id):
    wb = one("""SELECT w.*, c.name center_name FROM waybills w JOIN centers c ON c.id=w.center_id WHERE w.id=?""", (wb_id,))
    if not wb:
        raise ApiError("Waybill not found", 404)
    wb["pallets"] = rows("SELECT code,bags,status FROM pallets WHERE waybill_id=? ORDER BY id", (wb_id,))
    wb["bags_total"] = sum(p["bags"] for p in wb["pallets"])
    wb["pallets_total"] = len(wb["pallets"])
    wb["pallets_received"] = sum(1 for p in wb["pallets"] if p["status"] == "RECEIVED")
    return wb


def check_waybill_access(wb):
    u = g.user
    if u["role"] == "center" and wb["center_id"] != u["center_id"]:
        raise ApiError("This waybill is not for your center", 403)


@app.post("/api/waybills")
@require("admin", "warehouse")
def create_waybill():
    d = body(); need(d, "truck_plate", "driver_name", "center_id")
    cur = db().execute("INSERT INTO waybills(truck_plate,driver_name,center_id,created_by,created_at) VALUES(?,?,?,?,?)",
                       (d["truck_plate"].strip().upper(), d["driver_name"].strip(), d["center_id"], g.user["id"], now()))
    audit("WAYBILL_CREATE", f"#{cur.lastrowid} {d['truck_plate']} -> center {d['center_id']}")
    db().commit()
    return jsonify(id=cur.lastrowid)


@app.get("/api/waybills")
@require("admin", "warehouse", "driver", "center", "auditor")
def list_waybills():
    q = "SELECT w.*, c.name center_name FROM waybills w JOIN centers c ON c.id=w.center_id"
    args = ()
    if g.user["role"] == "center":
        q += " WHERE w.center_id=?"; args = (g.user["center_id"],)
    out = rows(q + " ORDER BY w.id DESC LIMIT 100", args)
    for w in out:
        w["pallets_total"] = one("SELECT COUNT(*) n FROM pallets WHERE waybill_id=?", (w["id"],))["n"]
        w["bags_total"] = one("SELECT COALESCE(SUM(bags),0) n FROM pallets WHERE waybill_id=?", (w["id"],))["n"]
    return jsonify(out)


@app.get("/api/waybills/<int:wb_id>")
@require("admin", "warehouse", "driver", "center", "auditor")
def get_waybill(wb_id):
    wb = waybill_view(wb_id)
    check_waybill_access(wb)
    return jsonify(wb)


@app.post("/api/waybills/<int:wb_id>/load")
@require("warehouse", "admin")
def load_scan(wb_id):
    d = body(); need(d, "pallet_code")
    wb = waybill_view(wb_id)
    code = d["pallet_code"].strip().upper()
    device, lat, lng = scan_meta(d)

    def reject(reason):
        db().execute("INSERT INTO scans(waybill_id,pallet_code,scan_type,user_id,device,lat,lng,note,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (wb_id, code, "REJECTED_LOAD", g.user["id"], device, lat, lng, reason, now()))
        audit("LOAD_REJECTED", f"wb#{wb_id} {code}: {reason}"); db().commit()
        raise ApiError(reason)

    if wb["status"] != "LOADING":
        reject("Waybill is no longer open for loading")
    p = one("SELECT * FROM pallets WHERE code=?", (code,))
    if not p:
        reject("Unknown pallet code (not registered in the system)")
    if p["status"] != "BUILT":
        reject(f"Pallet already {p['status']} (possible duplicate or reused label)")
    if p["dest_center_id"] != wb["center_id"]:
        reject("Pallet is assigned to a different distribution center")
    db().execute("UPDATE pallets SET status='LOADED', waybill_id=? WHERE id=?", (wb_id, p["id"]))
    db().execute("INSERT INTO scans(waybill_id,pallet_code,scan_type,user_id,device,lat,lng,created_at) VALUES(?,?,?,?,?,?,?,?)",
                 (wb_id, code, "LOAD", g.user["id"], device, lat, lng, now()))
    db().commit()
    return jsonify(waybill_view(wb_id))


@app.post("/api/waybills/<int:wb_id>/driver-confirm")
@require("driver", "admin")
def driver_confirm(wb_id):
    d = body(); need(d, "pallets", "bags")
    wb = waybill_view(wb_id)
    if wb["status"] != "LOADING":
        raise ApiError("Waybill is not in loading state")
    if int(d["pallets"]) != wb["pallets_total"] or int(d["bags"]) != wb["bags_total"]:
        audit("DRIVER_COUNT_MISMATCH", f"wb#{wb_id} driver said {d['pallets']}/{d['bags']} system {wb['pallets_total']}/{wb['bags_total']}")
        db().commit()
        raise ApiError(f"Count does not match. System shows {wb['pallets_total']} pallets / {wb['bags_total']} bags.")
    db().execute("UPDATE waybills SET driver_ack=1 WHERE id=?", (wb_id,))
    audit("DRIVER_CONFIRM", f"wb#{wb_id}"); db().commit()
    return jsonify(waybill_view(wb_id))


@app.post("/api/waybills/<int:wb_id>/dispatch")
@require("warehouse", "admin")
def dispatch(wb_id):
    d = body(); need(d, "seal_no")
    wb = waybill_view(wb_id)
    if wb["status"] != "LOADING":
        raise ApiError("Waybill already dispatched")
    if wb["pallets_total"] == 0:
        raise ApiError("No pallets loaded")
    if not wb["driver_ack"]:
        raise ApiError("Driver must confirm pallet and bag counts before dispatch")
    db().execute("UPDATE waybills SET status='IN_TRANSIT', seal_no=?, dispatched_at=? WHERE id=?",
                 (d["seal_no"].strip().upper(), now(), wb_id))
    db().execute("UPDATE pallets SET status='IN_TRANSIT' WHERE waybill_id=?", (wb_id,))
    audit("DISPATCH", f"wb#{wb_id} seal={d['seal_no']}")
    emit("waybill.dispatched", {"waybill_id": wb_id, "truck_plate": wb["truck_plate"], "driver": wb["driver_name"],
                                "seal_no": d["seal_no"].strip().upper(), "pallets": wb["pallets_total"],
                                "bags": wb["bags_total"], "center": center_ref(wb["center_id"])})
    db().commit()
    return jsonify(waybill_view(wb_id))


@app.post("/api/waybills/<int:wb_id>/unload")
@require("center")
def unload_scan(wb_id):
    d = body(); need(d, "pallet_code")
    wb = waybill_view(wb_id)
    check_waybill_access(wb)
    code = d["pallet_code"].strip().upper()
    device, lat, lng = scan_meta(d)

    def reject(reason):
        db().execute("INSERT INTO scans(waybill_id,pallet_code,scan_type,user_id,device,lat,lng,note,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                     (wb_id, code, "REJECTED_UNLOAD", g.user["id"], device, lat, lng, reason, now()))
        db().execute("INSERT INTO discrepancies(waybill_id,kind,detail,created_at) VALUES(?,?,?,?)",
                     (wb_id, "UNEXPECTED_PALLET", f"{code}: {reason}", now()))
        audit("UNLOAD_REJECTED", f"wb#{wb_id} {code}: {reason}"); db().commit()
        raise ApiError(reason)

    if wb["status"] != "IN_TRANSIT":
        raise ApiError("Waybill is not in transit")
    p = one("SELECT * FROM pallets WHERE code=?", (code,))
    if not p or p["waybill_id"] != wb_id:
        reject("Pallet is NOT on this waybill")
    if p["status"] == "RECEIVED":
        raise ApiError("Pallet already scanned")
    db().execute("UPDATE pallets SET status='RECEIVED' WHERE id=?", (p["id"],))
    db().execute("INSERT INTO scans(waybill_id,pallet_code,scan_type,user_id,device,lat,lng,created_at) VALUES(?,?,?,?,?,?,?,?)",
                 (wb_id, code, "UNLOAD", g.user["id"], device, lat, lng, now()))
    db().commit()
    return jsonify(waybill_view(wb_id))


@app.post("/api/waybills/<int:wb_id>/finalize")
@require("center")
def finalize(wb_id):
    d = body(); need(d, "seal_no")
    wb = waybill_view(wb_id)
    check_waybill_access(wb)
    if wb["status"] != "IN_TRANSIT":
        raise ApiError("Waybill is not in transit")
    issues = []
    if d["seal_no"].strip().upper() != (wb["seal_no"] or ""):
        db().execute("INSERT INTO discrepancies(waybill_id,kind,detail,created_at) VALUES(?,?,?,?)",
                     (wb_id, "SEAL_MISMATCH", f"Expected seal {wb['seal_no']}, center recorded {d['seal_no']}", now()))
        issues.append("SEAL_MISMATCH")
    missing = [p for p in wb["pallets"] if p["status"] != "RECEIVED"]
    if missing:
        bags = sum(p["bags"] for p in missing)
        db().execute("UPDATE pallets SET status='MISSING' WHERE waybill_id=? AND status!='RECEIVED'", (wb_id,))
        db().execute("INSERT INTO discrepancies(waybill_id,kind,detail,bags_missing,created_at) VALUES(?,?,?,?,?)",
                     (wb_id, "SHORTFALL",
                      f"Truck {wb['truck_plate']} driver {wb['driver_name']}: {len(missing)} pallet(s) missing: "
                      + ", ".join(p["code"] for p in missing), bags, now()))
        issues.append("SHORTFALL")
    if issues or one("SELECT 1 FROM discrepancies WHERE waybill_id=? AND status='OPEN'", (wb_id,)):
        status = "DISCREPANCY"
    else:
        status = "COMPLETED"
    db().execute("UPDATE waybills SET status=?, finalized_at=? WHERE id=?", (status, now(), wb_id))
    audit("FINALIZE", f"wb#{wb_id} -> {status} {issues}")
    got = sum(p["bags"] for p in wb["pallets"] if p["status"] == "RECEIVED")
    emit("waybill.finalized", {"waybill_id": wb_id, "status": status, "issues": issues,
                               "bags_expected": wb["bags_total"], "bags_received": got,
                               "bags_missing": wb["bags_total"] - got, "center": center_ref(wb["center_id"])})
    db().commit()
    return jsonify(status=status, issues=issues, waybill=waybill_view(wb_id))


# ---------------------------------------------------------------- discrepancies, audit, sms, overview
@app.get("/api/discrepancies")
@require("admin", "auditor", "warehouse", "center")
def discrepancies():
    q = """SELECT d.*, w.truck_plate, w.driver_name, c.name center_name FROM discrepancies d
           JOIN waybills w ON w.id=d.waybill_id JOIN centers c ON c.id=w.center_id"""
    args = ()
    if g.user["role"] == "center":
        q += " WHERE w.center_id=?"; args = (g.user["center_id"],)
    return jsonify(rows(q + " ORDER BY d.id DESC LIMIT 200", args))


@app.post("/api/discrepancies/<int:did>/resolve")
@require("admin", "auditor")
def resolve(did):
    d = body(); need(d, "resolution")
    db().execute("UPDATE discrepancies SET status='RESOLVED', resolution=?, resolved_at=? WHERE id=?",
                 (d["resolution"], now(), did))
    audit("DISCREPANCY_RESOLVE", f"#{did}: {d['resolution']}"); db().commit()
    return jsonify(ok=True)


@app.get("/api/scans")
@require("admin", "auditor")
def scans():
    return jsonify(rows("""SELECT s.*, u.username FROM scans s LEFT JOIN users u ON u.id=s.user_id
                           ORDER BY s.id DESC LIMIT 300"""))


@app.get("/api/audit")
@require("admin", "auditor")
def audit_log():
    return jsonify(rows("""SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON u.id=a.user_id
                           ORDER BY a.id DESC LIMIT 300"""))


@app.get("/api/sms")
@require("admin")
def sms_outbox():
    return jsonify(rows("SELECT * FROM sms_outbox ORDER BY id DESC LIMIT 100"))


@app.get("/api/summary")
@require()
def summary():
    return jsonify(
        open_discrepancies=one("SELECT COUNT(*) n FROM discrepancies WHERE status='OPEN'")["n"],
        waybills_in_transit=one("SELECT COUNT(*) n FROM waybills WHERE status='IN_TRANSIT'")["n"],
        vouchers_paid=one("SELECT COUNT(*) n FROM vouchers WHERE status='PAID'")["n"],
        vouchers_redeemed=one("SELECT COUNT(*) n FROM vouchers WHERE status='REDEEMED'")["n"])


@app.get("/")
def index():
    return render_template("index.html")


# ---------------------------------------------------------------- ERP / external-system integration
# Generic, system-neutral. Three ways to connect (use any combination):
#   1. PUSH  - events are POSTed (signed) to ERP_WEBHOOK_URL, with automatic retry
#   2. PULL  - the ERP polls GET /api/integration/events and acknowledges them
#   3. FILES - CSV import/export for farmers, centers, allocations, vouchers, stock...
# Inbound master data (centers, farmers, allocations) is upserted by external_id, so repeats are safe.
import csv
import hmac
import io
import json
import threading
import time
import urllib.request

from flask import Response

ERP_WEBHOOK_URL = os.environ.get("ERP_WEBHOOK_URL", "")
ERP_WEBHOOK_SECRET = os.environ.get("ERP_WEBHOOK_SECRET", "")
OUTBOX_MAX_ATTEMPTS = 10


def center_ref(center_id):
    c = one("SELECT id,name,external_id FROM centers WHERE id=?", (center_id,)) or {}
    return {"id": c.get("id"), "external_id": c.get("external_id"), "name": c.get("name")}


def farmer_ref(farmer_id):
    f = one("SELECT id,name,national_id,phone,external_id FROM farmers WHERE id=?", (farmer_id,)) or {}
    return {"id": f.get("id"), "external_id": f.get("external_id"), "national_id": f.get("national_id"),
            "name": f.get("name"), "phone": f.get("phone")}


def emit(event_type, payload):
    """Queue an event in the same transaction as the business change (so none is ever lost)."""
    db().execute("INSERT INTO outbox(event_type,payload,created_at,next_try_at) VALUES(?,?,?,?)",
                 (event_type, json.dumps(payload, default=str), now(), now()))


def integration(write=False):
    """Allow an API key (header X-API-Key) or a logged-in admin. Auditors may read but not write."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            key = request.headers.get("X-API-Key")
            if key:
                k = one("SELECT * FROM api_keys WHERE key_hash=? AND active=1", (sha(key),))
                if not k:
                    raise ApiError("Invalid or revoked API key", 401)
                db().execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (now(), k["id"]))
                g.user = {"id": None, "role": "integration", "username": "api:" + k["name"], "center_id": None}
            else:
                u = current_user()
                if not u:
                    raise ApiError("API key or login required", 401)
                if u["role"] != "admin" and (write or u["role"] != "auditor"):
                    raise ApiError("Your role is not allowed to do this", 403)
                g.user = u
            return fn(*a, **kw)
        return wrapper
    return deco


def _ext(v):
    v = str(v).strip() if v not in (None, "") else ""
    return v or None


def _center_lookup(ext, name):
    c = one("SELECT * FROM centers WHERE external_id=?", (ext,)) if ext else None
    return c or (one("SELECT * FROM centers WHERE name=?", (name.strip(),)) if name else None)


def upsert_centers(items):
    res = {"created": 0, "updated": 0, "errors": []}
    for i, it in enumerate(items, 1):
        try:
            name, area = (it.get("name") or "").strip(), (it.get("area") or "").strip()
            if not name or not area:
                raise ValueError("name and area are required")
            ar = one("SELECT id FROM areas WHERE name=?", (area,))
            area_id = ar["id"] if ar else db().execute("INSERT INTO areas(name) VALUES(?)", (area,)).lastrowid
            ext = _ext(it.get("external_id"))
            c = _center_lookup(ext, name)
            if c:
                db().execute("UPDATE centers SET name=?, area_id=?, external_id=COALESCE(?,external_id) WHERE id=?",
                             (name, area_id, ext, c["id"])); res["updated"] += 1
            else:
                db().execute("INSERT INTO centers(name,area_id,external_id) VALUES(?,?,?)", (name, area_id, ext))
                res["created"] += 1
        except Exception as e:
            res["errors"].append({"row": i, "error": str(e)})
    return res


def upsert_farmers(items):
    res = {"created": 0, "updated": 0, "errors": []}
    for i, it in enumerate(items, 1):
        try:
            nid, ext = str(it.get("national_id") or "").strip(), _ext(it.get("external_id"))
            name, phone = (it.get("name") or "").strip(), (it.get("phone") or "").strip()
            center = _center_lookup(_ext(it.get("center_external_id")), it.get("center"))
            if not center:
                raise ValueError("unknown center (give center_external_id or center name)")
            max_bags = int(it.get("max_bags") or 20)
            f = one("SELECT * FROM farmers WHERE external_id=?", (ext,)) if ext else None
            f = f or (one("SELECT * FROM farmers WHERE national_id=?", (nid,)) if nid else None)
            if f:
                db().execute("""UPDATE farmers SET name=COALESCE(NULLIF(?,''),name), phone=COALESCE(NULLIF(?,''),phone),
                                area_id=?, center_id=?, max_bags=?, external_id=COALESCE(?,external_id) WHERE id=?""",
                             (name, phone, center["area_id"], center["id"], max_bags, ext, f["id"])); res["updated"] += 1
            else:
                if not (nid and name and phone):
                    raise ValueError("national_id, name and phone are required for a new farmer")
                db().execute("INSERT INTO farmers(national_id,name,phone,area_id,center_id,max_bags,external_id) VALUES(?,?,?,?,?,?,?)",
                             (nid, name, phone, center["area_id"], center["id"], max_bags, ext)); res["created"] += 1
        except Exception as e:
            res["errors"].append({"row": i, "error": str(e)})
    return res


def upsert_allocations(items):
    res = {"created": 0, "updated": 0, "errors": []}
    for i, it in enumerate(items, 1):
        try:
            center = _center_lookup(_ext(it.get("center_external_id")), it.get("center"))
            if not center:
                raise ValueError("unknown center (give center_external_id or center name)")
            total, price = int(it["total_bags"]), float(it["price_per_bag"])
            if total < sold_bags(center["id"]):
                raise ValueError("total_bags is below bags already sold")
            existed = one("SELECT 1 FROM allocations WHERE center_id=?", (center["id"],))
            db().execute("""INSERT INTO allocations(center_id,total_bags,price_per_bag,product,external_id) VALUES(?,?,?,?,?)
                            ON CONFLICT(center_id) DO UPDATE SET total_bags=excluded.total_bags,
                            price_per_bag=excluded.price_per_bag, product=excluded.product,
                            external_id=COALESCE(excluded.external_id,external_id)""",
                         (center["id"], total, price, it.get("product") or "Fertilizer", _ext(it.get("external_id"))))
            res["updated" if existed else "created"] += 1
        except Exception as e:
            res["errors"].append({"row": i, "error": str(e)})
    return res


UPSERTS = {"centers": upsert_centers, "farmers": upsert_farmers, "allocations": upsert_allocations}


def _sync(kind, items):
    if not isinstance(items, list):
        raise ApiError("Send a JSON list of records")
    res = UPSERTS[kind](items)
    audit("INTEGRATION_" + kind.upper(), f"[{g.user['username']}] created={res['created']} updated={res['updated']} errors={len(res['errors'])}")
    db().commit()
    return jsonify(res)


@app.post("/api/integration/<kind>")
@integration(write=True)
def int_push(kind):
    """Inbound master data as JSON. kind = centers | farmers | allocations (body: list of records)."""
    if kind not in UPSERTS:
        raise ApiError("Unknown kind", 404)
    return _sync(kind, request.get_json(silent=True))


@app.post("/api/integration/import/<kind>")
@integration(write=True)
def int_import_csv(kind):
    """Inbound master data as CSV (file field 'file' or raw body). Header row = field names."""
    if kind not in UPSERTS:
        raise ApiError("Unknown kind", 404)
    raw = request.files["file"].read().decode("utf-8-sig") if "file" in request.files else request.get_data(as_text=True)
    reader = csv.DictReader(io.StringIO(raw))
    items = [{(k or "").strip().lower(): (v or "").strip() for k, v in row.items()} for row in reader]
    return _sync(kind, items)


def _stock_rows():
    out = []
    for c in rows("SELECT c.id,c.external_id,c.name FROM centers c ORDER BY c.id"):
        al = one("SELECT total_bags FROM allocations WHERE center_id=?", (c["id"],))
        out.append({"center_external_id": c["external_id"], "center": c["name"],
                    "allocated": al["total_bags"] if al else 0, "sold": sold_bags(c["id"]),
                    "received": one("SELECT COALESCE(SUM(bags),0) n FROM pallets WHERE dest_center_id=? AND status='RECEIVED'", (c["id"],))["n"],
                    "issued": one("SELECT COALESCE(SUM(bags),0) n FROM vouchers WHERE center_id=? AND status='REDEEMED'", (c["id"],))["n"],
                    "in_stock": center_stock(c["id"])})
    return out


EXPORT_SQL = {
    "vouchers": """SELECT v.code, f.external_id farmer_external_id, f.national_id, f.name farmer, c.external_id center_external_id,
                   c.name center, v.bags, v.amount, v.status, p.mpesa_ref, v.created_at, v.expires_at, v.redeemed_at
                   FROM vouchers v JOIN farmers f ON f.id=v.farmer_id JOIN centers c ON c.id=v.center_id
                   LEFT JOIN payments p ON p.voucher_id=v.id ORDER BY v.id""",
    "farmers": """SELECT f.external_id, f.national_id, f.name, f.phone, c.external_id center_external_id, c.name center, f.max_bags
                  FROM farmers f JOIN centers c ON c.id=f.center_id ORDER BY f.id""",
    "centers": "SELECT c.external_id, c.name, a.name area FROM centers c JOIN areas a ON a.id=c.area_id ORDER BY c.id",
    "allocations": """SELECT c.external_id center_external_id, c.name center, al.total_bags, al.price_per_bag, al.product
                      FROM allocations al JOIN centers c ON c.id=al.center_id ORDER BY al.id""",
    "waybills": """SELECT w.id waybill_id, w.truck_plate, w.driver_name, c.external_id center_external_id, c.name center, w.seal_no,
                   w.status, w.created_at, w.dispatched_at, w.finalized_at,
                   (SELECT COUNT(*) FROM pallets p WHERE p.waybill_id=w.id) pallets,
                   (SELECT COALESCE(SUM(bags),0) FROM pallets p WHERE p.waybill_id=w.id) bags_loaded,
                   (SELECT COALESCE(SUM(bags),0) FROM pallets p WHERE p.waybill_id=w.id AND p.status='RECEIVED') bags_received
                   FROM waybills w JOIN centers c ON c.id=w.center_id ORDER BY w.id""",
    "discrepancies": """SELECT d.id, d.waybill_id, w.truck_plate, w.driver_name, c.name center, d.kind, d.detail, d.bags_missing,
                        d.status, d.resolution, d.created_at, d.resolved_at
                        FROM discrepancies d JOIN waybills w ON w.id=d.waybill_id JOIN centers c ON c.id=w.center_id ORDER BY d.id""",
}


@app.get("/api/integration/export/<kind>.csv")
@integration()
def int_export(kind):
    if kind == "stock":
        data = _stock_rows()
    elif kind in EXPORT_SQL:
        data = rows(EXPORT_SQL[kind])
    else:
        raise ApiError("Unknown export. Use: stock, " + ", ".join(EXPORT_SQL), 404)
    buf = io.StringIO()
    if data:
        w = csv.DictWriter(buf, fieldnames=list(data[0].keys()))
        w.writeheader(); w.writerows(data)
    return Response(buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={kind}.csv"})


@app.get("/api/integration/events")
@integration()
def int_events():
    """PULL mode: events not yet delivered/acknowledged, oldest first. Use after_id as a cursor."""
    after = int(request.args.get("after_id", 0)); limit = min(int(request.args.get("limit", 100)), 500)
    ev = rows("SELECT id,event_type,payload,created_at FROM outbox WHERE status!='SENT' AND id>? ORDER BY id LIMIT ?", (after, limit))
    for e in ev:
        e["data"] = json.loads(e.pop("payload"))
    return jsonify(ev)


@app.post("/api/integration/events/ack")
@integration(write=True)
def int_ack():
    ids = [int(i) for i in (body().get("ids") or [])]
    for i in ids:
        db().execute("UPDATE outbox SET status='SENT', sent_at=? WHERE id=?", (now(), i))
    db().commit()
    return jsonify(acknowledged=len(ids))


@app.post("/api/integration/keys")
@require("admin")
def int_key_create():
    d = body(); need(d, "name")
    key = "fk_" + secrets.token_urlsafe(32)
    db().execute("INSERT INTO api_keys(name,key_hash,created_at) VALUES(?,?,?)", (d["name"].strip(), sha(key), now()))
    audit("API_KEY_CREATE", d["name"]); db().commit()
    return jsonify(name=d["name"], api_key=key, note="Copy it now. It is not stored and cannot be shown again.")


@app.get("/api/integration/keys")
@require("admin")
def int_key_list():
    return jsonify(rows("SELECT id,name,active,created_at,last_used_at FROM api_keys ORDER BY id DESC"))


@app.post("/api/integration/keys/<int:kid>/revoke")
@require("admin")
def int_key_revoke(kid):
    db().execute("UPDATE api_keys SET active=0 WHERE id=?", (kid,))
    audit("API_KEY_REVOKE", str(kid)); db().commit()
    return jsonify(ok=True)


@app.get("/api/integration/outbox")
@require("admin")
def int_outbox():
    counts = {r["status"]: r["n"] for r in rows("SELECT status, COUNT(*) n FROM outbox GROUP BY status")}
    return jsonify(webhook_configured=bool(ERP_WEBHOOK_URL), webhook_url=ERP_WEBHOOK_URL, counts=counts,
                   recent=rows("SELECT id,event_type,status,attempts,last_error,created_at,sent_at FROM outbox ORDER BY id DESC LIMIT 50"))


@app.post("/api/integration/outbox/flush")
@require("admin")
def int_flush():
    db().commit()
    if not ERP_WEBHOOK_URL:
        raise ApiError("ERP_WEBHOOK_URL is not set. Events wait for the ERP to pull them.")
    sent, failed = flush_outbox()
    return jsonify(sent=sent, failed=failed)


@app.post("/api/integration/outbox/retry-failed")
@require("admin")
def int_retry():
    db().execute("UPDATE outbox SET status='PENDING', attempts=0, next_try_at=? WHERE status='FAILED'", (now(),))
    db().commit()
    return jsonify(ok=True)


def flush_outbox(limit=50):
    """PUSH mode: deliver due events to ERP_WEBHOOK_URL. Signed with HMAC-SHA256 (header X-Signature).
    The ERP must answer 2xx; anything else is retried with growing delays (30s, 60s, ... max 1h)."""
    if not ERP_WEBHOOK_URL:
        return 0, 0
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    sent = failed = 0
    try:
        for ev in con.execute("SELECT * FROM outbox WHERE status='PENDING' AND next_try_at<=? ORDER BY id LIMIT ?",
                              (now(), limit)).fetchall():
            payload = json.dumps({"id": ev["id"], "type": ev["event_type"], "created_at": ev["created_at"],
                                  "data": json.loads(ev["payload"])}).encode()
            headers = {"Content-Type": "application/json", "X-Event-Id": str(ev["id"]), "X-Event-Type": ev["event_type"]}
            if ERP_WEBHOOK_SECRET:
                headers["X-Signature"] = hmac.new(ERP_WEBHOOK_SECRET.encode(), payload, hashlib.sha256).hexdigest()
            try:
                urllib.request.urlopen(urllib.request.Request(ERP_WEBHOOK_URL, data=payload, headers=headers, method="POST"), timeout=10).close()
                con.execute("UPDATE outbox SET status='SENT', sent_at=?, attempts=attempts+1, last_error=NULL WHERE id=?", (now(), ev["id"]))
                sent += 1
            except Exception as e:
                n = ev["attempts"] + 1
                wait = min(30 * 2 ** n, 3600)
                con.execute("UPDATE outbox SET attempts=?, last_error=?, status=?, next_try_at=? WHERE id=?",
                            (n, str(e)[:200], "FAILED" if n >= OUTBOX_MAX_ATTEMPTS else "PENDING",
                             (datetime.utcnow() + timedelta(seconds=wait)).strftime("%Y-%m-%d %H:%M:%S"), ev["id"]))
                failed += 1
            con.commit()
    finally:
        con.close()
    return sent, failed


def outbox_worker():
    while True:
        try:
            flush_outbox()
        except Exception:
            pass
        time.sleep(20)


# ---------------------------------------------------------------- init + seed
def init_db(seed=True):
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    # migrate databases created before external_id existed
    for table in ("centers", "farmers", "allocations"):
        cols = [r[1] for r in con.execute(f"PRAGMA table_info({table})")]
        if "external_id" not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN external_id TEXT")
        con.execute(f"CREATE UNIQUE INDEX IF NOT EXISTS ix_{table}_ext ON {table}(external_id) WHERE external_id IS NOT NULL")
    if seed and not con.execute("SELECT 1 FROM users LIMIT 1").fetchone():
        con.executemany("INSERT INTO areas(name) VALUES(?)", [("Kesses",), ("Moiben",), ("Turbo",)])
        con.executemany("INSERT INTO centers(name,area_id) VALUES(?,?)",
                        [("Kesses NCPB Depot", 1), ("Moiben Cooperative Store", 2), ("Turbo Agro Center", 3)])
        users = [("admin", "admin123", "admin", "System Admin", None),
                 ("warehouse1", "ware123", "warehouse", "Warehouse Clerk", None),
                 ("driver1", "drive123", "driver", "Driver", None),
                 ("auditor1", "audit123", "auditor", "Auditor", None),
                 ("kesses_clerk", "center123", "center", "Kesses Clerk", 1),
                 ("moiben_clerk", "center123", "center", "Moiben Clerk", 2)]
        con.executemany("INSERT INTO users(username,password_hash,role,full_name,center_id) VALUES(?,?,?,?,?)",
                        [(u, generate_password_hash(p), r, n, c) for u, p, r, n, c in users])
        con.executemany("INSERT INTO allocations(center_id,total_bags,price_per_bag) VALUES(?,?,?)",
                        [(1, 2000, 3500), (2, 1500, 3500), (3, 1000, 3500)])
        con.executemany("INSERT INTO farmers(national_id,name,phone,area_id,center_id,max_bags) VALUES(?,?,?,?,?,?)",
                        [("12345678", "Jane Chebet", "+254700000001", 1, 1, 20),
                         ("23456789", "Peter Kiprop", "+254700000002", 1, 1, 20)])
    con.commit()
    con.close()


init_db()

if __name__ == "__main__":
    if ERP_WEBHOOK_URL:
        threading.Thread(target=outbox_worker, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
