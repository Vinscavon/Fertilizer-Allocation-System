"""Integration-layer test: python test_integration.py"""
import os, tempfile, json, hmac, hashlib, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

os.environ["FERT_DB"] = os.path.join(tempfile.mkdtemp(), "i.db")
os.environ["ERP_WEBHOOK_SECRET"] = "topsecret"
received, fail_first = [], {"on": True}

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        if fail_first["on"]:
            fail_first["on"] = False
            self.send_response(500); self.end_headers(); return
        sig = hmac.new(b"topsecret", raw, hashlib.sha256).hexdigest()
        received.append((self.headers["X-Signature"] == sig, json.loads(raw)))
        self.send_response(200); self.end_headers()
    def log_message(self, *a): pass

srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
os.environ["ERP_WEBHOOK_URL"] = f"http://127.0.0.1:{srv.server_port}/hook"
import app as A

def login(u, p):
    c = A.app.test_client(); assert c.post("/api/login", json={"username": u, "password": p}).status_code == 200; return c
def ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.get_data(as_text=True)[:300]); return r.json

adm = login("admin", "admin123"); ck = login("kesses_clerk", "center123"); au = login("auditor1", "audit123")
anon = A.app.test_client()

# --- API keys
ok(anon.post("/api/integration/farmers", json=[]), 401)
key = ok(adm.post("/api/integration/keys", json={"name": "county-erp"}))["api_key"]
H_ = {"X-API-Key": key}
ok(anon.post("/api/integration/farmers", json=[], headers={"X-API-Key": "wrong"}), 401)
ok(ck.post("/api/integration/keys", json={"name": "x"}), 403)
ok(au.post("/api/integration/farmers", json=[]), 403)          # auditor read-only

# --- inbound JSON (idempotent)
c = [{"external_id": "ERP-C1", "name": "Ziwa Depot", "area": "Soy"}]
print("centers:", ok(anon.post("/api/integration/centers", json=c, headers=H_)))
print("centers again:", ok(anon.post("/api/integration/centers", json=c, headers=H_)))
fa = [{"external_id": "ERP-F1", "national_id": "30000001", "name": "Mary Jebet", "phone": "+254711000001", "center_external_id": "ERP-C1", "max_bags": 10},
      {"national_id": "30000002", "name": "No Center", "phone": "1", "center": "Nowhere"}]
r = ok(anon.post("/api/integration/farmers", json=fa, headers=H_)); print("farmers:", r)
assert r["created"] == 1 and len(r["errors"]) == 1
print("allocations:", ok(anon.post("/api/integration/allocations", json=[{"center_external_id": "ERP-C1", "total_bags": 500, "price_per_bag": 3600}], headers=H_)))

# --- inbound CSV
csv_text = "external_id,national_id,name,phone,center,max_bags\nERP-F2,30000003,Samuel Rono,+254722000003,Ziwa Depot,15\n"
print("csv import:", ok(anon.post("/api/integration/import/farmers", data=csv_text, headers=H_)))

# --- voucher for ERP-created farmer -> event with external ids
fid = [f for f in ok(adm.get("/api/farmers")) if f["national_id"] == "30000001"][0]["id"]
v = ok(adm.post("/api/vouchers", json={"farmer_id": fid, "bags": 10, "mpesa_ref": "ERP-REF-1"}))

# --- PULL mode
ev = ok(anon.get("/api/integration/events?after_id=0", headers=H_)); print("pull:", [(e["id"], e["event_type"]) for e in ev])
vc = [e for e in ev if e["event_type"] == "voucher.created"][0]["data"]
assert vc["farmer"]["external_id"] == "ERP-F1" and vc["center"]["external_id"] == "ERP-C1" and vc["bags"] == 10

# --- PUSH mode: first attempt fails (500) -> retried -> signed delivery
r1 = A.flush_outbox(); print("flush #1 (ERP down):", r1); assert r1 == (0, 1) and not received
con = A.sqlite3.connect(A.DB_PATH); con.execute("UPDATE outbox SET next_try_at='2000-01-01 00:00:00'"); con.commit(); con.close()
r2 = A.flush_outbox(); print("flush #2 (ERP up):", r2); assert r2[0] >= 1 and received
assert all(sig for sig, _ in received), "bad signature"
print("delivered:", [p["type"] for _, p in received])
assert not ok(anon.get("/api/integration/events?after_id=0", headers=H_)), "sent events should leave the pull queue"

# --- pull + ack
ok(adm.post("/api/vouchers", json={"farmer_id": fid, "bags": 0, "mpesa_ref": "x"}), 400)  # validation still works
ev = ok(anon.get("/api/integration/events", headers=H_)); assert ev == []

# --- CSV exports
for kind in ["vouchers", "farmers", "centers", "allocations", "stock", "waybills", "discrepancies"]:
    r = anon.get(f"/api/integration/export/{kind}.csv", headers=H_); assert r.status_code == 200, kind
    print(f"export {kind}: {len(r.get_data(as_text=True).splitlines())} lines")
assert "ERP-F1" in anon.get("/api/integration/export/vouchers.csv", headers=H_).get_data(as_text=True)
ok(au.get("/api/integration/export/stock.csv"))                 # auditor can read
ok(anon.get("/api/integration/export/nope.csv", headers=H_), 404)

# --- outbox status / revoke
st = ok(adm.get("/api/integration/outbox")); print("outbox:", st["counts"], "webhook:", st["webhook_configured"])
kid = ok(adm.get("/api/integration/keys"))[0]["id"]; ok(adm.post(f"/api/integration/keys/{kid}/revoke"))
ok(anon.get("/api/integration/events", headers=H_), 401)
print("INTEGRATION TESTS PASSED")
