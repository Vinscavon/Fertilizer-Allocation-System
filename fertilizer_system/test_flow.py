"""End-to-end test: run with  python test_flow.py"""
import os, tempfile
os.environ["FERT_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
import app as A

def client(user, pw):
    c = A.app.test_client()
    r = c.post("/api/login", json={"username": user, "password": pw}); assert r.status_code == 200, r.json
    return c

def ok(r, code=200):
    assert r.status_code == code, (r.status_code, r.json); return r.json

adm = client("admin", "admin123"); wh = client("warehouse1", "ware123")
dr = client("driver1", "drive123"); ck = client("kesses_clerk", "center123"); mk = client("moiben_clerk", "center123")
au = client("auditor1", "audit123")

# --- voucher: payment -> unique voucher
f = ok(adm.get("/api/farmers"))[0]
v = ok(adm.post("/api/vouchers", json={"farmer_id": f["id"], "bags": 20, "mpesa_ref": "REF001"}))
print("voucher:", v["code"], v["bags"], "bags KES", v["amount"])
ok(adm.post("/api/vouchers", json={"farmer_id": f["id"], "bags": 1, "mpesa_ref": "REF002"}), 400)   # cap 20 reached
ok(adm.post("/api/vouchers", json={"farmer_id": f["id"], "bags": 1, "mpesa_ref": "REF001"}), 400)   # reused mpesa ref

# --- redeem before stock arrives must fail
r = ok(ck.post("/api/redeem", json={"code": v["code"], "otp": v["otp_demo"], "national_id": f["national_id"]}), 400)
print("redeem before stock:", r["error"])

# --- warehouse: 5 pallets x 40 bags = 200 for Kesses (center 1)
codes = ok(wh.post("/api/pallets", json={"center_id": 1, "count": 5, "bags_per_pallet": 40}))["codes"]
other = ok(wh.post("/api/pallets", json={"center_id": 2, "count": 1}))["codes"][0]
wb = ok(wh.post("/api/waybills", json={"truck_plate": "kdb 123x", "driver_name": "Joseph", "center_id": 1}))["id"]
for c in codes: ok(wh.post(f"/api/waybills/{wb}/load", json={"pallet_code": c}))
r = ok(wh.post(f"/api/waybills/{wb}/load", json={"pallet_code": codes[0]}), 400); print("double load:", r["error"])
r = ok(wh.post(f"/api/waybills/{wb}/load", json={"pallet_code": other}), 400); print("wrong center pallet:", r["error"])
r = ok(wh.post(f"/api/waybills/{wb}/load", json={"pallet_code": "PLT-FAKE"}), 400); print("fake code:", r["error"])
r = ok(wh.post(f"/api/waybills/{wb}/dispatch", json={"seal_no": "S1"}), 400); print("dispatch w/o driver:", r["error"])
r = ok(dr.post(f"/api/waybills/{wb}/driver-confirm", json={"pallets": 4, "bags": 160}), 400); print("driver wrong count:", r["error"])
ok(dr.post(f"/api/waybills/{wb}/driver-confirm", json={"pallets": 5, "bags": 200}))
ok(wh.post(f"/api/waybills/{wb}/dispatch", json={"seal_no": "SEAL-001"}))

# --- THEFT: center only scans 4 of 5 pallets, wrong seal
r = ok(mk.post(f"/api/waybills/{wb}/unload", json={"pallet_code": codes[0]}), 403); print("other center blocked:", r["error"])
for c in codes[:4]: ok(ck.post(f"/api/waybills/{wb}/unload", json={"pallet_code": c}))
res = ok(ck.post(f"/api/waybills/{wb}/finalize", json={"seal_no": "SEAL-999"}))
print("finalize:", res["status"], res["issues"])
assert res["status"] == "DISCREPANCY" and "SHORTFALL" in res["issues"] and "SEAL_MISMATCH" in res["issues"]
ds = ok(au.get("/api/discrepancies")); print("alerts:", [(d["kind"], d["bags_missing"]) for d in ds])
assert sum(d["bags_missing"] for d in ds) == 40
al = ok(adm.get("/api/allocations"))[0]; print("center stock (received only):", al["in_stock"])
assert al["in_stock"] == 160

# --- redeem: wrong otp / wrong id / wrong center / success / reuse
bad = ok(ck.post("/api/redeem", json={"code": v["code"], "otp": "000000", "national_id": f["national_id"]}), 400); print("bad otp:", bad["error"])
bad = ok(ck.post("/api/redeem", json={"code": v["code"], "otp": v["otp_demo"], "national_id": "99999999"}), 400); print("bad id:", bad["error"])
bad = ok(mk.post("/api/redeem", json={"code": v["code"], "otp": v["otp_demo"], "national_id": f["national_id"]}), 403); print("wrong center:", bad["error"])
good = ok(ck.post("/api/redeem", json={"code": v["code"], "otp": v["otp_demo"], "national_id": f["national_id"]})); print("redeemed:", good)
assert good["stock_left"] == 140
bad = ok(ck.post("/api/redeem", json={"code": v["code"], "otp": v["otp_demo"], "national_id": f["national_id"]}), 400); print("reuse:", bad["error"])

# --- roles
ok(dr.get("/api/audit"), 403); ok(dr.post("/api/redeem", json={}), 403); ok(ck.post("/api/allocations", json={}), 403)
print("audit rows:", len(ok(au.get("/api/audit"))), "| scans:", len(ok(au.get("/api/scans"))), "| sms:", len(ok(adm.get("/api/sms"))))
print("ALL TESTS PASSED")
