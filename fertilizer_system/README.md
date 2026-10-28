# Fertilizer Slot Allocation & Distribution Tracking (prototype)

## Run
    pip install -r requirements.txt
    python app.py            # open http://localhost:5000
    python test_flow.py      # end-to-end test (uses a temporary database)

## Demo logins (change before real use)
| Role | Username / password | What they do |
|---|---|---|
| Admin | admin / admin123 | allocations, farmers, vouchers, everything |
| Warehouse | warehouse1 / ware123 | build pallets, print labels, load trucks, seal & dispatch |
| Driver | driver1 / drive123 | confirm pallet/bag counts before dispatch |
| Center clerk | kesses_clerk / center123 | receive trucks (scan pallets), redeem vouchers |
| Auditor | auditor1 / audit123 | alerts, scan log, audit log |

## Flow
1. Admin sets allocation (bags + price) per distribution center.
2. Farmer registered (national ID, phone, center, bag cap).
3. Farmer pays (e.g. 20 bags) -> system issues unique voucher code + QR + OTP by SMS. Cannot exceed farmer cap or center allocation; M-Pesa reference cannot be reused.
4. Warehouse builds pallets (unique QR labels), creates a waybill for a truck, scans every pallet on loading. Wrong-center, duplicate, or unknown pallets are rejected and logged.
5. Driver confirms counts, warehouse enters seal number and dispatches.
6. Center scans every pallet at unloading and checks the seal. Missing pallets / seal mismatch / foreign pallets create discrepancy alerts naming truck and driver. Only RECEIVED pallets count as center stock.
7. Farmer collects: clerk scans voucher, enters OTP and checks ID. Voucher is single-use, center-bound, expires after 30 days; stock is deducted.

## Integration with an ERP / other system
See `INTEGRATION.md` and the admin **Integration** tab: API keys, JSON master-data sync (by `external_id`), signed webhook or pull events with retry, CSV import/export. Tests: `python test_integration.py`.

## Still to do for production
- M-Pesa Daraja STK push + callback (see `create_voucher`), SMS gateway (see `sms()`)
- PostgreSQL, HTTPS, strong secrets (`SECRET_KEY`), `DEMO_MODE=0`, change demo passwords
- Offline-capable scanner app (PWA/Flutter) with sync
- Optional: GPS truck tracking, per-bag stickers, reports/exports
