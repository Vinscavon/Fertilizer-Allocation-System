# Connecting this system to an ERP or any other system

Three methods. Use one or combine them.

| Method | Direction | Best when |
|---|---|---|
| **A. JSON API** | ERP -> here (master data) | The ERP can call web APIs |
| **B. Events: push (webhook) or pull** | here -> ERP (payments, redemptions, deliveries) | The ERP wants to post receipts and stock movements |
| **C. CSV import/export** | both | The ERP has no API, or as a first step |

Admin screen: **Integration** tab (create API keys, see event delivery, download/upload CSV).

## 1. Authentication
An admin creates a key in the Integration tab (or `POST /api/integration/keys {"name":"County ERP"}`).
Send it on every call: `X-API-Key: fk_...`. The key is shown once; revoke it any time.

## 2. Settings (environment variables)
| Variable | Purpose |
|---|---|
| `ERP_WEBHOOK_URL` | Where to push events. Leave empty to use pull mode only |
| `ERP_WEBHOOK_SECRET` | Shared secret used to sign pushes (HMAC-SHA256) |
| `SECRET_KEY`, `DEMO_MODE=0`, `FERT_DB` | Production settings |

## 3. Master data into this system (ERP is the source of truth)
`POST /api/integration/centers | farmers | allocations` with a JSON list. Records are matched on `external_id`
(your ERP's own ID), then on name / national ID. Sending the same record again updates it, never duplicates it.
Each call returns `{"created":n,"updated":n,"errors":[{"row":2,"error":"..."}]}`; good rows are saved even if others fail.

```bash
curl -X POST $URL/api/integration/centers -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '[{"external_id":"ERP-C1","name":"Ziwa Depot","area":"Soy"}]'

curl -X POST $URL/api/integration/farmers -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '[{"external_id":"ERP-F1","national_id":"30000001","name":"Mary Jebet","phone":"+254711000001","center_external_id":"ERP-C1","max_bags":10}]'

curl -X POST $URL/api/integration/allocations -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '[{"center_external_id":"ERP-C1","total_bags":500,"price_per_bag":3600}]'
```

## 4. Events out of this system
| Event | When | Suggested ERP action |
|---|---|---|
| `voucher.created` | Farmer paid, voucher issued | Post receipt / sales order (with `mpesa_ref`, `amount`) |
| `waybill.dispatched` | Truck sealed and left | Stock transfer: warehouse -> in transit |
| `waybill.finalized` | Center finished unloading | Goods receipt for `bags_received`; loss/write-off for `bags_missing` |
| `voucher.redeemed` | Farmer collected bags | Delivery / stock issue to farmer |

Sample push body:
```json
{"id": 12, "type": "voucher.created", "created_at": "2026-10-28 10:15:00",
 "data": {"code": "FV-2DYJ62R2JY", "bags": 20, "amount": 70000.0, "mpesa_ref": "SJK4X9L2QW",
          "expires_at": "2026-11-27 10:15:00",
          "farmer": {"external_id": "ERP-F1", "national_id": "30000001", "name": "Mary Jebet", "phone": "+254711000001"},
          "center": {"external_id": "ERP-C1", "name": "Ziwa Depot"}}}
```

**Push (webhook):** headers `X-Event-Id`, `X-Event-Type`, `X-Signature`. The ERP must reply `2xx`.
Anything else is retried (30 s, 1 min, 2 min ... up to 1 h, 10 tries, then marked FAILED; admin can retry).
Delivery is at-least-once, so **use `X-Event-Id` to ignore repeats**. Verify the signature:
```python
import hmac, hashlib
expected = hmac.new(SECRET.encode(), raw_body, hashlib.sha256).hexdigest()
assert hmac.compare_digest(expected, request.headers["X-Signature"])
```
**Pull:** `GET /api/integration/events?after_id=0&limit=100`, process, then
`POST /api/integration/events/ack {"ids":[12,13]}`. Unacknowledged events keep coming back.

Events are saved in the same database transaction as the business action, so none is lost if the ERP is offline.

## 5. CSV
**Export** (`GET /api/integration/export/<name>.csv`): `vouchers`, `farmers`, `centers`, `allocations`, `stock`, `waybills`, `discrepancies`.
**Import** (`POST /api/integration/import/<centers|farmers|allocations>`, upload field `file` or raw CSV body):

| Type | Columns |
|---|---|
| centers | `external_id, name, area` |
| farmers | `external_id, national_id, name, phone, center_external_id` (or `center`), `max_bags` |
| allocations | `center_external_id` (or `center`), `total_bags, price_per_bag, product` |

## 6. Questions to ask the ERP team
1. Does the ERP have a REST/SOAP API or only file import? (decides method A/B or C)
2. What are the IDs for farmers, depots and products? (use as `external_id`)
3. Which accounts/GL codes should payments, stock transfers and write-offs post to?
4. Can the ERP receive webhooks, or must it poll?
5. Does KIAMIS (or another registry) remain the master list of farmers?
