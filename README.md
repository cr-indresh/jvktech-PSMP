# Publication & Sales Operations Management Portal (PSMP) — JVK Technologies

A Django 5 proof of concept recreated **exactly to the FTSD specification**
(*Detailed Functional & Technical Specifications Document v1.0.0*): a
role-separated portal that tracks academic publishing deals end to end —
from BDE slot booking to Accounts payment clearing to the 7-stage
publication lifecycle, with a full admin analytics + audit layer.

## Spec coverage map (FTSD Sec. → implementation)

| FTSD | Requirement | Where |
|------|-------------|-------|
| Sec.2.0 | Role matrix (Super Admin / BDE / Accounts+Ops) | Role-separated dashboards + server-side role checks on every endpoint |
| Sec.3.1 | 13-category service master, base price, slot config, admin-configurable | `ServiceType` (seeded with the exact catalogue) + Admin → Service Catalog |
| Sec.3.1 | Title max 500 chars | `Project.title` |
| Sec.3.2 | Full author profile (position, designation, department, company, address, city/district/state/country/pin, nationality, email, mobile) | `Author` + BDE creation form + project page |
| Sec.3.3 | Installment log: auto number, phase (Advance / Installment 2 / Remaining), amount paid, transaction ref, mode (UPI/Bank), date, remarks | `PaymentInstallment` + BDE payment logging |
| Sec.3.3 | **Paying author per installment** (authors pay individually) | `PaymentInstallment.author` FK — paid-by picker on every payment form + payer column on Accounts queue, Admin payment ledger and the project page |
| Sec.3.3 | **Transaction ref (UTR) + entry ID visible to Accountant & Admin** | Accounts queue / verified tables + Admin “Payment ledger — UTR register” (every DB entry: author, UTR, entry ID, status, cleared by) |
| Sec.3.3 | verification_status: Pending / Verified / **Rejected** | Accounts dashboard clearing queue (Verify / Reject / Revert) |
| Sec.3.4 | Editorial status: Draft → Submitted → Under Review → Accepted → Published → Completed / Withdrawn | `Project.publication_status` + Accounts lifecycle modal |
| Sec.3.4 | Acceptance proof upload (PNG/JPG/PDF ≤ 10 MB) + live publication URL | Accounts lifecycle modal (multipart upload) |
| Sec.4.1 | App provisions total author slots; booked slot LOCKS for others | `Project.total_slots` from the catalogue + UNIQUE(project, position) + capped form |
| Sec.4.2 | Remaining balance = SaleValue − Σ installments; rows default to Pending | Live schedule calculator + default PENDING |
| Sec.4.3 | Accounts clearing + operations lifecycle + instant BDE visibility | Accounts dashboard + BDE "My projects" payment/lifecycle cells |
| Sec.5.0 | Filters: BDE, category, payment status (Fully Paid / Advance Paid / Overdue), lifecycle, date range | Admin dashboard filter sidebar |
| Sec.5.0 | Export engine (CSV/Excel) | One-click **Export CSV** of the filtered table (Excel-friendly BOM) |
| Sec.5.0 | KPIs: receivables vs collected, volume by category, outstanding aging per BDE | Admin KPI cards + breakdown + aging report |
| Sec.7.0 | Data immutability: verified installments locked for BDE | Server-side lock + "ask Accounts to revert" approval flow |
| Sec.7.0 | Audit trail: timestamp, user, action, old/new values | `AuditLog` + Admin → Audit Trail page — filterable by role / team member / action, full paginated history, readable field-by-field old → new diffs (never raw JSON), sign-in / sign-out tracking |
| Oversight | Admin can DO every Accountant / BDE action — and correct any of them | Accounts Workspace (verify / reject / revert payments + publication status), BDE Workspace (create deals, attribute to any executive), edit project / authors / payments on ANY project, admin payment overrides (edit ANY payment incl. verified · revert verifications), full audit trail + per-member "every action" links |
| Sec.7.0 | Field-level encryption (phones + UTRs) | `EncryptedCharField` (stdlib cipher, zero crypto deps) at rest |
| Sec.7.0 | Role-isolated endpoints, token/session auth | Session auth + `role_required` on every endpoint |
| Transcript Sec.2 | Slot & position configuration per service | Service Catalog (base price + slot limits) |
| Transcript Sec.3 | Copy/paste / bulk paste author details | BDE "Quick paste client details" parser |
| Transcript Sec.7 | Office-IP whitelist, admin remote access | `LocationAndDeviceSecurityMiddleware` |

## Tech stack

| Layer    | Choice                                                  |
|----------|---------------------------------------------------------|
| Backend  | Python 3.12 · Django 5.1 (`django>=5.1,<6.0`)           |
| Security | Standard-library field cipher (SHA-256-CTR + HMAC-SHA256) |
| Database | SQLite (zero-config, file at `db/db.sqlite3`)           |
| Frontend | Django templates · Tailwind CSS (Play CDN) · vanilla JS |

No build step and no external services are required. The only network
dependency is the Tailwind CDN + Google Fonts (styling). No Pillow is
needed — proofs are plain `FileField`s.

## Quick start

```bash
# 1) create an isolated environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2) install dependencies
pip install -r requirements.txt

# 3) run — the repo already ships a seeded SQLite DB + demo proof images
python manage.py runserver       # http://127.0.0.1:8000/
```

To start from an empty database instead:

```bash
rm db/db.sqlite3
python manage.py migrate
python manage.py seed_demo       # idempotent demo dataset (16 projects)
```

## Demo credentials (shipped DB)

| Role     | Username  | Password   |
|----------|-----------|------------|
| Admin    | admin     | Admin@123  |
| BDE      | bde.priya | Demo@123   |
| BDE      | bde.arjun | Demo@123   |
| Accounts | acc.meera | Demo@123   |

The seeded dataset covers all 13 catalogue categories, **all seven
lifecycle stages**, Verified + Pending + Rejected payments, payment
modes/dates/remarks, full author profiles (encrypted phones), payment
proof receipts and acceptance letters.

## Project layout

```
config/            Django project (settings, root urls, ASGI/WSGI)
tracker/
  models.py        ServiceType, Project (slots + lifecycle), Author,
                   PaymentInstallment (3-state clearing), AuditLog,
                   EncryptedCharField (stdlib cipher at rest)
  views.py         Role dashboards, clearing/lifecycle JSON APIs,
                   admin filters + CSV export + aging, service catalog,
                   audit trail, slot provisioning
  forms.py         Auth, project, author, installment, status, service,
                   team forms (role-scoped field whitelists)
  middleware.py    Office-IP whitelist (admins bypass) · iframe-compatible cookies
  decorators.py    role_required and login helpers
  templates/       Shared shell + one dashboard per role + Service
                   Catalog + Audit Trail
  management/commands/seed_demo.py
db/db.sqlite3      Pre-seeded demo database
media/             Uploaded payment proofs + acceptance letters (demo data included)
```

## Security model (PoC level)

- Session auth + Django's CSRF protection everywhere — including the JSON
  `fetch()` endpoints, which read the server-rendered
  `<meta name="csrf-token">`.
- Role-based access: every dashboard and every mutating endpoint re-checks
  the role server-side; Accounts can never touch sale values (the fields
  simply do not exist in its forms).
- **Data immutability (FTSD Sec.7.0):** once Accounts verifies a payment, the
  BDE can no longer edit or delete it; Accounts must revert it first (the
  admin-approval flow). Rejected payments can be corrected by the BDE and
  are re-queued as Pending.
- **Field-level encryption (FTSD Sec.7.0):** author phone numbers and payment
  transaction references are stored as authenticated ciphertext
  (`enc::v2.…`, SHA-256-CTR keystream + HMAC-SHA256 tag, keys derived from
  `settings.FIELD_ENC_KEY`) — implemented with the Python standard library
  only, so decryption can never break because of a missing crypto package.
  The ORM decrypts transparently on every screen. Set a dedicated secret
  in production.
- **Audit trail (FTSD Sec.7.0):** every critical operation (create/update/
  delete of projects, authors, payments, verifications, lifecycle changes,
  team and catalogue operations) is logged with timestamp, user, action
  and old → new values, visible to admins on the Audit Trail page.
- Office-IP whitelist middleware: non-admin roles are restricted to the
  office IP range; admins are allowed remote access.
- Deleting a project-owning BDE cascades their projects (authors,
  installments, proofs) in one transaction behind an escalating confirm.

## Notes

- `DEBUG=True` and placeholder secrets ship with this PoC on purpose.
  Before any real deployment set `DEBUG=False`, a real `SECRET_KEY`, a
  dedicated `FIELD_ENC_KEY` and explicit `ALLOWED_HOSTS`.
- The sandbox preview reaches this app through a gateway; since Task 34
  the gateway root serves the app at clean URLs (the Next.js dev server
  transparently proxies every non-Next path — `/login/`, `/dashboard/`,
  `/static/**`, … — to the Django service), so no query parameter is
  visible in the address bar.  The legacy `?XTransformPort=...` deep
  links keep working; the `qp` context processor only appends that param
  when the current request already carries it, and is a no-op (`""`) in a
  normal deployment like this one.
