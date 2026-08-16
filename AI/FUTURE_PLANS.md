# FUTURE_PLANS.md — Planned Work & Direction

Sourced from the planning documents at the repository root, cross-checked against what is actually built. **Plans in this repo are frequently ahead of or behind the code — always verify against source before acting on one.**

Related: [KNOWN_BUGS.md](KNOWN_BUGS.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [PERFORMANCE.md](PERFORMANCE.md)

---

## 1. Mobile App — the largest active workstream

`MOBILE_APP_ARCHITECTURE_PLAN.md` (65 KB) is the best-researched document in the repository. It was written from a direct audit of the backend and its §0 findings independently confirm several conclusions in this knowledge base.

### Status: M0–M2 complete, M3–M14 pending
| Milestone | Est. | Scope | State |
|---|---|---|---|
| M0 | 3 d | Contract lock, foundation | ✅ `src/types/backend/` (13 files) |
| M1 | 4 d | Shell, navigation, design system | ✅ routes + `src/ui/` + `src/theme/` |
| M2 | 6 d | Transport + authentication | ✅ `src/api/`, `src/auth/`, cookie mirroring |
| M3 | 6 d | Property discovery | ⬜ stub |
| M4 | 7 d | Detail, gallery, map | ⬜ stub |
| M5 | 4 d | Favorites, saved searches, notifications | ⬜ stub |
| M6 | 7 d | Chat | ⬜ stub |
| M7 | 5 d | Profile, settings, rewards | ⬜ stub |
| M8 | 10 d | Owner mode: listings + uploads | ⬜ stub |
| M9 | 5 d | Leads + analytics | ⬜ stub |
| M10 | 5 d | Agreements | ⬜ stub |
| M11 | 8 d | Projects, units, campaigns, bookings | ⬜ stub |
| M12 | 6 d | Deep linking, offline, performance | ⬜ stub |
| M13 | 4 d | Push notifications | ⬜ **blocked — needs a backend change** |
| M14 | 6 d | Store readiness, release | ⬜ |

Roughly 63 days of the 76-day plan remain.

### Constraints the plan locks in — do not violate
1. **Cookie auth only.** The session token is an opaque 48-byte random string, hashed at rest, never returned in a response body. There is no bearer-token login and no refresh flow. Do not invent one.
2. **The User-Agent must be byte-identical across requests and version-independent.** `validateFingerprintLenient` revokes on OS-family or device-type change. App version goes in `X-App-Version`, never the UA — a version bump in the UA would log out every user on release day.
3. **Socket auth is two-step and uncacheable.** `GET /api/chat/socket-token` mints a 5-minute JWT; every reconnect needs a fresh one.
4. **No generic response unwrapper is possible.** Envelopes differ per endpoint (bare array, bare object, `{success,data}`, `{success,data,count}`, `{data,total,page,pages}`, `{suggestions}`). Each endpoint gets its own typed adapter.
5. **Only `GET /api/properties/search` is paginated.** Infinite scroll must be built on it. `/property-list` and `/filter` return every matching property and must never be called from mobile.
6. **No push infrastructure exists** — no FCM, no APNs, no device-token model, no `pushToken` field anywhere. M13 requires an additive backend change behind a formal change request.
7. **Bundle identifiers `in.dealdirect.mobile` are frozen** (`app.config.js`, 2026-07-31). After a store release neither can change without orphaning installed users.

---

## 2. Builder Project Flow — `PLAN.md`

Feature plan for the Builder → Project → UnitType → GroupBuyCampaign/Booking hierarchy. The infrastructure is built; several features listed remain.

**Feature 1 (flagged as a live bug):** `CampaignCard` in `client-next/src/app/projects/[id]/units/[unitTypeId]/UnitDetailContent.jsx` reads fields the backend never sends — `c.currentBuyers`, `c.maxBuyers`, `c.regularPrice`, `c.groupBuyPrice`. The backend produces `memberCount`, `buyerTargets.maxBuyers`/`.minBuyers`, and `discountPerBuyer` (flat ₹). Campaigns carry no price field at all, so price must be passed down from the parent. Client-only fix, fully specified in `PLAN.md`.

**Cross-cutting rules from that document, worth repeating:**
- Use the **controller-local** `uploadToCloudinary`/`uploadMany` helpers in `projectController.js`/`unitTypeController.js`, **not** the `validateAndUploadToCloudinary` middleware — those routes don't use it.
- Buyers must never see builder phone/email; keep the `isAdmin`-conditional `builderFields` in `getProject` and the hardcoded `salesContact` in `createProject`.
- Any **new** project-level file field must be added to `ALLOWED_PROJECT_FIELDS` in `routes/projectRoutes.js` or the upload 400s.
- Never fold GST / stamp duty / registration into `effectivePrice` — they are additive taxes kept out of the pre-save calculation by design.

---

## 3. Project Creation Fixes — `docs/PROJECT_FIXES_PLAN.md`

A handoff doc with locked decisions. Most appear **already applied**:

| Item | Decision | State |
|---|---|---|
| `POST /api/projects` 401s | Loosen the IP-prefix fingerprint check only, keep OS + device revokes | ✅ applied — `AdminSession.validateFingerprintLenient` now allows IP-prefix change with a refresh |
| `Project.financials` | Keep in schema for back-compat, stop writing it | ✅ still in schema; booking terms live on `UnitType.paymentTerms` |
| Booking/payment location | Move to unit type | ✅ `UnitType.paymentTerms` exists |
| Nominatim CORS | Frontend fix — global `axios.defaults.withCredentials = true` makes third-party calls credentialed, which Nominatim's `ACAO: *` rejects | ⬜ **verify** — `Admin/src/main.jsx` still sets it globally, and the doc warns it cannot simply be removed because `AllCategory`, `AddCategory`, and `AddSubCategory` use bare `axios` for backend GETs and depend on it |
| `POST /api/projects` 500s | Add a fail-fast Cloudinary guard instead of a generic `catch → 500` | ⬜ verify |
| `/api/builders` 409s | Duplicate phone/email — correct behaviour, needs friendly handling | ⬜ open |

---

## 4. Other Planning Documents

| Document | Subject | Notes |
|---|---|---|
| `BLOG_IMPLEMENTATION_PLAN.md` | SEO blog | Appears **complete** — model, controller, routes, admin editor, public pages, JSON-LD all exist |
| `group_buying_implementation_plan.md` | Group buy | Appears **complete** — see [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) §10 |
| `MIGRATION_EXECUTION_PLAN.md` | Vite → Next.js | **Complete.** The `NEXT.JS MIGRATION NOTES` comment blocks throughout `client-next` are its residue |
| `CLIENT_APP_IMPLEMENTATION_GUIDE.md` (49 KB) | Client implementation | Reference |
| `implementation_plan.md` | General | Reference |
| `mongodb_vs_postgresql_analysis.md` | Datastore choice | Decision record — MongoDB retained |
| `SECURITY_FIXES_SUMMARY.md`, `TECHNICAL_REVIEW_FIXES.md`, `Technical_Review_Response.md` | Security remediation | **The origin of the `SECURITY FIX:`, `H4`, `H5`, `H6`, `C2`, `C4`, `C6`, `H12` markers in source.** Read these before touching anything marked with one — the marker means a specific finding was closed there, and reverting the pattern reopens it |
| `adminfixes.md` (34 KB) | Admin fixes | Reference |
| `DealDirect_SOA_Report.md` | Service-oriented architecture | Reference |

---

## 5. Direction Implied by the Code

Things the codebase is visibly built to accommodate but has not yet adopted:

**Redis.** `config/redis.js` ships a `MemoryCache` shaped exactly like ioredis, with the real client commented out and installation instructions in the file. `cacheOrCompute` and `invalidateCache` are exported and unused. This is the intended path and it unblocks horizontal scaling (see [PERFORMANCE.md](PERFORMANCE.md) P5–P8).

**Admin RBAC.** A complete Role/Permission model exists with levels, codes, and `requirePermission`/`requireRoleLevel`/`requireSuperAdmin` middleware — but only 5 endpoints use it. Applying it across the remaining admin surface is a designed-for, unfinished feature ([SECURITY.md](SECURITY.md) M1).

**Referral milestones 2 and 3.** Flags, dates, stats counters, and handler branches all exist for `first_action` and `deal_closure`; nothing fires them ([KNOWN_BUGS.md](KNOWN_BUGS.md) B11).

**Monthly login streak.** `LoginTracker` and `Reward.monthlyLoginDays` both exist for the documented "15+ days/month → 100 pts" rule. Neither awards anything (B12).

**Payment gateway.** `Agreement.payments[]`, the HMAC-verified webhook, and `PAYMENT_WEBHOOK_SECRET` are all built for a gateway that is not connected. Bookings and group-buy tokens use manual UPI + UTR + screenshot instead.

**Sentry on the backend.** `@sentry/node` is installed and `SENTRY_DSN` is configured, but `Sentry.init()` is never called ([DEPENDENCIES.md](DEPENDENCIES.md)).

---

## 6. Suggested Priorities

Not from any plan document — this is the assessment from the audit.

### Correctness first
1. **B17** — mount the chat feature, or confirm it was disabled deliberately and delete it. A 950-line feature is either live or gone; it should not be neither.
2. **B2** — deal verification is unreachable, which blocks the entire deal-reward pipeline.
3. **B1** — account deletion leaves sessions and other records behind. This is a data-retention obligation, not a nice-to-have.
4. **B4** — decide whether `isBanned`/`isActive` on `Property` are real. Right now two documented safety filters do nothing.
5. **PLAN.md Feature 1** — `CampaignCard` renders undefined fields on a live page.

### Then security
6. **SECURITY H2** — make the payment webhook fail closed when the secret is missing.
7. **SECURITY H3** — stop leaking account existence on password reset.
8. **SECURITY H1** — re-enable CSRF (both the commented `app.use` and the `/api/` early-return).
9. **SECURITY M3** — one-word fix for the unescaped chat preview.

### Then foundations
10. Initialise `@sentry/node` — you cannot prioritise performance work without visibility.
11. Introduce Redis; move rate limiting, caching, Socket.IO adapter, and the Hubble token store onto it. This is the single change that unblocks scaling.
12. Add a test runner. There is currently **no automated verification of anything**, and every fix above must be tested by hand.

### Then the plans
13. Mobile M3 onward.
14. Apply `requirePermission` across the admin surface.
15. Extract `Reward.transactions` into its own collection before a heavy user hits the BSON ceiling.
