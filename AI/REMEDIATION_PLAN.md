# REMEDIATION_PLAN.md — Verified Findings & Execution Plan

Created 2026-08-01, after the first fix round shipped to production.

**Every finding below states how it was verified.** Items that could not be proven reachable are marked as such and ranked accordingly — this follows two false positives earlier in the audit (chat "not mounted" was an intentional client decision; "bank details in plaintext" had no write path at all).

Related: [KNOWN_BUGS.md](KNOWN_BUGS.md) · [SECURITY.md](SECURITY.md) · [PERFORMANCE.md](PERFORMANCE.md) · [CHANGELOG_AI.md](CHANGELOG_AI.md)

---

## Verification legend

| Mark | Meaning |
|---|---|
| 🔬 **PROVEN** | Reachability demonstrated against running code or production |
| 📖 **CODE-ONLY** | Confirmed in source; user-facing reachability not demonstrated |
| 💭 **DESIGN** | Not a defect — a gap or decision needing a product answer |

---

## P0 — Do first

### P0.1 🔬 Unescaped regex on a **public** endpoint (ReDoS)
**`backend/controllers/projectController.js:318`** — `listProjects`

```js
if (city) filter["location.city"] = { $regex: city, $options: "i" };
```

Route is `router.get("/", attachAdminIfPresent, listProjects)` — **public, unauthenticated**.

**Proof:** `GET /api/projects?city=^Mum` against production returned filtered results, confirming the input is compiled as a regex rather than matched literally. *(A catastrophic-backtracking payload was deliberately not fired at the live site.)*

**Impact:** any anonymous visitor can send a pathological pattern and pin a CPU core. The endpoint is rate-limited only by the global limiter (500 / 15 min), which is far more than enough to sustain an outage.

**Fix:** escape with the existing `escapeRegExp` helper, or switch to the `$text` index already defined on `Project`.

**Effort:** ~15 min · **Risk:** very low

---

### P0.2 🔬 Same flaw, 11 more sites (admin-only)
| File | Lines | Reachable by |
|---|---|---|
| `leadController.js` | 551 | Admin Lead Monitoring search box — **proven**: the page sends `search` straight through |
| `builderController.js` | 32–35 | Admin builder search |
| `contactController.js` | 82–85 | Admin inquiries search |
| `rewardsController.js` | 300–301 | Admin rewards overview search |

Only `propertyController` (4 sites) and `adminController:1401` escape correctly today.

**Impact:** lower than P0.1 — requires an admin session — but an admin pasting a string containing regex metacharacters can hang the API by accident, with no error to explain it.

**Fix:** extract `escapeRegExp` into `backend/utils/` and apply at all 12 sites, so there is one implementation instead of three.

**Effort:** ~1 hr · **Risk:** low — pure input sanitisation

---

## P1 — High value, low risk

### P1.1 🔬 Property visibility filters are decorative (was B4)
`isBanned` and `isActive` are **not on `propertySchema`** (`grep -c` → 0). Mongoose `strict` silently drops them, so every public query's safety clause matches everything:

```js
$or: [{ isActive: { $ne: false } }, { isActive: { $exists: false } }],
isBanned: { $ne: true },
```

Also silently dropped: `approvedAt`, `approvedBy`, `disapprovedAt`, `disapprovedBy` (written by admin approve/disapprove) and `location` (GeoJSON).

**Impact:** there is **no working ban or soft-delete for a listing** — only `isApproved` and `status`. Admin approve/disapprove audit stamps are lost. Geo queries are impossible.

**Decision needed:** which of these are real features? Adding `isActive`/`isBanned` to the schema changes the meaning of existing filters, so any migration must backfill (`isActive: true`, `isBanned: false`) in the same step.

**Effort:** 2–3 hrs incl. backfill · **Risk:** medium — touches every public read

---

### P1.2 🔬 Rewards promised but never awarded
| Feature | Reality | Verified |
|---|---|---|
| 5+ photo bonus | `awardPoints("upload_5_photos")` — action absent from `ACTION_CATEGORY_MAP`, returns `{success:false}`, result discarded | 🔬 line 537, fires on every owner listing with ≥5 images |
| Referral milestone 2 (`first_action`) | Handler exists; **nothing ever calls it**. Action also missing from the map | 🔬 |
| Referral milestone 3 (`deal_closure`) | Same | 🔬 |
| "Log in 15+ days/month → 100 pts" | `LoginTracker` collection **never written**; `trackDailyLogin` writes to `Reward.monthlyLoginDays` and awards nothing | 🔬 |

**Impact:** users take actions the product tells them are rewarded and receive nothing. Silent — only a `console.warn`. Trust issue, not security.

**Decision needed:** implement these, or remove the promises from the UI copy. Half-built is the worst of both.

**Effort:** 1 day to implement all four · **Risk:** low

---

### P1.3 🔬 Unbounded public endpoints
Measured against production today:

| Endpoint | Size | Docs |
|---|---|---|
| `/api/properties/property-list` | 100 KB | 147 |
| `/api/properties/list` | 105 KB | 147 |
| `/api/properties/filter` | 100 KB | 147 |

None paginate. At ~700 bytes/property, **10 000 listings ≈ 7 MB per request**. `/filter` additionally loads everything into memory, then filters and sorts in JavaScript.

Also unbounded: `getMyProperties`, `getMyBookings`, `getMyInquiries`, `getPropertyLeads`, `getMyNotifications`.

**Impact:** none today at 147 properties. Becomes the first thing that breaks as inventory grows, and it degrades gradually rather than failing loudly.

**Fix:** add `limit`/`page` with sane defaults; push `/filter`'s populated-field matching into an aggregation.

**Effort:** 3–4 hrs · **Risk:** medium — response shapes change, both frontends need updating in step

---

### P1.4 🔬 Socket JWT accepted as a REST bearer token (B7)
`GET /api/chat/socket-token` mints a 5-minute JWT `{id, purpose:'socket_auth'}`. `handleJWTAuth` **never inspects `purpose`** (verified: no `purpose` reference in `authUser.js`), so the token authenticates ordinary REST calls.

**Impact:** narrow — the requester is already authenticated, window is 5 minutes. But the token crosses into a third-party real-time layer and was not scoped for API use.

**Fix:** reject `decoded.purpose && decoded.purpose !== 'api'` in `handleJWTAuth`. Three lines.

**Effort:** 15 min · **Risk:** very low

---

## P2 — Data retention (needs your decisions)

### P2.1 💭 Orphaned Cloudinary assets (B26)
Every property deleted **before** the 2026-08-01 fix left its images on Cloudinary — publicly reachable and still billed. Three sources: the owner-path `slice(-2)` bug, the admin path never walking `categorizedImages`, and account deletion having no cleanup at all.

**Plan:** reconciliation script — list `dealdirect/properties` via the Cloudinary Admin API, collect every URL still referenced by a `Property`, destroy the difference.
⚠️ **Dry-run first.** Must also exclude assets referenced by `Project.media`, `UnitType.photos`, `Builder.logoUrl`, and `Blog.coverImage`.

**Effort:** 3 hrs incl. dry run · **Risk:** high if rushed — deletes real images if the "still referenced" query is wrong

### P2.2 💭 Deal-closure documents never deleted (B23) — *accepted risk, pending client*
Sale deeds, agreements, and ID documents on permanent public Cloudinary URLs. No deletion path anywhere. You are discussing handling with the client.

### P2.3 💭 Six collections retain a deleted user's PII (B27)
`Lead`, `Agreement`, `TransactionVerification`, `RedemptionRequest`*, `CampaignMember`, `ProjectBooking` each carry a `userSnapshot` with name, email, and phone that survives account deletion.
*(`RedemptionRequest` has since been deleted, so five remain.)*

**Options per collection:** delete · anonymise (strip `userSnapshot`, null the ref) · retain for a defined period. Anonymising is usually right for the counterparty-facing ones — the owner keeps a usable lead history without holding a deleted user's contact details.

---

## P3 — Correctness cleanup

| # | Finding | Status | Effort |
|---|---|---|---|
| P3.1 | `validatePropertyCreate` commented out of the route (B13) — no length/type/enum validation on property creation. The controller whitelist still blocks mass assignment; what's lost is **value** validation. Blocked on reconciling two disagreeing field lists | 🔬 verified still disabled | 2 hrs |
| P3.2 | `propertyApi.search()` sends `q`; backend reads `search` (B19) | 📖 helper unused by screens — trap for the next dev | 5 min |
| P3.3 | `notificationApi` calls `PUT`; routes are `PATCH`, one path also wrong (B20) | 📖 same | 5 min |
| P3.4 | `fetchCsrfToken()` reads a field the server deliberately removed (B15) | 📖 always returns `undefined`, unused | 5 min |
| P3.5 | Six duplicate Mongoose index definitions (B24) — 6 warnings every boot train you to ignore startup output | 🔬 seen on every boot | 30 min |
| P3.6 | Dead `newLead` email template (B25) — owners get the generic template instead of the designed one | 🔬 `createLead` only appears in a comment | 30 min |
| P3.7 | `PasswordResetToken` model + validate endpoint dead (B8); live path uses fields the schema calls "deprecated" | 🔬 | 2 hrs to migrate, 15 min to delete |
| P3.8 | Orphaned components (B18) — incl. two **duplicate** implementations (`AgreementGenerator`, `LogoLoop`) where the live copy is inlined elsewhere | 🔬 | 1 hr |
| P3.9 | Dead MFA code in `AuthContext` (B9/B10) — calls two non-existent endpoints, redirects to three non-existent routes | 🔬 unreachable | 30 min |
| P3.10 | 6 unused backend dependencies (`jspdf`, `jspdf-autotable`, `morgan`, `body-parser`, `file-type`, `axios`) | 🔬 grep-verified | 15 min |
| P3.11 | Chat inbox preview stores unescaped HTML (B3) | 🔬 code confirmed; **not reachable while chat is hidden** — fix before re-enabling | 1 min |

---

## P4 — Foundations

| # | Item | Why |
|---|---|---|
| P4.1 | **No test suite anywhere** | Every fix in this document is verified by hand. This is the single largest risk multiplier — it is why the deal-verification regression shipped unnoticed |
| P4.2 | **Single-instance-only backend** | Socket.IO presence, Hubble SSO tokens, all rate-limit counters, upload concurrency and cache are in-process. `config/redis.js` already ships an ioredis-shaped shim with the real client commented out |
| P4.3 | **Notification email fan-out is synchronous** | `post('save')` does a User lookup + SMTP send per document, inside the request path |
| P4.4 | **Saved-search matching is O(all active searches)** per property creation, loaded into memory |
| P4.5 | **Admin RBAC applied to 5 of ~40 endpoints** | Accepted while there is one admin; revisit before adding staff |
| P4.6 | **Mail still sends from a personal Gmail** | Migration package ready; deprioritised by owner |

---

## Suggested sequencing

**Round 1 — half a day, near-zero risk**
P0.1 · P0.2 · P1.4 · P3.2 · P3.3 · P3.4 · P3.10
→ Closes the only publicly-exploitable issue and clears the trivia. No behaviour change users can see.

**Round 2 — one day, needs decisions**
P1.2 (rewards: implement or remove the promises) · P3.5 · P3.6 · P3.9 · P3.11
→ Mostly deletion and small features. Needs your answer on the reward promises first.

**Round 3 — two days, medium risk, test carefully**
P1.1 (property schema fields + backfill) · P1.3 (pagination) · P3.1 (re-enable validation)
→ Touches public reads and response shapes. Both frontends must move in step. Do **not** batch with Round 1.

**Round 4 — needs client input**
P2.1 (orphan cleanup, dry-run first) · P2.2 (deal documents) · P2.3 (PII retention)

**Round 5 — foundations**
P4.1 tests first, then P4.2 Redis. Everything else is easier afterwards.

---

## Decisions blocking work

1. **Rewards (P1.2)** — implement the 5-photo bonus, referral milestones 2–3, and the login streak? Or remove the promises from the UI?
2. **Property flags (P1.1)** — are `isBanned` / soft-delete real features, or should the dead filter clauses simply be removed?
3. **Deleted-user PII (P2.3)** — delete, anonymise, or retain, per collection?
4. **Orphan cleanup (P2.1)** — go ahead with a dry-run?
5. **`/filter` endpoint (P1.3)** — is it still used by any screen, or can it be retired instead of paginated?

---

## Explicitly not included

- **Chat** — hidden by client decision. Not a defect.
- **Agreements** — hidden by client decision. ⚠️ Re-enabling re-opens the unauthenticated payment webhook ([SECURITY.md](SECURITY.md) H2); set `PAYMENT_WEBHOOK_SECRET` or make it fail closed first.
- **Forgot-password account enumeration** — accepted, UX trade-off.
- **Admin RBAC gaps** — accepted while there is a single admin.
- **`bankDetails` in plaintext** — withdrawn, was a false positive.
