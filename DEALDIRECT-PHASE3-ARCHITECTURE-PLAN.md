# DealDirect — Phase 3 Architecture & Target-State Plan

**Produced:** 2026-08-16 · **Status:** planning only. No application code was modified, no migration was executed, no write of any kind was made to any collection.

**Repository context.** This is the development/source repository. `origin/main` here is a development checkpoint, not production. The live production repository is separate and receives finalised code after remediation, architecture work, testing and review. Nothing in this plan assumes or touches production infrastructure.

**Inputs.** [DEALDIRECT-SYSTEM-FLOW-AUDIT.md](DEALDIRECT-SYSTEM-FLOW-AUDIT.md) (current-state audit), Phase 0–2 as shipped (`4dea196`…`898896c`), and fresh read-only queries run against the development database on 2026-08-16 for the migration sections.

---

## 1. Current-State Summary

Phases 0–2 are complete: 471 tests across 92 suites, and the defects that made individual request handlers untrustworthy are closed. What remains is structural — the problems that live *between* handlers rather than inside them.

| Area | State after Phase 2 |
|---|---|
| Request-handler correctness | Good. Ownership checks, field whitelists, rate limits, regex safety, atomic claims all in place |
| Cross-handler invariants | **Weak.** No cascades, no enforced state transitions, no shared field contract beyond property |
| Data integrity | **Two known corruptions**, neither migrated: property taxonomy, one booking amount |
| Test coverage | Source-level and unit. **No integration tests, no test database** |
| Authorization | Working but half-built: RBAC on 5 of ~75 admin endpoints, structurally unusable |
| Notifications | Correct but architecturally misplaced: delivery inside a Mongoose post-save hook |
| API client | Two-thirds dead helpers; screens hand-write URLs |
| Scaling | Single-instance only. Six in-process stores; `REDIS_URL` read and ignored |

**The headline finding of this planning pass** is in §5: the property taxonomy is not merely corrupt, it is *semantically inverted*. That changes the migration from a backfill into a product decision.

---

## 2. Target-State Architecture

The target is not a rewrite. It is the current architecture with four properties added:

1. **Invariants are enforced where they are defined.** State transitions in the model or a guard, not scattered across controllers.
2. **Referential integrity is explicit.** Every delete either cascades deliberately or is refused.
3. **Side effects are visible.** Email leaves the model layer and becomes a call you can grep for.
4. **Correctness is provable.** An integration suite against a real database, so cascade and concurrency behaviour is executed rather than asserted from source text.

```
                         ┌──────────────────────────────┐
  Clients                │  typed API layer (one per     │
  web · admin · mobile   │  endpoint, no drifting stubs) │
                         └───────────────┬──────────────┘
                                         ▼
                         ┌──────────────────────────────┐
                         │  Express routes (unchanged)   │
                         │  auth → authz → validate      │
                         └───────────────┬──────────────┘
                                         ▼
                         ┌──────────────────────────────┐
                         │  Controllers (business logic) │
                         │  + state-transition guards    │  ← NEW
                         │  + explicit notify() calls    │  ← NEW
                         └───────────────┬──────────────┘
                                         ▼
                         ┌──────────────────────────────┐
                         │  Models                       │
                         │  + cascade / delete-refusal   │  ← NEW
                         │  − email side effects         │  ← REMOVED
                         └───────────────┬──────────────┘
                                         ▼
                              MongoDB · Cloudinary · external
```

Deliberately **not** in the target: a service layer for domain logic, a monorepo, GraphQL, or a rewrite of the four apps into shared packages. Each would be a large change justified by taste rather than by a defect in this audit.

---

## 3. Target Business Flows

### 3.1 Master flow — CURRENT vs TARGET

```
                          VISITOR
                             │
              ┌──────────────┴──────────────┐
        browse / search               register
     CURRENT: capped 50 (fixed 2.2)   CURRENT: buyer direct · owner SMS OTP
     TARGET:  server-side, paginated  TARGET:  unchanged
              └──────────────┬──────────────┘
                             ▼
                       AUTHENTICATED
                    ┌────────┴────────┐
                 BUYER              OWNER
                    │                 │
                    │           CREATE PROPERTY
                    │      CURRENT: auto-approved, ~34 fields dropped (fixed 2.2/0.5)
                    │      TARGET:  auto-approved, full field contract, one listing/owner
                    │                 │
                    │            PUBLIC LISTING
                    ▼                 │
             PROPERTY DETAIL ◄────────┘
   CURRENT: owner phone+email public (FIXED Phase 1)
   TARGET:  name + photo only; contact reaches the buyer through the lead
                    │
              EXPRESS INTEREST
   CURRENT/TARGET: max 5 active, one per property, lead created, owner notified
                    │
                    ▼
                  LEAD
   CURRENT: 6 statuses, no transitions enforced, deal flow never writes it
   TARGET:  enforced transitions; deal closure writes `converted`
                    │
                    ▼
             NEGOTIATION  ← PRODUCT DECISION, see §3.9
   CURRENT: does not exist; happens off-platform via tel/mailto/wa.me
   TARGET:  option A keep off-platform (default) · option B on-platform offers
                    │
                    ▼
          DEAL SUBMITTED (owner)
   CURRENT: proof docs + named buyer; buyer now notified (2.8)
   TARGET:  + property reserved while pending; + upload after authorization
                    │
                    ▼
            ADMIN VERIFICATION
   CURRENT: approve → sold/rented · reject → active; both terminal
   TARGET:  + correction path for a wrong approval
                    │
                    ▼
                 CLOSURE
   CURRENT: sold/rented terminal; still listed publicly until 2.2's status filter
   TARGET:  removed from discovery, lead marked converted, both parties notified
                    │
                    ▼
            REWARDS / POST-DEAL
   CURRENT: pull-based claim, once per party, atomic (Phase 1)
   TARGET:  unchanged
```

### 3.2 Seller journey

| Stage | CURRENT | TARGET | GAP |
|---|---|---|---|
| Register | SMS OTP, hard dependency on Equence (500 if unconfigured) | Same, but a configuration failure returns a clear error rather than 500 | Small: error mapping |
| Create listing | One per owner, auto-approved, transaction-guarded | Same | None |
| Moderation | Admin disapproves reactively; owner sees reason and can fix (2.1) | Same | None |
| Receive leads | In-app + email + WhatsApp; viewed/contact now recorded (2.7) | Same | None |
| Negotiate | Off-platform via deep links | Decision §3.9 | Product |
| Close deal | Uploads before authorization; property not reserved | Authorize → upload; property reserved while pending | Architecture |
| Get paid | Pull-based reward claim | Same | None |

### 3.3 Buyer journey

| Stage | CURRENT | TARGET | GAP |
|---|---|---|---|
| Discover | Server-side search, paginated (2.2) | Same + working taxonomy filters | **Data migration** (§5) |
| View property | Owner name + photo only | Same | None |
| Express interest | Max 5 active; lead created; enquiry reward | Same + refuse interest on sold/rented listings | Small guard |
| Await contact | Owner calls/emails/WhatsApps | Same, or on-platform (§3.9) | Product |
| Named in a deal | Notified on submission and rejection (2.8) | Same + notified on reservation | None material |
| Claim reward | Atomic, once (Phase 1) | Same | None |

### 3.4 Admin journey

| Stage | CURRENT | TARGET | GAP |
|---|---|---|---|
| Log in | TOTP MFA, lockout, audit trail | Same | None |
| Moderate listings | Approve/disapprove with reason | Same + audit entry per action | Small |
| Verify deals | `protectAdmin` only; no attributed audit | Same + attributed audit with before/after | Small, blocked on the `AuditLog.category` enum |
| Adjust rewards | Capped, reasoned, audited (Phase 1) | + permission check | **RBAC decision** (§7) |
| Manage taxonomy | Reachable since 2.9 | Same, over a coherent taxonomy | **Data/product decision** (§5) |
| Manage campaigns | No UI for members or payments | Admin UI for the 6 orphaned endpoints | Product (Group Buy) |
| Read audit log | **No UI at all** | A viewer for `GET /admin/audit-logs` | Small build |

### 3.5 Property lifecycle

**CURRENT** — two independent axes, which is the root of the confusion:

```
moderation:  isApproved  true ⇄ false        (admin only)
lifecycle:   status      active → pending_verification → sold | rented
                                            → active (on reject)
             plus enum values never written: pending, inactive
```

**TARGET** — same two axes, with transitions enforced and dead values removed:

```
              create
                ↓
         active + approved ──────────┐
           │        ▲                │ owner submits deal
   admin   │        │ admin approve  ▼
disapprove │        │          reserved (pending_verification)
           ▼        │            │            │
     active + disapproved   admin approve  admin reject
     (hidden, owner can fix)     │            │
                                 ▼            └──→ active + approved
                            sold | rented
                                 │
                            admin correction ──→ active  ← NEW, audited
```

**GAP:** transition guard; drop `pending`/`inactive` from the enum or start using them; add the correction path; reserve the property while a verification is pending.

### 3.6 Lead lifecycle

**CURRENT** — six statuses, every edge legal in both directions, no terminal state, and the deal flow never touches it. `conversionRate` therefore measures a self-set field.

**TARGET**

```
new ──→ contacted ──→ interested ──→ negotiating ──→ converted   [terminal]
 │           │              │              │
 └───────────┴──────────────┴──────────────┴────────→ lost       [terminal]

 · forward moves and "lost" are owner-settable
 · `converted` is written by the SYSTEM on deal approval, not by the owner
 · backward moves are refused; a mistake is corrected by an admin
```

**GAP:** transition table; write `converted` from `approveDealVerification`; make `converted`/`lost` terminal.

### 3.7 Deal lifecycle

**CURRENT**

```
TransactionVerification: pending → approved | rejected   (both terminal)
claims: ownerClaimed / buyerClaimed, atomic since Phase 1
```

**TARGET** — same states, three additions:

```
pending ──approve──→ approved ──→ (claims) ──→ settled
   │                    │
   │                    └── admin correction ──→ rejected   ← NEW, audited
   └──reject──→ rejected

 + the property is RESERVED while pending (blocks new interest)
 + deletion of a property with a pending verification is REFUSED
 + Lead.status := converted on approval
```

**GAP:** reservation, delete-refusal, lead write, correction path.

### 3.8 Group-buy lifecycle

**CURRENT** — the threshold and the discount **do not exist in code**. `discountPerBuyer` appears in four places, all schema or admin-form; nothing compares members to `minBuyers` and nothing applies a discount. `expired` is never written. `activeCampaignCount` is never written, so the unit-type delete guard is inert.

**TARGET (if built)**

```
draft → active ⇄ paused
          │
          ├─ member joins ──→ memberCount recount
          │                        │
          │                  memberCount >= minBuyers
          │                        ▼
          │                THRESHOLD MET  ← persisted flag + timestamp
          │                        │
          │                  discount locked in per member
          │
          ├─ endDate passes ──→ expired    ← scheduled or lazy transition
          ├─ admin ──→ completed | cancelled
          └─ member exits ──→ recount; if below threshold, previously locked
                              discounts REMAIN honoured (persisted per member)
```

**GAP:** the entire feature. This is a build, not a repair. **Product decision required before any work** (§12).

### 3.9 Negotiation — PRODUCT DECISION, both options documented

**CURRENT.** There is no negotiation subsystem. `Lead.status='negotiating'` is a dropdown label with no associated record. `Property.negotiable` is a display-only boolean. Chat is fully built server-side and deliberately unmounted. Everything between interest and closure happens off-platform.

**Option A — keep negotiation off-platform (recommended default)**

- *What it means.* The platform observes the start (interest) and the end (verified deal) and nothing in between. This is what "Deal Direct" means: no broker, no intermediation.
- *Work required.* None. Optionally rename `negotiating` to something honest, or drop it.
- *Cost.* No price history, no dispute evidence, no way to correlate a proof document with anything the platform recorded. Deal verification rests entirely on documents.
- *Risk.* Low. It is the status quo.

**Option B — bring negotiation on-platform**

- *What it means.* An `Offer` record: amount, party, status (`offered → countered → accepted | withdrawn | rejected`), tied to a Lead. Optionally re-mount chat as the discussion channel.
- *Work required.* New model, endpoints, state machine, UI on both sides, notifications per event. Chat re-mount is a separate product decision (it was hidden by client request).
- *Benefit.* Price history, an audit trail for disputes, a real basis for `negotiating`, and closure that can be checked against a recorded agreed price rather than a PDF.
- *Cost.* Large. Roughly two to three weeks including UI, and it changes the product's positioning from "introduce and get out of the way" to "mediate the transaction".
- *Risk.* Medium-high. It is the largest single addition on this list.

**Recommendation.** Take Option A for Phase 3 and revisit Option B only if deal disputes become a real operational problem. Nothing else in this plan depends on the answer.

### 3.10 Booking / payment lifecycle

**CURRENT** (hardened in Phase 1): `enquiry → payment_submitted → confirmed → completed`, with `cancelled` reachable from any non-terminal state, inventory decremented atomically before confirmation, and inventory restored on cancellation from a holding state.

**TARGET** — unchanged. This is the best-specified lifecycle in the system after Phase 1. The only gap is **one historical record** with `tokenAmount: 0` (§5.3).

### 3.11 Rewards lifecycle

**CURRENT** (hardened in Phases 1–2): one listing reward per account, 5 enquiries/day, deal rewards pull-based and atomic, reversal no longer inflates lifetime points, rarity now reaches the reveal.

**TARGET** — one addition: `Reward.transactions` is an unbounded embedded array loaded in full on every read. Cap or archive it before a heavy user reaches the 16 MB document ceiling and their wallet becomes unwritable.

**GAP:** transaction archival. Not urgent at current volume; it is a cliff rather than a slope.

### 3.12 Notification lifecycle

**CURRENT**

```
controller → Notification.create() → post('save') hook → User.findById → sendEmail()
                                                          (N+1)          (2 SMTP handshakes each)
```

**TARGET**

```
controller → notify({ user, template, data })
                 │
                 ├─→ Notification.create()      (in-app, no side effects)
                 └─→ queued email delivery      (batched user lookup, pooled transporter)
```

**GAP:** §9.

---

## 4. State-Machine Definitions

Proposed shape, consistent across all four. Each lives beside its model and is imported by the controller — no new abstraction layer.

```js
export const LEAD_TRANSITIONS = {
  new:         ['contacted', 'interested', 'negotiating', 'lost'],
  contacted:   ['interested', 'negotiating', 'lost'],
  interested:  ['negotiating', 'lost'],
  negotiating: ['lost'],
  converted:   [],   // terminal — written by the system only
  lost:        [],   // terminal
};

/** Statuses only the system may assign, never a user. */
export const LEAD_SYSTEM_ONLY = ['converted'];
```

| Machine | States | Terminal | System-only | Guard location |
|---|---|---|---|---|
| Property lifecycle | active, pending_verification, sold, rented | sold, rented (until admin correction) | pending_verification, sold, rented | `updateMyProperty`, `closeDeal`, verification handlers |
| Property moderation | approved, disapproved | none | both | approve/disapprove handlers |
| Lead | new, contacted, interested, negotiating, converted, lost | converted, lost | converted | `updateLeadStatus`, admin lead update |
| Verification | pending, approved, rejected | approved, rejected (until correction) | all | verification handlers |
| Booking | enquiry, payment_submitted, confirmed, completed, cancelled | completed, cancelled | confirmed | already implemented Phase 1 |
| Campaign | draft, active, paused, completed, expired, cancelled | completed, cancelled | expired | not implemented |

**Rule for all of them:** the guard runs before the write, an illegal transition returns 400 with a code naming both states, and the transition table is exported so tests assert the real rule rather than a copy.

---

## 5. Data Migration Plan

**No write was performed. Every figure below comes from a read-only query run on 2026-08-16 against the development database.**

### 5.1 The finding that changes the plan

The taxonomy collections are **semantically inverted**:

| Collection | Rows | Actually contains |
|---|---|---|
| `propertytypes` | 3 | `Residential`, `Commercial`, `Plot` — these are **categories** |
| `categories` | 19 | `Apartment`, `Villa`, `Office Space`, `Warehouse/Godown`… — these are **property types**, plus `Buy`, `Rental`, `Rent`, which are **listing intents and not taxonomy at all** |
| `subcategories` | 48 | Populated, but **referenced by zero properties** |

Meanwhile the denormalised columns on `Property` are correct in their own terms: `categoryName` holds `Residential`/`Commercial`, `propertyTypeName` holds `Apartment / Flat`, `Villa`, and so on.

So `Property.category` should point into `propertytypes`, and `Property.propertyType` should point into `categories`. A naive `categoryName → categories` backfill resolves **0 of 47 records**. This is why the corruption was never repairable by the obvious script.

**Consequence: this is not a backfill. It is a taxonomy redesign with a backfill attached, and it needs a product decision first.**

### 5.2 Dry-run results — property taxonomy

Corpus: **47 properties** (46 owner-feed, 1 builder-feed).

**Current reference state**

| Field | Null | Distinct non-null ids |
|---|---|---|
| `category` | 22 | 2 |
| `subcategory` | 47 | 0 |
| `propertyType` | 22 | 2 |

Twenty-five rows carry a ref, but only two distinct values exist across all of them — the "everything points at one wrong id" cohort.

**`categoryName` → candidate id (matched against `propertytypes`)**

| Outcome | Records |
|---|---|
| Exact match | **47 / 47** |
| Ambiguous | 0 |
| Unmatched | 0 |

Clean. `Residential` ×37, `Commercial` ×10.

**`propertyTypeName` → candidate id (matched against `categories`)**

| Outcome | Records | Detail |
|---|---|---|
| Exact, unambiguous | **19** | Independent House ×9, Villa ×5, Penthouse ×2, Warehouse / Godown ×2 (whitespace-normalised) |
| Exact but **ambiguous** | **3** | `Office Space` ×3 — the collection contains both `Office space` and `Office Space` as separate documents |
| Fuzzy, needs review | **24** | `Apartment / Flat` ×21 → `Apartment` (0.50) · `Shop / Retail` ×1 → `Shop / Showroom` (0.50) · `Showroom` ×2 → `Shop / Showroom` (0.50) |
| No candidate | **2** | `Commercial Building / Floor` ×1 · `Restaurant / Cafe` ×1 |

**`subcategoryName` → candidate id**

| Outcome | Records |
|---|---|
| Name field empty | **47 / 47** |

Nothing to migrate. 48 subcategory documents exist and are referenced by nothing.

### 5.3 Dry-run results — `priceUnit` and bookings

**`priceUnit` distribution across 47 properties**

| Value | Records | Reading |
|---|---|---|
| `Lac` | **22** | The schema default, never overwritten — the legacy cohort |
| `Monthly` | 16 | Written correctly by the current form |
| `Total` | 9 | Written correctly by the current form |

- 12 rows carry `priceUnit: "Lac"` alongside a price above 100,000, i.e. plainly already in rupees.
- 31 listings are rentals; **15 of them** do not have `priceUnit: "Monthly"`.

Because Phase 2 removed `normalizePrice` and filters server-side on raw rupees, `priceUnit` is now **display metadata only and affects no calculation**. That downgrades this from a correctness migration to a tidiness one.

**Booking `tokenAmount`**

| Measure | Value |
|---|---|
| Total bookings | 6 |
| `tokenAmount` 0 or absent | **1** (status `completed`) |
| Recoverable from `unitType.paymentTerms.bookingAmount` | **1** |
| Not recoverable | 0 |

One record, fully recoverable. This is a single targeted update, not a migration.

### 5.4 Proposed migration design

**Stage 0 — product decision (blocking).** Decide what the taxonomy means before writing anything:

- **Option 1 — swap the collections' meaning.** Accept that `propertytypes` holds categories and `categories` holds types. Migrate refs accordingly. Cheapest; leaves the naming permanently misleading.
- **Option 2 — rename to match reality.** Move the 3 rows into a correctly-named `categories` collection and the 19 into `propertytypes`. Correct, but touches every taxonomy consumer in three apps.
- **Option 3 — rebuild the taxonomy.** Define the intended category/type/subcategory tree, seed it, map the 47 rows onto it, retire `Buy`/`Rental`/`Rent` (which are intents and duplicate `listingType`), and resolve the `Office space`/`Office Space` duplicate. Most work, only option that leaves the model coherent.

**Recommended: Option 3**, scoped tightly — 47 properties and 19+3 taxonomy rows is a small corpus, and this is the cheapest moment it will ever be.

**Stage 1 — resolve the 5 blockers** (whatever option is chosen):

| Blocker | Records | Decision needed |
|---|---|---|
| `Office space` vs `Office Space` duplicate | 3 | Which document survives; delete the other |
| `Apartment / Flat` → `Apartment` | 21 | Confirm they are the same thing |
| `Shop / Retail` and `Showroom` → `Shop / Showroom` | 3 | Confirm, or split into distinct types |
| `Commercial Building / Floor` | 1 | Create the type, or map to an existing one |
| `Restaurant / Cafe` | 1 | Create the type, or map to an existing one |

**Stage 2 — build the mapping table.** An explicit, reviewed `name → ObjectId` map committed to the repository, not computed at runtime. 47 rows is small enough to review by hand, and a reviewed table is auditable in a way that fuzzy matching is not.

**Stage 3 — dry run.** Script emits, per property: `_id`, current ref, proposed ref, match type (`exact` / `mapped` / `unresolved`). Zero writes. Output reviewed and signed off.

**Stage 4 — execute** inside a transaction, writing `migrationBatch` and `previousValue` onto each touched document so a rollback is a data operation rather than a restore.

**Stage 5 — verify.** Re-run the analysis; assert 0 unresolved, 0 nulls on owner-feed rows, and that `?categoryName=Residential` and `?category=<id>` return identical sets.

**Rollback strategy**

1. Primary: `previousValue` stamped per document; reverse-apply by `migrationBatch`.
2. Secondary: full `properties` collection export taken immediately before Stage 4.
3. The migration is idempotent — re-running maps to the same ids and writes nothing new.
4. `priceUnit` and taxonomy are migrated **separately**, so either can be rolled back alone.

**`priceUnit` migration (separate, low priority).** Set `Monthly` for rentals and `Total` for sales; the value is display-only now. 22 rows would change. Safe to defer indefinitely.

**Booking migration.** One document. Set `payment.tokenAmount` from its unit type. Do it as a reviewed one-off with the value recorded in the commit message, not as a script.

---

## 6. Integration-Test Strategy

**Nothing is installed or implemented in this phase.** This is the design.

### 6.1 Why it comes first

Most current assertions read source text. That caught real regressions in Phases 0–2, but it cannot execute a cascade, a transaction, or two concurrent requests. Every remaining Phase 3 item — state machines, cascades, migration — changes behaviour that only an integration test can verify. Building them after the changes inverts the safety.

### 6.2 Architecture

```
backend/tests/
  unit/          existing 471 — unchanged, no database, fast
  integration/   NEW — real MongoDB, real Express app, real transactions
    setup/
      db.js         start/stop an isolated database, truncate between tests
      app.js        boot the Express app without listening on a port
      factories.js  build valid User / Property / Lead / Booking fixtures
```

**Database.** `mongodb-memory-server` with a **replica set** — required because `addProperty` uses a transaction and a standalone `mongod` cannot run one. Alternative: a disposable Atlas database keyed by an env var, if in-memory proves slow. Never the development database.

**App under test.** `supertest` against the Express app directly. No network port, no separate process, real middleware chain so auth, CSRF and rate limits are exercised as they actually run.

**Isolation.** Truncate collections between tests rather than reseeding, and give each test its own users. Tests must not depend on ordering.

### 6.3 Coverage targets, in build order

| # | Suite | What only integration can prove |
|---|---|---|
| 1 | **Authentication** | Session cookie issued, restored, revoked on password change; lockout after 5 failures actually locks |
| 2 | **Authorization** | User A cannot read or mutate User B's property, lead, booking or notification — executed, not grepped |
| 3 | **Property field contract** | Create → read round trip preserves every field the form sends. **The single highest-value test in the plan** |
| 4 | **State transitions** | Illegal lead/property/deal transitions are refused; legal ones persist |
| 5 | **Transactions** | One-listing-per-owner holds under a real transaction; abort leaves no partial document |
| 6 | **Concurrency** | Two simultaneous claims award once; two close-deals create one verification; the `$gte:1` decrement never oversells |
| 7 | **Cascades** | Deleting a builder/project/property leaves no orphan, or is refused |
| 8 | **Migration** | Run the taxonomy migration against a seeded fixture and assert the post-conditions, then assert the rollback restores exactly |

### 6.4 What stays a unit test

The 471 existing tests keep their value and their speed. Pure logic — the reward ledger arithmetic, rarity bands, the sanitizer, transition tables, `escapeRegExp` — should not acquire a database.

---

## 7. Admin RBAC — Decision Options

**Current.** `requirePermission` guards 5 of roughly 75 admin endpoints. `Permission.resource` is a closed enum of 12 values with no entry for verifications, bookings, projects, campaigns, builders, blogs or rewards. `Admin.getPermissions()` has no super-admin bypass and returns `[]` for an empty role — which can lock a level-100 admin out of the dashboard. **There is no seed script in the repository.** Whether the 5 guarded endpoints work at all in any given environment is unknown.

### Option A — complete the layer

1. Open the `resource` enum to cover the real surface.
2. Add a super-admin bypass to `getPermissions()`.
3. Write and **commit** a seed script for roles and permissions.
4. Roll guards out endpoint by endpoint, verifying against a real admin account at each step.

*Effort:* ~3 days. *Risk:* high — this gates admin access, and getting it wrong locks out operators. *Benefit:* least-privilege admin access, which matters more as the admin team grows.

### Option B — retire the layer

1. Remove `requirePermission` from the 5 endpoints.
2. Keep `protectAdmin` (which already enforces MFA) and `requireRoleLevel` for the few genuinely privileged actions.
3. Delete `Permission`, and `Role.permissions`, keeping `Role.level`.

*Effort:* ~half a day. *Risk:* low. *Cost:* every admin can do everything except the level-gated actions. Acceptable for a small trusted team; not acceptable if admins are outsourced or numerous.

**Recommendation.** The deciding question is **how many people have admin accounts and whether you trust all of them equally**. For a small in-house team, Option B is honest and cheap. For anything else, Option A. The half-built state is the one option that should not persist — it already caused the B2 regression that 403'd every admin.

---

## 8. Cascade / Data-Integrity Strategy

**Current.** Zero cascade hooks across all 31 models; roughly 70 `ref` fields with no referential integrity. Partial mitigation exists only in `userController.deleteAccount`.

**Worst chain:** deleting a `Builder` orphans Project → UnitType → GroupBuyCampaign → CampaignMember (including **paid** members) plus every ProjectBooking. Deleting a property with a pending verification makes that verification permanently unresolvable — both approve and reject then throw — and the buyer's reward permanently unclaimable.

### Option A — cascade functions per aggregate root (recommended)

Explicit, greppable functions in the shape of the existing `deletePropertyAssets`:

```js
deleteBuilderCascade(builderId)   // refuses if any paid CampaignMember or verified ProjectBooking exists
deleteProjectCascade(projectId)
deletePropertyCascade(propertyId) // refuses if a pending TransactionVerification exists
```

*Pros:* explicit, testable, refusal is expressible. *Cons:* every new relationship must be added by hand.

### Option B — Mongoose middleware hooks

`pre('findOneAndDelete')` on each parent model.

*Pros:* harder to forget. *Cons:* invisible action at a distance — the same property that makes the notification post-save hook a problem today. **Not recommended**, for exactly that reason.

### Option C — soft delete everywhere

Add `deletedAt` and filter every read.

*Pros:* nothing is ever lost. *Cons:* touches every query in the codebase, and conflicts with the DPDP expectation that deletion means deletion. **Not recommended.**

**Recommended: Option A, with refusal preferred over cascade wherever money or a counterparty is involved.** Deleting a builder with paid group-buy members should fail loudly, not silently destroy their commitments.

---

## 9. Notification Architecture — Options

**Current.** Delivery lives in `Notification`'s `post('save')` hook: an N+1 `User.findById` per document, and `createTransporter()` + `transporter.verify()` on every send — two full TCP/TLS/AUTH round trips per email. One property listing can fan out to hundreds of notifications and hundreds of serial SMTP handshakes on the request's microtask queue. Phase 2.5 fixed the duplicate-send-on-read bug; the architecture is untouched.

### Option A — extract a `notify()` service (recommended)

```js
await notify({ user, template: 'newLead', data });
```

Model creates the record; the service sends. Batch the user lookup with one `$in`; hoist a pooled transporter and drop the per-send `verify()`.

*Effort:* ~2 days. *Risk:* medium — every notification path changes. *Benefit:* removes the N+1 and the handshake cost, and makes delivery greppable.

### Option B — queue-backed delivery

Option A plus a job queue (BullMQ/Redis), retries and a dead-letter queue.

*Effort:* ~4 days plus Redis. *Benefit:* email failures become retryable instead of silently logged. *Cost:* an infrastructure dependency the system does not currently have.

### Option C — leave it, add batching only

Keep the hook, batch the lookup, pool the transporter.

*Effort:* ~4 hours. *Benefit:* most of the performance win for a fraction of the risk. *Cost:* delivery stays invisible inside the model.

**Recommendation.** Option A. Option C is a reasonable stopgap if Phase 3 is time-boxed; Option B only once Redis exists for other reasons (§11).

---

## 10. API-Client Architecture — Options

**Current.** 8 of 12 groups in `client-next/utils/api.js` and 7 of 16 in `Admin/api/adminApi.js` have zero call sites, and the dead ones are precisely the ones that drifted — helpers pointing at endpoints that never existed, wrong methods, wrong parameter names. Screens bypass them and hand-write URLs, which is why nobody noticed. This has already shipped broken auth flows into the mobile client.

### Option A — delete dead, migrate live (recommended)

1. Delete every helper with zero call sites (zero risk — they are unused).
2. Migrate screens onto what remains, one at a time, so drift becomes a visible break.

*Effort:* half a day to delete, ~3 days to migrate. *Risk:* very low for step 1.

### Option B — generate the client from the routes

Derive a typed client from an OpenAPI description of the Express routes.

*Effort:* ~1 week plus ongoing annotation. *Benefit:* drift becomes impossible. *Cost:* a new build step and annotations on 187 routes.

### Option C — delete only

Step 1 alone; screens keep hand-writing URLs.

*Effort:* half a day. *Cost:* the next helper will drift the same way.

**Recommendation.** Option A. Do step 1 immediately regardless of what else is decided — it is free and removes a live trap.

---

## 11. Performance Improvements

Ranked by likelihood of being the first thing that breaks. None is urgent at current volume; all are cliffs rather than slopes.

| # | Item | Current | Target | Effort |
|---|---|---|---|---|
| 1 | Notification fan-out | N+1 lookups, 2 SMTP handshakes per email, serial | Batched lookup, pooled transporter | §9 |
| 2 | Saved-search matching | Loads **all** active saved searches per property create, filters in JS | Filter in the database query | 3 h |
| 3 | Unbounded list endpoints | `/list`, `/property-list`, `/filter` return every approved listing | Paginate; retire `/filter` (no client calls it) | 4 h |
| 4 | `Reward.transactions` | Unbounded embedded array, loaded in full on every read | Cap or archive before the 16 MB ceiling | 1 d |
| 5 | `force-dynamic` on 9 routes | Every `revalidate` inert; every request hits the backend | Solve build-time API availability, then restore ISR | 1 d |
| 6 | Admin property manager | Returns the entire populated collection | Paginate | 3 h |
| 7 | `AuditLog` | Unbounded, no TTL, stores full request bodies including PII | TTL index + tighter redaction | 3 h |
| 8 | Single-instance coupling | 6 in-process stores; `REDIS_URL` read and **ignored** | Real Redis, or log loudly that it is ignored | 2 d |

Item 8 is the one that blocks horizontal scaling. At minimum, make `config/redis.js` warn when `REDIS_URL` is set but `ioredis` is absent — today it silently constructs a `MemoryCache`.

---

## 12. Product Decisions Required

Ordered by how much downstream work they block.

| # | Decision | Blocks | Options |
|---|---|---|---|
| 1 | **Taxonomy meaning** | The entire property-data migration and working category filters | Swap · rename · rebuild (§5.4) |
| 2 | **The 5 taxonomy mappings** | Migration execution | Per §5.4 Stage 1 |
| 3 | **Group Buy** | The whole campaign module | Build the threshold + discount · withdraw the public promise |
| 4 | **Negotiation** | Lead lifecycle semantics | Off-platform (default) · on-platform offers (§3.9) |
| 5 | **Admin RBAC** | ~75 endpoints | Complete · retire (§7) |
| 6 | **Deleted-user PII** | DPDP posture | Delete · anonymise · retain, per collection |
| 7 | **Chat** | Whether negotiation Option B is even available | Stays hidden · re-mount |
| 8 | **Login phone** | Whether it is a real field | Cosmetic · enforced (needs a backend change) |
| 9 | **Popular Properties** | A disabled admin page | Build · delete |
| 10 | **Reward rarity bands** | Reveal presentation | Accept the 25/5/0.5/0.05% thresholds · retune |
| 11 | **Audit documents gitignored** | Whether the analysis is versioned | Track · leave out |

---

## 13. Engineering Decisions Required

| # | Decision | Recommendation |
|---|---|---|
| 1 | Test database: in-memory replica set vs disposable Atlas | In-memory first; Atlas if transactions prove slow |
| 2 | Where transition tables live | Beside the model, exported, imported by controllers |
| 3 | Cascade vs refusal per relationship | Refuse where money or a counterparty is involved; cascade otherwise |
| 4 | Notification queue now or later | Later — extract the service first (§9 Option A) |
| 5 | Redis now or later | Later, unless the notification queue is chosen |
| 6 | Migration idempotency | Required. Stamp `migrationBatch` + `previousValue` |
| 7 | Whether to keep `subcategory` at all | 48 rows, referenced by zero properties. Decide before migrating |
| 8 | Dead `Property` enum values (`pending`, `inactive`) | Remove, or start using them |

---

## 14. Risks and Dependencies

**Dependency graph**

```
Integration-test infrastructure  ──┬──→ State machines
                                   ├──→ Cascade strategy
                                   └──→ Migration verification

Taxonomy product decision ──→ Migration design ──→ Migration execution ──→ Working filters

RBAC decision ──→ (admin endpoint work)

Notification service extraction ──→ (optional) queue ──→ Redis
```

**Risks**

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Migration writes wrong taxonomy refs | Medium | High — corrupts the fix | Reviewed mapping table, dry run, `previousValue`, export |
| RBAC rollout locks admins out | Medium | High | Verify against a real account per endpoint; keep a break-glass super admin |
| Cascade deletes more than intended | Medium | **Very high** — irreversible | Refuse-by-default; integration tests before enabling; dry-run counts |
| Notification extraction drops an email path | Medium | Medium | Enumerate all call sites first; the event map in the audit is complete |
| State machines reject legitimate existing data | Medium | Medium | Apply to new writes only; do not retro-validate |
| Test suite slows to the point of being skipped | Low | Medium | Keep the 471 unit tests separate and fast |
| Scope creep into a rewrite | **Medium** | High | Each item ships alone with its own tests |

**Prerequisite chain, honestly stated.** The single highest-value item is the integration-test infrastructure, because four other items depend on it for safety. The single most *valuable outcome* is the taxonomy migration, because it is the last correctness defect affecting what users see. But it is blocked on a product decision that nobody can make from the code.

---

## 15. Recommended Implementation Sequence

**Stage 1 — foundations (no product decisions needed)**
1. Integration-test infrastructure (§6) — database, app harness, factories
2. Suites 1–3: authentication, authorization, property field contract
3. Delete the dead API-client helpers (§10 step 1) — free, removes a live trap

**Stage 2 — data (blocked on decision #1)**
4. Taxonomy decision, then mapping table, then dry run, then execute, then verify (§5)
5. The one booking `tokenAmount` record
6. `priceUnit` tidy-up (optional; display-only since Phase 2)

**Stage 3 — integrity (needs Stage 1)**
7. Cascade strategy (§8) with integration tests first
8. State machines (§4) — property, lead, verification
9. Deal reservation and the admin correction path

**Stage 4 — architecture**
10. Notification service extraction (§9 Option A)
11. RBAC resolution (§7) — whichever option is chosen
12. API-client migration (§10 step 2)

**Stage 5 — performance**
13. Items 2–7 from §11
14. Redis and the single-instance coupling, if horizontal scaling is actually needed

**Deliberately unscheduled:** Group Buy and Negotiation. Both are product decisions, and both are builds rather than repairs. Neither belongs in a remediation phase.

---

## Appendix — Item Classification

| # | Item | Type | Prereq | Blast radius |
|---|---|---|---|---|
| 1 | Integration tests | Architecture | none | Test-only; zero production risk |
| 2 | Taxonomy migration | **Data migration** + product decision | Decision #1, #2 | 47 properties; all category/type filtering |
| 3 | Property state machine | Architecture | Integration tests | Every property write path |
| 4 | Lead state machine | Architecture | Integration tests | Lead updates, analytics, conversion rate |
| 5 | Deal lifecycle | Architecture + bug fix | Integration tests | Close-deal, verification, rewards |
| 6 | Group-buy lifecycle | **Product decision** → build | Decision #3 | Entire campaign module |
| 7 | RBAC | **Product decision** → architecture | Decision #5 | ~75 admin endpoints |
| 8 | Cascades | Architecture | Integration tests | Every delete path; irreversible if wrong |
| 9 | Notifications | Architecture | none | Every notification path |
| 10 | API client | Architecture | none (step 1) | All three clients |
| 11 | Performance | Bug fix + architecture | varies | Isolated per item |

---

**End of plan.** No application code was modified. No migration was executed. No production repository or infrastructure was touched.
