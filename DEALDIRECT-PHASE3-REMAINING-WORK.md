# Phase 3 — Remaining Work Report

Built from the repository as it stands at `129e2a9`, not from the audit text.
Every claim below was re-checked against source; where a re-check changed the
audit's conclusion, that is called out.

Test baseline: **472 unit, 278 integration, 750 total, 0 failures, 0 todos.**

---

## 1. Completed Phase 3 workstreams

| Workstream | State | Evidence |
|---|---|---|
| 3A integration-test foundation | done | harness, provable DB and egress isolation |
| 3A.1 fixes found by the harness | done | 4 production defects, each with a regression test |
| 3B.0 development database separation | done | `dealdirect_dev`, anonymised |
| 3B.1 taxonomy redesign + migration | done | migration UP/DOWN verified on real data |
| 3B.2 production read-only validation | done | 47/47 mapped, 0 unknown, 0 ambiguous |
| 3B.3 cutover preparation | done | backup, gate, dry run, plan |
| 3B.4 taxonomy production-readiness | **done this pass** | admin mutation guard, Admin page repair |

**Not in the roadmap's Phase 3 list.** The taxonomy workstream came out of the
audit, not from 3.1–3.6. It is finished as code; only the production cutover
remains, and that is deferred by decision.

---

## 2. Remaining Phase 3 workstreams

Roadmap items 3.1–3.6, each re-verified.

### A. Taxonomy production cutover — *prepared, deferred*

Not blocked by code. Held until phases 4 and 5 land, by decision on 2026-08-17.
Re-run the dry run before executing: it is pinned to 47 properties.

### B. Cascade handling (3.3) — **verified, worst finding standing**

```
delete hooks across 31 models : 0
```

Grep for `pre|post('remove'|'deleteOne'|'deleteMany'|'findOneAndDelete')` returns
nothing in any model file. The audit is correct and understated: there is no
cascade layer at all, so every delete is a potential orphan.

Two chains carry money:

- `Builder → Project → UnitType → GroupBuyCampaign → CampaignMember` — deleting a
  builder strands paid campaign members and every `ProjectBooking`.
- `Property → TransactionVerification → Reward` — deleting a property orphans a
  pending verification, after which admin approve and reject both throw and the
  buyer's reward is permanently unclaimable.

### C. State-transition enforcement (3.1) — **verified**

- **Lead:** `sanitizeLeadStatus` checks enum membership and nothing else. It
  never reads the current status, so `lost → converted` and `converted → new`
  both succeed. Confirmed by reading `updateLeadStatus`: it builds
  `updates.status` and calls `findByIdAndUpdate` with no comparison to the
  stored value.
- **Lead, second half:** no code path writes `Lead.status = 'converted'` from
  deal approval, so `conversionRate` measures a field owners set by hand.
- **Campaign:** `expired` is in the `GroupBuyCampaign` enum and is written by no
  controller or service. Grep across `controllers/` and `services/` returns
  nothing.
- **Property:** owner cannot set `status` directly any more (fixed in 0.3), but
  there is still no correction path for a wrongly approved verification.

### D. Notification architecture (3.6) — **partly fixed, three defects standing**

The re-send bug is fixed and well documented in `models/Notification.js`. The
architectural problems the audit named are still there, and the file says so
itself in a scope note. Standing:

- `post("save")` does `User.findById` per notification.
- `post("insertMany")` loops `User.findById` per document — the actual N+1, and
  the fan-out path.
- Dispatch is inside the model, so it fires from 9 call sites across three
  controllers with no way to grep for "who sends mail".

Per-send SMTP transporter creation was not re-verified in this pass; treat that
one as audit-claimed, not confirmed.

### E. Admin RBAC (3.2) — **verified, decision still open**

```
routes using requirePermission : 8
routes using protectAdmin      : 93
role/permission seed script    : none
```

Slightly better than the audit's "5 of 75", worse in the way that matters: the
8 guarded routes depend on permission strings that no committed script creates.
Whether they work in production is still unknown from inside this repository.

### F. API-client architecture (3.4) — **verified, larger than described**

```
client-next/src/utils/api.js   754 L
Admin/src/api/adminApi.js      631 L
dealdirect-mobile/src/api/      9 modules
```

Three hand-maintained clients, no shared package. The mobile one is a different
architecture entirely (`request.ts`, `queryClient.ts`, typed `endpoints/`), so
"collapse the API client layer" is really two jobs: delete dead helpers in the
two axios clients, and decide whether mobile's design becomes the target.

### G. Performance (Phase 4 by the roadmap, but the pagination gap is integrity-adjacent)

```
validatePagination : exists in middleware/validators/index.js
                     mounted on leadRoutes only
/list, /property-list, /search, /filter : unguarded
Reward.transactions : unbounded array, no cap
```

The audit's claim holds. `/filter` still has no caller in any of the four apps.

---

## 3. Dependency order

```
B. cascades ─────────────┐
                         ├──> A. cutover (deferred by decision, not by code)
C. state transitions ────┘

E. RBAC decision ──> any further admin-surface work
D. notifications ──> Phase 4.1 fan-out performance
F. API clients ────> (independent; blocks nothing)
```

- **B before C.** A transition table that forbids `converted → new` is worth
  little while deleting the parent still orphans the record silently.
- **D before 4.1.** Moving dispatch out of the model is the refactor; batching
  the lookup is the optimisation. Doing them in the other order means optimising
  code that is about to move.
- **E gates admin work.** Every new admin endpoint has to choose guarded or
  unguarded, and right now that choice is being made by coin flip.
- **F blocks nothing** and is the only one safe to interleave.

---

## 4. Risk ranking

Ranked on the criteria given: data integrity, security, financial, blast radius,
user impact, reversibility.

| # | Workstream | Integrity | Financial | Blast radius | Reversible? | Rank |
|---|---|---|---|---|---|---|
| 1 | **B. Cascades** | severe — silent orphans | yes — paid members, unclaimable rewards | whole aggregate chain | **no**, deleted data is gone | **highest** |
| 2 | **C. State transitions** | high — invalid states persist | indirect, deal/reward flow | per record | partly | high |
| 3 | **E. RBAC** | none | none | admin access, all 93 routes | yes | high (security) |
| 4 | **D. Notifications** | none | none | every notification path | yes | medium |
| 5 | **G. Pagination / unbounded arrays** | low now, fatal at the 16 MB BSON ceiling | no | per endpoint | yes | medium |
| 6 | **F. API clients** | none | none | per screen | yes | low |

B outranks everything because it is the only one whose failure is unrecoverable.
A wrong lead status can be corrected; a cascade-deleted `CampaignMember` who paid
cannot be reconstructed from anything in the database.

E is ranked high on security rather than integrity: the 8 guarded routes may be
failing open or closed in production and nobody can tell from here.

---

## 5. Recommended next workstream

**B. Cascade and delete-integrity handling.**

Highest integrity risk, the only irreversible one, and it is the prerequisite
for C. It also has a natural first slice that is pure protection and ships
without deleting anything:

1. **Refuse** deletes that would destroy a financial record — a property with a
   pending verification, a unit type with paid campaign members, a builder with
   any project. Refusing is reversible; cascading is not.
2. Then explicit cascade functions per aggregate root, shaped like the existing
   `deletePropertyAssets`, dry-run each against `dealdirect_dev`.

Step 1 alone closes the unrecoverable half of the risk. It is also the same
shape as the guard just shipped for the taxonomy — `TAXONOMY_IN_USE` refuses a
delete that would strand references — so the pattern is established and tested.

**Not recommended next:** D or F. Both are refactors of working code, and
starting a refactor while deletes still orphan paid records is the wrong order.

---

## 6. Production blockers

| Blocker | Owner | Status |
|---|---|---|
| Cutover deferred until phases 4 and 5 | Chirag | decided 2026-08-17 |
| Three separate app deploys, order-dependent | Chirag | order documented and now test-asserted |
| Maintenance window, write-freeze method | Chirag | not chosen |
| Dry run pinned to 47 properties | — | re-run before executing |
| RBAC state in production unknown | Chirag | needs a live check, not a code change |

Nothing in the code blocks the cutover. Every blocker is a decision or an
environment fact.

---

## 7. Product decisions still required

Carried from the roadmap, none answered yet. The first two gate Phase 3 work.

1. **Admin RBAC (3.2)** — commit to the layer or remove it? Affects 93 routes.
   Blocks E and any new admin surface.
2. **Group buy (3.5)** — build the threshold and discount, or withdraw the
   promise? Nothing in the campaign module is worth doing until this is
   answered, and it changes how much B's builder-chain cascade matters.
3. **Deleted-user PII** — for `Lead`, `Agreement`, `TransactionVerification`,
   `CampaignMember`, `ProjectBooking`: delete, anonymise, or retain? This is an
   input to B, not a separate task: the cascade design has to know the answer.
4. **Reward promises** — implement the 5-photo bonus, referral milestones 2 and
   3, and the login streak, or remove the UI copy?
5. **Orphaned Cloudinary assets** — run a dry-run reconciliation?
6. **Deal-closure documents** on permanent public URLs — still an accepted risk.
7. **`/properties/filter`** — retire it rather than paginate it? No caller in any
   of the four apps.
8. **Chat and agreements** — confirm they stay hidden.

Decisions 1 and 3 are the ones that actually block the recommended next
workstream.

---

## 8. What this pass changed

| Commit | Change |
|---|---|
| `ef0da6e` | canonical taxonomy is immutable through the admin API; referenced rows cannot be deleted; `createPropertyType` matches its own index |
| `0dc7f58` | Admin taxonomy page repaired (had never rendered data); dead `AddSubCategory.jsx` removed; axios-without-import and retired-route sweeps across all admin pages |
| `129e2a9` | cutover plan records the guard and the eased legacy-cleanup stage |

Three defects were found that the audit did not list: the admin mutation hole,
the `createPropertyType` index disagreement, and the third instance of the
axios-without-import bug. The first was reproduced against live endpoints before
being fixed — an admin could empty the property-type taxonomy in twenty requests
and strand every listing in the database.

Production remains untouched.
