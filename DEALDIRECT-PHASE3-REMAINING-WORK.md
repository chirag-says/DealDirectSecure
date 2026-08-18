# Phase 3 — Status Report

Built from the repository, not from the audit text. Every claim was re-checked
against source; where a re-check changed the audit's conclusion, that is called
out.

**Test baseline: 529 unit, 440 integration, 969 total, 0 failures, 0 todos.**

**Phase 3 engineering is complete.** The one item that remains, 3.5 Group Buy,
is a product decision that has now been taken: deferred. See §3.

Production remains untouched: no write, no deploy, no migration.

---

## 1. Phase 3, item by item

The roadmap defines Phase 3 as 3.1 to 3.6. Taxonomy came from the audit rather
than the roadmap and is tracked alongside.

| # | Item | State | Commit |
|---|---|---|---|
| 3.1 | Enforce state transitions | **done** | `ff29117` |
| 3.2 | Decide the fate of admin RBAC | **done** — retired | `be600e2` |
| 3.3 | Add cascade handling | **done** | `a1651e9`, `8822206` |
| 3.4 | Collapse the API client layer | **done** | `3e115d2` |
| 3.5 | Group buy — build or withdraw | **DEFERRED, see §3** | — |
| 3.6 | Move email out of the model layer | **done** | `2e0ebf6` |

Audit-originated work in the same phase:

| Workstream | State | Commit |
|---|---|---|
| 3A integration-test foundation | done | `2e2ca2a` |
| 3A.1 fixes the harness found | done | 4 defects, each with a regression test |
| 3B.0 development database separation | done | `dealdirect_dev`, anonymised |
| 3B.1–3B.3 taxonomy redesign, validation, cutover prep | done | `4957022`…`f87c573` |
| 3B.4 taxonomy production-readiness | done | `ef0da6e`, `0dc7f58` |
| CampaignMember payment-state integrity | done | `b14ecf1` |
| Aggregate-root deletion | done | `8822206` |

---

## 2. What each workstream actually found

Kept short; the detail is in the commit messages and the decision documents.

**3.1 State transitions.** Lead had no transition validation on either write
path — the owner path checked enum membership only, the admin path had no
whitelist at all — so `converted → new` erased a closed deal and
`lost → converted` manufactured a conversion. Nothing anywhere wrote
`Lead.status = "converted"`, so `conversionRate` measured a field owners set by
hand. `expired` was in the campaign enum and set by no code.

**3.2 RBAC.** Reasoning from the repository alone gave the wrong answer twice,
recorded in `DEALDIRECT-DELETION-AND-RBAC-DECISION.md` §2.6. Production holds 45
permissions wired to four roles and every admin holds all 45, so the layer
separated nothing while remaining able to 403 the whole panel when a code could
not resolve (`79ae3ab`). Retired. Implementing it surfaced that
`requireSuperAdmin` denied **everyone**, including genuine level-100 accounts,
because `Admin.role` is `Mixed` and a bare `populate` cannot resolve it.

**3.3 Cascades.** The audit's "zero cascade hooks" was true but misleading — an
explicit twelve-collection cascade already existed in `deleteAccount` — and its
builder-chain claim was wrong: builders soft-delete and each level refuses when
children exist. The real holes were narrower: a unit type guarded on a cached
counter that only counted *active* campaigns, so a completed campaign holding
PAID members deleted cleanly; and `ProjectBooking`, holding the UTR and payment
screenshot, blocked nothing anywhere.

**3.4 API client.** Structural finding: each app has two layers and pages use
the axios instance directly (66 raw calls web, 33 Admin), so most of the helper
layer had never been called. 14 groups referenced nowhere were deleted; two
equally-unreferenced groups were kept because they are the client half of held
features. No shared abstraction was built — there is no root `package.json` or
workspace, so it would mean introducing monorepo tooling.

**3.6 Notifications.** The SMTP claim was confirmed and understated: a new
transport per message *and* a `verify()` handshake before each one. Delivery
moved out of Mongoose middleware; the fan-out recipient lookup went from one
query per document to one `$in` for the batch.

---

## 3. Deferred by product decision

### Group Buy = intentionally deferred product build

**Decided 2026-08-18.** Group Buy will not be built during remediation. It will
be handled after the entire roadmap — Phases 3, 4 and 5 — as a dedicated
product-hardening and build effort.

**Reason, as given:** the current Group Buy business logic is immature and
should be redesigned as a complete workflow rather than incrementally patched
during the remediation phase.

That is the right call on the evidence. Verified by exhaustive search: no code
compares `memberCount` to `minBuyers`, and no code applies `discountPerBuyer` to
any price, booking or token amount. The feature is a schema, an admin form, a
client-side progress bar and marketing copy. Patching it piecemeal would mean
inventing product rules nobody has decided, which is how the current state was
reached.

**Not built, deliberately:** minimum-buyer completion, discount calculation,
join UX, refund workflow, campaign payment workflow, admin campaign-management
UI, any further campaign state machine.

**The safety work already done STAYS, and must not be removed:**

| Protection | Commit | What it prevents |
|---|---|---|
| Paid `CampaignMember` blocks unit-type deletion | `a1651e9` | destroying the only record that money moved — there is no gateway, the UPI reference and screenshot *are* the receipt |
| Booking → member reversal on cancellation | `b14ecf1` | a cancelled booking leaving a paid member inflating `paidMemberCount` |
| Paid members cannot self-exit | `b14ecf1` | a silent `paid` + `exited` state with no refund obligation recorded anywhere |
| Campaign lazy expiry | `ff29117` | a campaign past its end date reporting itself active forever |
| Aggregate-root deletion refusals | `8822206` | orphaning deal, payment or legal evidence |

These are integrity guards, not feature code. They hold the data still so the
eventual build starts from something coherent.

**One consequence of deferring, stated plainly and NOT acted on.** The promise
is still live on the site. `ProjectDetailContent.jsx` and `UnitDetailContent.jsx`
both render a discount figure, a progress bar and an "N+ buyers needed" line for
a discount no code can deliver. Withdrawing that copy is roughly half a day and
is independent of building the feature, but it is a product and marketing call,
not an engineering one, so it is recorded here rather than done.

A second fact worth carrying into the future build: **the web app has no join
path at all.** Nothing reaches campaign join or exit by any route, so the
feature is not merely undelivered, it is unreachable. The client helpers were
kept for exactly this reason.

### Builder / Project / UnitType redesign = intentionally deferred product hardening

**Decided 2026-08-18.** The `Builder → Project → UnitType → GroupBuyCampaign →
CampaignMember` chain is a future end-to-end hardening effort, not a remediation
task. Its product workflow is not being redesigned now.

**Same reason:** redesigning a workflow incrementally, inside a remediation
phase, produces the half-built state that remediation exists to clear up.

**What remediation still maintains on that chain, and only this:**

- deletion integrity — refusals before destructive work, at every level
- state integrity — booking transitions, campaign expiry, member reversal
- reference integrity — no orphaned campaigns, members, bookings or unit types
- protection against financial and data loss — paid tokens, UTRs, payment proofs

Nothing beyond that list should be touched before the dedicated effort.

---

## 4. Still open, but not Phase 3 engineering

| Item | Type | Blocked on |
|---|---|---|
| Taxonomy production cutover | operational | prepared and tested; held until all phases land |
| Index drift: `builders.email_1`, `agreements.idempotencyKey_1` | engineering | both deployed unique and non-sparse against a schema that says otherwise; queued for the index-cleanup stage, which is itself held behind the cutover |
| Invalid ObjectId returns 500 | engineering | global error-handler change; touches every route, needs its own pass |
| Deleted-user PII policy | product + legal | `DEALDIRECT-DELETION-AND-RBAC-DECISION.md` §1.6 |
| Retention period for retained records | legal | as above |
| Refund workflow | product + ops | folded into the deferred Group Buy build |
| Legacy taxonomy document deletion | operational | after the cutover |
| RBAC collection cleanup | operational | after the code change has been stable |

The `builders.email_1` drift has a live consequence today: creating a **second**
builder without an email address fails with a duplicate-key error, because one
document already holds `email: null`. Worth knowing while the fix is queued.

---

## 5. What comes next

**Phase 3 engineering is complete.** 3.1, 3.2, 3.3, 3.4 and 3.6 are implemented,
tested and committed; 3.5 is deferred by decision rather than outstanding.

Next is **Phase 4 — Performance**, which the roadmap defines as its own
top-level phase with ten items (4.1 to 4.10). Confirmed by re-reading the
roadmap rather than inferring: nothing performance-related sits under Phase 3.

Two Phase 4 items already have verified evidence gathered during Phase 3, so
they need measurement rather than investigation:

- **4.1 notification fan-out** — the N+1 and the per-message SMTP handshake were
  both fixed in `2e0ebf6`. This item is largely already done; re-scope it rather
  than re-doing it.
- **4.3 / 4.4 unbounded list endpoints and uncapped pagination** —
  `validatePagination` exists in `middleware/validators/index.js` and is mounted
  on lead routes only. `/list`, `/property-list`, `/search` and `/filter` are
  unguarded. `/filter` still has no caller in any of the four applications.
