# Phase 4 — Performance Baseline

Reconciliation pass. Every item in the roadmap's Phase 4 table was re-verified
against the current code rather than carried forward from the audit. **No code
was changed. Production was read only.**

Phase 3 engineering is complete, so this is the first Phase 4 artefact.

---

## The number that reframes the whole backlog

Production, measured read-only on 2026-08-18:

```
properties        47 docs     115 KB    avg 2.5 KB
savedsearches      0 docs
auditlogs        833 docs     907 KB
rewards           38 docs      51 KB    transactions: max 71, avg 5
notifications    140 docs      62 KB
users            100 docs      48 KB
```

**Nothing here is slow today, and nothing is close to a limit.** The largest
collection is under 1 MB. `Reward.transactions` peaks at 71 entries against a
16 MB ceiling. There are **zero saved searches**, so the fan-out path this phase
worries about has never executed in production.

That does not make the backlog worthless — it changes what it is. These are
**scalability risks, not live defects**, with two exceptions called out below.
Ordering them by "likelihood of being the first thing that breaks", as the
roadmap does, is right; treating them as urgent is not.

The honest consequence: several items are cheap insurance worth taking now
precisely *because* the data is small, since the same change on a large
collection is a migration rather than an edit.

---

## Status of every Phase 4 item

| # | Item | Status |
|---|---|---|
| 4.1 | Notification fan-out: N+1 plus two SMTP round trips per message | **ALREADY FIXED** |
| 4.2 | Saved-search matching filters in JS | **STILL OPEN** — zero current load |
| 4.3 | Unbounded list endpoints | **STILL OPEN** |
| 4.4 | Uncapped search pagination | **ALREADY FIXED** for `/search`; open elsewhere |
| 4.5 | `Reward.transactions` unbounded | **STILL OPEN** — far from the ceiling |
| 4.6 | `force-dynamic` on nine routes | **STILL OPEN** — product/infra decision |
| 4.7 | Admin property manager returns everything | **STILL OPEN** |
| 4.8 | `AuditLog` unbounded, no TTL, stores bodies | **PARTIALLY FIXED** |
| 4.9 | Hubble debit idempotency is an O(n) scan | **NOT REPRODUCIBLE as described** |
| 4.10 | `setCsrfToken` runs on every request | **STILL OPEN** |

Plus one item the roadmap does not list, found during this pass — see 4.11.

---

## 4.1 — Notification fan-out · ALREADY FIXED

Fixed in `2e0ebf6` (Phase 3E), which is why it must be re-scoped rather than
re-done.

| Roadmap fix | State |
|---|---|
| Pooled module-level transporter | done — `pool: true`, `maxConnections: 5`, single `getTransporter()` |
| Drop the per-send `verify()` | done — the handshake is gone |
| Batch the user lookup with one `$in` | done — `notifyUsers` issues one query |

Measured against `dealdirect_dev`: 20 recipients resolved in **1** query, and a
15-watcher saved-search fan-out in **1**. The audit's SMTP claim was confirmed
and understated: it was a new transport *and* a full connect/EHLO/auth round
trip per message, so two connections before anything moved.

**Nothing left to do.** Close it.

---

## 4.2 — Saved-search matching · STILL OPEN

**Current implementation.** `notifySavedSearchMatches`
(`services/notificationService.js:127`) does
`SavedSearch.find({ isActive: true }).lean()` and filters city and price range
in JavaScript.

**Evidence.** The query has no `filters.city` predicate. Phase 3E moved this
code out of two drifted copies in `propertyController` and unified the rules,
but deliberately preserved the matching behaviour — consolidation and
optimisation in one change would have made a behavioural regression hard to
attribute.

**Measured impact.** **Zero.** There are no saved searches in production, so
this has never run against real data. Cost is `O(active searches)` per property
creation, in memory.

**Proposed minimal fix.** Push `filters.city` into the query with a case-folded
comparison, keeping the price-range test in JS — it is a bucketed comparison
against three ranges, not an indexable predicate. Add an index on
`{ isActive: 1, "filters.city": 1 }`.

**Dependencies.** None.

**Production risk.** Low, but not zero: a missed match is silent. The matching
rules must stay identical, and the existing tests in
`tests/integration/notification-service.test.js` cover match, non-match and
20-watcher fan-out. Any change must keep those green and add a case-mismatch
case, since moving the comparison into Mongo changes how casing behaves.

---

## 4.3 — Unbounded list endpoints · STILL OPEN

**Current implementation.**

| Endpoint | Handler | Bounded? |
|---|---|---|
| `/properties/list` | `getProperties:693` | partial — one limit reference |
| `/properties/property-list` | `getAllPropertiesList:1148` | **no** — `find().populate×3.sort()`, nothing else |
| `/properties/filter` | `filterProperties:2133` | **no** |
| `/properties/search` | `searchProperties:1861` | yes — see 4.4 |

**Evidence.** `getAllPropertiesList` returns every approved owner listing with
three populates and no limit. It is the home-page feed.

**Measured impact.** 47 documents, ~115 KB, three populates. Imperceptible now.
Linear in the corpus: at 5,000 listings this is a ~12 MB response on every home
page load.

**Proposed minimal fix.** `limit`/`page` with a sane default on
`property-list`. For `/filter`: **retire it.** Re-verified this pass — no client
in any of the four applications calls it, which makes deletion cheaper and safer
than pagination.

**Dependencies.** Retiring `/filter` should follow the same evidence rule used
in Phase 3G: prove zero call sites repository-wide first.

**Production risk.** Medium and user-visible. Adding a default limit changes
what the home page returns; if the client does not paginate, listings silently
disappear below the cut. The client change and the server change must land
together, which on this deploy topology means `client-next` before `backend`
(see the taxonomy cutover plan §5).

---

## 4.4 — Uncapped search pagination · ALREADY FIXED, narrowly

**Current implementation.** `searchProperties:1861` already clamps:

```js
const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 12, 1), 60);
const safePage  = Math.max(parseInt(page, 10) || 1, 1);
```

with a comment recording that `?limit=200000` used to return everything. So the
specific defect the roadmap names is fixed.

**What is still open.** `validatePagination` exists in
`middleware/validators/index.js` and is mounted on **lead routes only**. The
roadmap's fix — "mount the existing `validatePagination`" — remains undone
everywhere else; `searchProperties` solved it locally instead.

**Proposed minimal fix.** Fold into 4.3 rather than doing separately: whatever
bounds `property-list` should use the same mechanism, and a single mounted
middleware beats three hand-rolled clamps.

**Production risk.** Low on its own.

---

## 4.5 — `Reward.transactions` unbounded · STILL OPEN

**Current implementation.** `transactions: [transactionSchema]` embedded in the
Reward document (`models/Reward.js:80`), pushed on every award
(`rewardService.js:178`), and the whole wallet is loaded to read it. Pagination
exists but is applied **after** loading, in JS (`rewardService.js:416`).

**Measured impact.** 38 wallets, **max 71 transactions**, avg 5, whole
collection 51 KB. The 16 MB BSON ceiling is roughly 100,000 transactions away
for the busiest wallet.

**Proposed minimal fix.** Not a cap and not an archive yet — both are migrations.
The proportionate step now is to stop loading the array when it is not needed:
audit the reads that fetch a wallet only for `totalPoints` or `tier` and add a
projection excluding `transactions`.

**Dependencies.** None.

**Production risk.** Low. Projection changes are reversible and the wallet
arithmetic is already covered by `tests/reward-adjustment.test.js`.

**Note.** The roadmap's framing — "the ceiling eventually makes a wallet
unwritable" — is correct and remains the reason to act eventually. It is not the
reason to act this quarter.

---

## 4.6 — `force-dynamic` on nine routes · STILL OPEN (product/infra decision)

**Current implementation.** Nine route files export `dynamic = 'force-dynamic'`:
`/`, `/blog`, `/blog/[slug]`, `/projects`, `/projects/[id]`,
`/projects/[id]/units/[unitTypeId]`, `/properties`, `/properties/[id]`,
`/sitemap.js`.

**Evidence.** Every one is server-rendered on demand, so any `revalidate` is
inert and no page is cached.

**Measured impact.** Not measured, and not measurable from here — it is a
hosting-cost and TTFB question that needs production traffic data.

**Proposed minimal fix.** None yet. The roadmap is explicit that "build-time API
availability needs solving first": these routes fetch from the API at build
time, and if the API is unreachable during a build, static generation fails. That
is an infrastructure question, not a code change.

**Dependencies.** Requires knowing whether the backend is reachable from the
build environment. On this deploy topology — three independently hosted apps —
that is not obviously true and must be confirmed rather than assumed.

**Production risk.** High if done carelessly: a failed build is a failed deploy.
**Recommend deferring** until someone can answer the build-time question.

---

## 4.7 — Admin property manager returns everything · STILL OPEN

**Current implementation.** `getAdminProperties` (`/properties/admin/all`)
executes `Property.find(query)` with **four** populates and a sort, and no
`.limit()` or `.skip()` anywhere in the handler.

**Measured impact.** 47 documents today. Same linear growth as 4.3, with one
more populate, on a page an admin opens routinely.

**Proposed minimal fix.** Paginate, sharing whatever mechanism 4.3 settles on.

**Dependencies.** The Admin property manager page must paginate at the same time.

**Production risk.** Medium, admin-facing only. Lower blast radius than 4.3
because the audience is three accounts, one of them active.

---

## 4.8 — `AuditLog` unbounded, no TTL, stores bodies · PARTIALLY FIXED

**Current implementation.** Five indexes exist, **none of them a TTL index**.
Request bodies are stored at `models/AuditLog.js:68`, but through a sanitiser
(`:167-192`) that strips sensitive fields before writing.

| Roadmap concern | State |
|---|---|
| Stores full request bodies including PII | **partly addressed** — sanitised, not raw |
| No TTL | **open** |
| Unbounded | **open** |

**Measured impact.** 833 documents, 907 KB. Growing with admin activity, which
is currently one active account.

**Proposed minimal fix.** Add a TTL index on `createdAt` with a retention period.
The period is the decision, not the index — and it interacts with the unanswered
retention question in `DEALDIRECT-DELETION-AND-RBAC-DECISION.md` §1.6.

**Dependencies.** **Blocked on a legal answer**, same as the deleted-user
retention period. Audit logs are exactly the records a data-protection request
argues about.

**Production risk.** Low to add, **irreversible in effect** — a TTL index starts
deleting on the next sweep, and there is no undo. This is the one Phase 4 item
that destroys data, so it needs the backup discipline used for the taxonomy
cutover.

---

## 4.9 — Hubble debit idempotency · NOT REPRODUCIBLE as described

**Claim.** "Hubble debit idempotency is an O(n) scan" — fix by indexing the
reference id.

**What the code does.** `hubbleController.js:253` scans the transaction array of
**one already-loaded wallet document**:

```js
const existingTxn = reward.transactions.find(
  (t) => t.metadata?.referenceId === referenceId && t.type === "redeem"
);
```

**Why the described fix does not apply.** This is not a collection scan. It is an
in-memory `Array.find` over one user's embedded array, bounded by that user's
transaction count — **max 71 in production**. There is no separate collection to
index, and adding an index to `Reward` would not touch this code path;
`metadata.referenceId` lives inside an embedded array on a document already in
memory.

**Reclassified.** Not a performance defect at current or plausible scale. It
becomes one only if 4.5 is solved by moving transactions into their own
collection, at which point the reference id genuinely needs an index — so the
two are linked, and this item should be folded into 4.5 rather than tracked
separately.

---

## 4.10 — `setCsrfToken` on every request · STILL OPEN

**Current implementation.** `app.use(setCsrfToken)` at `server.js:685`, global.
The middleware reads the cookie, generates a token when absent, and calls
`res.cookie(...)` on **every** request including safe methods and static assets.

**Measured impact.** Per request: a cookie parse, an occasional 32-byte random
generation, and a `Set-Cookie` header on every response. Small individually;
`Set-Cookie` on static asset responses also makes them uncacheable by shared
caches, which is the larger cost.

**Proposed minimal fix.** Skip safe methods and static paths, exactly as the
roadmap says. Half an hour.

**Dependencies.** None, but it interacts with the double-submit pattern: the
browser needs the cookie present *before* a mutating request. Skipping GET
entirely would break the first mutation of a session. The correct rule is to
skip static paths, and to keep issuing on HTML/API GETs.

**Production risk.** Medium despite the size — get the skip rule wrong and CSRF
breaks for real users. It needs the header-and-cookie tests that
`verify-api-client-dev.mjs` already performs.

---

## 4.11 — Retired `subcategory` still populated on every list · NEW

Not in the roadmap; found during this reconciliation.

**Current implementation.** `populate("subcategory")` appears **10 times** across
the property controllers, including in `getProperties`, `getAllPropertiesList`
and `getAdminProperties`.

**Evidence.** The subcategory level was retired in Phase 3B (decision D9): its
API is unmounted, `applyTaxonomy` strips any inbound reference, and zero of 47
properties ever referenced one. The schema path still exists
(`models/Property.js:15`), so the populate is legal — it just resolves nothing.

**Measured impact — CORRECTED after measuring.** **Zero queries.** Mongoose
skips a populate entirely when no document in the result set has the field set,
and zero of 47 properties have ever had a subcategory. The ten calls issued no
lookups at all.

An earlier draft of this document claimed "one extra lookup per populated
query". That was reasoning, not measurement, and it was wrong. Recorded here
rather than quietly corrected, because it is exactly the kind of plausible
number this baseline is supposed to avoid.

The change still earns its place — it removes a join on a retired relation that
would begin costing a lookup the moment any document acquired the field, and it
stops ten read paths referencing a level the product retired — but it is a
correctness and clarity fix, not a performance win.

**Proposed minimal fix.** Delete the ten `populate("subcategory")` calls. Leave
the schema path alone — removing it is part of the deferred destructive cleanup,
alongside deleting the 48 documents.

**Production risk.** Very low. Nothing consumes the populated value; the frontend
subcategory filter was removed in Phase 3B.

---

## The backlog, ordered

Ordered by production impact, then scalability risk, user-visible impact,
effort, and reversibility — as instructed.

| Rank | Item | Status | Effort | Reversible | Why here |
|---|---|---|---|---|---|
| 1 | **4.10** CSRF middleware scope | open | 30 m | yes | only item touching **every** request; makes static responses uncacheable |
| 2 | **4.11** retired subcategory populate | open | 30 m | yes | pure waste on the busiest reads, zero behavioural risk |
| 3 | **4.3 + 4.4** list bounds, retire `/filter` | open | 4 h | yes, with care | linear growth on the home feed; cheapest to fix while the corpus is 47 |
| 4 | **4.7** admin manager pagination | open | 3 h | yes | same growth, smaller audience |
| 5 | **4.5 + 4.9** wallet projection | open | 3 h | yes | stop loading arrays that are not read; defer the split |
| 6 | **4.2** saved-search query predicate | open | 3 h | yes | correct fix, but **zero** production load today |
| 7 | **4.8** AuditLog TTL | partial | 3 h | **NO** | blocked on a legal retention answer; deletes data |
| 8 | **4.6** `force-dynamic` | open | 1 d | no | blocked on build-time API availability |
| — | **4.1** notification fan-out | **done** | — | — | close it |

**Ranks 1 and 2 are the ones I would take first** — an hour together, no product
decision, no data movement, and both reversible.

**Ranks 7 and 8 should not start.** One is blocked on legal, the other on
infrastructure, and both are irreversible in different ways.

---

## What this baseline does not claim

No timings were taken. Everything above is document counts, byte sizes and code
reading — enough to size the risk and to reject 4.9's premise, not enough to
claim a latency improvement. Any item that ships should be measured before and
after against `dealdirect_dev` rather than asserted, the way the notification
N+1 was measured in `2e0ebf6`.

Production remains untouched: no write, no deploy, no migration, no index change.
