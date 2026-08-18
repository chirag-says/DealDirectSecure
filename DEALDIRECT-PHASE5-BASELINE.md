# Phase 5 — Baseline and Scope Reconciliation

Every item in the roadmap's Phase 5 table re-verified against the current code,
not carried forward from the audit. Three of the eleven have moved since the
audit was written, in both directions.

**No code was changed. Production was read-only. Nothing was committed.**

Test baseline: **536 unit, 589 integration, 1125 total, 0 failures, 0 todos.**

---

## Summary

| # | Item | Status |
|---|---|---|
| 5.1 | Correct stale claims in `AI/` | **STILL OPEN — and larger than the audit says** |
| 5.2 | Delete orphaned components | **FIXED (batch 1)** — 2 orphans, not 13 |
| 5.3 | Delete the dead MFA branch in `AuthContext` | **STILL OPEN** |
| 5.4 | Remove six duplicate Mongoose index definitions | **FIXED in code (batch 1)** — and it was hiding a real defect, see 3b |
| 5.5 | Remove six unused backend dependencies | **STILL OPEN — exactly six** |
| 5.6 | Decide on four half-adopted models/fields | **PARTIALLY OBSOLETE — two are now in use** |
| 5.7 | `notFound()` on property detail; projects in sitemap | **STILL OPEN** |
| 5.8 | Security headers in `next.config.mjs` | **STILL OPEN** |
| 5.9 | Bare-array handling zeroes the `/properties` SEO block | **FIXED (batch 1)** |
| 5.10 | `getSuggestions` localities facet always empty | **FIXED (batch 1)** — free-text search was broken too |
| 5.11 | Newsletter stub that posts nothing | **FIXED by removal (batch 1)** |

Nine are safe to complete now. None is blocked on a decision. None touches
production.

**Batch 1 completed 5.2, 5.4, 5.9, 5.10 and 5.11.** Remaining: 5.1, 5.3, 5.5,
5.6, 5.7, 5.8.

---

## 5.1 — Stale claims in `AI/` · STILL OPEN, and it grew

**Evidence.** 17 documents in `AI/`. Mention counts for things this remediation
changed or removed:

```
requirePermission   16   ← the layer was RETIRED in be600e2
subcategory         15   ← the level was RETIRED in 3b88ee0
ProtectedRoute      13   ← the audit's original example
group buy / -buy    15   ← now formally deferred (9360f41)
filterProperties     1   ← the endpoint was RETIRED in 3d8904b
```

The audit counted 24 stale claims. Phases 3 and 4 invalidated more: every
description of the permission layer, the subcategory taxonomy level, the
`/filter` endpoint, the notification post-save hook, and the unbounded list
endpoints is now wrong.

**Honest note:** this is partly self-inflicted. `CLAUDE.md` instructs appending
to `AI/CHANGELOG_AI.md` after any architectural change, and that did not happen
across Phases 3 and 4 — the decision documents were written instead. The
changelog entries are owed.

**Dependency.** None. **Effort:** larger than the 4 h estimated.

---

## 5.2 — Orphaned components · FIXED (batch 1)

**Evidence.** 40 components under `client-next/src/components`. Referenced
nowhere but their own file:

```
components/HeroSection/HeroSection_omnibox.jsx
components/MiddelComp.jsx
```

**Two, not thirteen.** The Phase 2.9 reachability work and the Phase 3G client
cleanup removed the rest.

The duplicate-copy half of the item is **obsolete**: there is exactly one
`AgreementGenerator.jsx` and one `LogoLoop.jsx`. Nothing to reconcile.

**Caveat.** Detection is by identifier reference across all of
`client-next/src`. A component reached only through a computed dynamic import
would not be seen. Both candidates were re-checked by name and have no
reference of any kind.

**Dependency.** None. **Effort:** minutes, not 4 h.

---

## 5.3 — Dead MFA branch in `AuthContext` · STILL OPEN

**Evidence.** `client-next/src/context/AuthContext.jsx` is 614 lines with **53**
MFA references. It posts to `users/verify-mfa` (line 262) and routes to
`/verify-mfa` (552, 571).

`backend/routes/userRoutes.js` registers **no** `/verify-mfa` route. MFA exists
for *admins* only, under `/api/admin/mfa/*`. The user-facing branch calls
endpoints that do not exist and routes to pages that do not exist.

**Risk of leaving it.** A login response containing `requiresMfa` would send a
user to a dead route. Nothing sets that flag today, so it is latent rather than
live.

**Dependency.** None. **Effort:** 1 h, as estimated.

---

## 5.4 — Duplicate Mongoose index definitions · FIXED in code (batch 1); one deployed index still wrong, see 3b

**Evidence.** Loading all 31 models emits exactly six warnings:

```
2 ×  Duplicate schema index on {"email":1}
2 ×  Duplicate schema index on {"expiresAt":1}
1 ×  Duplicate schema index on {"name":1}
1 ×  Duplicate schema index on {"referralCode":1}
```

Six, matching the roadmap. Each is a field declared with `index: true` or
`unique: true` **and** re-declared in a `schema.index()` call.

**Why it matters beyond noise.** Two related index defects were found during
Phases 3 and 4 — `builders.email_1` and `agreements.idempotencyKey_1` are both
deployed unique-and-non-sparse against schemas that say otherwise. Six warnings
on every boot is exactly the condition under which that kind of drift goes
unnoticed.

**Dependency.** None for the warnings themselves. Removing a *duplicate
declaration* does not alter the deployed index, so this is safe; changing what
an index IS belongs to the deferred index-cleanup stage.

**Effort:** 30 m.

---

## 5.5 — Unused backend dependencies · STILL OPEN

**Evidence.** 30 declared dependencies; six with no `import` or `require`
anywhere in `backend/` outside tests:

```
axios  body-parser  file-type  jspdf  jspdf-autotable  morgan
```

Six, matching the roadmap. `file-type` was checked specifically — magic-byte
validation is hand-rolled in `middleware/upload.js` and does not use it.
`axios` is a frontend dependency that never migrated out of the backend manifest.

**Caveat before deleting.** `jspdf` / `jspdf-autotable` are PDF libraries and the
backend does export PDFs — via `pdfkit`, which IS imported. Worth one more look
at the export controllers before removing, since a dynamic require would not be
caught by this scan.

**Effort:** 30 m.

---

## 5.6 — Four half-adopted models and fields · PARTIALLY OBSOLETE

The audit asked whether to migrate onto or delete four things. Two answered
themselves during Phases 3 and 4.

| Thing | Refs | Where | Verdict |
|---|---|---|---|
| `PasswordResetToken` | 8 | `userController`, its model, `aggregateDelete` | **IN USE — obsolete item.** The account cascade deletes it |
| `LoginTracker` | 11 | `userController`, its model, `aggregateDelete` | **IN USE — obsolete item.** Same |
| `sessionVersion` | 7 | `userModel` + `scripts/migrateLegacyUsers.js` only | **STILL OPEN.** Declared and migrated onto, but no auth path reads it |
| `hasCompletedFirstAction` | 1 | `userModel` only | **STILL OPEN.** Declared, written by nothing, read by nothing |

So the real item is two fields, not four models. `sessionVersion` is the
interesting one: the session-invalidation-on-password-change behaviour described
in `CLAUDE.md` is attributed to it, and nothing reads it — worth confirming what
actually provides that guarantee before deleting the field.

**Dependency.** None. **Effort:** under the 3 h estimated, now that half is moot.

---

## 5.7 — Soft-404 and sitemap · STILL OPEN

**Evidence.**

```
client-next/src/app/properties/[id]/page.js  calls notFound(): NO
client-next/src/app/sitemap.js               includes /projects: NO
                                             includes /properties: YES
```

A missing property renders a page with HTTP 200, so search engines index a
not-found page as real content. The projects vertical — an entire section with
its own detail and unit-type pages — is absent from the sitemap.

**Dependency.** None. **Effort:** 2 h.

---

## 5.8 — Security headers on the HTML origin · STILL OPEN

**Evidence.** `client-next/next.config.mjs` has no `headers()` block. The only
security-related line is a comment about not exposing the Next.js version. The
backend has Helmet; the origin that actually serves HTML to browsers has
nothing.

**Dependency.** None technically, but the roadmap's advice holds: start with
`Content-Security-Policy-Report-Only`. A blocking CSP on a page using inline
styles and third-party embeds breaks the site quietly, in the browser, where no
backend test will see it.

**Effort:** 4 h, and the report-only period is calendar time on top.

---

## 5.9 — Bare-array handling zeroes the SEO block · FIXED (batch 1)

**Root cause now certain**, from Phase 4.3.

`client-next/src/app/properties/page.js:35`:

```js
properties: propsData?.data || propsData?.properties || [],
```

It fetches `/api/properties/list?limit=50`. That endpoint returns a **bare
array** — confirmed in Phase 4.3, and recorded in mobile's own type definitions:
*"Returns a BARE ARRAY, no envelope."* An array has neither `.data` nor
`.properties`, so this always evaluates to `[]` and the hidden SEO block renders
with zero properties.

Phase 4.3 deliberately preserved the bare-array shape (wrapping it would have
been a breaking change), so this is unchanged and still broken.

**Fix:** `Array.isArray(propsData) ? propsData : (propsData?.data ?? [])`.
The file is 70 lines now, not the 765 the audit cites.

**Dependency.** None. **Effort:** 15 m.

---

## 5.10 — Empty localities facet · FIXED (batch 1); it also broke free-text search

**Evidence.** `getSuggestions` queries `address.locality` in four places
(`propertyController.js:2043, 2124, 2132, 2133`). The `address` subdocument is:

```
line  area  city  state  pincode  landmark  nearby  latitude  longitude
```

**No `locality`.** The audit is correct. The real field is a top-level
`locality` (`models/Property.js:58`), and production confirms where the data is:

```
properties with address.locality : 0
properties with top-level locality : 47
```

So the facet has never returned anything, for any user, since it was written.

**Fix:** point the four references at `locality`. **Effort:** 1 h.

---

## 5.11 — Newsletter stub · FIXED by removal (batch 1)

**Evidence.** `client-next/src/components/Footer/Footer.jsx:35-40`:

```js
// Simulate API call
setTimeout(() => {
  toast.success("Subscribed successfully!");
  setEmail("");
}, 500);
```

It validates the address, waits half a second, and tells the user they are
subscribed. Nothing is stored and nothing is sent.

**Dependency.** A product call on whether newsletters are wanted at all. If they
are, this is a feature; if not, remove the control. Removing it is the
conservative move — telling users they subscribed when no list exists is the
part that is actually wrong.

**Effort:** 15 m to remove.

---

## Deferred cross-phase items

These are not Phase 5. They are tracked here so the phase can close without
losing them.

### 1. Taxonomy production cutover

- **State:** fully prepared and rehearsed. Backup script, production-gated
  migration, dry run (47/47 mapped, 0 unknown), pre-cutover compatibility suite,
  and `DEALDIRECT-PRODUCTION-TAXONOMY-CUTOVER-PLAN.md`. Never executed.
- **Risk:** low to execute, high to execute carelessly. Deploy order matters:
  `client-next → backend → migration → Admin`.
- **Dependency:** decision of 2026-08-17 — ship once at the end, after all
  phases.
- **Phase 5?** No. **Operational/cutover:** yes. **Product/legal decision:** no.
- **Note:** the dry run is pinned to 47 properties. Re-run it before executing;
  the corpus will have moved.

### 2. `builders.email_1` index drift

- **State, verified in production today:** `unique=true, sparse=false`, against a
  schema declaring `{ email: 1 }, { sparse: true }` and NOT unique. One builder
  already holds a null email.
- **Risk:** live. **Creating a second builder without an email address fails
  right now** with a duplicate-key error, and `email` is not a required field so
  the admin form permits leaving it blank.
- **Dependency:** an index drop, which belongs to the deferred index-cleanup
  stage behind the cutover.
- **Phase 5?** No. **Operational:** yes. **Product/legal:** no.

### 3. `agreements.idempotencyKey_1` index drift

- **State, verified in production today:** `unique=true, sparse=false`. Zero
  documents currently hold a null key, so nothing is failing.
- **Risk:** latent. It bites the moment a second agreement is written without a
  key — and the agreements feature is currently unmounted, which is the only
  reason it has not.
- **Dependency:** same index-cleanup stage.
- **Phase 5?** No. **Operational:** yes. **Product/legal:** no.

### 3b. `adminsessions.expiresAt_1` is a plain index, not a TTL — **found while fixing 5.4**

- **State, verified in `dealdirect_dev`:** `adminsessions.expiresAt_1` exists
  with **no `expireAfterSeconds`**. `usersessions.expiresAt_1` has
  `expireAfterSeconds: 0`. Two collections, the same intent, different indexes.
- **Cause:** `AdminSession` declared `expiresAt` twice — `index: true` inline
  and an explicit TTL below. Mongoose creates the inline one first, as a plain
  index. The TTL that follows has the same key with different options, so
  MongoDB rejects it (`IndexOptionsConflict`) and Mongoose never retries.
  `UserSession` declared its TTL inline, so nothing shadowed it.
- **Consequence:** expired admin sessions are never removed. The collection
  grows without bound, and every expiry check has to be done in application
  code. It holds 0 rows in dev, so the size has not yet been noticed.
- **What 5.4 fixed:** the duplicate declaration. A **fresh** environment now
  builds the TTL correctly. It cannot repair an index that already exists —
  Mongoose only ever creates, it never alters or drops.
- **What remains:** dropping and recreating `adminsessions.expiresAt_1` in each
  deployed environment. That is a database change, so it joins the index-cleanup
  stage above rather than this batch.
- **Note:** this makes 5.4 a real defect rather than the boot-log noise it was
  filed as. The duplicate declaration was not cosmetic — it silently suppressed
  the index that was supposed to win.
- **Production state:** unverified. No production connection string is present
  in the repository, and this batch made no attempt to obtain one.
- **Phase 5?** No. **Operational:** yes. **Product/legal:** no.

### 4. Invalid ObjectId returns 500 — **reassessed, and smaller than recorded**

- **State:** `middleware/errorHandler.js:350` **already** maps `CastError` to a
  400 `CAST_ERROR`. The infrastructure is correct.
  The 500 comes from `getPropertyById` catching the error itself
  (`propertyController.js:858`) and returning its own `Failed to fetch property`.
- **Correction:** this was previously recorded as a global error-handler change
  that "touches every route". It is not. It is a controller that swallows an
  error the platform already handles correctly.
- **Risk:** low, and cosmetic-adjacent — users see "server error" for a bad link,
  and it is 5xx noise in Sentry.
- **Dependency:** none. Small enough to sit inside Phase 5 if wanted.
- **Phase 5?** Reasonably, yes. **Operational:** no. **Product/legal:** no.

### 5. Deleted-user retention policy

- **State:** the account cascade deletes twelve collections and retains five,
  with the decision boundary documented in `utils/aggregateDelete.js` and
  `DEALDIRECT-DELETION-AND-RBAC-DECISION.md` §1.6.
- **Risk:** the retained collections keep the person's name, email and phone
  indefinitely, with no retention period set.
- **Dependency:** **a product and legal answer.** No code change should precede
  it.
- **Phase 5?** No. **Operational:** no. **Product/legal decision:** yes.

### 6. AuditLog retention (Phase 4.8)

- **State, verified today:** 833 documents, **no TTL index**. Request bodies are
  stored but sanitised.
- **Risk:** unbounded growth, slowly. The larger risk is the opposite direction:
  a TTL index starts deleting on the next sweep and there is no undo.
- **Dependency:** the **same** legal retention answer as item 5. Audit logs are
  precisely the records a data-protection request argues about.
- **Phase 5?** No — it is Phase 4.8 and correctly blocked.
  **Operational:** partly. **Product/legal decision:** yes.

---

## Recommended order

Grouped by whether anything has to be decided first.

**Safe to complete now, no decision, no production contact** — roughly a day:

1. **5.9** bare-array SEO block — 15 m, root cause known, one line
2. **5.11** newsletter stub — 15 m
3. **5.4** duplicate index declarations — 30 m, and it makes future index drift visible
4. **5.10** localities facet — 1 h, confirmed against production data
5. **5.2** two orphaned components — minutes
6. **5.5** six unused dependencies — 30 m, with one check on the PDF libraries
7. **5.3** dead MFA branch — 1 h
8. **5.7** `notFound()` and the projects sitemap — 2 h
9. **Invalid ObjectId 500** — small, and narrower than previously recorded

**Needs care but no external decision:**

10. **5.8** security headers — start report-only; the risk is browser-side and
    invisible to the test suite
11. **5.6** `sessionVersion` and `hasCompletedFirstAction` — confirm what
    actually provides session invalidation before deleting the field

**Last, because it should describe the finished state:**

12. **5.1** correct `AI/` — do it after the rest of Phase 5 lands, or it will be
    stale again immediately. The owed `CHANGELOG_AI.md` entries for Phases 3 and
    4 belong here too.

**Intentionally deferred, not Phase 5:**

- taxonomy production cutover — operational, after all phases
- both index drifts — operational, in the index-cleanup stage behind the cutover
- deleted-user retention — product and legal
- AuditLog TTL (4.8) — same legal answer
- `force-dynamic` (4.6) — needs build-time API availability confirmed
- Group Buy and the builder-chain redesign — post-Phase-5 product build

---

## Verification

```
npm test                  536 pass, 0 fail, 0 todo
npm run test:integration  589 pass, 0 fail, 0 todo
npm run test:all          1125 total, 0 fail, 0 todo

production writes      = 0
production deployment  = 0
```

Production was read only, to confirm the two index drifts, the AuditLog TTL
state, and which locality field actually holds data.

### After batch 1 (5.9, 5.11, 5.4, 5.10, 5.2)

```
npm test                  536 pass, 0 fail
npm run test:integration  619 pass, 0 fail   (+30, suite 24)
npm run test:all          1155 total, 0 fail

mutation harness          8 killed, 0 survived
client-next build         succeeds
dealdirect_dev            7 pass, 0 fail; counts unchanged, the run wrote nothing
production writes         = 0
```
