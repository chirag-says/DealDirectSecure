# DealDirect: Production Taxonomy Cutover Plan

Phase 3B.3. **Preparation only. Nothing in this plan has been executed against
production.** No production data, index or deployment was touched.

**Status: READY, DEFERRED.** The plan is complete and its tooling is tested.
Execution is held until phases 4 and 5 land, by decision on 2026-08-17.

No credentials or connection strings appear below.

---

## 1. Preflight checklist

| # | Item | Status |
|---|---|---|
| 1 | Production identity confirmed (`dealdirect.rrp09uc` / `Deal-Direct`) | **done** |
| 2 | Mapping coverage 47/47, unknown 0, ambiguous 0 | **done** |
| 3 | Zero drift between production and the rehearsed baseline | **done** |
| 4 | Migration rehearsed end to end on real data | **done** (development) |
| 5 | Rollback proven, twice | **done** (§8) |
| 6 | Production gate implemented and tested | **done** (§4) |
| 7 | Backup script written and guard-tested | **done**, not run (§2) |
| 8 | Dry-run artifact generated from production | **done** (§6) |
| 9 | New code proven safe on pre-migration data | **done** (§3) |
| 10 | **Maintenance window agreed** | **operator** |
| 11 | **Write freeze mechanism chosen** | **operator** |
| 12 | **Three app deploys scheduled, in order** | **operator** (§5) |
| 13 | **Phases 4 and 5 complete** | **outstanding** |

Items 10 to 12 are decisions and access this repository does not have. Everything
else is prepared.

Item 13 is a sequencing decision taken on 2026-08-17: production receives
finalised code only after the remaining phases are done, so this cutover is
**deferred**, not pending. The plan below stays valid; re-run the dry run before
using it, because the corpus will have moved.

---

## 2. Backup procedure

`backend/scripts/taxonomy-backup.sh`. **Not run.**

```bash
MONGO_URI='<production uri>' bash backend/scripts/taxonomy-backup.sh
```

- Read-only at the source. `mongodump` cannot write to what it reads.
- Collections: `properties`, `categories`, `propertytypes`, `subcategories`.
- Preserves index definitions and collection options via `.metadata.json`.
- Refuses unless the database is exactly `Deal-Direct` and the host contains
  `dealdirect.rrp09uc`. A backup of the wrong database is worse than none,
  because it looks like one.
- Refuses any output path inside the repository.
- Verifies every `.bson` and `.metadata.json` exists and is non-empty, and fails
  loudly if not.
- Writes `manifest.txt`: timestamp, host, database, document counts, reference
  split, and a `sha256` of every file.
- The URI is passed in the environment and never written to a file in the repo.

**Retention and recovery window.** Keep the archive until the migration is
verified in production **and for 30 days after**, then delete it: it is a copy of
production data. Recovery from it is a `mongorestore` of the four collections and
is the fallback if the migration log is unusable; expect single-digit minutes for
this corpus.

---

## 3. Deployment compatibility

Tested, not reasoned about. `tests/integration/taxonomy-precutover.test.js`
reproduces production's exact pre-migration state (legacy taxonomy only, **no**
canonical documents, 25 stale refs, 22 null) and exercises every path.

**18 tests, all passing. No compatibility fix was required.**

| Path | Result on pre-migration data |
|---|---|
| Public property list | works, no crash on stale or null refs |
| Property details, stale-ref listing | 200 |
| Property details, null-ref listing | 200 |
| Search by name | works, returns results |
| Owner dashboard | 200 |
| Owner edit screen load | 200 |
| Edit **not** touching taxonomy | **200**, stale ref left exactly as it was |
| Edit touching taxonomy | **400**, nothing changed |
| Create a property | **400** `TAXONOMY_UNKNOWN_NAME`, nothing stored |
| Legacy row resolved into a new ref | **impossible**, refused |
| Category selector | **empty** |
| Property type selector | **empty** |
| Admin taxonomy page | renders its empty state, no crash |

The new code satisfies all four requirements: it reads existing properties
safely, never creates a new stale reference, does not crash on temporarily
inconsistent refs, and enforces the contract on new writes.

### The one consequence that shapes the runbook

**Both taxonomy selectors are empty between the deploy and the seed.** The active
filter admits only canonical documents and none exist yet, so the create form
cannot be completed during that window.

This is correct behaviour for an allow-list, and it is deliberately not worked
around. The alternative, showing legacy rows until the seed lands, would let
someone file a listing under `Buy` during the very window the migration exists to
close. It is handled by keeping the window short and freezing writes, not by
loosening the filter.

Reads are unaffected throughout, so the site stays browsable.

---

## 4. Migration command and gate

Production is **not** on `ALLOWED_DATABASES`, and must not be added to it: that
would make every future run production-capable by default, including the ones
aimed at development by mistake. It requires four independent things:

```bash
MIGRATION_TARGET=production \
CONFIRM_DATABASE=Deal-Direct \
CONFIRM_CLUSTER=dealdirect.rrp09uc \
CONFIRM_PRODUCTION_MIGRATION=YES_I_UNDERSTAND \
MONGO_URI='<production uri>' \
node backend/scripts/taxonomy-migration.js up
```

The database name and cluster are checked against what **the live connection
reports**, not against what the operator typed, so a perfectly-formed
confirmation aimed at the wrong URI still fails.

Gate behaviour, verified across ten cases:

| Scenario | Result |
|---|---|
| dev database, no env vars | allowed |
| test database, no env vars | allowed |
| production database, no `MIGRATION_TARGET` | **refused** |
| dev database name on the production cluster | **refused** |
| unknown database | **refused** |
| production mode, no confirmations | **refused** |
| production mode, partial confirmation | **refused** |
| production mode, wrong phrase | **refused** |
| production mode, all confirmations, **wrong database** | **refused** |
| production mode, everything correct | allowed |

---

## 5. Cutover sequence

Estimated write freeze: **10 to 15 minutes**. The migration itself writes 47
documents and seeds 23; the time is dominated by verification, not by the write.

| # | Step | Command / action | Rollback if this fails |
|---|---|---|---|
| 0 | Announce the window | operator | abandon, nothing has changed |
| 1 | **Freeze writes** | maintenance mode, or scale the backend to zero | unfreeze, abandon |
| 2 | **Independent backup** | §2 | abandon; do not proceed without a verified archive |
| 3 | Verify the backup | manifest exists, counts match 47/19/3/48, checksums recorded | re-run step 2; abandon if it fails twice |
| 4a | **Deploy `client-next`** | its own repo | redeploy the previous build |
| 4b | **Deploy `backend`** | its own repo | redeploy the previous build; **no data has changed yet**, so this is a clean revert |
| 5 | Health check | `/health` 200; startup log shows `database=Deal-Direct` | roll back the deploy |
| 6 | Confirm the pre-migration state | `status` reports 47 properties, 0 consistent, 22 null | roll back the deploy; investigate before writing |
| 7 | **Run the migration** | §4 `up` | run `down`, then roll back the deploy |
| 8 | Verify invariants | §7 queries, expect 47/47 consistent, 0 broken, 0 null | run `down`; restore from backup if `down` misbehaves |
| 9 | Verify search equivalence | §7, every category and type | run `down` |
| 10 | Verify create and edit | create one listing per category, edit one, then delete the test listings | run `down` |
| 11 | **Unfreeze writes** | exit maintenance mode | re-freeze if step 12 finds anything |
| 12 | Monitor | §10 | `down` plus redeploy the previous build |

**The deploy and the migration are one operation.** Splitting them either leaves
the create form unusable (deploy without migrate, §3) or leaves the old code free
to write fresh stale references over the repaired data (migrate without deploy).

### Deploy order is not free: client-next before backend

This repository is the development source. It is **not** what production runs.
`backend`, `client-next` and `Admin` each live in their own repository and are
hosted independently, so "deploy Phase 3B" is three deploys, and their order
decides whether the site keeps working.

The live `client-next` fetches its add-property metadata like this:

```js
const [cats, subs, types] = await Promise.all([
  api.get('/categories/list-category'),
  api.get('/subcategories/list'),      // <- unmounted by the backend deploy
  api.get('/propertyTypes/list-propertytype')
]);
setMetadata({ ... });                  // never reached if any leg rejects
```

`Promise.all` rejects as a unit. The moment the backend unmounts
`/api/subcategories`, that 404 takes down the whole call, `setMetadata` never
runs, and the add-property form loses **all three** dropdowns, not just the
retired one. That is not the short seed window described above; it lasts until
`client-next` ships.

Deploying `client-next` first is safe in the other direction: it simply stops
asking for a route the old backend still serves. So:

```
client-next  ->  backend  ->  migration  ->  Admin
```

Keep `client-next` and `backend` close together. Between them the site runs new
frontend against old backend, which means the category dropdown still lists the
19 legacy rows, exactly as it does today. That is the current broken state
continuing briefly, not a new failure.

`Admin` can follow at any point. Its add-property screen never fetched
subcategories, and its `/add-subcategory` page is only reachable by URL once the
sidebar entry is gone.

---

## 6. Dry-run artifact

`backend/scripts/taxonomy-dryrun.mjs`, run against production **read-only**
(`find()` only; the file contains no update, insert, delete or index call).

Artifact: `~/dealdirect-taxonomy-dryrun-prod.tsv`, 47 rows, kept **outside the
repository**. It carries listing titles, which are public content, and no owner,
buyer or contact information.

It uses the same literal mapping table the migration uses, so it is a prediction
of that run rather than a separate approximation of it.

```
total properties : 47
mapped           : 47
stale replacement: 25
null fill        : 22
unknown          :  0
ambiguous        :  0   (keyed on the exact pair; one key cannot yield two targets)

GATE: PASS, coverage complete
```

Where the 47 land:

| Target | Rows |
|---|---|
| Residential / Apartment / Flat | 21 |
| Residential / Independent House | 9 |
| Residential / Villa | 5 |
| Residential / Penthouse | 2 |
| Commercial / Office Space | 3 |
| Commercial / Warehouse / Godown | 2 |
| Commercial / Showroom | 2 |
| Commercial / Shop / Retail | 1 |
| Commercial / Restaurant / Cafe | 1 |
| Commercial / Commercial Building / Floor | 1 |
| **Land & Plots** | **0** |

The proposed columns name the target rather than an id, because the canonical
documents do not exist in production yet. That is the honest representation of
"this document will be created"; inventing an id would make the artifact look
more verified than it is.

Every row also records what it is replacing, so the 25 stale ones can be checked
individually against the plan before the window opens.

---

## 7. Verification queries

Run after step 7. All read-only.

**Invariants** — `node backend/scripts/taxonomy-migration.js status`

```
properties      47
consistent      47      <- must equal properties
broken           0      <- must be zero
nullRefs         0      <- must be zero
categories      22      <- 19 legacy + 3 seeded
propertyTypes   23      <-  3 legacy + 20 seeded
```

`status` checks all three invariants per property: `category.name === categoryName`,
`propertyType.name === propertyTypeName`, and `propertyType.category === property.category`.

**Search equivalence** — the assertion that would have caught the original bug:

```
GET /api/properties/search?categoryName=Residential      ==  ?category=<Residential id>
GET /api/properties/search?categoryName=Commercial       ==  ?category=<Commercial id>
GET /api/properties/search?propertyTypeName=<each type>  ==  ?propertyType=<its id>
```

Compare returned id sets, not counts: equal counts with different members is a
failure that a count comparison cannot see.

**Active taxonomy**

```
GET /api/categories/list-category        -> exactly Residential, Commercial, Land & Plots
GET /api/propertyTypes/list-propertytype -> exactly 20
GET /api/subcategories/list              -> 404
```

No legacy name (`Buy`, `Rent`, `Rental`, `Apartment`, `Office space`,
`Shop / Showroom`, `Plots`, `Plot`) may appear in either list.

**Corpus unchanged**

Owner feed, builder feed and home page counts must match their pre-migration
values. The taxonomy changes; the listings do not.

---

## 8. Rollback

Two independent mechanisms. Neither is trusted alone.

### Mechanism 1: the migration log (primary)

Every repoint writes `previousCategory`, `previousPropertyType` and
`previousSubcategory` to `taxonomy_migration_log`, keyed by run id, **before**
the change. `down` replays that log.

```bash
MIGRATION_TARGET=production CONFIRM_DATABASE=Deal-Direct \
CONFIRM_CLUSTER=dealdirect.rrp09uc CONFIRM_PRODUCTION_MIGRATION=YES_I_UNDERSTAND \
MONGO_URI='<production uri>' node backend/scripts/taxonomy-migration.js down
```

It restores the exact previous values, wrong ones included. It never
reconstructs them from the mapping table, because 25 of the 47 are wrong in ways
no rule reproduces. A null reference comes back null, not "sensibly filled".

**Limitation, stated plainly:** if the run dies partway, this log covers only the
rows it reached. That is precisely why mechanism 2 exists.

### Mechanism 2: the independent backup (fallback)

`mongorestore` the four collections from the §2 archive. Covers every row
regardless of how the run ended, and is the only option if the log is unusable.

### Mechanism 3: the data itself

`categoryName` and `propertyTypeName` are **never written** by either direction.
Even with no log and no archive, the references can be rebuilt by re-running the
migration, because its only input survived untouched.

### Re-verified on development for this phase

```
before: 47 consistent, 0 null
DOWN  : 47 restored
after :  0 consistent, 22 null   <- exact original state
UP    : 47 written
final : 47 consistent, 0 broken
```

---

## 9. Index cleanup: a separate follow-up

**Not part of the cutover.** Production keeps all three indexes through the
migration.

| Index | State | Why it is left alone for now |
|---|---|---|
| `propertytypes.name_1` UNIQUE | keep | All 20 canonical names are distinct, so it admits the seed. It only conflicts with the *future* ability to reuse a type name under a second category |
| `categories.name_1_propertyType_1` UNIQUE | keep | The three new categories have distinct names and no `propertyType`, so it admits them |
| `categories.name_1` UNIQUE | keep permanently | Correct: categories are the top level |
| `propertytypes.category_1_name_1` UNIQUE | will be created on deploy | Declared in the schema, so the application builds it on first use of the model |

Combining index changes with the reference migration would mean two unrelated
failure modes in one window, and an index drop is not covered by the migration
log. The follow-up, on its own day:

```
migration verified in production
   -> confirm no query plan depends on propertytypes.name_1
   -> confirm categories.name_1_propertyType_1 is unused
   -> drop propertytypes.name_1
   -> drop categories.name_1_propertyType_1
   -> verify category_1_name_1 exists and is unique
   -> verify same-name-different-category is now insertable
```

Both were already dropped in development, where the parent-scoped constraint is
covered by tests.

### The legacy-document cleanup got easier

The other deferred stage, deleting the nineteen obsolete categories and the
three parentless property types, no longer needs a bespoke script. After the
migration every listing points at a canonical document, so the legacy rows are
unreferenced, and the admin delete endpoint now refuses only two things: a
canonical document, and one still referenced by a listing (§9a). A legacy row is
neither, so it deletes through the normal endpoint with the integrity check
enforced server-side.

The 48 subcategory documents still need a direct database delete: their API is
unmounted and nothing reads them.

---

## 9a. The canonical taxonomy is protected server-side

Added after the cutover plan was first written, because the plan assumed the
seeded documents would stay as seeded and nothing enforced that.

Four admin endpoints could rename or delete any taxonomy document:

```
PUT    /api/categories/edit/:id       DELETE /api/categories/delete/:id
PUT    /api/propertyTypes/edit/:id    DELETE /api/propertyTypes/delete/:id
```

None knew the contract existed. Renaming `Residential` raises no error anywhere:
the document stays valid and stays referenced by 37 listings. It just stops
matching the allow-list, so it vanishes from every dropdown and every create
against it starts returning `TAXONOMY_UNKNOWN_NAME`. Nothing reports that.
Deleting is faster: twenty requests empty the property type taxonomy and strand
every listing in the database. Both were reproduced against the real endpoints
before the guard was written.

Two rules now, both returning 409:

| Code | Refuses |
|---|---|
| `TAXONOMY_PROTECTED` | editing or deleting a canonical document, including moving a canonical type to another category |
| `TAXONOMY_IN_USE` | deleting any document listings still reference |

A property type is canonical **for its parent**, so a row named `Villa` under a
legacy category is history and stays deletable. Everything outside the canonical
set stays editable, which is what keeps the cleanup stage above possible.

The vocabulary changes through `config/taxonomy.js` and a migration, so the data
and the contract move together. That is the only path.

---

## 10. Outage expectations and monitoring

**Write freeze: 10 to 15 minutes.** Reads work throughout; the site stays
browsable. During the freeze, creating or editing a listing fails, and after the
deploy but before the seed the create form's dropdowns are empty (§3).

**Watch for 24 hours afterwards:**

| Signal | Meaning |
|---|---|
| `TAXONOMY_UNKNOWN_NAME` in logs | a client is sending a non-canonical name. Mobile is the likely source: it still ships the merged vocabulary and would be rejected |
| `TAXONOMY_PARENT_MISMATCH` | a client is pairing a type with the wrong category |
| `TAXONOMY_RETIRED` | something is still offering a legacy row |
| 500s from `/api/categories/*` or `/api/propertyTypes/*` | the selectors are down and the create form is unusable |
| Owner feed count drift | the corpus changed, which the migration must not have caused |
| New properties with null refs | the contract is being bypassed somewhere |

**Known follow-ups, not blockers:** mobile still carries the merged vocabulary
and would be rejected by the contract (it is stub-only with no submissions); the
obsolete taxonomy rows and 48 subcategories remain physically present pending the
destructive stage; there is no admin screen for creating property types.

---

## 11. Confirmation

- **Production data write = 0**
- **Production index write = 0**
- **Production deployment = 0**
- **Cutover plan = READY**

Production access this phase was `find()` only, to generate the dry-run artifact.
The backup script, the migration command and the index cleanup were prepared and
guard-tested but not executed. All rollback testing ran against `dealdirect_dev`.
