# DealDirect: Production Taxonomy Dry Run

Phase 3B.2. **Read-only.** Every database operation was `find()` or
`listIndexes()`. No document was created, updated or deleted, and no index was
altered, in either environment.

No credentials or connection strings appear below. Hosts and database names only.

**Verdict: PRODUCTION MIGRATION BLOCKED.** The data is ready; three
preconditions are not. See §10.

---

## 1. Identity gate

| Check | Result |
|---|---|
| host is `dealdirect.rrp09uc.mongodb.net` | PASS |
| database is `Deal-Direct` | PASS |
| not the old ex-employee cluster (`vwlhuto`) | PASS |
| not the development cluster (`o1hwmkp`) | PASS |
| not the `dealdirect_dev` database | PASS |
| differs from the current `.env` target | PASS |

The production URI is not present in the working tree. `backend/.env` points at
development and `backend/.env.production` holds placeholders, so this validation
read the connection string from the pre-separation backup held outside the
repository. That is the only copy on this machine.

---

## 2. Source inventory (production)

| Collection | Count |
|---|---|
| `properties` | **47** |
| `categories` | 19 |
| `propertytypes` | 3 |
| `subcategories` | 48 |

**Distinct `categoryName`:** Residential 37, Commercial 10
**Null `categoryName`:** 0 · **Null `propertyTypeName`:** 0

**Distinct `propertyTypeName` (10):**

| Count | Name | | Count | Name |
|---|---|---|---|---|
| 21 | Apartment / Flat | | 2 | Warehouse / Godown |
| 9 | Independent House | | 1 | Shop / Retail |
| 5 | Villa | | 1 | Commercial Building / Floor |
| 3 | Office Space | | 1 | Restaurant / Cafe |
| 2 | Showroom | | 2 | Penthouse |

**`(categoryName, propertyTypeName)` pairs: 10**, identical to the mapping table.

**Reference distribution**

| State | Count |
|---|---|
| carrying a reference | **25** |
| both references null | **22** |
| `subcategory` set | 0 |
| distinct `category` refs | `"Residential Plot"`, `"Commercial Land"` |
| distinct `propertyType` refs | `"Plot"`, `"Commercial"` |

Two distinct values across 25 rows, neither describing the property that carries
it. Unchanged from the original analysis: the references hold no information and
are rebuilt from the name columns rather than repaired.

**Integrity**

| Check | Result |
|---|---|
| cross-category mismatches | **0** |
| duplicate names in `categories` | none |
| duplicate names in `propertytypes` | none |

---

## 3. Production vs the development baseline

| | Production | Development | Note |
|---|---|---|---|
| properties | 47 | 47 | |
| categories | 19 | 22 | dev includes 3 seeded canonical |
| propertytypes | 3 | 23 | dev includes 20 seeded canonical |
| subcategories | 48 | 48 | |

| Comparison | Result |
|---|---|
| property ids in production but not in the dev copy | **0** |
| property ids in the dev copy but not in production | **0** |
| properties whose `(categoryName, propertyTypeName)` differ | **0** |
| category names only in production | none |
| category names only in dev | Residential, Commercial, Land & Plots (seeded) |

Reference state differs exactly as expected: production 25 with-ref / 22 null,
development 47 with-ref / 0 null because development is migrated.

**The corpus has not drifted.** No listing was added, removed, or re-categorised
between the copy and this validation. The rehearsal on development is therefore a
faithful rehearsal of this data, not merely a similar one.

---

## 4. Mapping coverage

```
mapped     47 / 47   (100%)
unknown     0        REQUIRED: 0   PASS
ambiguous   0        REQUIRED: 0   PASS
```

Ambiguity is zero by construction, not by luck: the table is keyed on the exact
`categoryName|propertyTypeName` pair, so a single key cannot resolve to two
targets. Coverage is the empirical result, and it is complete.

The dry run performs exact-match lookups only. No substring, no fuzzy scoring, no
case folding, no positional fallback, no nearest candidate. A pair absent from
the table aborts the run.

---

## 5. Proposed property changes

All 47 properties are repointed. No name column is written.

| Action | Count | Meaning |
|---|---|---|
| repoint (replace stale) | **25** | had a reference describing a different property |
| repoint (fill null) | **22** | had no reference |

By pair:

| `categoryName` \| `propertyTypeName` | n | → Category | → Property Type |
|---|---|---|---|
| Residential \| Apartment / Flat | 21 | Residential | Apartment / Flat |
| Residential \| Independent House | 9 | Residential | Independent House |
| Residential \| Villa | 5 | Residential | Villa |
| Commercial \| Office Space | 3 | Commercial | Office Space |
| Commercial \| Showroom | 2 | Commercial | Showroom |
| Residential \| Penthouse | 2 | Residential | Penthouse |
| Commercial \| Warehouse / Godown | 2 | Commercial | Warehouse / Godown |
| Commercial \| Shop / Retail | 1 | Commercial | Shop / Retail |
| Commercial \| Commercial Building / Floor | 1 | Commercial | Commercial Building / Floor |
| Commercial \| Restaurant / Cafe | 1 | Commercial | Restaurant / Cafe |

Sample rows, as printed by the dry run (full 47-row output is reproducible by
re-running it):

```
692dbf64fd51d265479cb820  4 BHK Independent House for   Residential  Independent House            Residential Plot  Plot        -> Residential  Independent House            replace stale
692dc28ff254af1814393044  Shop / Retail for Rent in HS  Commercial   Shop / Retail                Commercial Land   Plot        -> Commercial   Shop / Retail                replace stale
692ee0b7145d115592d7d5f8  Commercial Building / Floor   Commercial   Commercial Building / Floor  Commercial Land   Commercial  -> Commercial   Commercial Building / Floor  replace stale
692f05002b1351ba9cda49dc  Office Space for Rent in Yel  Commercial   Office Space                 Commercial Land   Plot        -> Commercial   Office Space                 replace stale
```

Titles are public listing content. No owner, buyer, contact detail or other
personal data appears in the dry-run output.

---

## 6. Proposed taxonomy seed

| Change | Count | Detail |
|---|---|---|
| Categories to create | **3** | Residential, Commercial, Land & Plots |
| Property types to create | **20** | into `propertytypes`, each with a `category` parent |
| Name collisions with existing rows | **none** | no canonical type name currently exists in `propertytypes` |
| Documents renamed | **0** | |
| Documents deleted | **0** | |

Expected counts after the migration, before any cleanup:

| Collection | Before | After |
|---|---|---|
| `categories` | 19 | **22** |
| `propertytypes` | 3 | **23** |
| `properties` | 47 | 47 |
| `subcategories` | 48 | 48 |

The 19 obsolete category rows, the 3 obsolete type rows and the 48 subcategories
remain physically present and are hidden from the API by the active-taxonomy
filter. Deleting them is a separate destructive stage.

---

## 7. Production index differences

**Production today**

| Collection | Index | Key | Unique |
|---|---|---|---|
| `propertytypes` | `_id_` | `{_id:1}` | |
| `propertytypes` | **`name_1`** | `{name:1}` | **UNIQUE** |
| `categories` | `_id_` | `{_id:1}` | |
| `categories` | `name_1` | `{name:1}` | UNIQUE |
| `categories` | **`name_1_propertyType_1`** | `{name:1, propertyType:1}` | **UNIQUE** |

**Differences from the development model**

| Index | Production | Development | Conflict |
|---|---|---|---|
| `propertytypes.name_1` | present | dropped | Enforces global uniqueness; the target model scopes uniqueness to the parent category |
| `propertytypes.category_1_name_1` | **absent** | present, UNIQUE | The constraint the target model relies on does not exist yet |
| `categories.name_1_propertyType_1` | present | dropped | Indexes a parent field the target model removes from Category |
| `categories.name_1` | present, UNIQUE | present, UNIQUE | Correct in both |

**Neither conflicting index blocks the migration.** All 20 canonical type names
are distinct, so `name_1` admits the seed; the three new categories have distinct
names and no `propertyType`, so the compound index admits them too. The conflicts
matter afterwards, not during:

- while `propertytypes.name_1` exists, two categories cannot share a type name,
  which the target model is supposed to allow;
- `categories.name_1_propertyType_1` indexes a field new documents will not have.

Dropping them is a **separate reviewed step**, deliberately not part of this
migration and not performed here.

One sequencing note: `propertytypes.category_1_name_1` is declared in the schema,
so the application will attempt to build it on the first use of the model after
deployment. That is an index write triggered by a deploy rather than by the
migration script, and it is worth expecting rather than discovering.

---

## 8. Rollback prerequisites

Not yet satisfied. All are mechanical.

1. **Export first.** A JSON snapshot of `categories`, `propertytypes` and the 47
   properties' taxonomy fields, taken in the same session, stored outside the
   repository. Nothing has been exported yet.
2. **The migration log is the rollback.** Every repoint writes its previous
   `category`, `propertyType` and `subcategory` to `taxonomy_migration_log`
   keyed by run id, before the change. DOWN replays that log and never
   reconstructs values from the mapping table, because 25 of the 47 previous
   values are wrong in ways no rule reproduces.
3. **Name columns are never written**, in either direction. The reconstruction
   input survives, so the migration can be undone from the data itself even if
   the log were lost.
4. **Stage 1 and 2 are additive.** Rollback repoints properties and leaves the
   seeded taxonomy in place; removing seeded documents is a separate decision.
5. **Verified on development**, not merely designed: UP → UP (idempotent, 0
   written) → DOWN (47 restored, back to exactly 25 stale / 22 null) → UP
   (47 written, 47/47 consistent).

---

## 9. Preconditions

| # | Precondition | Status |
|---|---|---|
| 1 | Production identity positively confirmed | **PASS** |
| 2 | `unknown mappings = 0` | **PASS** |
| 3 | `ambiguous mappings = 0` | **PASS** |
| 4 | Null name columns = 0 | **PASS** |
| 5 | Cross-category mismatches = 0 | **PASS** |
| 6 | Corpus matches the rehearsed baseline | **PASS** (0 added, 0 removed, 0 changed) |
| 7 | Migration rehearsed on real data | **PASS** (development, full cycle) |
| 8 | Rollback mechanism verified | **PASS** (on development) |
| 9 | Pre-migration export taken | **FAIL, not done** |
| 10 | Migration script permits the production database | **FAIL, by design** |
| 11 | Application code deployed to production | **FAIL, not deployed** |

---

## 10. Blockers

**PRODUCTION MIGRATION BLOCKED.** Three items, none of them about the data.

### B1. The migration script refuses this database, deliberately

```js
const ALLOWED_DATABASES = ['dealdirect_dev', 'dealdirect_test'];
```

`Deal-Direct` is absent, so `migrateUp()` throws before touching anything. The
allow-list is positive rather than a block-list, so adding production has to be a
reviewed edit rather than an omission that stops mattering. It should be added in
the same change that runs the migration, and removed afterwards.

### B2. No pre-migration export exists

Rollback from the log is verified, but a run that dies partway depends on a log
written in the same run. The export is the independent copy. It takes a minute
and it has not been done.

### B3. Code and data must land together

This is the one worth pausing on. The deployed production backend is still the
pre-Phase-3B code. If the data is migrated while the old code is live:

- `Category.find().populate("propertyType")` still runs. The three new categories
  have no such field, so they populate as null rather than erroring, and the
  admin dropdown shows all 22 categories with the obsolete ones mixed in.
- The old create path still resolves taxonomy in the browser with the substring
  matcher, so **new listings would be written with wrong references again**,
  re-corrupting the corpus the migration just repaired.
- There is no active-taxonomy filter, so `Buy`, `Rent` and `Rental` remain
  selectable as categories.

Conversely, deploying the code before migrating the data leaves every existing
listing failing the consistency contract on edit, because their references do not
match their names.

**The two must ship together**, or the migration must run immediately after the
deploy with the window kept short. That sequencing decision is yours; it is not
something the dry run can settle.

---

## 11. Confirmation

- **production writes = 0**
- **taxonomy writes = 0**
- **property writes = 0**
- **index writes = 0**
- Database access was `find()` and `listIndexes()` only, against production and
  development
- No schema, code or environment file was modified while producing this report
- No credentials or connection strings recorded
