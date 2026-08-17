# DealDirect: Taxonomy Decision (definitive)

Phase 3B, design only. No code, schema, collection or property record was
modified. No migration was run. All database access was `find` and `aggregate`.

This document supersedes §5 of `DEALDIRECT-PHASE3-ARCHITECTURE-PLAN.md` wherever
they conflict, and it corrects that section in one material way (§1.1).

Every figure comes from read-only queries against the single database this
repository is configured to reach, re-run on 2026-08-17 for this revision.
**Which environment that database represents is unresolved: see §0.** §10 states
what must be re-measured once the target is confirmed.

**Status: BLOCKED.** Two independent blockers: database identity (§0) and
open decisions (§12). The first outranks the second.

---

## 0. BLOCKER: database identity unresolved

**No write operation of any kind is permitted until this is resolved.**

`backend/.env` and `backend/.env.production` currently contain **byte-identical
`MONGO_URI` values**. They name the same cluster host and the same database.

This repository alone cannot establish which environment that database
represents. It may be production, it may be development, or the two may share
one database. The deployed application may also receive its connection string
from the host at deploy time rather than from `.env.production`, in which case
that file is stale and misleading. Nothing inside this repository distinguishes
these cases.

**Consequences that follow immediately**

- The corpus measured throughout this document, 47 properties and the three
  taxonomy collections, came from that single database. Earlier revisions of this
  document and of the Phase 3 plan described it as "the development database".
  That label was inherited from context, not established by evidence, and is
  withdrawn. All access was read-only, so nothing was altered.
- There is no separate development database to rehearse a migration against. The
  only isolated target available is the in-memory replica set used by the
  integration harness.
- A migration run from this repository would write to whatever that URI serves.
- §10's production dry-run cannot be performed as specified, because no second
  corpus is reachable from here to compare against.

### 0.1 What repository configuration does and does not show

Investigated read-only, from repository files only. No credentials are recorded
below; hosts and database names only.

| Question | Finding |
|---|---|
| Configured database host | One real Atlas cluster, `deal-direct.vwlhuto.mongodb.net`. The only other Mongo hosts in the repository are placeholders: `cluster.mongodb.net` in the deployment template and `cluster0.example.mongodb.net` in a test fixture |
| Configured database name | `Deal-Direct` |
| Environment-file source | `backend/.env` and `backend/.env.production`, both untracked. `server.js` prefers `.env` when present and falls back to `.env.production` |
| Where production receives its runtime URI | **Contradictory evidence, unresolved.** `HOSTINGER_DEPLOYMENT.md` §2.3 says the backend's variables, including `MONGO_URI`, are set in the Hostinger panel; `backend/.env.production` says to copy itself to `.env` on the server. Platform variables win over any `.env` file, so these are mutually exclusive. Investigated in full in [`DEALDIRECT-DATABASE-ENVIRONMENT-REPORT.md`](DEALDIRECT-DATABASE-ENVIRONMENT-REPORT.md) |
| Separate development DB configuration | **None.** No second `MONGO_URI` exists anywhere. No CI workflow, Dockerfile, compose file, PM2 ecosystem file or platform config exists that could inject a different value |
| A true isolated writable development database | **None persistent.** The only isolated writable database in the repository is the in-memory replica set the integration harness starts per test process. It is ephemeral and cannot serve as a migration rehearsal target for real data |

**What this does not settle.** The repository describes what *should* be
deployed, not what *is*, and it gives two incompatible accounts of even that. The
full investigation is in
[`DEALDIRECT-DATABASE-ENVIRONMENT-REPORT.md`](DEALDIRECT-DATABASE-ENVIRONMENT-REPORT.md);
its conclusion is that the roles are **Unknown**, not "shared". An earlier
revision of this section leaned toward "one database serves both", which the
deployment guide's §2.3 does not support. Both readings remain open.

**DATABASE IDENTITY CANNOT BE ESTABLISHED FROM THIS REPOSITORY.**

**Required before any write**

1. Establish, outside this repository, which database each environment uses.
2. If production and development share one database, that is a separate and more
   urgent problem than the taxonomy.
3. If they are distinct, correct `.env.production` or document that the deployed
   value is injected elsewhere.
4. Re-run the §10 read-only validation against the confirmed production target.

No credentials or connection strings are recorded in this document. The
comparison above was made on host and database name only.

**Still blocked by this:** taxonomy seed, taxonomy repoint, deletion of any
taxonomy document, taxonomy-related schema changes, and subcategory retirement.

**Not blocked by this:** the create-time resolver hardening, which touches no
database and is recorded in §14.

---

## 1. Verification of the findings

Seven conclusions, each re-checked against the live database rather than carried
forward from the previous pass. All seven hold. See §0 on what that database is.

| # | Conclusion | Verdict | Evidence |
|---|---|---|---|
| C1 | `propertytypes` behaves as the parent (category) collection | **PASS** | 3 rows, none carries a parent ref; 19 of 19 `categories` carry a `propertyType` parent, all resolving into `propertytypes` |
| C2 | `categories` behaves as the child (property type) collection | **PASS** | 19 rows, every one has a parent |
| C3 | `Buy`, `Rental`, `Rent` are listing intents, not types | **PASS** | 3 rows present in `categories`, referenced by 0 properties; `listingType` already carries the same information on all 47 |
| C4 | Existing property ObjectIds are not trustworthy | **PASS** | 25 rows carry refs; **0** have both refs matching their own name columns. Only 2 distinct `category` refs exist (`Residential Plot`, `Commercial Land`) and 2 distinct `propertyType` refs (`Plot`, `Commercial`) |
| C5 | `categoryName` and `propertyTypeName` are the trusted inputs | **PASS** | 47 of 47 populated; **0** rows place a commercial type under Residential or vice versa |
| C6 | `subcategory` is unused | **PASS** | 0 of 47 reference one, 0 of 47 carry a `subcategoryName`; of the 48 documents, 30 are BHK values and 9 are the literal `Standard` |
| C7 | Web, mobile and database vocabularies differ | **PASS** | 10 distinct pairs across 47 properties; four divergent client surfaces, detailed in §7 |

C4 is stronger than previously reported. The earlier pass said one row had a
matching `propertyType`; checking **both** refs against both name columns gives
zero. Not one ref in the corpus is correct.

### 1.1 The correction to the architecture plan

§5.1 of the plan called this a "semantic inversion" and implied the refs could be
swapped into correctness. The collections are indeed inverted. **The property
refs are not.** They are a constant, produced by two resolution bugs in the create
form:

1. `findObjectId` fell through to a substring match, so `"Residential"` matched
   the document named `"Residential Plot"` and `"Commercial"` matched
   `"Commercial Land"`.
2. When that failed too, the old code stamped `metadata.propertyTypes[0]._id`,
   which is how apartments, villas and penthouses all became `Plot`.

Both are fixed; refs are now omitted rather than guessed, which is why newer rows
are null. The 22 nulls are the corrected behaviour and the 25 refs are the
wreckage.

**Consequence for the migration: no existing ref is an input. All 47 are rebuilt
from the name columns.**

### 1.2 Current state, for reference

| Collection | Rows | Holds | Level |
|---|---|---|---|
| `propertytypes` | 3 | `Residential`, `Commercial`, `Plot` | parent |
| `categories` | 19 | 16 property types, 3 listing intents | child |
| `subcategories` | 48 | 15 distinct names, mostly BHK | grandchild, unreferenced |

47 properties, 10 distinct `(categoryName, propertyTypeName)` pairs, 46 owner-feed
and 1 builder-feed, `listingType` split 31 Rent and 16 Sell.

---

## 2. Final proposed target taxonomy

Two levels. Subcategory retired (§4).

```
Category
   |
   +-- Property Type
```

**Residential** (8)
`Apartment / Flat` · `Independent House` · `Villa` · `Builder Floor` ·
`Row House` · `Studio Apartment` · `Penthouse` · `Farm House`

**Commercial** (8)
`Office Space` · `Shop / Retail` · `Showroom` · `Restaurant / Cafe` ·
`Co-Working Space` · `Warehouse / Godown` · `Industrial Shed` ·
`Commercial Building / Floor`

**Land & Plots** (4)
`Residential Plot` · `Commercial Land` · `Industrial Land` · `Agricultural Land`

Three categories, twenty property types. This is a proposal, not an approved
schema.

### 2.1 How the collections get there

The earlier framing offered "rename the collections" and "move the contents" as
distinct options. They are not: renaming collection A to B and B to A produces
exactly the same end state as swapping their contents. The real choice is only
between making each collection hold what its name says, and repointing the
`Property` fields to cross over.

| Option | End state | Verdict |
|---|---|---|
| Make contents match names | `categories` holds the 3 categories; `propertytypes` holds the 20 types | **Recommended** |
| Repoint `Property.category` at `propertytypes` and vice versa | A collection named `categories` permanently holds property types | Rejected: leaves the lie in place forever |

Implementation is a fresh seed of both collections followed by a repoint, not a
collection rename. Renaming reaches the same place but is harder to roll back, and
it does not avoid re-seeding: nine property types do not exist under any name
today, four need renaming and six must go, so the child level is largely rewritten
regardless.

**No public API path changes.** `/api/categories/list-category` keeps its URL and
starts returning Residential, Commercial and Land & Plots, which is what its name
always implied. `/api/propertyTypes/list-propertytype` keeps its URL and starts
returning the twenty types.

---

## 3. The remaining product decisions

### D5. `Shop / Retail` versus `Showroom`

**Evidence**

| Source | Treatment |
|---|---|
| Web form | Two separate options: `Shop / Retail` and `Showroom` |
| Admin form | Two separate options, list identical to web |
| Mobile | One merged option: `Shop / Showroom` |
| Database | One merged row: `Shop / Showroom` |
| Existing properties | 1 listing chose `Shop / Retail`, 2 chose `Showroom`. Zero chose a merged label, because no client offers one |

**Recommendation: keep them separate.**

Three owners were shown both options and made a choice between them. Merging
discards a distinction they actively drew, and it cannot be recovered afterwards:
once three rows read `Shop / Showroom`, nothing records which was a shop and which
was a showroom. Splitting later would mean asking the owners again.

The case for merging rests on the database and mobile happening to have a merged
row, but neither has produced a listing, so neither reflects a user choice.

**Downstream effects**

- `Shop / Showroom` is retired, not renamed; two rows take its place.
- Mobile's `COMMERCIAL_TYPES` gains an entry and loses the merged one.
- Search by `propertyTypeName=Showroom` returns 2 rather than 0.
- Any saved search or filter chip referencing `Shop / Showroom` breaks. A grep
  found none outside mobile's constant list.
- If wrong, the cost is two rows that can be merged later with the distinction
  still in the data. The reverse is not recoverable, which is why this is the
  safer direction to be wrong in.

### D8. Land and Plot hierarchy

**Alternatives**

| Option | Shape | Consequence |
|---|---|---|
| **A. Third top-level category** | `Land & Plots` alongside Residential and Commercial, 4 types | Matches the existing database shape; plots stop pretending to be dwellings |
| B. Types inside Residential and Commercial | `Plot / Land` under Residential, `Commercial Plot` under Commercial (mobile's model) | Two categories only, but a plot inherits a field set built for buildings |
| C. Remove entirely | No land in the taxonomy | Smallest surface; forecloses a segment the data model already anticipates |

**Recommendation: A, a third top-level category.**

A plot has no BHK, no furnishing, no bathrooms, no floor number and no
construction status. Those field sets are chosen by category in every form in the
product. Putting land under Residential means either showing a buyer a bedroom
count for a field, or special-casing a type inside a category that is supposed to
be homogeneous. The database already models it as a parent with four children,
which is evidence that someone reached this conclusion before.

**Explicit impacts**

- **Create-property UI.** A third category card and a field set that suppresses
  the residential and commercial blocks. This is the largest single piece of work
  in the proposal and the reason D8 is a real decision rather than a formality.
- **Filters.** The category filter gains a third value. The type filter is already
  driven by the selected category and follows automatically.
  `PropertyListContent` derives `isResidential` / `isCommercial` from
  `categoryName` and needs a third branch rather than an else.
- **Mobile vocabulary.** `Plot / Land` and `Commercial Plot` leave
  `RESIDENTIAL_TYPES` and `COMMERCIAL_TYPES` and become the four Land & Plots
  types.
- **Admin taxonomy.** Three parents instead of two. No structural change.
- **Existing listings.** **Zero properties affected.** No listing uses a land type
  today, so this decision changes no record. It is entirely about what the product
  offers next.

Because no data moves, D8 can be deferred without blocking the migration: seed
Residential and Commercial now, add Land & Plots when the create UI is ready. It
is the one decision here with a safe "decide later" option, and §12 records that.

### D6. `Commercial Building / Floor`

**Recommendation: create it as its own type under Commercial.**

One listing uses it. Every alternative loses information:

- Mapping to `Office Space` asserts the space is fitted out for office use. A
  whole building or a bare floor is a shell, and the buyer's question is different.
- Mapping to `Commercial Land` is plainly wrong: there is a building on it.
- Web and Admin both offer it, so the option would have to be removed from two
  UIs to stop the pair recurring, and the next owner wanting it would choose
  something inaccurate instead.

The cost of creating it is one row.

### D7. `Restaurant / Cafe`

**Recommendation: create it as its own type under Commercial.**

One listing uses it. A restaurant carries fittings no other commercial type
implies: kitchen area, bar area, outdoor seating. Those fields already exist on
`propertySchema` and are already in the create form's commercial configuration,
which means the product has effectively decided this is a distinct type. Folding
it into `Shop / Retail` would leave a listing whose kitchen and bar fields are
populated under a type with no reason to show them.

---

## 4. D9. Subcategory

**Technical recommendation: retire it. Product decision: yours.**

The distinction matters. The evidence is one-sided on whether the level *works*
and silent on whether the product *wants* one. Nobody populating a field is not
proof that it should not exist.

**Evidence for retiring**

| Finding | Figure |
|---|---|
| Properties referencing a subcategory | **0 of 47** |
| Properties with a `subcategoryName` | **0 of 47** |
| Documents that are BHK values, duplicating `Property.bhk` | **30 of 48** |
| Documents that are the literal string `Standard` | **9 of 48** |
| Documents that are early experimentation | **9 of 48**, including `Offece`, `Banglows`, `yearly`, `Family` |
| Distinct names across all 48 | **15** |

The BHK duplication is the substantive point. `Property.bhk` is a first-class
field the create form fills on every residential listing. Modelling `2 BHK` a
second time as a taxonomy node gives two places to store one fact and no rule for
which wins.

**The live consumer.** `HomeContent.jsx` fetches
`/subcategories/byCategory/:categoryId` and renders a filter. Because no property
references a subcategory, selecting any value returns zero results. The feature is
reachable, visible, and cannot work.

**What retiring means.** Remove the third level from the create and filter UIs,
retire the five `/api/subcategories/*` routes, keep the `SubCategory` model file
and the 48 documents until the migration is confirmed, then delete at stage 5.

**What retaining would require.** A decision on what a subcategory is *for*, given
BHK already exists; then populating it for 47 existing listings, which is 47
judgement calls; then adding a field to the create form. Nothing in the codebase
suggests a purpose beyond BHK.

**Recommendation: retire.** But this permanently narrows the product, so it should
be an explicit approval rather than an inference from disuse.

---

## 5. Naming conventions, ratified

Canonical names are the **web product vocabulary**, because it is the only
vocabulary that has produced a listing, and Admin already matches it exactly.
Where the database differs, the database row is renamed.

| Canonical name | Database today | Action |
|---|---|---|
| `Apartment / Flat` | `Apartment` | Rename |
| `Independent House` | `Independent House` | Unchanged |
| `Villa` | `Villa` | Unchanged |
| `Office Space` | `Office Space` **and** `Office space` | Keep one, delete the duplicate |
| `Warehouse / Godown` | `Warehouse/Godown` | Rename, spaces around the slash |
| `Co-Working Space` | `Co-working` | Rename |
| `Farm House` | not present | Create |

**No aliases.** Not a lookup table, not a synonym list, not a case-insensitive
resolver. An alias layer is how a second vocabulary becomes permanent: it removes
the pressure to converge and guarantees the next client picks whichever spelling
it prefers. One name per concept everywhere, enforced by the mapping table
aborting on anything it does not recognise.

The one legitimate exception is a UI label. If a screen needs to show "Apartment"
for space reasons, that is a display string; the stored value stays
`Apartment / Flat`.

---

## 6. Canonical taxonomy contract

The source for the migration. Ids are truncated to 8 characters for readability;
the migration uses full ids.

**Category level** (target: `categories` collection)

| Canonical name | Status | Existing row | Action |
|---|---|---|---|
| `Residential` | existing, reusable | `propertytypes` / `691a98fb` | Seed at category level with this name |
| `Commercial` | existing, reusable | `propertytypes` / `691ad6e1` | Seed at category level with this name |
| `Land & Plots` | rename | `propertytypes` / `69209a69` (`Plot`) | Seed at category level, renamed. **Depends on D8** |

**Property type level** (target: `propertytypes` collection)

| Category | Canonical name | Status | Existing row | Action |
|---|---|---|---|---|
| Residential | `Apartment / Flat` | rename | `categories` / `69209a66` (`Apartment`) | Seed renamed |
| Residential | `Independent House` | existing, reusable | `categories` / `69209a66` | Seed as-is |
| Residential | `Villa` | existing, reusable | `categories` / `69209a67` | Seed as-is |
| Residential | `Builder Floor` | create | none | Seed new |
| Residential | `Row House` | create | none | Seed new |
| Residential | `Studio Apartment` | existing, reusable | `categories` / `69209a67` | Seed as-is |
| Residential | `Penthouse` | existing, reusable | `categories` / `69209a68` | Seed as-is |
| Residential | `Farm House` | create | none | Seed new |
| Commercial | `Office Space` | existing, reusable | `categories` / `691d66a3` | Seed as-is; delete `691b06b0` (`Office space`) |
| Commercial | `Shop / Retail` | create | none, `Shop / Showroom` retired | Seed new. **Depends on D5** |
| Commercial | `Showroom` | create | none, `Shop / Showroom` retired | Seed new. **Depends on D5** |
| Commercial | `Restaurant / Cafe` | create | none | Seed new. **Depends on D7** |
| Commercial | `Co-Working Space` | rename | `categories` / `69209a68` (`Co-working`) | Seed renamed |
| Commercial | `Warehouse / Godown` | rename | `categories` / `69209a68` (`Warehouse/Godown`) | Seed renamed |
| Commercial | `Industrial Shed` | existing, reusable | `categories` / `69209a69` | Seed as-is |
| Commercial | `Commercial Building / Floor` | create | none | Seed new. **Depends on D6** |
| Land & Plots | `Residential Plot` | existing, reusable | `categories` / `69209a69` | Seed as-is. **Depends on D8** |
| Land & Plots | `Commercial Land` | existing, reusable | `categories` / `69209a69` | Seed as-is. **Depends on D8** |
| Land & Plots | `Industrial Land` | existing, reusable | `categories` / `69209a69` | Seed as-is. **Depends on D8** |
| Land & Plots | `Agricultural Land` | existing, reusable | `categories` / `69209a69` | Seed as-is. **Depends on D8** |

**Rows to delete** (stage 5, after verification)

| Name | Collection | Reason |
|---|---|---|
| `Buy` | `categories` | Listing intent, not a type. D2 |
| `Rental` | `categories` | Listing intent. D2 |
| `Rent` | `categories` | Listing intent. D2 |
| `Office space` | `categories` | Case duplicate of `Office Space`. D3 |
| `Shop / Showroom` | `categories` | Replaced by two rows. D5 |
| `Plots` | `categories` | Redundant with `Commercial Land` under Land & Plots |
| 48 subcategory documents | `subcategories` | D9 |

Totals: 3 categories, 20 property types, 9 types created, 4 renamed, 6 taxonomy
rows deleted, 48 subcategories deleted.

---

## 7. Canonical vocabulary contract for all clients

Three vocabularies, each needing exactly one canonical form.

### 7.1 Category vocabulary

| Surface | Today | Canonical |
|---|---|---|
| Database | `Residential`, `Commercial`, `Plot` | `Residential`, `Commercial`, `Land & Plots` |
| Web | `Residential`, `Commercial` | add `Land & Plots` |
| Admin | `Residential`, `Commercial` | add `Land & Plots` |
| Mobile | `Residential`, `Commercial` | add `Land & Plots` |

### 7.2 Property type vocabulary: every current mismatch

`OK` means the surface already uses the canonical name.

| Canonical | Database | Web | Admin | Mobile |
|---|---|---|---|---|
| `Apartment / Flat` | `Apartment` | OK | OK | OK |
| `Independent House` | OK | OK | OK | merged into `Independent House / Villa` |
| `Villa` | OK | OK | OK | merged |
| `Builder Floor` | absent | OK | OK | absent |
| `Row House` | absent | OK | OK | absent |
| `Studio Apartment` | OK | OK | OK | OK |
| `Penthouse` | OK | OK | OK | OK |
| `Farm House` | absent | OK | OK | `Farmhouse` |
| `Office Space` | OK, plus duplicate `Office space` | OK | OK | OK |
| `Shop / Retail` | merged as `Shop / Showroom` | OK | OK | merged |
| `Showroom` | merged | OK | OK | merged |
| `Restaurant / Cafe` | absent | OK | OK | absent |
| `Co-Working Space` | `Co-working` | OK | OK | `Co-working Space` |
| `Warehouse / Godown` | `Warehouse/Godown` | OK | OK | OK |
| `Industrial Shed` | OK | OK | OK | OK |
| `Commercial Building / Floor` | absent | OK | OK | absent |
| `Residential Plot` | OK | absent | absent | `Plot / Land` |
| `Commercial Land` | OK | absent | absent | `Commercial Plot` |
| `Industrial Land` | OK | absent | absent | absent |
| `Agricultural Land` | OK | absent | absent | absent |

Web and Admin agree exactly on all sixteen non-land types. Mobile diverges on
eight. The database diverges on nine.

**Mobile follows.** It has produced no listings and every feature screen is a
stub. It must not introduce a fourth vocabulary, and its two merges are exactly
the distinctions D5 and D11 resolve in the other direction.

### 7.3 Listing intent vocabulary

Not previously documented, and a live divergence.

| Surface | Value used for a sale |
|---|---|
| `propertySchema` enum | accepts `Sell`, `Sale`, `sell`, `sale` |
| Web form | sends `Sell` |
| Admin form | defaults to `Sale` |
| Mobile types | declares `'Rent' \| 'Sale'` |
| Data today | 16 `Sell`, 31 `Rent`, zero `Sale` |

Six enum values encode two intents, and two clients disagree on which to send. No
`Sale` row exists yet only because Admin has not created one; the first Admin
listing would be invisible to any filter matching `Sell`.

**Canonical: `Rent` and `Sell`.** Chosen because it is what all 47 rows already
use, so ratifying it costs zero data changes while `Sale` would cost 16.

Narrowing the enum to `["Rent", "Sell"]` and correcting Admin and mobile is a
schema and client change, out of scope here. It is recorded as a dependency in
§9.2 and is **not** part of the taxonomy migration.

---

## 8. Migration mapping specification

**Literal table only.** No substring matching, no fuzzy matching, no
case-insensitive fallback, no closest candidate, no guessing. A pair absent from
this table **aborts the run**. Runtime matching is what produced the current
state; a migration that repeated it would recreate the bug with more confidence.

All 10 current pairs, covering all 47 properties:

| # | `categoryName` | `propertyTypeName` | n | → Category | → Property Type | → Subcategory | Confidence / source | Action |
|---|---|---|---|---|---|---|---|---|
| 1 | Residential | Apartment / Flat | 21 | Residential | `Apartment / Flat` | none | **High** · web and Admin option; DB row renamed per D4 | Repoint 21 |
| 2 | Residential | Independent House | 9 | Residential | `Independent House` | none | **High** · exact in web, Admin and DB | Repoint 9 |
| 3 | Residential | Villa | 5 | Residential | `Villa` | none | **High** · exact in web, Admin and DB; separate per D11 | Repoint 5 |
| 4 | Commercial | Office Space | 3 | Commercial | `Office Space` | none | **High** · exact once the case duplicate is resolved per D3 | Repoint 3 |
| 5 | Commercial | Showroom | 2 | Commercial | `Showroom` | none | **Medium** · web and Admin option; new row per D5 | **D5**, then repoint 2 |
| 6 | Residential | Penthouse | 2 | Residential | `Penthouse` | none | **High** · exact in web, Admin and DB | Repoint 2 |
| 7 | Commercial | Warehouse / Godown | 2 | Commercial | `Warehouse / Godown` | none | **High** · DB row renamed per D10 | Repoint 2 |
| 8 | Commercial | Shop / Retail | 1 | Commercial | `Shop / Retail` | none | **Medium** · web and Admin option; new row per D5 | **D5**, then repoint 1 |
| 9 | Commercial | Commercial Building / Floor | 1 | Commercial | `Commercial Building / Floor` | none | **Medium** · web and Admin option; new row per D6 | **D6**, then repoint 1 |
| 10 | Commercial | Restaurant / Cafe | 1 | Commercial | `Restaurant / Cafe` | none | **Medium** · web and Admin option; new row per D7 | **D7**, then repoint 1 |

Totals reconcile: 21+9+5+3+2+2+2+1+1+1 = **47**.

Rows 1 to 4, 6 and 7 are ready once naming is ratified, covering 42 of 47
listings. Rows 5, 8, 9 and 10 carry the remaining 5 and are blocked on D5, D6 and
D7.

Subcategory is `none` on every row because no property has ever had one. If D9
retains subcategory, all ten rows need a subcategory answer and this table is
incomplete.

---

## 9. Design, preparation, migration, verification

### 9.1 Design (this document)

What the taxonomy should be: §2, §5, §6, §7. Complete except for the decisions in
§12.

### 9.2 Preparation (not started)

1. Ratify D1 to D11 in writing.
2. Freeze the §8 mapping table as code, reviewed row by row.
3. Remove `findObjectId`'s substring fallback from the web and Admin create forms.
   **Ordering matters:** migrating while a client can still write a substring
   match would re-corrupt rows within days.
4. Build a seeded fixture reproducing all 10 pairs and run the dry run against it.
5. Run the §10 read-only validation against the real target corpus.
6. Write the DOWN script and prove it on the fixture before UP runs anywhere.
7. Export the three taxonomy collections and the 47 properties' taxonomy fields to
   JSON, stored outside the database.

Separately tracked, not blocking: narrowing the `listingType` enum and correcting
Admin and mobile (§7.3).

### 9.3 Migration (not to be implemented until approved)

| Stage | Writes | Reversible by |
|---|---|---|
| 1 | Seed `categories` with 3 category documents | Delete seeded rows |
| 2 | Seed `propertytypes` with 20 property type documents, each with a `category` parent | Delete seeded rows |
| 3 | Repoint 47 properties' `category`, `propertyType`, `subcategory`, recording previous values to a migration log keyed by property id and run id | DOWN script from the log |
| 4 | Nothing. Verification gate | n/a |
| 5 | **Separately, later:** delete 6 taxonomy rows and 48 subcategories | Re-insert from the stage 0 export |

Stages 1 and 2 are additive. Stage 3 writes only the three ref fields and never
touches `categoryName` or `propertyTypeName`, which is what makes rollback
possible from the source of truth itself. Stage 5 is the only destructive step and
must not run on the same day as stages 1 to 4.

### 9.4 Verification

**Data**

1. All 47 properties have non-null `category` and `propertyType`.
2. `category.name === categoryName` and `propertyType.name === propertyTypeName`
   on all 47. Zero disagreements, against 25 today.
3. Every property type's parent category equals the property's category. No
   apartment under Commercial.
4. Zero properties reference a deleted row.
5. `subcategory` null on all 47 and no code path reads it.

**Behaviour**

6. `?categoryName=Residential` and `?category=<id>` return **identical id sets**.
   Same for Commercial and for every property type. This is the assertion that
   would have caught the original bug and the single most valuable test here.
7. Owner feed, builder feed and home page counts unchanged. The taxonomy changes;
   the listings do not.
8. A listing created through the web form produces refs resolving to documents
   whose names equal the submitted names, with no substring matching in the path.
9. Admin taxonomy screens list and create against the new shape.

**Process**

10. The dry run's predicted per-row output matches the actual output exactly.
11. The DOWN script restores the pre-migration state on the fixture, proven by
    comparison rather than inspection.
12. Integration tests cover 1, 2, 6 and 8, and fail if the mapping table is edited
    without updating them.

---

## 10. Production-data prerequisite

**Development counts must not be assumed to equal production counts.** Every
figure here describes 47 development listings. Production may hold a different
volume, a different distribution, and property type names absent from this
document entirely: any listing created before the create form's type list last
changed could carry a name no current client offers.

The mapping table's *shape* is expected to survive. Its *coverage* is not, and
coverage is what makes the migration safe.

### 10.1 Read-only validation procedure

Run against the real target corpus before migration. Reads only, writes nothing,
produces a report.

| # | Check | Output |
|---|---|---|
| 1 | Distinct `categoryName` values with counts | List; expected `Residential`, `Commercial` |
| 2 | Distinct `propertyTypeName` values with counts | List; expected to cover the 10 pairs' types |
| 3 | Distinct `(categoryName, propertyTypeName)` pairs with counts | List, reconciling to the total |
| 4 | **Mapping coverage**: pairs present in the §8 table | Count and percentage |
| 5 | **Unknown pairs**: pairs absent from the table | List with counts and example property ids |
| 6 | **Ambiguous pairs**: pairs matching more than one target, or whose target name matches more than one taxonomy row | List |
| 7 | Expected record counts per mapping row | Table matching §8's `n` column |
| 8 | Properties with null `categoryName` or null `propertyTypeName` | Count. These have no reconstruction input |
| 9 | Rows placing a commercial type under Residential or vice versa | Count. Currently 0 in development |
| 10 | Existing ref state: null, stale, distinct values | For sizing the rollback log |

### 10.2 Required condition before migration

```
unknown mapping count   = 0
ambiguous mapping count = 0
```

Neither may be satisfied by widening the matcher. Both are satisfied by adding
reviewed rows to the mapping table, or by deciding those listings need manual
handling. If check 8 returns non-zero, those properties are excluded from the
automated run and listed for a human: a property with no name columns has no
trustworthy input at all.

---

## 11. Relationship to the architecture plan

`DEALDIRECT-PHASE3-ARCHITECTURE-PLAN.md` §5 is superseded by this document. Its
dry-run numbers and its "semantic inversion" framing remain there as history;
where they conflict with anything here, this document is correct. The plan points
at this file rather than restating its conclusions.

---

## 12. Decision status

### Recommended, with evidence, ready to ratify

| ID | Decision | Recommendation | Confidence |
|---|---|---|---|
| **D1** | Collection strategy | Make each collection hold what its name says | High |
| **D2** | `Buy` / `Rental` / `Rent` | Delete from taxonomy; `listingType` already carries it | High |
| **D3** | `Office Space` duplicate | Keep `Office Space` (`691d66a3`), delete `Office space` | High |
| **D4** | Apartment canonical name | `Apartment / Flat` | High |
| **D5** | Shop and Showroom | Keep separate | High |
| **D6** | `Commercial Building / Floor` | Create as its own type | High |
| **D7** | `Restaurant / Cafe` | Create as its own type | High |
| **D10** | Canonical spellings | Web vocabulary, no aliases | High |
| **D11** | `Villa` separate from `Independent House` | Separate | High |

### Approved 2026-08-17

Both were carried as open product decisions because no evidence in the corpus
could settle them. Both have now been decided explicitly by the product owner
and are recorded here as approved targets.

| ID | Decision | Approved outcome |
|---|---|---|
| **D8** | Land & Plots hierarchy | **APPROVED: a third top-level category**, holding `Residential Plot`, `Commercial Land`, `Industrial Land`, `Agricultural Land` |
| **D9** | Subcategory | **APPROVED: retire it** |

Approval is of the *target*, not of execution. Neither consequence is
implemented: D8 still requires the third create-property field set, and D9 still
requires the UI, route and filter removals. Both remain blocked on §0.

Everything else is ratification of a convention rather than a choice between
viable alternatives.

### Migration readiness

**BLOCKED on database identity.** Decisions are settled; §0 is not.

Three independent blockers:

0. **Database identity.** See §0. Outranks everything below: no write may be
   planned against a database whose environment is unknown.
1. **Approval.** D8 and D9 are now approved (above). D1 to D7, D10 and D11 remain
   recommended but not separately ratified, and the mapping table quotes them
   literally.
2. **Production corpus.** The §10 validation has not been run against the real
   target. Until `unknown = 0` and `ambiguous = 0` there, coverage is unproven, and
   42 of 47 being ready in development says nothing about the target.

Blockers 0 and 2 both stand even if every decision is approved today.

---

## 13. Safety confirmation

- No application code changed
- No schema changed
- No collection changed
- No taxonomy document created, renamed or deleted
- No property record changed
- No migration executed
- No database write of any kind. All access was `find` and `aggregate` against
  the single configured database. Whether that database is production is
  **unresolved**, which is why §0 blocks every write until it is established
- 471 unit tests and integration tests remain green

---

## 14. Create-time resolver hardening (done, no database access)

The one piece of this work that was not blocked, because it touches no data.

The substring resolver that caused the corruption was still live in two clients.
Both now resolve by exact name only, and both omit the reference when no exact
match exists rather than substituting one.

| Change | Where |
|---|---|
| Exact-match resolver, no case folding, no substring, no positional fallback | `client-next/src/utils/taxonomyRef.js`, `Admin/src/utils/taxonomyRef.js` |
| Inline `findObjectId` replaced by the shared helper | `AddPropertyContent.jsx`, `AdminAddProperty.jsx` |
| Admin no longer appends `""` on a miss; it omits the field, matching web | `AdminAddProperty.jsx` |

A repository-wide search found no other name-to-ObjectId taxonomy resolver.
Mobile submits `categoryName` and `propertyTypeName` only and never sends a
reference; the edit form does the same; Admin's category screen binds ids chosen
from a select rather than resolving names.

**Expect most references to be omitted until the migration runs.** The canonical
vocabulary does not yet exist in the taxonomy: the database holds `Apartment`,
not `Apartment / Flat`. Omission is the correct state, and it is what keeps the
corpus from acquiring more wrong references while §0 is unresolved.

Covered by `backend/tests/integration/taxonomy-resolver.test.js`, which runs one
table against both hand-duplicated copies so they cannot drift apart, and
verifies that property creation still succeeds.

---

## 15. Migration contract (design only, not implemented)

Defines what the migration must establish and what the server must enforce
afterwards. **No application code implements any of this yet.**

### 15.1 The three data invariants

For every property, after migration:

```
category.name          === categoryName
propertyType.name      === propertyTypeName
propertyType.category  === property.category
```

The third is the one most easily overlooked and the most damaging to omit. The
first two can both hold while a listing sits under the wrong parent: a property
could carry `categoryName: "Residential"` with a correctly-named `Apartment / Flat`
type whose parent category is Commercial. That yields a listing that answers
correctly to a name filter and wrongly to a category filter, which is the exact
class of inconsistency this whole exercise exists to remove.

All three must hold for all 47 rows, with zero exceptions. A single violation
fails the migration and triggers rollback.

### 15.2 The server-side consistency rule

Today the backend accepts `category`, `categoryName`, `propertyType` and
`propertyTypeName` as four independent whitelisted fields and stores whatever
arrives. Nothing checks that a reference agrees with the name beside it. The
resolver hardening stopped the two known clients from guessing; it did not stop
the server from accepting a guess from anywhere else.

The rule to implement with the migration:

| Case | Required behaviour |
|---|---|
| ObjectId and name both supplied, and they agree | Accept both |
| ObjectId and name both supplied, and they disagree | **Reject the request.** Do not drop the ref and keep the name; do not prefer either |
| ObjectId supplied with no matching canonical name | **Reject the request** |
| Name supplied, no ObjectId | Accept. The server resolves the reference itself by exact name, or stores none |
| Neither supplied | Existing validation applies, unchanged |

Two prohibitions, stated separately because they are different failures:

- **Never silently accept a mismatched reference.** Storing a ref that disagrees
  with its name is what produced the current corpus.
- **Never fall back to another taxonomy document.** No substring, no case
  folding, no nearest match, no positional default, on the server for the same
  reasons it was removed from the clients.

Resolution moves server-side as a consequence. Once the server resolves names
itself, clients need not send references at all, which removes the whole class of
bug rather than fixing it in three places.

**This changes the create/update contract**, so it ships with the migration, not
before. A request that succeeds today can begin failing under this rule, and that
is the intent.

### 15.3 Integration test cases required

To be added to `backend/tests/integration/` when implementation is unblocked.
Listed here as design; none is written.

**Post-migration data invariants**

| # | Case | Expected |
|---|---|---|
| 1 | Every property has non-null `category` and `propertyType` | 0 nulls |
| 2 | `category.name === categoryName` across the corpus | 0 mismatches |
| 3 | `propertyType.name === propertyTypeName` across the corpus | 0 mismatches |
| 4 | `propertyType.category === property.category` across the corpus | 0 mismatches |
| 5 | A property whose type's parent disagrees with its category is detected | Fails loudly, not silently repaired |
| 6 | No property references a taxonomy document that does not exist | 0 dangling |

**Server-side consistency rule**

| # | Case | Expected |
|---|---|---|
| 7 | Create with agreeing ObjectId and name | 201, both stored |
| 8 | Create with `category` id of X and `categoryName` of Y | **4xx**, nothing stored |
| 9 | Create with `propertyType` id of X and `propertyTypeName` of Y | **4xx**, nothing stored |
| 10 | Create with an ObjectId that resolves to no document | **4xx** |
| 11 | Create with a well-formed but unknown ObjectId | **4xx**, and no fallback document selected |
| 12 | Create with names only, canonical | 201, server resolves refs itself, both invariants hold |
| 13 | Create with names only, non-canonical | 201 with no refs, or 4xx. Never a guessed ref |
| 14 | Update that would break agreement | **4xx**, stored document unchanged |
| 15 | Mismatch attempted through the multipart path as well as JSON | Same outcome; the whitelist path must not differ by content type |

**Search equivalence** (the assertion that would have caught the original bug)

| # | Case | Expected |
|---|---|---|
| 16 | `?categoryName=X` and `?category=<id of X>` | **Identical id sets**, for every canonical category |
| 17 | `?propertyTypeName=Y` and `?propertyType=<id of Y>` | Identical id sets, for every canonical type |
| 18 | Owner feed, builder feed and home page counts before and after migration | Unchanged |

**Rollback**

| # | Case | Expected |
|---|---|---|
| 19 | DOWN restores every touched property to its pre-migration ref state | Byte-equal comparison, not inspection |
| 20 | DOWN leaves `categoryName` and `propertyTypeName` untouched throughout | Never written by either direction |
| 21 | UP is idempotent: running it twice changes nothing the second time | 0 modifications on the second run |

Cases 16 and 17 are the highest-value pair. Everything else can pass while the
product is still broken for users; those two cannot.
