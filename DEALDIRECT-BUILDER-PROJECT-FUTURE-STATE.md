# DealDirect — Builder → Project → Inventory: Current State and Future State

The deep companion to [DEALDIRECT-FULL-SYSTEM-FORENSIC-AUDIT.md](DEALDIRECT-FULL-SYSTEM-FORENSIC-AUDIT.md).
Everything here is derived from the repository and the dev database, not from
generic real-estate assumptions. Where a recommendation is a judgment call, the
evidence it rests on is stated.

**The one-paragraph verdict.** The foundations are much better than the
product. The data model is rich (RERA, legal, payment plans, construction
updates, specifications down to switch brands), the admin wizards are real
(9-step and 10-step, zod-validated, draft-persisted), and the booking payment
pipeline is the most carefully hardened write path in the codebase. What is
missing is everything that turns authored data into a safe, sellable product:
a publish lifecycle, required-field enforcement, a non-payment lead path,
demand instrumentation, media maintenance, and any consequence for the
group-buy numbers being displayed. The pages are findable — navbar, home-page
rail and sitemap all link them, at working tree and repo HEADs alike — and
across seven authored projects they have produced zero bookings and zero
campaigns. Fix the seam, not the foundations.

---

## 1. Current architecture

```
Builder            contact card + profile. NO login (by design, Builder.js:3-5)
  └─ Project       admin-authored. basics/location/overview/amenities/media/
     │             documents/legal/paymentPlans/financials/bankApprovals/
     │             constructionUpdates/salesContact + denormalised priceRange,
     │             unitTypeCount, activeCampaignCount. Lifecycle: isActive ONLY.
     └─ UnitType   config/area/facing/furnishing/parking/specifications/
        │          floorPlans/photos/pricing(+auto effectivePrice)/paymentTerms/
        │          inventory{totalUnits,availableUnits,bookedUnits,blockedUnits,
        │          towerAllocation[{tower,units}]}
        ├─ GroupBuyCampaign   terms + counters; mechanic unimplemented (audit §6.1)
        │    └─ CampaignMember  active|exited × pending|paid|refunded, snapshots
        └─ ProjectBooking     enquiry→payment_submitted→confirmed→completed|cancelled
                              QR/UTR payment sub-state, statusHistory, snapshots
```

Design facts that matter:

- **There is no Unit entity.** Inventory is counters per UnitType with an
  optional per-tower split. No unit numbers, no floors, no per-unit price or
  status. `floorRisePerSqft` and `viewPremium` exist as *rates* but nothing
  records which floor or view a given buyer bought — they are display inputs
  folded flat into `effectivePrice`, not chargeable dimensions.
- **Money is admin-verified UPI**, not a gateway. The UTR + screenshot on the
  booking (and on the campaign member) *is* the receipt — which is why the
  delete-refusal guards treat those documents as evidence.
- **DealDirect is the only seller-side contact.** `salesContact` is forcibly
  overwritten with DealDirect's details at creation
  (`projectController.js:237-242`), and public reads strip builder
  phone/email. Disintermediation is enforced in code — good.
- **Counters are maintained honestly** where the booking engine runs: atomic
  `$gte:1` decrement before confirmation persists, restore on cancel from
  holding states, campaign member recount-from-DB in hooks.

## 2. Current Admin workflow (as built)

1. **Builder**: `BuilderManagement` → create (name+phone required, phone
   uniqueness pre-checked, logo upload) → `BuilderDetail` shows profile +
   project cards.
2. **Project**: `CreateProject` — 9 steps (Basics, Location, Nearby, Overview,
   Amenities, Media, Docs & Legal, Sales Contact, Review). Zod checks
   *format-only when filled* (pincode, lat/lng ranges, possession ≥ launch);
   nothing is compulsory by policy (`projectSchema.js:6-11`). Draft =
   localStorage, 24h TTL, files excluded (`useFormDraft.js`). Submit = one
   multipart POST carrying **all** media and documents; server uploads to
   Cloudinary *then* creates the document.
3. **Unit types**: `CreateUnitType` — 10 steps (Config, Area, Facing,
   Furnishing, Parking, Specs, Floor Plans, Pricing, Inventory, Highlights),
   same draft pattern, edit mode via `?edit=`.
4. **Campaign**: `CreateCampaign` on a unit type (name, min/max buyers, dates,
   flat discount, perks).
5. **Operate**: `ProjectDetail` (tabs over project + unit types + campaigns),
   `BookingManagement` (verify UTR/screenshot, confirm/cancel/complete),
   `GroupBuyManagement` (member payment verification).

What an admin **cannot** do today: save a server-side draft; publish/unpublish
as a distinct act (only the blunt `isActive`); delete or reorder project
images (append-only, `projectController.js:405-431`); required-check anything
before the public sees it; record a call with a booking client (single
overwrite-prone `adminNotes`); import anything in bulk; see why a project is
"incomplete".

## 3. Current weaknesses (each verified)

| # | Weakness | Evidence |
|---|---|---|
| W1 | Public-on-create; no draft/review/publish | `Project.js:236` default true; no status field |
| W2 | Nothing required to be sellable | 3/8 dev unit types lack `paymentTerms.bookingAmount` → ₹0-token bookings (audit §6.2) |
| W3 | Bookable against undefined inventory | `bookingController.js:124` checks `=== 0` only |
| W4 | Zero recorded demand, zero instrumentation | 7 projects, 0 bookings, 0 campaigns; payment-framed sole CTA; no view/enquiry metrics on Project (audit §10.2) |
| W5 | Group-buy numbers display-only | audit §6.1 |
| W6 | Builder deactivation leaves projects on sale | audit §7.1 |
| W7 | No inventory invariant; admin overwrite path | audit §7.3 |
| W8 | No non-payment enquiry; no contact history; no admin assignment | `bookingRoutes.js`, `ProjectBooking.js` |
| W9 | Media append-only; no delete/reorder; Cloudinary orphans on replace | `projectController.js:405-431`, `unitTypeController.js:302-319` |
| W10 | One-shot multipart authoring; draft can't hold files | routes use `.any()` memory upload; `useFormDraft.js` |
| W11 | No audit trail on verify/status/CRUD | audit §5.3 |
| W12 | towerAllocation unvalidated against totals or `overview.totalTowers` | schema only |

## 4. The Builder → Project → inventory lifecycle (business view)

What the material flow actually is (confirmed by the models): builder hands
DealDirect a brochure + media + price sheet + inventory sheet; admin transcribes;
buyers discover; enquiries/bookings arrive; admin verifies money; allocation
and paperwork happen offline with the builder; construction updates trickle in
for years; availability changes as the builder sells through *all* channels
(not only DealDirect — which is why admin inventory correction must exist).

The lifecycle the *data* needs, versus what exists:

| Needed state | Today | Gap |
|---|---|---|
| Draft (being transcribed) | localStorage only | server draft |
| Ready for review | — | checklist state |
| Published | `isActive: true` (implicit, immediate) | explicit act |
| Paused (builder request, price revision) | `isActive: false` (also means "deleted-ish") | distinct from retirement |
| Sold out | availableUnits hits 0 per type; nothing project-level | derived badge |
| Completed / Archived | `basics.status: "Completed"` describes *construction*, not listing | listing-level archive |

`basics.status` (New Launch → … → Completed) is a **construction** attribute
and correctly stays a plain descriptor; the listing lifecycle must not be
conflated with it.

## 5. Recommended future information architecture

### 5.1 Keep the aggregate-counter inventory as Level 1 — deliberately

A full `Tower → Floor → Unit` tree is the industry-standard answer and it is
the **wrong next step here**, for reasons in this repo, not in theory:

- Sales close offline with the builder; DealDirect never allocates a specific
  flat today. No flow anywhere consumes a unit number.
- The counters are already transactionally maintained by the only path that
  moves money.
- Admins really do use `towerAllocation` (5/8 real unit types carry it) — the
  tower dimension is wanted; the floor/unit dimensions have zero consumers.
- 500 or 50,000 units changes nothing about counter arithmetic.

So: **formalise Level 1** (invariants + tower validation + booking-time
allocation *note*), and specify Level 2 as a ready design with explicit
triggers, instead of building an empty tree now.

### 5.2 Level-1 formalisation (do this)

- Invariant, enforced in one shared util used by unitType update AND booking
  paths: `totalUnits = availableUnits + bookedUnits + blockedUnits`, each ≥ 0;
  `Σ towerAllocation.units ≤ totalUnits`; tower names unique per unit type;
  if `overview.totalTowers` is set, tower names count ≤ it.
- Admin corrections become **delta operations** (`+n available`, `−n blocked`)
  with reason + `AuditLog`, replacing wholesale `inventory` overwrite.
- Booking confirmation gains one optional human field: `allocation`
  (free text: "Tower B, floor 11, B-1104") on `ProjectBooking` — captures the
  offline allocation without inventing entities.

### 5.3 Level-2 Unit entity (build only when a trigger fires)

Triggers: DealDirect starts *holding specific flats*; floor-rise/view premiums
become actually charged per transaction; a builder integration supplies a unit
matrix; buyers pick exact units online.

```js
Unit {
  unitType, project, builder,             // refs (project/builder denormalised)
  tower: String, floor: Number, unitNumber: String,   // unique (project, unitNumber)
  facing, viewTags: [String],
  priceOverride: Number,                  // else derived: base + floorRise*floor + premiums
  status: enum [available, held, booked, blocked, sold],
  holdExpiresAt: Date,                    // TTL-released holds
  booking: ref ProjectBooking,            // when booked/sold
}
```

Migration is additive: counters become a projection
(`countDocuments` per status) behind the same read fields, so no client
changes; `towerAllocation` seeds the matrix.

### 5.4 Builder

Model is adequate. Add only: `status: enum [active, paused, delisted]`
replacing bare `isActive` (pausing a builder must pause the chain — audit
§7.1), and fix the deployed sparse-email index. A builder *login* remains
correctly out of scope until the product wants builder self-service; nothing
in the current flow needs it.

### 5.5 Lifecycle field (the core addition)

```js
// Project
publication: {
  status: { type: String, enum: ["draft","review","published","paused","archived"], default: "draft" },
  publishedAt: Date, publishedBy: ref Admin,
  checklist: [{ rule: String, level: "block"|"warn", passedAt: Date }],  // snapshot at publish
}
```

`isActive` is kept as a derived read (`status === "published"`) during
migration so no client breaks, then retired. Public queries change from
`isActive: true` to `publication.status: "published"` in the two controllers
that filter (`projectController.js:317-319,360`; unit types inherit via
parent-check at read).

## 6. Recommended Admin workflow

```
Create draft (name + builder only)            → status: draft, INVISIBLE
  ├─ edit any step, any order, any session    → PATCH per section (JSON, no files)
  ├─ upload media per batch                   → separate endpoints, appended per field,
  │                                             deletable + reorderable
  ├─ add unit types (each with its own draft) → existing wizard, unchanged
  ├─ "Check readiness"                        → server returns checklist (§10)
  ├─ Request review (optional, single-admin teams skip) → status: review
  └─ Publish                                  → server re-runs BLOCK rules; sets published
Published
  ├─ edit                                     → allowed; price/inventory edits audited
  ├─ Pause                                    → hidden from public, bookings kept
  ├─ Sold out                                 → derived (all unit types availableUnits = 0)
  └─ Archive                                  → terminal; bookings/campaigns must be terminal first
```

Two mechanical changes make this real without redesigning the wizards:

1. **Server draft replaces the one-shot POST.** `POST /api/projects` accepts
   the minimal draft; the existing 9-step wizard PATCHes sections as the admin
   completes them. The localStorage draft stays as offline insurance but stops
   being the only safety net; files stop being un-draftable (W10).
2. **Media endpoints**: `POST /:id/media/:field` (append),
   `DELETE /:id/media/:field` (body: urls → array-pull + Cloudinary destroy),
   `PUT /:id/media/:field/order`. Same for unit photos (delete already exists
   client-side; make it destroy — W9).

## 7. Required project fields (for **publish**, not for save)

Everything stays optional in draft — that design intent is preserved. The
gate moves to publish, where each rule exists because a concrete failure was
observed:

**BLOCK** (publish refused):
- `basics.name`, `basics.category`, `location.city` — listing cards render
  these; empty cards were reachable.
- ≥ 1 image across `media.exteriorImages | droneImages | masterPlan` — 6/7
  real projects have exteriors; the 7th renders an imageless card.
- builder exists and `status: active` — audit §7.1.
- ≥ 1 **publishable unit type** (see §8).
- `salesContact.phone` — auto-set today; keep the check so the invariant
  survives refactors.

**WARN** (publish allowed, flagged on the checklist):
- no `media.brochureUrl` (0/7 today — clearly admins skip it; warning, not wall)
- no `basics.reraNumber` (5/7 have it) / no RERA certificate document (1/7)
- no coordinates (map section hides)
- no `overview.totalTowers/totalUnits`
- `paymentPlans` empty (0/7 — either kill the section or start using it)

## 8. Required inventory structure (per publishable UnitType)

**BLOCK**: `config.name`; `pricing.basePrice > 0`; `inventory.totalUnits ≥ 1`;
`inventory.availableUnits` **defined** (0 is legal — sold-out type);
`paymentTerms.bookingAmount > 0` **if** the project is bookable — this is the
₹0-token fix at the root; invariant of §5.2 holds.
**WARN**: no floor plan; no photos; no `area.carpetSqft` (pricePerSqft can't
derive); towerAllocation missing while `overview.totalTowers > 1`.

Booking-time enforcement (belt to the publish braces): `createBooking` refuses
when `availableUnits` is undefined or `bookingAmount` resolves to 0 —
today's `=== 0` check becomes `!(availableUnits >= 1)` and
`!(tokenAmount > 0)`.

## 9. Media / brochure workflow

Storage layout already sane (`dealdirect/projects/<builderId>/<kind>`,
`dealdirect/unit-types/<builder>/<project>`). Add:
- destroy-on-remove/replace everywhere (brochure replace currently leaks the
  old file; unit-photo remove leaks; floor-plan replace leaks);
- upload-before-create orphan fix: create the draft first (§6), so uploads
  always attach to an existing document — the failure mode disappears
  structurally rather than by cleanup;
- a monthly orphan sweep script comparing Cloudinary folders against document
  URLs (one-way references make this the only recovery path for historical
  leaks — audit §7.7);
- gallery order = array order, editable (§6.2); captions exist on unit photos
  already, extend to project exteriors only if marketing asks.

Brochure-assisted entry (parse the PDF into fields) is **ADVANCED — not
recommended** until the manual flow has a publish gate; automating input into
an ungated pipeline just publishes mistakes faster.

## 10. Validation rules — where each lives

| Rule | Layer | Why there |
|---|---|---|
| Format/range (pincode, lat/lng, dates) | client zod (exists) + model | fast feedback; model as backstop |
| Enum integrity | model (exists) | already right |
| Publish BLOCK/WARN sets (§7–8) | **backend publish endpoint**, single `utils/projectPublishGuard.js` | client checklists lie under drift; one greppable rule set, mirroring the taxonomyGuard/deleteGuard pattern already proven here |
| Inventory invariant | shared util used by update + booking + import | two writers today, three with import |
| Tower name uniqueness / totals | same util | W12 |
| Builder active at booking | `createBooking` | the read gate alone can't stop in-flight links |
| UTR reuse | `verifyPayment` lookup + UI surface | audit §5.2 |

## 11. Publish workflow (states and transitions)

```
draft ──request-review──▶ review ──publish──▶ published
  ▲                         │                   │  ▲
  └───────changes-needed────┘        pause ─────┘  │ resume
                                     published ──archive──▶ archived (terminal)
draft ──publish (solo-admin shortcut, BLOCK rules still run)──▶ published
```

Transition guards in the same table style as `BOOKING_STATUS_TRANSITIONS`
(the codebase's established idiom). `archive` refuses while any booking is in
`enquiry|payment_submitted|confirmed` or any campaign `active|paused` — the
delete guards already express this shape; archiving reuses their predicates
minus the destruction.

## 12. Editing and versioning model

- Live edits stay live (no draft-of-published copy — needless machinery at
  this team size).
- **Price/inventory edits on published projects get an AuditLog line** with
  before/after; that plus `statusHistory` covers "what changed under my
  booking".
- The booking already snapshots `tokenAmount`; add `effectivePriceAtBooking`
  (one field) so later price edits can't rewrite what a buyer was shown.
- `constructionUpdates` is already an append-only timeline — the model's one
  existing versioned structure; leave it as the pattern to copy.
- Full document versioning: not justified by any current flow; revisit only if
  builder self-service lands.

## 13. Lead flow (unify the two funnels)

Today `ProjectBooking.status: "enquiry"` *is* the project lead — the modal
just frames it as payment-step-1, so every prospective buyer is greeted with a
QR code. Changes, cheapest first:

1. **"Enquire" CTA** beside "Book now" on unit + project pages → creates the
   same `ProjectBooking` in `enquiry` with a `source: "enquiry"|"booking"`
   discriminator — no new model, admin pipeline unchanged, payment framing
   removed from first contact.
2. **`contactHistory[]` + `assignedTo: ref Admin`** on `ProjectBooking` —
   mirrors `Lead`, fixes the overwrite-only `adminNotes` (audit §6.5) and
   answers "which admin is handling it".
3. **One pipeline screen**: extend `LeadMonitoring` with a source toggle
   (property leads | project enquiries) instead of a third page; retire
   `SiteVisitManagement` (audit §10.4) or make it a filter chip there.
4. Admin's questions, answered by fields after (2): project/unit/builder →
   existing refs; last user action → `statusHistory`; contact attempts →
   `contactHistory`; converted → `status: completed`; owning admin →
   `assignedTo`.

Campaign leads: `CampaignMember` already carries user snapshots; surfacing
members inside the same pipeline view (source: "group-buy") completes the
picture without new models.

## 14. Scalability model

| Load | Verdict | Detail |
|---|---|---|
| 1 project, 10 towers, 50 floors | fine | towerAllocation formalised (§5.2); floors don't exist as data until Level 2 |
| 500–50,000 units | fine (counters) | capability ceiling, not load ceiling — §5.3 triggers |
| 20 unit types / project | fine | `listByProject` unpaginated is acceptable at ≤ dozens; cap at 100 |
| thousands of images | needs §6 media endpoints | one-shot multipart (50×15MB RAM) is the binding constraint today |
| concurrent availability changes | already atomic on the booking path | close the admin-overwrite hole (§5.2) and it's consistent everywhere |
| 5,000 projects | add publication-status index | `{ "publication.status": 1, "location.city": 1 }` replacing the isActive compounds |

## 15. Bulk import strategy

**MVP (justified now)**: XLSX/CSV **unit-type importer** per project — one row
per unit type, columns for config/area/pricing/paymentTerms/inventory/tower
splits (`tower:count;tower:count`). Server parses (exceljs — already a
dependency), validates every row against the §8 rules + invariant, returns a
**dry-run report** (row → ok/errors), commits only on confirm, tags every
created document with `importBatchId`. Idempotent re-run by (project,
config.name) upsert. This kills the worst manual cost (10 towers × repeated
type entry) with zero new infrastructure.

**GOOD FUTURE**: project-shell importer (one sheet: basics/location/overview);
image ZIP ingest mapped by filename convention.

**ADVANCED (explicitly not now)**: brochure parsing (§9); builder-system API
integrations; per-unit matrix import (belongs with Level 2).

## 16. Recovery / rollback strategy

- Server drafts make abandonment safe (today: 24h localStorage or nothing).
- Import: `importBatchId` enables one-command rollback (`deleteMany` by batch,
  refused if any imported type has bookings — the deleteGuard already knows how).
- Failed multi-file upload: attach-to-draft (§6) removes the orphan window;
  the sweep (§9) cleans history.
- Payment races already recover explicitly (REFUND-DUE path); add the §5.2
  delta-corrections so inventory repair is auditable rather than a blind edit.
- Runbook note (audit §12): payment QR env + admin accounts exist only in
  production; a rebuilt environment cannot verify bookings until both are
  restored — document alongside the publish-gate work since it touches the
  same team.

## 17. Group buy — the honest redesign frame

Out of scope to build (standing deferral), but the future state must say what
"done" means, because the current object model is fine and the *mechanic* is
absent (audit §6.1):

1. Define the outcome event: `paidMemberCount ≥ minBuyers` at (or before)
   `endDate` → campaign `succeeded`; else `failed`.
2. On `succeeded`: notify members + admin; bookings by members get
   `discountApplied` recorded (snapshot, not recompute); banner flips to
   "unlocked".
3. On `failed`: defined token disposition (refund per the refund-policy
   decision doc) with the same evidence-preserving rules as everywhere else.
4. Until built: stop rendering the discounted price as if it applies
   (audit Phase A).

## 18. Final Builder/Project scorecard

Scored from evidence; the user's working "3/10" is compared at the end.

| Area | /10 | Why | Missing | Priority |
|---|---|---|---|---|
| Builder management | 6 | solid CRUD, uniqueness, profile, soft-delete | deactivation cascade (W6); sparse-email index repair; verification concept if ever wanted | P1 |
| Project creation | 6 | 9-step wizard, zod, drafts, hardened uploads | server draft; publish gate | P1 |
| Project editing | 5 | section merge + append media works | media delete/reorder; wholesale-replace sharp edge | P2 |
| Project media | 4 | good folders, transforms, doc types | destroy-on-remove; orphans; ordering | P2 |
| Project structure (model) | 8 | richest schema in the repo; sane hierarchy decision | lifecycle field | P1 |
| Tower/floor/unit model | 5 | honest Level-1 with used tower split | formalised invariant now; Level-2 spec on triggers | P1/P4 |
| Unit-type management | 7 | 10-step wizard, auto-pricing, photo rooms | publish rules; folder-path consistency | P1 |
| Inventory management | 5 | atomic on the money path | invariant; delta corrections; undefined-inventory bookings (W3/W7) | P1 |
| Pricing | 6 | effectivePrice auto-calc, charges itemised | snapshot-at-booking; floorRise/viewPremium are display-only (fine at Level 1, say so in UI) | P2 |
| Availability | 6 | decrement/restore correct | sold-out derivation; pause state | P2 |
| Bulk upload | 1 | nothing | §15 MVP importer | P3 |
| Validation | 2 | format-only, blocks nothing | §7/§8/§10 | **P1 — the keystone** |
| Publishing | 1 | isActive only, public-on-create | §5.5/§11 | **P1 — the keystone** |
| Lead capture | 3 | bookings double as enquiries, payment-framed; no project-interest path; builder-prop interest void | §13.1 | P1 |
| Lead management | 4 | BookingManagement solid for payments | contactHistory/assignedTo; unified pipeline | P2 |
| Admin usability | 5 | wizards + presets genuinely good | readiness checklist; media manager; IA orphans (site-visits, popular-properties unlinked) | P2 |
| Scale | 6 | counters + atomic ops scale; uploads don't | §14 items | P3 |
| Recoverability | 4 | statusHistory, refund-due path, delete guards | drafts; import rollback; audit on money actions | P1/P2 |

**Weighted read**: engine and model ≈ **6.5/10**; product wrapper
(visibility, lifecycle, validation, lead capture, bulk) ≈ **2.5/10**. The
"3/10" instinct is right about the workflow a real admin experiences with a
50-page brochure in hand, and wrong about the foundations — which are closer
to done than any earlier audit recorded. That asymmetry is good news: the
expensive parts exist; the missing parts are thin, well-bounded layers.

## 19. Implementation phases

**P1 — Integrity + visibility (the keystone, ~1–2 weeks)**
Publication lifecycle field + publish gate util + BLOCK rules (§5.5, §7, §8) ·
booking-time guards (₹0 / undefined inventory / builder active) · inventory
invariant + delta corrections + AuditLog on money actions · builder
deactivation cascade · project view/enquiry counters (audit §10.2) · Enquire
CTA (§13.1).

**P2 — Operability (~1–2 weeks)**
Server drafts + sectioned PATCH · media delete/reorder/destroy + orphan sweep ·
contactHistory/assignedTo + unified pipeline screen · price-snapshot on
booking · pause/sold-out/archive states + transition table.

**P3 — Throughput (~1 week)**
Unit-type XLSX importer with dry-run + batch rollback · list caps + publication
indexes · sitemap projection for scale.

**P4 — Only on trigger**
Level-2 Unit entity (§5.3) · builder self-service portal · brochure-assisted
entry · group-buy mechanic per §17 (its own product cycle, per the standing
deferral).

Each phase is independently shippable and none blocks the marketplace side.
