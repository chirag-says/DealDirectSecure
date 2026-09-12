# DealDirect — Project Authoring Pipeline

What an admin must fill, in what order, with what media, to fully explain a
builder project. Built from three evidence legs, not taste:

1. **Code** — every schema field mapped against what the buyer-facing pages
   actually render (`ProjectDetailContent.jsx`, `UnitDetailContent.jsx`).
2. **Real data** — field-by-field census of the 7 live projects and 8 unit
   types in `dealdirect_dev` (what admins actually fill when nothing forces
   them).
3. **Domain** — RERA advertising/disclosure obligations (MahaRERA Order
   46C/2025, GujRERA June-2025 circular, TNRERA 2025 norms) and the section
   anatomy of 99acres/Housing/Magicbricks project pages.

## 0. The verdict

**The schema does not need more fields. It needs three renders, two fixes,
one reorder, and a handful of rules.** DealDirect already collects more than
the portal benchmark — the failure is that a third of what admins diligently
fill is invisible to buyers, the steps that die (documents, brochure) sit at
the end of a nine-step wizard with nothing forcing them, and two
compliance-relevant items (the RERA number itself, carpet-area basis) are
treated as optional decoration.

The census proves admins are conscientious when the wizard leads them:
specifications 7/8, connectivity 5/7, locality/pincode/dates 7/7. They are
not lazy — the pipeline is leaky.

---

## 1. The evidence table — every field, three verdicts

Legend: **Filled** = dev census (projects n=7, unit types n=8) ·
**Rendered** = appears on a public page · Verdict:
`KEEP` (working) · `RENDER` (filled-but-invisible — build the section) ·
`FIX` (broken presentation) · `DEMOTE` (stop asking prominently) ·
`DROP` (dead) · `MERGE` (duplicate).

### Project

| Field | Filled | Rendered | Verdict |
|---|---|---|---|
| basics.name / category / subType / status / ownershipType | 7/7 | yes (badges, title, overview) | KEEP |
| basics.description | 6/7 | yes | KEEP |
| basics.highlights | 4/7 | yes (dark sidebar card) | KEEP |
| basics.isVastuCompliant | 6/7 | yes (badge) | KEEP |
| basics.reraNumber | 5/7 | **badge only — the number itself never shown** | **FIX — compliance** (§3.1) |
| basics.reraCertificateUrl | dup | no | **MERGE** into documents.reraCertificateUrl |
| location city/locality/microMarket/pincode | 7/7 | yes (header line) | KEEP |
| location.addressLine / landmark | 6/7 | **no** | RENDER (one "Address" line) or DEMOTE |
| location.coordinates | 7/7 | **no — no map on the page** despite react-leaflet installed and admin LocationPicker existing | **RENDER — highest-value gap** (§3.2) |
| location.connectivity (metro/airport/rail/bus) | 5/7 | **no** | RENDER (chips under the map) |
| nearbyPlaces | 6/7 | yes | KEEP |
| overview (all 7 stats) | 6–7/7 | yes | KEEP |
| amenities (names) | 7/7 | yes | KEEP (icon subfield: DROP — never rendered) |
| media.exteriorImages | 6/7 | yes (gallery + card hero) | KEEP |
| media.droneImages | 4/7 | yes (merged into gallery) | KEEP |
| media.masterPlan | 3/7 | **first image only, cropped** — `h-48 object-cover` crops a plan drawing into noise | **FIX** — `object-contain`, click-to-zoom, all images |
| media.locationMap | 3/7 | **no** | MERGE into the map section (or DROP once live map renders) |
| media.walkthroughVideoUrl | 1/7 | **no** | RENDER (embed) or DEMOTE to WARN-less optional |
| media.constructionProgressImages | 2/7 | **no** | MERGE into constructionUpdates (below) |
| media.amenityImages | 2/7 | yes | KEEP |
| media.brochureUrl | **0/7** | yes (download button) | KEEP + move earlier in wizard (§4) |
| documents.reraCertificateUrl | 1/7 | yes | KEEP |
| documents.commencementCertificateUrl | 1/7 | **no** | RENDER in Documents card |
| documents.occupancyCertificateUrl | 0/7 | **no** | RENDER — and it gates the RERA rule (§3.1) |
| documents.environmentalClearance / approvalDocumentUrls | 0/7 | **no** | RENDER (collapsed "Approvals" list) |
| legal.* | 0/7 | admin-only by design | KEEP (internal) |
| paymentPlans | 0/7 | yes (section exists, always empty) | KEEP — wizard must actually offer presets (CLP/DP templates) |
| financials.* (project-level) | 3/7 legacy | no (fallback only) | DEMOTE — legacy read path only, remove from wizard |
| bankApprovals | 1/7 | **no** | **RENDER — loan-trust signal every portal shows** |
| constructionUpdates | 0/7 | **no** | **RENDER as a timeline** — the model's best dark feature; monthly photos + % for under-construction trust |
| salesContact | forced | yes (hard-coded UI) | KEEP |

### Builder (shown on project pages)

| Field | Rendered | Verdict |
|---|---|---|
| name/company/logoUrl | yes (contact card chip) | KEEP |
| description, yearEstablished, totalProjectsDelivered, totalSqFtDelivered, operatingCities, awards | **none — the entire "About the Developer" block the model documents is unrendered** | **RENDER** — an expandable Developer section on the project page |

### UnitType

| Field | Filled | Rendered | Verdict |
|---|---|---|---|
| config (name/bed/bath/balconies/utility) | 7–8/8 | yes | KEEP |
| area carpet/builtUp/superBuiltUp | 7–8/8 | yes, carpet-led | KEEP (carpet becomes BLOCK for residential — §3.3) |
| area.plot* | villa-only | yes | KEEP |
| facing / furnishing | 8/8 | yes | KEEP |
| parking | 6/8 | yes | KEEP |
| specifications (6 groups) | 7/8 | yes (tabs) | KEEP |
| floorPlans.twoDUrl | 5/8 | yes | KEEP |
| floorPlans.threeDUrl | 2/8 | yes | KEEP |
| floorPlans.videoUrl | 1/8 | **no** | RENDER (embed under plans) or DROP the field |
| photos[] room-tagged | 1/8 | yes (grouped by room) | KEEP — census shows admins skip it; checklist WARN |
| photos[].caption | — | yes | FIX — admin UI never offers a caption input; add or stop rendering |
| pricing.basePrice / additionalCharges / viewPremium / effectivePrice | 8/8 | yes (breakdown) | KEEP |
| pricing.floorRisePerSqft | **7/8 — diligently filled** | **no, and not in any calculation** (`UnitType.js:188-209` excludes it) | **DROP from wizard** (or render as "+₹X/sqft per floor" note). Filled-and-dead is the worst state |
| paymentTerms (booking/GST/stamp/registration) | 5/8 | yes (all-inclusive cost sheet) | KEEP — bookingAmount is BLOCK (agreed) |
| additionalCharges.maintenance | — | yes, as one number | **FIX ambiguity** — add `maintenancePerSqftMonthly` (₹/sqft/month), the figure buyers actually ask; keep the one-time field separately labelled |
| inventory + towerAllocation | 8/8, 5/8 | yes | KEEP (invariant per agreed Stage 4) |
| highlights | 4/8 | yes | KEEP |

**Net new fields justified: two.** `maintenancePerSqftMonthly` and a
structured `connectivity` distance unit note (store km, render "X km"). Every
other gap is a render, a fix, or a rule — not a field.

---

## 2. What the research adds (and what it rejects)

**RERA obligations that bind a listing portal** (sources in §7):
- No advertising an unregistered project — *unless it has an Occupancy
  Certificate*. So the publish rule is conditional, not blanket (§3.1).
- The registration **number** must be displayed prominently; MahaRERA
  additionally mandates QR + website with font-size and top-right placement
  rules for ads, with ₹10k–50k penalties and active enforcement (628 projects
  penalized).
- **Carpet area** is the legal basis of sale; super built-up may be shown but
  carpet must be disclosed.
- TNRERA 2025: distances in **kilometres**, not minutes; amenity claims must
  be itemised (DealDirect already itemises).

**Portal benchmark** (99acres/Housing/Magicbricks project-page anatomy):
DealDirect already has every core section they show — overview, configs,
floor plans, amenities, gallery, brochure, RERA badge, possession — plus
several they don't (spec-level detail, all-inclusive cost sheet, tower
allocation). The two benchmark items DealDirect lacks are **the map view**
(collected, unrendered) and **locality insights/price trends** (rejected: needs
market data DealDirect doesn't have; not an admin-authoring concern).

**Rejected additions** (considered, not worth an admin's time): EMI calculator
(client-side compute, no field), locality write-ups (description covers),
water/power infra fields (amenity presets cover), possession-penalty terms
(brochure territory), reviews/ratings (needs users first).

---

## 3. Rule upgrades surfaced by the research — RATIFIED 2026-08-22

Decisions taken; this section records them.

### 3.1 RERA — display the number; no publish-BLOCK (decided)
- **ADOPTED**: the badge shows the actual number — "RERA: P52100012345" with
  a link to the state portal (and the certificate if uploaded). "RERA
  Verified" with no number is the pattern regulators are penalizing.
- **DECLINED**: the conditional publish-BLOCK (number required unless
  RTM/Completed with OC). `reraNumber` stays a checklist **WARN**. Recorded
  for the file: this accepts that an under-construction project without a
  RERA number can be published; the Act's advertising prohibition and the
  active enforcement documented in §7 are the exposure being accepted.

### 3.2 The map section — ADOPTED (part of the render pack)
Render a Leaflet map from `location.coordinates` (library already shipped,
admin picker already exists) with connectivity chips beneath it. Coordinates
move to WARN on the checklist.

### 3.3 Carpet area — BLOCK for residential — ADOPTED
`area.carpetSqft` becomes BLOCK for a publishable **residential** unit type
(apartment/villa); plotted developments BLOCK on `plotAreaSqft` instead.
Joins the agreed publishable-unit rule set (name, basePrice, totalUnits,
availableUnits defined, bookingAmount).

### 3.4 floorRisePerSqft — remove from the wizard — ADOPTED
7/8 admins filled a number that reaches no calculation and no pixel. The
field leaves the form (schema keeps it for existing data); revisit at
Level-2 per-unit pricing.

---

## 4. The pipeline (the deliverable)

### Stage 0 — Intake (before touching the wizard)
A one-page checklist the admin works through with the builder's material.
Chase what's missing *before* transcription, not after:

```
From the builder:  brochure PDF · price sheet per configuration · inventory
                   count per configuration (and per tower if split) · booking
                   amount + GST/stamp/registration figures · RERA number +
                   certificate (or OC if completed) · 6–10 photos (see specs)
                   · 2D floor plan per configuration · master plan · logo
Nice to have:      drone shots · 3D plans · walkthrough video · CC ·
                   bank-approval list · payment-plan schedule · amenity photos
```

### Stage 1 — Builder card (once per builder)
`name*, phone*` (uniqueness enforced) · company · email · RERA/GST numbers ·
logo (square, ≥400px — auto-cropped 400×400) · **profile block** (description
2–3 sentences, yearEstablished, totalProjectsDelivered, operatingCities) —
this feeds the Developer section (§1, Builder table) so it stops being dark.

### Stage 2 — Project wizard, reordered
Current order buries the money and documents at the end; the census shows
exactly where admins stop. New order front-loads sellability:

| Step | Fields | Publish rule fed |
|---|---|---|
| 1. Basics | name*, category*, subType, status, ownership, vastu, description (80–300 words: position, USP, who it's for), highlights (3–6 bullets, each a fact not an adjective) | BLOCK: name, category |
| 2. Location | city*, locality, microMarket, pincode, address line, **map pin** (drag on picker), connectivity **in km** | BLOCK: city · WARN: pin |
| 3. Compliance | **RERA number** + certificate upload — or OC upload for completed projects; CC; approvals | BLOCK: §3.1 conditional |
| 4. Overview | towers, floors/tower, total units, land area, open %, launch, possession | WARN set |
| 5. Media | per the image spec table (§5) | BLOCK: ≥1 exterior |
| 6. Amenities | preset picker + amenity photos | WARN: none selected |
| 7. Commercials | payment-plan **templates** (CLP/DP/Flexi pre-filled schedules the admin tweaks — 0/7 filled today because the step offers a blank form), bank approvals (bank + loan type) | WARN |
| 8. Nearby | category/name/**distance in km** | WARN |
| 9. Review | full checklist, every WARN listed, Save Draft / Publish | gate runs server-side |

Steps 3 and 7 are the reorder: documents climb from position 7 to 3;
sales-contact step disappears (it's hard-coded server-side anyway).

### Stage 3 — Unit-type wizard, reordered
`Config* → Area* (carpet leads) → Pricing* → Payment terms* (booking amount
bold — it gates bookability) → Inventory* (total/available; tower split if
towers > 1) → Floor plans → Photos (room-tagged, caption input added) → Specs
→ Facing/Furnishing/Parking → Highlights`. The starred first five are the
publishable-unit BLOCK set (agreed) + carpet (§3.3). floorRise removed (§3.4).

### Stage 4 — Readiness and publish
The ProjectDetail checklist panel (agreed Stage-3 work) shows BLOCK/WARN live
during authoring — this, not willpower, is what fixes the
trailing-steps-die-at-zero pattern. Publish runs the server gate. WARNs
publish with a visible "listing completeness" score so thin listings are a
choice, not an accident.

### Stage 5 — Life after publish (monthly rhythm)
- **Construction update** (under-construction projects): 3–5 photos + one
  line + % complete, monthly — renders as the new public timeline. This is
  the single strongest trust feature the model already has.
- Inventory deltas as bookings/verifications land (agreed adjust flow).
- Price revisions → checklist re-run stays green.
- Status transitions (New Launch → Under Construction → Ready To Move →
  Completed) with OC upload at the end.

---

## 5. Image specification — what, where, how many

| Slot | Field | Count | Content + technical spec |
|---|---|---|---|
| **Listing hero** | `exteriorImages[0]` | 1 | The decision image: daytime finished-elevation or best render, main tower/entrance, no text/watermark/collage. Landscape ≥1400×900 (server transforms to 1400×900 limit already). Order matters — first = card image everywhere |
| Gallery exteriors | `exteriorImages[1..]` | 4–8 | Elevation from 2–3 angles, entrance/lobby, landscape/podium. Mixed portrait ok from [1] on |
| Drone | `droneImages` | 2–4 (optional) | Site + surroundings context; one wide locality establishing shot |
| Master plan | `masterPlan` | 1–2 | Site layout with tower labels + legend readable at 1400px. **UI fix required: render `object-contain` full-width with zoom — current 12rem crop destroys plans** |
| Amenity photos | `amenityImages` | 2–6 | Only amenities that exist or are rendered honestly as renders; match the checked amenity list (TNRERA: claims must be itemised) |
| Construction progress | via `constructionUpdates[].images` | 3–5 / update | Same 2–3 vantage points every month so progress reads as a sequence; retire the parallel `media.constructionProgressImages` field |
| Location map image | `locationMap` | 0 | Superseded by the live map (§3.2); keep accepting as fallback, stop asking in the wizard |
| Brochure | `brochureUrl` | 1 PDF ≤15MB | The builder's own; link larger files externally |
| Certificates | `documents.*` | PDFs | RERA cert (or OC), CC, approvals — rendered as a collapsed Documents list |
| Unit 2D plan | `floorPlans.twoDUrl` | 1/unit type | White background, dimensions legible, north arrow if available; rendered `object-contain` (already correct on unit page) |
| Unit 3D | `threeDUrl` | 0–1 | Optional isometric |
| Unit interiors | `photos[]` | 3–6/unit type | Room-tagged (Living/Bedroom/Kitchen/Bathroom/Balcony); show-flat or render; caption input to be added |
| Builder logo | `logoUrl` | 1 | Square ≥400px, transparent or white background |

Folder layout stays as built (`dealdirect/projects/<builderId>/<kind>`,
`dealdirect/unit-types/<builder>/<project>`); delete/reorder + destroy comes
with the agreed media work.

---

## 6. Implementation deltas vs the agreed work order

Already covered by agreed stages: publish gate + checklist (Stage 3), media
delete/reorder/destroy (Stage 5), inventory invariant (Stage 4), booking
guards (Stage 2), Enquire CTA (Stage 4).

**Ratified 2026-08-22:**
1. §3.1 — RERA number **display** adopted; conditional BLOCK **declined**
   (reraNumber stays WARN; exposure recorded in §3.1).
2. §3.3 — carpet-area BLOCK for residential unit types: **adopted**.
3. The **render pack**: **full pack adopted** — map + connectivity,
   construction-updates timeline, bank approvals, full Documents list,
   Developer profile section, master-plan fix, video embeds.
4. §3.4 + wizard bundle: **all adopted** — floorRise off the form,
   reraCertificateUrl duplicate merged, maintenancePerSqftMonthly added,
   photo caption input, both wizards reordered, payment-plan templates,
   connectivity stored in km.

## 7. Sources

- [MahaRERA Order 46C/2025 — QR, registration number, font/placement rules](https://complinity.com/legal-update/maharashtra-real-estate-regulatory-authority-maharera-issues-order-regarding-the-mandatory-display-of-qr-code-font-size-specifications-for-maharera-registration-number-and-website-address-in-advertisements-18613/)
- [MahaRERA QR mandate from Aug 2023](https://goodbrickrealty.com/maharera-qr-code-mandatory-for-all-registered-projects-from-august-1-2023/)
- [628 developers penalized for missing RERA number/QR in ads](https://rera.news/updates/628-Real-Estate-Developers-Under-MahaRERA-Scrutiny-for-Missing-RERA-Registration-Number-and-QR-Code-in-Advertisements)
- [GujRERA: QR + registration display mandatory in all ads (June 2025)](https://realestatelawjournal.in/gujarat-rera-makes-qr-code-and-registration-display-mandatory-in-all-real-estate-ads/)
- [TNRERA 2025 ad rules — km distances, itemised amenities, QR](https://blog.maadiveedu.com/hysense/rera-tamil-nadu-real-estate-ad-rules-2025-qr-codes-disclosure-norms--transparency-standards)
- [MahaRERA advertising enforcement overview — Desai & Diwanji](https://desaidiwanji.com/insights/articles/transparency-first-maharera-enforces-stricter-rules-for-real-estate-advertising)
- [RERA carpet-area definition and disclosure duty](https://www.ltfinance.com/blog/home-loan/carpet-area)
- [Delhi RERA move to carpet-area-basis advertising](https://therealtytoday.com/news/delhi-rera-to-mandate-carpet-area-disclosure-in-place-of-super-built-up-area-in-property-ads/)
- [10 RERA rules for buyers — registration before advertising](https://rerafiling.com/rera-article-detail.php/679/10-rera-rules-every-buyer-should-be-aware-of)
- [99acres project microsite anatomy](https://www.99acres.com/articles/how-to-use-99acres-to-buy-your-dream-home-bgid.html)
