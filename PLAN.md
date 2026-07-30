# DealDirect — Implementation Plan

Hierarchy: **Builder → Project → UnitType → GroupBuyCampaign / Booking**

Two Cloudinary upload patterns exist in this repo. **Use the controller-local `uploadToCloudinary` / `uploadMany` helper** (the one already in `unitTypeController.js` / `projectController.js`), NOT the `validateAndUploadToCloudinary` middleware in `upload.js` (these routes don't use it).

**Cross-cutting rules (apply to every feature):**
- Buyers never see builder phone/email — keep the `isAdmin`-conditional `builderFields` in `getProject` and the hardcoded `salesContact` in `createProject` intact.
- Any NEW project-level file field **must** be added to the `ALLOWED_PROJECT_FIELDS` Set in `routes/projectRoutes.js` or the upload is rejected with 400.
- `memoryUpload` is images-only (JPEG/PNG/GIF/WebP, 10MB/file, magic-byte validated) — fine for all galleries here.
- Don't fold GST / stamp duty / registration into `effectivePrice` — they're additive taxes/fees, kept out of the pre-save calc by design.

---

## ✅ FEATURE 1 — Fix broken Group-Buy CampaignCard (do first — live bug)

`CampaignCard` in `client-next/src/app/projects/[id]/units/[unitTypeId]/UnitDetailContent.jsx` reads fields the backend **never sends**: `c.currentBuyers`, `c.maxBuyers`, `c.regularPrice`, `c.groupBuyPrice`. Backend only produces `memberCount`, `buyerTargets.maxBuyers`/`.minBuyers`, and `discountPerBuyer` (flat ₹). Campaigns carry **no price field**, so price must come from the parent component.

**Client only — no backend change.**

In `UnitDetailContent.jsx`:
1. Where campaigns render (~line 323), pass the unit price down:
   ```jsx
   {campaigns.map(c => <CampaignCard key={c._id} c={c} effectivePrice={price} onBook={handleBookClick}/>)}
   ```
   (`price` = `ut.pricing?.effectivePrice`, already computed in this component.)
2. Rewrite `CampaignCard({ c, effectivePrice, onBook })`:
   - `const joined = c.memberCount || 0;`
   - `const maxBuyers = c.buyerTargets?.maxBuyers;`
   - `const minBuyers = c.buyerTargets?.minBuyers;`
   - `const pct = Math.min(100, Math.round((joined / (maxBuyers || minBuyers || 1)) * 100));`
   - `const discount = c.discountPerBuyer || 0;`
   - `const groupBuyPrice = effectivePrice ? effectivePrice - discount : null;`
   - `const savings = effectivePrice ? Math.round((discount / effectivePrice) * 100) : 0;`
   - Render `{joined}/{maxBuyers||minBuyers} joined`, `groupBuyPrice` with `effectivePrice` struck through, and `{savings}% off`.

The dark group-buy banner in `ProjectDetailContent.jsx` already uses correct fields — leave it.

---

## ✅ FEATURE 2 — All-inclusive cost sheet (HIGH)

GST / stamp duty / registration are collected per-unit in `paymentTerms` but never shown to buyers. **Client only.**

In `UnitDetailContent.jsx`, add a "Total Cost" card in the right sidebar. Taxes apply **on top of** `effectivePrice`:

```
base   = ut.pricing.effectivePrice
gst    = base * (paymentTerms.gstPercentage || 0) / 100
stamp  = base * (paymentTerms.stampDutyPercentage || 0) / 100
reg    = paymentTerms.registrationCharges || 0
total  = base + gst + stamp + reg
```

Show line items (Base Price, GST %, Stamp Duty %, Registration, **All-Inclusive Total**) and the booking amount (`paymentTerms.bookingAmount`) as "Pay now to book". Only render rows where the value > 0.

---

## ✅ FEATURE 3 — Unit interior photo gallery (HIGH)

A unit currently only shows floor plans. Add a real interior photo gallery.

**Backend — `models/UnitType.js`:** add
```js
photos: [{
  url: String,
  room: { type: String, enum: ["Living Room","Bedroom","Kitchen","Bathroom","Balcony","Dining","Exterior","Other"], default: "Other" },
  caption: String
}]
```

**Backend — `routes/unitTypeRoutes.js`:** add to BOTH `.fields([...])` arrays (POST `/` and PUT `/:id`):
```js
{ name: "unitPhotos", maxCount: 20 }
```

**Backend — `controllers/unitTypeController.js`:**
- `createUnitType`: after floor-plan uploads, upload each `files.unitPhotos`, pair with `JSON.parse(body.unitPhotoRooms || "[]")` (parallel array of room tags by index), build the `photos` array, add to `UnitType.create({...})`.
- `updateUnitType`: if `files.unitPhotos` present, upload and **append** to `unitType.photos`. If `body.removePhotoUrls` (JSON array) present, filter those URLs out first.

**Admin — `CreateUnitType.jsx` (Step 7 "Floor Plans"):**
- Extend `files` state with `unitPhotos: []`.
- Add a multi-file picker + a room-tag `<select>` per selected file (parallel state array of tags).
- In `handleSubmit`: append each photo file under `unitPhotos`, and `fd.append("unitPhotoRooms", JSON.stringify(roomTags))`.
- `unitTypeSchema.js` Step 7: optional, no change (only the 2D plan stays required).

**Client — `UnitDetailContent.jsx`:** add a gallery section rendering `ut.photos`, grouped by `room`, with a simple grid or lightbox.

---

## ⚙️ FEATURE 4 — Plot/land fields for Villa & Plotted projects (MEDIUM)

**Backend — `models/UnitType.js`:** add to `area`:
```js
plotAreaSqft: Number,
plotDimensions: { length: Number, width: Number }
```

**Backend — `controllers/unitTypeController.js`:** in `createUnitType`'s `area` object add `plotAreaSqft` and `plotDimensions` (parse from flat body fields `plotAreaSqft`, `plotLength`, `plotWidth`). For `updateUnitType`, add explicit flat-field mapping mirroring how `paymentTerms` is handled (the form sends flat fields, not an `area` JSON blob).

**Admin — `CreateUnitType.jsx` (Step 2 "Area"):** conditionally render plot inputs only when the parent project's `subType` is `"Villa Community"` or `"Plotted Development"`. Component already loads `project` — gate on `project?.basics?.subType`.

**Client — `UnitDetailContent.jsx`:** show plot area & dimensions if `ut.area.plotAreaSqft` exists.

---

## ⚙️ FEATURE 5 — Amenity photos (MEDIUM)

Use the **existing flat-gallery pattern** (like `exteriorImages`), NOT a per-amenity index map.

**Backend — `routes/projectRoutes.js`:** add `"amenityImages"` to the `ALLOWED_PROJECT_FIELDS` Set.

**Backend — `models/Project.js`:** add a top-level `amenityImages: [String]`.

**Backend — `controllers/projectController.js`:** in `createProject`/`updateProject`, upload `files.amenityImages` via `uploadMany()` and set `amenityImages` (append on update, like other media arrays).

**Admin — `CreateProject.jsx` (Step 5 or 6):** add `amenityImages: []` to `files` state + a multi-file picker (reuse the existing Step-6 file-grid block). Don't forget to also reset it in the "Clear draft" handler's `setFiles({...})`.

**Client — `ProjectDetailContent.jsx`:** render `amenityImages` as a small gallery near the Amenities list.

---

## ⚙️ FEATURE 6 — Payment plans display + Admin UI (MEDIUM)

**Backend is already done** — `Project.paymentPlans` schema exists and `safeParse(body.paymentPlans)` is wired in both create & update (and the generic `allowed` merge on update). **No backend change.**

**Admin — `CreateProject.jsx`:** add a repeatable builder (Step 4 or a new step) for `paymentPlans`. Each row = `planType` (select: CLP / Down Payment / Flexi / Subvention), `description`, and a `schedule` list of `{ stage, percentage }`. Store in `form.paymentPlans` (already in initial state) — it's already JSON.stringify'd by the generic submit loop.

**Client — `ProjectDetailContent.jsx`:** render a "Payment Plans" card showing each plan's schedule.

---

## ⚙️ FEATURE 7 — Builder photo gallery (LOW)

**Backend — `routes/builderRoutes.js`:** change `memoryUpload.single("logo")` → `.fields([{name:"logo",maxCount:1},{name:"gallery",maxCount:10}])` on POST & PUT.

**Backend — `models/Builder.js`:** add `galleryUrls: [String]`.

**Backend — `controllers/builderController.js`:** `req.file` → `req.files`; upload `files.logo[0]` (as now) and each `files.gallery` (append on update).

Builder API is admin-only, so this is admin-facing only unless later exposed.

---

## ⚙️ FEATURE 8 — Per-unit video tour URL (LOW)

**Backend — `models/UnitType.js`:** add `floorPlans.videoUrl: String` (or top-level `videoTourUrl`).
**Admin — `CreateUnitType.jsx` Step 7:** add a text input.
**Backend — `unitTypeController.js`:** map flat `body.videoTourUrl`.
**Client:** embed if present.

---

## ❌ SKIP (with reasons — do NOT add these)

- **Booking ↔ Campaign link** — `CampaignMember` and `ProjectBooking` are intentionally separate systems (`joinCampaign` creates a `CampaignMember`, not a booking). Merging is an architecture decision, out of scope.
- **Stamp-duty auto-fill from state** — hardcoding government tax rates ships stale/wrong data. Manual entry is safer.

---

## Suggested order
1. Feature 1 (live bug, client-only)
2. Feature 2 (client-only, high value)
3. Feature 3 (full-stack, most code)
4. Features 4–6
5. Features 7–8 if time permits
