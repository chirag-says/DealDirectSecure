# Project Creation Flow — Fix & Redesign Plan

> Handoff doc. Implement with Sonnet; verify with Opus. Decisions already locked:
> - **401 fix:** loosen IP‑prefix fingerprint check only (keep OS + device revokes).
> - **Project financials:** keep `Project.financials` in schema for back‑compat, stop writing it.
> - Booking/payment moves to the **unit type**.

---

## 0. Root-cause summary

| Symptom (console) | Real cause | Primary file(s) |
|---|---|---|
| Nominatim `blocked by CORS … wildcard '*' … credentials mode 'include'` | Global `axios.defaults.withCredentials = true` makes third‑party (Nominatim) calls credentialed; Nominatim returns `ACAO: *`, which browsers reject for credentialed requests. | `Admin/src/main.jsx:11`, `Admin/src/components/LocationPicker.jsx:142,201`, `Admin/src/pages/AdminAddProperty.jsx:935,986` |
| `POST /api/projects 401` | POST route uses `protectAdmin` → `validateFingerprintLenient`, which **revokes** the session on IP‑prefix change (CDN/proxy IP rotation). GET routes use `attachAdminIfPresent` (no fingerprint check), so reads keep working while the create POST 401s. | `backend/middleware/authAdmin.js:234`, `backend/models/AdminSession.js:280-290` |
| `POST /api/projects 500` | `createProject` has no fail‑fast Cloudinary guard and masks the real error in a generic `catch → 500`. Likely a raw‑PDF/Cloudinary upload failure; currently undiagnosable. | `backend/controllers/projectController.js:209-216` |
| `/api/builders 409 (x2)` | Re‑creating an existing builder (duplicate phone/email). Correct behavior, but surfaced as a raw error with no friendly handling. | `backend/controllers/builderController.js:130-136,189` |
| Design flaw: booking/payment on the project | Booking amount / GST / stamp duty / registration collected at project level (step 8) but vary per unit type. | `Admin/src/pages/CreateProject.jsx:639-671`, `backend/models/Project.js:189-195` |

---

## 1. Fix Nominatim CORS  (frontend only)

**Do NOT** remove `axios.defaults.withCredentials = true` in `main.jsx` — `AllCategory.jsx`, `AddCategory.jsx`, `AddSubCategory.jsx` use bare `axios` for backend GETs and depend on it.

**Change:** override `withCredentials` to `false` on third‑party geocoding calls only.

- `Admin/src/components/LocationPicker.jsx`
  - Add a dedicated instance: `const geo = axios.create({ withCredentials: false });`
  - Replace `axios.get(...)` with `geo.get(...)` at the forward‑geocode (`~line 142`) and reverse‑geocode (`~line 201`) calls.
- `Admin/src/pages/AdminAddProperty.jsx`
  - Same pattern for the two Nominatim calls (`~line 935`, `~line 986`).

**Verify:** On the Location step, typing a city ("Locating on map…") and "Pick on Map" reverse‑geocode auto‑fill state/city/pincode with **no** CORS / `ERR_FAILED` in console.

---

## 2. Fix 401 on create  (session fingerprint + graceful FE)

### 2a. Backend — `backend/models/AdminSession.js` (`validateFingerprintLenient`, ~line 280)
Demote the **IP‑prefix change** from hard revoke to *allow‑with‑refresh*. Keep OS change and device‑type change as hard revokes.

- Remove (or convert to `needsRefresh = true`) the block at `~line 283-290` that returns `{ valid: false, reason: "IP range changed …" }`.
- Move it down to the "MINOR CHANGES — allow and optionally refresh" section alongside the browser/UA‑variation handling, setting `needsRefresh = true` and a `console.warn`.
- Leave the OS check (`~258`) and device check (`~269`) untouched.

### 2b. Frontend — `Admin/src/pages/CreateProject.jsx` (`handleSubmit` catch)
On `err.response?.status === 401`: the draft is already auto‑saved in localStorage, so don't clear it. Show a toast like "Session expired — please log in and resume; your draft is saved" and route to login. (The axios response interceptor in `adminApi.js` already fires `onAuthError`; just make sure the draft is NOT cleared on the 401 path.)

**Verify:** Confirm the real `code` on a live 401 (`SESSION_FINGERPRINT_MISMATCH` confirms this bug; `INVALID_SESSION` = genuine expiry). After 2a, a create POST from the same machine/browser succeeds even when the edge IP prefix rotates between requests.

---

## 3. Fix + diagnose 500 on create  (`backend/controllers/projectController.js`)

1. **Fail fast:** at the top of `createProject`, import `isCloudinaryConfigured` from `../middleware/upload.js` and, if `!isCloudinaryConfigured()`, return `503 { code: 'STORAGE_NOT_CONFIGURED' }` (mirrors `validateAndUploadToCloudinary` at `upload.js:379`).
2. **Surface upload failures:** wrap the media/doc upload block (`~lines 62-107`); on failure return a clear `code: 'UPLOAD_FAILED'` instead of falling into the generic catch.
3. **Make the generic catch diagnosable:** in the final `catch` (`~line 209`), add `...(process.env.NODE_ENV !== 'production' && { debugInfo: error.message })` to the JSON (pattern already used at `upload.js:566`).

**Verify:** Reproduce a create, read the now‑surfaced `debugInfo`/backend log line `[projectController.createProject]`, fix the specific failure, then confirm a valid submission returns `201` and the project appears in the builder's project list.

---

## 4. Friendly 409 handling  (`Admin/src/pages/BuilderManagement.jsx`)

In `handleSubmit`'s catch, detect `err.response?.status === 409` and show "A builder with this phone/email already exists." with an action/link to open the existing builder. Submit is already gated by `disabled={submitting}`, so no double‑submit guard needed.

**Verify:** Submitting a duplicate phone shows the friendly message, not a raw console error.

---

## 5. Redesign — move booking/payment to the unit type

Booking terms vary per unit, so collect them on the unit type, not the project.

### 5a. Model — `backend/models/UnitType.js`
Add a new sub‑doc (keep it OUT of the `effectivePrice` pre‑save calc — these are booking/tax, not list price):
```
paymentTerms: {
  bookingAmount:        { type: Number, min: 0 },
  gstPercentage:        { type: Number, min: 0, max: 28 },
  stampDutyPercentage:  { type: Number, min: 0, max: 20 },
  registrationCharges:  { type: Number, min: 0 },
}
```

### 5b. UnitType controller — `backend/controllers/unitTypeController.js`
Map the four fields from `req.body` in both `createUnitType` (~line 65) and the `directFields` merge in `updateUnitType` (~line 208, add `"paymentTerms"` and/or parse the flat fields).

### 5c. Admin UnitType form — `Admin/src/pages/CreateUnitType.jsx`
Add the four inputs to the **Pricing** step (step 8). Add them to `form` state, `resetForm`, and the edit‑load mapping. Append to the submitted `FormData`.

### 5d. Admin UnitType schema — `Admin/src/schemas/unitTypeSchema.js`
Add validation for `bookingAmount` (required, `>= 0`) under the pricing step; the percentage/registration fields optional with sane bounds.

### 5e. Admin Project form — `Admin/src/pages/CreateProject.jsx`
- Remove the "Payment & Banking" inputs from step 8 (`~lines 639-671`); rename step to "Sales Contact" (or fold into Review and renumber).
- Drop `bookingAmount`, `gstPercentage`, `stampDutyPercentage`, `registrationCharges` from `form` state and the `Clear draft` reset.

### 5f. Project schema (Admin) — `Admin/src/schemas/projectSchema.js`
Delete `step8Schema` and its entry in `schemaMap`. Re‑check `handleSubmit`'s `for (let s = 1; s <= 8; s++)` loop bounds after any step renumber.

### 5g. Backend Project — `backend/controllers/projectController.js`
Stop writing `financials` in `createProject` (decision: keep the field in `Project.js` schema for back‑compat, just don't populate it). Leave `Project.js` model untouched.

### 5h. Client display — `client-next`
Grep for `financials` and `bookingAmount`; repoint any project‑level reads to the unit type. Booking already happens at unit level (`client-next/src/app/projects/[id]/units/[unitTypeId]/BookingModal.jsx`), so this is mostly display wiring.

**Verify:** Create a unit type with booking/GST/stamp‑duty/registration → values persist on the unit; project create no longer asks for them and still succeeds; client unit/booking views read the unit‑level numbers.

---

## 6. Opus verification checklist (post‑Sonnet)

- [ ] Location step geocodes with no CORS errors (Fix 1).
- [ ] `validateFingerprintLenient` no longer revokes on IP‑prefix change; OS/device revokes intact (Fix 2a). Unit-test or trace the three branches.
- [ ] 401 on create preserves draft + routes to login cleanly (Fix 2b).
- [ ] `createProject` returns 503 when Cloudinary unconfigured; surfaces `debugInfo` in dev; valid submit → 201 (Fix 3).
- [ ] Duplicate builder → friendly 409 message (Fix 4).
- [ ] Booking/payment fields persist on UnitType; absent from project create; client reads unit‑level values (Fix 5).
- [ ] `git grep -n financials` / `bookingAmount` shows no orphaned project‑level reads in `client-next`.
