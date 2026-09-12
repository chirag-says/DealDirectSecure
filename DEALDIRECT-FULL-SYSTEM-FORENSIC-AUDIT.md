# DealDirect — Full-System Forensic Audit

Fresh, repository-wide, adversarial review. Read-only: no code, schema, index,
database or environment change was made in producing this. Every claim carries
a file reference or a measured number; where something could not be verified
(production state), that is said rather than assumed.

Companion deep-dive: [DEALDIRECT-BUILDER-PROJECT-FUTURE-STATE.md](DEALDIRECT-BUILDER-PROJECT-FUTURE-STATE.md).

---

## 1. Executive summary

DealDirect is **two products sharing one backend, plus three dark features**.

**Product one — the owner marketplace** (owners list properties, buyers express
interest, leads progress, deals close, rewards pay out) is genuinely mature.
Its auth, state machines, delete-integrity, bounds, notification and reward
paths have been hardened over five remediation phases and are covered by most
of the 48 test suites. Its weakest points are now product decisions, not
defects: auto-publish moderation posture, and the parked deleted-user PII
policy.

**Product two — the builder vertical** (Builder → Project → UnitType →
booking with real money over UPI) has a far better data model and payment
pipeline than any prior audit recorded — and **no demand and no safety rail**.
It is navigable (a top-level "Projects" nav item, a home-page rail, and the
sitemap all point at it — verified at working tree and at both repo HEADs),
yet across seven admin-authored projects there are **zero bookings and zero
campaigns ever created**, the only buyer entry point is a payment-framed
booking modal (no plain "enquire"), and a project becomes public the instant
an admin creates it, with not one field required. The engine is strong; the
product wrapper around it — lifecycle, validation, demand capture — is where
it fails.

**The dark features:**
- **Chat**: a full Socket.IO server, `Conversation`/`Message` models, seven
  API routes, CSRF guards and an admin moderation page — for a widget no page
  mounts (`ChatWidget` is imported by nothing; `server.js:857-884` notes it is
  deliberately hidden).
- **Agreements**: fully and correctly retired on all three sides — the page
  calls `notFound()`, the three navbar links are commented out, the backend
  mount is off (client decision, 2026-08-01, documented at every site).
  **CORRECTION:** an earlier draft of this audit called this a live-UI-over-
  dead-API defect. That was wrong — the grep behind it counted `href="/agreements"`
  occurrences sitting inside `{/* ... */}` JSX comments. Nothing to fix here;
  the retirement is a model of how to do it.
- **Group buy**: display-only. `minBuyers` and `discountPerBuyer` are stored,
  shown, and **never enforced anywhere** — no code reads the threshold, applies
  the discount, or notifies anyone when the goal is met.

The single most damaging *class* of defect across the system is the same one
three times over: **a UI that promises what no backend performs, or a backend
that performs what no UI can reach.** The remediation phases fixed the
correctness of what runs; this audit's main finding is about what is wired to
what.

Top five actions (detail in §17):
1. Add a publish gate to Project (draft state) — creation is public today, empty or not.
2. Extend the CSRF Phase-1 list to `/api/bookings` (money-adjacent, currently unguarded).
3. Fix builder deactivation so a deactivated builder's projects stop being sold.
4. Give the project pages a non-payment "Enquire" path — today the only CTA
   asks for money, and seven projects have produced zero bookings.
5. Render what admins already fill — map, construction timeline, developer
   profile and documents are all collected and none of it reaches a buyer.

---

## 2. Architecture map

### 2.1 Applications and repositories

| App | Stack | Port | Own repo | Uncommitted paths in it |
|---|---|---|---|---|
| `backend/` | Express 5, Mongoose, Socket.IO | 9000 | yes (`a9a44e7`) | 124 |
| `client-next/` | Next.js 16 App Router | 3000 | yes (`fdb7085`) | 28 |
| `Admin/` | Vite + React | 5174 | yes (`57f5091`) | 12 |
| `dealdirect-mobile/` | Expo / expo-router | — | yes | — |
| repo root | orchestration only, not hosted | — | yes (`f38ae24`) | — |

Each app folder deploys independently (Hostinger git import). **All Phase 3–5
work lives only in the root repo**; the per-app repos that actually deploy
carry it as uncommitted working-tree changes. No monorepo tooling; types,
enums and validation are hand-duplicated across apps, held together by drift
tests (`api-client-contract.test.js`, `taxonomy-contract.test.js`,
`property-field-contract.test.js`).

### 2.2 Backend route mounts (`server.js`)

Mounted: `propertyTypes, users, admin, categories, properties, leads,
notifications, contact, blogs, chat, rewards, hubble, builders, projects,
unit-types, campaigns, bookings, saved-searches` + `/health`,
`/debug-startup`, `/api/csrf-token`, static `/uploads`.

Deliberately **not** mounted: `/api/subcategories` (`server.js:910`, taxonomy
retirement) and `/api/agreements` (`server.js:936`, including its payment
webhook). Both removals are one-sided: the *live production* client still
bundles `/subcategories/list` into a `Promise.all` (deploy-order constraint,
recorded in the cutover plan). The agreements removal, by contrast, was done
correctly on all three sides — see §10.1.

### 2.3 Auth planes

Three, all sound at the transport level:

1. **User**: JWT-in-HttpOnly-cookie carrying a `sessionId` →
   `UserSession` lookup (revocable). Legacy no-`sessionId` tokens fall back to
   `changedPasswordAfter` (`authUser.js:326`). Session revocation — not
   `passwordChangedAt`, not the removed `sessionVersion` — is what invalidates
   sessions on password change (proven end-to-end in
   `phase5-cleanup-batch2.test.js`).
2. **Admin**: `AdminSession` + TOTP MFA (speakeasy) + fingerprint checks +
   role level (`requireRoleLevel`). The permission layer is retired
   (`authAdmin.js:492-524` records why). `attachAdminIfPresent`
   (`authAdmin.js:460`) grants read-only elevation and requires an active,
   MFA-verified session — it is not spoofable by header.
3. **Server-to-server (Hubble)**: `X-Hubble-Secret` shared-secret header,
   fail-closed when unconfigured (`hubbleController.js:26-44`). Comparison is
   `!==`, not timing-safe (LOW, §5.9).

### 2.4 External services

Cloudinary (all media), Gemini (agreement generation — dark), SMTP (pooled,
via `notificationService`/`emailService`), Equence SMS + WAHA WhatsApp
(`smsService`/`whatsappService`, used by contact/property/user controllers),
RewardPort catalogue + Hubble gift-card SDK (two overlapping reward vendors —
§10.6), Sentry (backend + client-next).

---

## 3. Product capability map

Labels are proven, not asserted. *Reachable* means a signed-in user can get
there from rendered navigation.

| Capability | Backend | Web UI | Reachable | Verdict |
|---|---|---|---|---|
| Register / OTP / login / sessions | full | full | yes | **ACTIVE** |
| Password change / reset | full | full | yes | **ACTIVE** |
| User MFA | none | removed (5.3) | — | correctly absent |
| Admin auth + TOTP MFA | full | full (Admin) | yes | **ACTIVE** |
| Property CRUD (owner) | full | full | yes | **ACTIVE** |
| Property browse/search/suggest | full | full | yes | **ACTIVE** |
| Interest → Lead (owner props) | full | full | yes | **ACTIVE** |
| Interest on builder-feed props | records into array, no lead, no notify | button renders | via direct URL only | **INCONSISTENT** (§6.3) |
| Lead pipeline (owner) | full state machine | full | yes | **ACTIVE** |
| Deal close → TransactionVerification → rewards | full | full | yes | **ACTIVE** |
| Saved properties / saved searches + alerts | full | full | yes | **ACTIVE** |
| Notifications (in-app + email) | full | full | yes | **ACTIVE** |
| Rewards wallet / daily login / referral | full | full | yes | **ACTIVE** |
| Hubble gift-card redemption | full | storefront iframe | yes | **ACTIVE** (unverified against live Hubble) |
| Builder/Project/UnitType admin CRUD | full | full wizards (Admin) | yes (Admin) | **ACTIVE** |
| Project browse (public) | full | full | yes — navbar ×3, home rail, sitemap | **ACTIVE** (zero recorded demand — §10.2) |
| Unit booking + QR payment + admin verify | full, hardened | full | yes | **ACTIVE** (0 bookings to date) |
| Group buy campaigns | CRUD + join/exit APIs | banner + card → routes to *booking* | join API called by nothing | **DISPLAY-ONLY** (§6.1) |
| Chat + visit requests | full incl. Socket.IO | components unmounted | no | **BACKEND-ONLY, dark** |
| Agreements (Gemini, HMAC, payment) | written, **unmounted** | full UI, **navbar-linked** | yes — and always fails | **BROKEN-BY-DESIGN-DRIFT** (§10.1) |
| Blog | full | full | yes | **ACTIVE** |
| Contact form | full (SMS/WA alerts) | full | yes | **ACTIVE** |
| Site-visit scheduling | none (no model) | fake modal (unmounted) + admin page reading leads | admin: routed, unlinked | **FRONTEND-ONLY fiction** (§10.4) |
| Mobile app | n/a | expo-router app with tabs, projects, property, owner, chat, rewards routes | not deployed | **SUBSTANTIALLY BUILT, UNVERIFIED** — the "M1–M2 stubs" claim in `AI/` is stale |
| Legacy builder-feed Properties | model + admin add | excluded from `/list`, `/property-list`, `/search` (`propertyController.js:760,1221,1971`) | direct URL only | **DEAD STRATUM** |

---

## 4. Major end-to-end flows

### 4.1 Owner property lifecycle

`add-property` → `POST /api/properties/add` (CSRF-guarded, upload-validated) →
**created with `isApproved: true`** — auto-publish is explicit
(`propertyController.js:368`, "client requirement"). Admin moderation is
therefore **reactive**: disapprove (`:1173`), ban, or delete after the fact.
Public visibility (`:836-840`) requires `isApproved && !isBanned &&
isActive !== false && status ∉ ['rejected','suspended','draft','pending']`.

Two rots inside that rule: `rejected`, `suspended`, `draft` are **not in the
status enum** (`Property.js:107`) — dead vocabulary that can never match — and
`status: 'inactive'`, which *is* in the enum, does **not** hide a property;
only the separate `isActive` boolean does. Two fields both claiming to mean
"inactive", only one of which works (§7.2).

Close-deal: owner initiates, buyer confirms, `TransactionVerification`
(pending → approved/rejected) gates both parties' rewards; races covered by
`deal-races.test.js`; deletion of the property is refused while a
verification or binding agreement exists (`aggregateDelete.js:70-100`).

### 4.2 Interest → lead → conversion

`POST /properties/interested/:id` (auth + CSRF): cap of 5 concurrent
interests, self-interest blocked, duplicate blocked, `interestedUsers` push +
`likes` inc, then — **only if `property.owner` exists** — `Lead.create` with
user/property snapshots + owner notification (`propertyController.js:1691-1737`).
Lead statuses `new → contacted → interested → negotiating → converted | lost`
enforced by `leadState.js`; converted is terminal; deal close converts the
lead. Owner surface: list/analytics/XLSX export/contact history. Admin
surface: `GET /api/admin/leads` (paginated, default 20).

### 4.3 Project booking (the money flow)

`UnitDetailContent` (inline modal, `UnitDetailContent.jsx:16-156`) →
`POST /api/bookings` (auth) → server-side token amount resolution
(`unitType.paymentTerms.bookingAmount ?? project.financials.bookingAmount ?? 0`,
`bookingController.js:149`) → QR + UPI from `GET /bookings/payment-config`
(auth-gated env config) → user submits UTR/screenshot (ownership-checked) →
admin verifies in `BookingManagement` → **inventory decremented atomically
under `$gte:1` before the confirmation is persisted**
(`bookingController.js:302-387`), race loser becomes
`cancelled + payment.verified + REFUND DUE` explicitly → confirmation email →
auto-enrolment as paid campaign member if an active campaign matches.
Transition table `BOOKING_STATUS_TRANSITIONS` (`:461`) makes `confirmed`
unreachable except through payment verification; cancel out of
confirmed/completed restores inventory and reverses campaign membership.

This is the best-engineered write path in the system. Its problems are around
it, not in it: CSRF (§5.1), UTR reuse (§5.2), ₹0 tokens (§6.2), no user-side
cancel (§6.6), and a funnel that opens with a payment demand (§10.2).

### 4.4 Rewards

Registration/referral/daily-login/listing/deal-close accrue points through
`rewardService` (wallet + embedded transaction ledger, tier multipliers,
same-day-login dedup). Redemption is Hubble: client gets `/hubble/token`,
storefront iframe runs, Hubble's servers call back `/hubble/sso|balance|
debit|reverse` under the shared secret. Admin can adjust points
(CSRF-guarded). RewardPort catalogue endpoints are also still mounted and
public — a second, older vendor surface (§10.6).

---

## 5. Security findings

Ranked. Every item verified in source; none is speculative.

### 5.1 MEDIUM — booking endpoints lack CSRF protection
`POST /api/bookings` and `POST /api/bookings/:id/payment` are cookie-
authenticated, state-changing, money-adjacent — and absent from the Phase-1
CSRF list (`server.js:857-884`), which covers property add/edit, interest,
report, campaign join/exit, contact, chat, and account deletion. A cross-site
page can create bookings in a logged-in victim's name (payment submission is
additionally ownership-checked, limiting the second endpoint's blast radius to
the victim's own bookings). **Fix**: add both routes to the list; the guard
(`requireCsrf`) is origin-based and the live client sends same-origin
requests, so it is a two-line change with no client impact.

### 5.2 MEDIUM — UTR replay across bookings is invisible to the verifying admin
`payment.utrNumber` is indexed but not unique (`ProjectBooking.js:113`), and
`verifyPayment` never checks whether the submitted UTR was already used to
confirm another booking. One real ₹50k transfer can be screenshotted into two
bookings; nothing surfaces the collision. **Fix**: at verify time, look up
other bookings sharing the UTR and show them in the verification modal;
require an explicit override note.

### 5.3 MEDIUM — booking and campaign money actions have no audit trail
`AuditLog` is written by `adminController` (26 call sites: auth events, admin
lifecycle), `authAdmin` (7), and — to its credit — the rewards point
adjustment (`rewardsController`, 1). **Booking payment verification, booking
status changes, campaign payment verification, and all project/unit/builder
CRUD write no audit record.** `statusHistory` on the booking document is good
but is deletable with the document and not queryable as "what did admin X do
yesterday". **Fix**: reuse the existing `AuditLog.log` in
`bookingController.verifyPayment/updateBookingStatus` and
`campaignController.verifyPayment` first; the rest can follow.

### 5.4 LOW-MEDIUM — booking enquiry spam has no dedicated limiter
`POST /api/bookings` sits under only the global 500/15min IP limit. An
authenticated user can create hundreds of enquiries (no per-user cap, no
duplicate guard on user+unitType). Admin queue noise rather than data damage.
**Fix**: reuse `transactionalLimiter` (already defined, currently pointed at
the unmounted agreements route) and/or an open-enquiry cap per user.

### 5.5 LOW — Socket.IO surface runs for zero users
JWT-authenticated (`server.js:498-520`), but it is idle attack surface +
resource cost for a feature no client mounts. **Fix**: gate `io` setup behind
an env flag until chat ships.

### 5.6 LOW — public project/builder list `limit` is unbounded
`listProjects` and `listBuilders` cast `Number(limit)` with no cap
(`projectController.js:328`, `builderController.js:41`) — the Phase-4 bounds
convention was applied to properties but not here. Harmless at 7 projects;
wrong pattern to scale. **Fix**: clamp like `searchProperties` (≤60).

### 5.7 LOW — Cloudinary orphaning on failed/replaced uploads
`createProject` uploads all media **before** `Project.create`; a validation
failure strands the uploads. Unit-photo removal filters the array but never
calls `cloudinary.uploader.destroy` (`unitTypeController.js:302-319`);
brochure/floor-plan replacement overwrites URLs likewise. Cost + PII surface
(payment screenshots live in Cloudinary too), not exploitable. **Fix**:
destroy-on-remove/replace; a periodic orphan sweep for the rest. (Property
deletion already does this properly via `propertyAssets.js`.)

### 5.8 LOW — `attachAdminIfPresent` on public routes
Verified sound (session + MFA + active admin, read-only elevation). Listed
only because it is the kind of pattern that rots — a test pinning "no
`isAdminViewer` without `mfaVerified`" would be cheap insurance.

### 5.9 LOW — Hubble secret comparison is not timing-safe
`hubbleSecret !== expectedSecret` (`hubbleController.js:37`). Network jitter
makes practical exploitation unrealistic; `crypto.timingSafeEqual` is a
five-line fix while touching the file for anything else.

### 5.10 Verified non-findings
IDOR on booking payment (blocked, `bookingController.js:185`); builder
contact leakage on public project reads (stripped, `projectController.js:272`);
litigation details public (stripped, `:297`); owner email/phone on public
property reads (removed in an earlier phase, documented at
`propertyController.js:809-825`); campaign join race on `maxBuyers` (atomic
`$expr` filter); inventory oversell (atomic `$gte:1` with decrement-first
ordering); upload validation (magic bytes, size caps 10/15MB, field
allow-lists, concurrency guard); CSRF token handling in the shared clients;
NoSQL injection on search (regex-escaped everywhere it matters).

---

## 6. Business-logic findings

### 6.1 CRITICAL (as a product claim) — the group-buy mechanic does not exist
`GroupBuyCampaign` stores `minBuyers`, `discountPerBuyer`, perks. The UI
computes and advertises the discounted price (`UnitDetailContent.jsx:159-167`).
**No code anywhere reads `paidMemberCount >= minBuyers`, applies
`discountPerBuyer` to any booking or price, or notifies anyone that a goal was
met** (repo-wide grep, §investigation). The campaign card's CTA routes to the
*ordinary booking flow* at full token; `api.js:505` (`joinCampaign`) is called
by no page. The one live enrolment path is the admin-side back-fill when a
booking is confirmed (`syncBookingToCampaign`). If a campaign ends short of
`minBuyers`, members who paid tokens exist in a structure with no outcome
logic at all — no refund path, no conversion path, nothing fires on expiry
beyond the status flip (`campaignExpiry.js`).
This matches the standing Phase-3.5 deferral decision — but the deferral doc
framed it as "immature"; the accurate framing is **"advertised and absent"**.
Until the redesign, the honest minimum is to stop *displaying* the discount as
if it applies.

### 6.2 HIGH — bookings can be created and paid against ₹0 or missing inventory
Every UnitType field is optional. Two live consequences:
- 3 of 8 real dev unit types have no `paymentTerms.bookingAmount`; where the
  parent project also lacks the legacy amount, the modal renders and the
  booking persists **`tokenAmount: 0`** — "Pay exactly ₹0", then an admin
  verifies a zero payment.
- `createBooking` blocks only `availableUnits === 0`
  (`bookingController.js:124`); `undefined` passes. A unit type whose
  inventory was never configured accepts enquiries and *payments*, then every
  verification attempt dies on the `$gte:1` decrement → auto-cancel →
  "REFUND DUE". Money taken for stock that never existed, by construction.
**Fix**: treat missing `availableUnits`/`bookingAmount` as not-bookable at
enquiry time, and gate them at publish (report 2, §10).

### 6.3 HIGH — interest on builder-feed properties is a silent void
`markInterested` creates the lead and sends the notification **only when
`property.owner` exists** (`propertyController.js:1691,1727`). For a
builder-feed property (owner null): the user's tap is recorded into
`interestedUsers`, likes increments — and no lead is created, no one is
notified, no admin screen lists it. The buyer believes they registered
interest with a seller; the data goes nowhere. (Mitigated only by the stratum
being unreachable from public feeds — §3 last row.)

### 6.4 MEDIUM — campaign cancellation strands paid members
`updateCampaign` accepts any status change (`campaignController.js:158`) with
no member handling: cancel a campaign with `tokenStatus: "paid"` members and
they remain active-paid on a cancelled campaign — the same
obligation-without-record shape the exit guard (`assertSelfExitAllowed`) was
built to prevent, reachable through the admin edit instead.

### 6.5 MEDIUM — `adminNotes` on bookings is overwrite-only
`verifyPayment` assigns `booking.adminNotes = adminNotes || booking.adminNotes`
(`bookingController.js:384`); each verification/rejection cycle destroys the
prior note (the race path *appends* — the only path that does). Contact
history for project buyers has no home at all: `Lead` has `contactHistory`,
`ProjectBooking` has a single mutable string.

### 6.6 MEDIUM — users cannot cancel their own booking
No user-facing cancel route exists (`bookingRoutes.js`); my-bookings renders
status only. An enquiry made by mistake sits in the admin queue until an admin
notices. Terminal-state hygiene exists for admins but not for the person who
created the record.

### 6.7 LOW — the interest cap counts dead listings
The 5-interest cap counts `interestedUsers` membership across **all**
properties including sold/inactive (`propertyController.js:1651`), so a user
whose five interests all sold is locked out until they manually un-save.

### 6.8 LOW — `completed → cancelled` is legal for bookings
Deliberate (deal falls through post-completion) and correctly restores
inventory + reverses enrolment — but it also means "completed" is not a
terminal state, which any downstream revenue reporting must remember.

---

## 7. Data-integrity findings

### 7.1 HIGH — builder deactivation leaves the chain publicly for sale
`deleteBuilderAggregate` refuses only while **approved legacy Properties**
exist, then sets `builder.isActive = false` (`aggregateDelete.js:188-211`).
Projects check only their own `isActive` for public visibility
(`projectController.js:317-319`) — so a deactivated builder's projects remain
listed, browsable and **bookable**, and money can be taken against them. The
refusal guards the dead stratum and ignores the live one. **Fix**: refuse on
active projects, or cascade `isActive` down, and re-check builder state at
booking creation.

### 7.2 MEDIUM — two contradictory "inactive" concepts on Property
`status: 'inactive'` (enum) does nothing; `isActive: false` (boolean) hides.
Plus three guard statuses that cannot exist (§4.1). Fix by either wiring
`status` into visibility or deleting the dead values from both places.

### 7.3 MEDIUM — inventory counters are admin-clobberable with no invariant
`updateUnitType` accepts a wholesale `inventory` object
(`unitTypeController.js:257-264`). Nothing enforces
`total = available + booked + blocked`, and no reconciliation exists against
confirmed bookings. The booking path maintains counters atomically; one admin
edit desynchronises them silently. (An escape hatch is genuinely needed — the
cancel-restore path logs "may need manual correction" — but it should be a
delta operation with an audit line, not a blind overwrite.)

### 7.4 MEDIUM — denormalised counter drift windows
`priceRange`/`unitTypeCount` recalc is fire-and-forget
(`unitTypeController.js:42-60`: errors logged, not retried);
`CampaignMember` post-save recount swallows errors
(`CampaignMember.js:87-90`) and campaign edits race the recount's
`campaign.save()`. All self-heal on next write; none self-detects.

### 7.5 MEDIUM — retention: nothing expires and one policy is parked
`Notification` and `AuditLog` have **no TTL** (verified); both grow without
bound. The deleted-user cascade retains counterparty records **with the
user's name/email/phone in snapshots, forever** — explicitly parked as the
§1.6 product/legal decision (`aggregateDelete.js:222-247`), restated here
because "parked" has no clock either.

### 7.6 Deployed-index drift (production changes, all deferred, all still owed)
- `adminsessions.expiresAt_1` deployed **plain** — admin sessions never
  auto-expire (Phase 5 finding 3b; code fixed, deployed index not).
- `builders.email_1` deployed unique+non-sparse against a sparse schema — the
  second builder without an email **fails today**; `createBuilder` masks it as
  a 409 with a misleading message (`builderController.js:191`).
- `agreements.idempotencyKey_1` unique+non-sparse — latent while agreements
  stay unmounted.

### 7.7 LOW — media references are one-directional
Cloudinary URLs are stored as strings with no reverse index; nothing can
answer "which document owns this asset", which makes the orphan sweep (§5.7)
harder the longer it waits.

---

## 8. Architecture findings

### 8.1 The missing lifecycle is the root defect of the builder vertical
The schema comment says it plainly: *"no data field is compulsory"*
(`Project.js:25`) — incremental authoring is the design. But `isActive`
defaults true and there is no draft/review/published state, so **the moment an
admin clicks create, however empty, the project is public**. Client-side zod
validation blocks nothing by policy (`projectSchema.js:6-11`); the wizard's
draft is localStorage with a 24-hour TTL that cannot hold files
(`useFormDraft.js`). Intent (author over days) and mechanism (public on
create) contradict each other. Full treatment in report 2.

### 8.2 Two demand funnels, two vocabularies, no bridge
Owner side: `Lead` (new→…→converted, contact history, analytics, export).
Builder side: `ProjectBooking` (enquiry→…→completed, statusHistory, one notes
field). No lightweight "enquire about this project" exists — the only entry is
the payment-framed booking modal — and nothing lets an admin see demand across
both worlds in one place. `Lead.property/propertyOwner` are `required`, so the
model cannot be reused as-is.

### 8.3 Controllers as the service layer (standing, accepted)
19 controllers, 2,400 lines at the largest, all business logic inline. It has
held because tests pin behaviour, but every fix this engagement made
(transition tables, guards, aggregate deletes) had to be *extracted into
utils* to be testable — that extraction pattern (`utils/*State.js`,
`utils/*Guard.js`) is the de-facto service layer and should be named as such
rather than fought.

### 8.4 Feature flags by amputation
Chat: API mounted, UI unmounted. Agreements: UI mounted, API unmounted.
Subcategories: API unmounted, prod UI still calling. Three features, three
different halves removed, zero flags. The system needs one boring convention
(env-driven flag read by both sides) instead of asymmetric surgery.

### 8.5 Duplicated money UI
Two `BookingModal` implementations in the same route directory — the live
inline one (`UnitDetailContent.jsx:16`) and an orphaned standalone file
(`BookingModal.jsx`, raw `fetch`, no caller). The 5.2 orphan sweep checked
`components/`, not `app/`. Delete the orphan before it diverges further.

---

## 9. Performance and scale

**Current production problems**: none found at current data volumes (47
properties, 7 projects). The Phase-4 work (bounds, projections, predicate
pushdown, batched notification lookups) holds.

**Near-future risks**
- Uncapped `limit` on projects/builders lists (§5.6).
- `getMyBookings` and `listByProject` (unit types) are unpaginated full
  fetches — fine per-user/per-project, wrong pattern if copied.
- All admin project/unit uploads are memory-buffered multipart with up to 50
  files × 15MB in one request (`upload.js:355-357`) — a large authoring
  session risks one giant all-or-nothing request (mitigated by the
  concurrency guard; still the wrong shape for bulk import — report 2 §15).
- `SiteVisitManagement` fetches page 1 (20 leads) and filters client-side —
  already wrong today (§10.4), worse at scale.

**Long-term scale risks**
- 5,000 properties: `/list?limit=5000` for the sitemap becomes the heaviest
  query in the system; move the sitemap to a projected cursor walk.
- 50,000 units: the aggregate-counter inventory model itself is *not* the
  bottleneck (counters scale); the missing per-unit layer is a *capability*
  ceiling, not a load one — see report 2 §14.
- Wallet `transactions` embedded array grows per user forever; Phase 4.5's
  projection contains reads, but the array itself needs a cap-and-archive
  policy eventually.
- Socket.IO in-process `Map` (`server.js:496`) pins chat to single-instance
  deployment the day chat ships.

---

## 10. Cross-application inconsistencies

### 10.1 Agreements — RETRACTED, no defect here
An earlier draft ranked this "worst in class": navbar-linked UI over an
unmounted API. **It is wrong.** `app/agreements/page.js` calls `notFound()`,
all three navbar links sit inside JSX comments, and the backend mount is
commented out — a deliberate, documented three-place withdrawal dated
2026-08-01, with restore instructions at each site.

The error was mine: `grep -c 'href="/agreements"'` returns 3 whether or not
those lines are commented. The lesson generalises — two findings in this audit
came from greps that ignored comment context, and both were caught only by
reading the surrounding lines. Source-matching without context is how the
localities facet stayed broken for a year, and it is how this audit nearly
manufactured a critical finding.

### 10.2 The builder vertical converts nothing, and nothing measures why
Navigation exists (navbar ×3, home-page project rail, sitemap — verified at
working tree and both repo HEADs; only the Footer omits it). Yet dev holds
**7 projects, 0 bookings, 0 campaigns ever created**. Two structural
contributors are visible in code: the only buyer CTA is the booking modal,
which opens with a token-payment framing (no plain "enquire" — §8.2), and
nothing instruments the funnel (no view counts on projects — `Property` has
`views`, `Project` has nothing — no enquiry events, no drop-off signal). The
vertical can be found; it cannot be *wanted measurably*.

### 10.3 Admin naming lies
`BuilderVerification.jsx` manages **owner users** (list/block/export —
`:76,99,144`), surfaced in the sidebar as "All Owners" — the filename and any
doc referencing "builder verification" describe a feature that does not exist
(no verification fields on `Builder` at all). `SiteVisitManagement` (§10.4) is
routed at `/site-visits` but absent from the sidebar; `PopularProperties`
likewise routed, unlinked.

### 10.4 Site visits are a fiction with three unconnected pieces
User-side `VisitModal` fabricates success with a `setTimeout` when no
`onConfirm` is passed (`VisitModal.jsx:45-50`) — currently unreachable since
its only consumer is the unmounted chat. Chat-side visits are plain messages
(`visit_request` type). Admin-side `SiteVisitManagement` shows *property
leads* in `interested|negotiating` — and only the newest 20, because it calls
the paginated `/api/admin/leads` with no params and filters client-side
(`SiteVisitManagement.jsx:40-47`). No date, no slot, no visit entity anywhere.

### 10.5 Enum/shape drift held only by tests
Six `listingType` spellings tolerated by alias maps
(`propertyController.js:2020-2026`); bare-array vs enveloped responses
memorialised per-endpoint; four hand-copies of taxonomy resolution. The drift
tests are load-bearing — worth saying that any new client work *must* extend
them or the pattern fails silently.

### 10.6 Two reward vendors mounted at once
RewardPort catalogue routes (public) and the Hubble stack coexist in
`rewardsRoutes.js`/`hubbleRoutes.js`; the CSRF comment (`server.js:860`)
records the pre-Hubble store as removed, but the catalogue endpoints remain.
Decide which is the product and retire the other's surface.

### 10.7 Mobile parity is unrecorded
`dealdirect-mobile` has expo-router routes for tabs, projects, property,
owner, chat, rewards, claim-reward, blog — far past the "M1–M2 placeholder"
state the `AI/` docs describe (that is a 5.1 docs item, deferred, but the gap
now includes a whole app's worth of claims).

---

## 11. Test-quality review

48 suites, 1,265 tests, 0 failures, mutation-hardened in the areas the
remediation touched. What the numbers do **not** cover:

- **Never executed anywhere**: project/unit-type/builder/campaign controller
  CRUD (the admin authoring path), chat controller + socket auth, hubble
  webhooks, blog, contact, admin dashboard aggregation. The booking
  *lifecycle* is well covered (`booking-lifecycle`, `deal-races`,
  `campaign-member-state`, `state-transitions`); the *authoring* of the things
  being booked is not.
- **Source-assertion ceiling**: the client-side suites assert on source text
  (comment-stripped) or extracted expressions. They caught real regressions,
  but nothing renders a React tree — hydration, effect ordering and
  Suspense behaviour are unobserved. The related-properties regression (a
  feature silently dead for months) is exactly the class this misses; one
  Playwright smoke over login → search → property → book would close the
  worst of it.
- **Admin app and mobile**: zero tests of any kind.
- **Fixture realism**: good on the property side; the builder side's only
  deep fixtures live in `booking-lifecycle` — none exercise the all-optional
  emptiness that real dev data shows (0/7 brochures, 3/8 missing booking
  amounts).

Highest-risk untested workflow, full stop: **admin verifies a payment while a
colleague edits inventory for the same unit type** — every individual half is
tested, the interleaving is not.

---

## 12. Operational review

- **Deploy topology**: root repo (all remediation) vs per-app deploy repos
  (124/28/12 uncommitted paths). Until the per-app repos are committed and
  pushed deliberately, *nothing from Phases 3–5 can reach production*, and the
  longer the gap, the harder the reconciliation.
- **Ordering constraint standing**: new backend drops `/api/subcategories`;
  live client still calls it → client-next must deploy before or with the
  backend (cutover plan).
- **Exists only in production, not in the repo**: the three admin accounts;
  the 45-permission/4-role RBAC data (its seeder deleted; recoverable at
  `68ebab2`); the deployed index set with its three drifts (§7.6);
  `DEALDIRECT_PAYMENT_QR_URL` / UPI env (payment-config 503s without it);
  `HUBBLE_WEBHOOK_SECRET`. A rebuild-from-repo would produce a system with no
  admins and no payment QR — document a bootstrap runbook.
- **Env validation** at boot requires only `JWT_SECRET`/`MONGO_URI`
  (`server.js:65`); the payment QR and Hubble secret fail at request time
  instead — add them to the production-recommended list.
- **Backups**: none automated; `mongodump` not even installed on the dev
  machine (checked). The gitignore work now at least guarantees a dump can't
  be committed.
- **Logging/monitoring**: Sentry wired both sides; booking/campaign money
  paths log to console only — the REFUND-DUE auto-cancel deserves an alert,
  not a log line.
- **Untracked working docs**: the improvement roadmap itself is gitignored
  and untracked — it exists on one machine.

---

## 13. Product maturity scorecard

| Area | Verdict | One-line reason |
|---|---|---|
| User auth/sessions | **Mature** | revocation proven end-to-end; legacy path preserved |
| Admin auth/MFA | **Mature** | TOTP + sessions + audit of auth events |
| Property CRUD + search | **Mature** | bounded, tested, taxonomy-guarded |
| Interest→Lead→Deal→Reward | **Mostly mature** | solid machine; auto-publish posture + builder-props hole |
| Saved search / notifications | **Mostly mature** | pushdown + batching done; no TTLs |
| Rewards + Hubble | **Functional but fragile** | live path fine; two vendors, webhook tests absent |
| Builder/Project/UnitType authoring | **Functional but fragile** | rich model, real wizards — no publish gate, no required fields |
| Unit booking + payment | **Mostly mature** (engine) / **unproven** (product) | best write path in the repo; zero bookings ever taken |
| Group buy | **Prototype** | display-only; mechanic unimplemented |
| Chat | **Dead (dark)** | full stack, zero mounting |
| Agreements | **Dead (half-retired)** | API off, UI on |
| Site visits | **Dead (fiction)** | three unconnected fragments |
| Blog/SEO/public web | **Mostly mature** | 5.7/5.8 fixed the real gaps |
| Mobile | **Partially implemented** | substantial, unverified, undocumented |
| Ops/deploy | **Functional but fragile** | repo topology + prod-only artifacts |

---

## 14. Critical findings (act before any builder-vertical launch)

| # | Finding | § |
|---|---|---|
| C1 | Group buy advertised with no mechanic behind it | 6.1 |
| C2 | Projects public-on-create with zero required fields (₹0-token bookings reachable on real data) | 8.1, 6.2 |
| C3 | Deactivated builder's projects remain bookable | 7.1 |
| ~~C0~~ | ~~Agreements dead-API~~ — **RETRACTED**, was a grep error | 10.1 |

## 15. High-priority findings

| # | Finding | § |
|---|---|---|
| H1 | CSRF gap on booking endpoints | 5.1 |
| H2 | UTR replay invisible at verification | 5.2 |
| H3 | Builder-feed interest void (or retire the stratum) | 6.3 |
| H4 | No audit trail on booking/campaign money actions | 5.3 |
| H5 | Inventory invariant absent + admin clobber path | 7.3 |
| H6 | Per-app deploy repos uncommitted (nothing can ship) | 12 |
| H7 | Deployed index drifts (admin-session TTL, builders.email) | 7.6 |
| H8 | Zero demand instrumentation on the builder funnel | 10.2 |

## 16. Medium / low findings

Campaign cancel strands paid members (6.4) · adminNotes overwrite (6.5) · no
user booking cancel (6.6) · SiteVisitManagement pagination lie + IA orphans
(10.4, 10.3) · status-vs-isActive contradiction and dead enum vocabulary (7.2)
· counter drift windows (7.4) · retention TTLs + parked PII policy (7.5) ·
booking spam limiter (5.4) · unbounded project/builder list limits (5.6) ·
Cloudinary orphans (5.7) · Socket.IO idle surface (5.5) · orphan BookingModal
(8.5) · interest cap counts sold listings (6.7) · Hubble timing-safe compare
(5.9) · two reward vendors (10.6) · sitemap query shape at 5k listings (9) ·
wallet array growth (9) · mobile/docs parity (10.7).

## 17. Recommended roadmap

**Phase A — truth-in-UI (days, client-only, deployable alone)**
Remove the group-buy sections until the mechanic exists (C1) · add the
non-payment "Enquire" CTA (§10.2, §8.2) · delete the orphan BookingModal.
(Agreements needs nothing — see §10.1.)

**Phase B — money-path hardening (days, backend)**
CSRF list += bookings (H1) · UTR-reuse check in verify modal (H2) ·
AuditLog on verify/status/campaign-verify (H4) · booking limiter (5.4) ·
enquiry guard on undefined inventory/amount (6.2 stopgap).

**Phase C — builder-vertical integrity (1–2 weeks, with report 2)**
Publish gate + draft state + required-for-publish set (C4) · builder
deactivation cascade + booking-time builder check (C5) · inventory invariant +
delta-based corrections (H5) · media destroy-on-remove (5.7).

**Phase D — ship what exists (operational)**
Commit per-app repos in dependency order; deploy client-next before/with
backend (H6) · production index repairs in one maintenance window: admin-
session TTL, builders.email sparse, plus the long-planned taxonomy cutover
(H7) · bootstrap runbook for prod-only artifacts (12).

**Phase E — decide the dark features (product decisions, then small code)**
Chat: ship (mount + flag + horizontal-scale note) or delete the stack ·
Agreements: remount behind flag or remove UI+controller · Site visits: build
the small real thing (entity + admin list) or delete all three fragments ·
Reward vendor: pick one · Group buy: the report-2 §17 redesign or withdrawal.

---

*Report 2 — the Builder→Project deep dive and future-state design — is at
[DEALDIRECT-BUILDER-PROJECT-FUTURE-STATE.md](DEALDIRECT-BUILDER-PROJECT-FUTURE-STATE.md).*
