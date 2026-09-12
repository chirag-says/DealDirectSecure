# DealDirect Mobile Implementation Plan

Date: 2026-08-22. Derived from `DEALDIRECT-MOBILE-PARITY-AUDIT.md` (finding IDs PA-1..PA-14 refer to that document). Honors decisions D1 (agreements withdrawn), D2 (chat dark), D3 (redemption is a separate workstream), D4 (group buy held, pending re-decision, see §5).

Scope rule carried over from the audit: this plan brings mobile to behavioral parity with the **current** DealDirect product, with mobile-native UX. It does not port web markup, does not resurrect withheld features, and does not touch the backend except where a deploy-ordering note says so.

Estimates: S ≤ 0.5 d · M 1–2 d · L 3–5 d · XL 1–2 wk. All are implementation-plus-self-verification on one device; the test work is itemized separately in Phase 5.

---

## 1. Work item register

### P0 — broken core flows against the current backend

**W1 — Booking contract catch-up** (PA-2) — **L**
Files: `src/api/endpoints/projects.ts`, `src/features/projects/bookings*`, `src/types/backend/project.ts`, `app/projects/unit/[unitTypeId].tsx`, `app/projects/booking/[bookingId].tsx`, `app/projects/bookings.tsx`.
1. Declare `POST /bookings/:id/cancel` (`{reason?}` → `{status, previousStatus, refundMayBeDue}`) and add cancel UI to the booking detail and list screens: quiet action, inline confirm, refund warning on `payment_submitted`, toast branching on `refundMayBeDue` (mirror web's `MyBookingsContent` behavior, not its markup).
2. Add the enquiry path: a second CTA on the unit screen ("Enquire — no payment needed") posting `intent:'enquiry'`; when `paymentTerms.bookingAmount ?? project.financials.bookingAmount` resolves to 0, show **only** the enquiry CTA (the book CTA would be refused with `BOOKING_NOT_CONFIGURED`).
3. Handle the refusal codes with specific copy and actions: `NO_INVENTORY` (sold-out state, disable CTAs), `BOOKING_NOT_CONFIGURED` (fall back to enquiry), 409 `DUPLICATE_ENQUIRY` (link to the existing booking in My bookings).
4. Type and read `source` on `ProjectBooking` and the create response; label enquiry rows differently from booking rows in the list ("Enquiry — our team will call you" vs the payment progress strip).
Acceptance: against the local backend, every one of the 8 seeded unit types either books or enquires successfully; a second enquiry on the same unit routes to the existing booking; cancel works from both cancellable states and is refused (with copy) elsewhere; `tokenAmount` is always displayed from the server response, never computed client-side.

**W2 — Account deletion sends the password** (PA-1) — **S**
Files: `app/settings/delete-account.tsx`, `src/features/profile/hooks.ts`, `src/api/endpoints/users.ts`.
Add a password field, thread `{password}` through `useDeleteAccount` into the request body, map 400 `PASSWORD_REQUIRED` / 401 `INVALID_PASSWORD` to field-level errors. Keep the typed confirmation. Surface `retainedListings` from the response when present ("Your listing with a pending verification was kept" copy).
Acceptance: deletion succeeds with the correct password on a test account; wrong password shows an inline error without tearing down the session; success tears down exactly like logout.

**W3 — Global session teardown** (PA-3) — **M**
Files: `src/api/client.ts`, `src/auth/AuthProvider.tsx`.
Extend the response observer: when a normalized error is session-fatal (`SESSION_FATAL_CODES`) **and** the app currently believes it is authenticated, call a debounced `AuthProvider.endSession(reason)` (the `endingRef` guard already exists). Exclude the auth endpoints themselves (login/register/otp) so a failed login does not "log out" a guest. Show the existing `endedReason` banner on the login screen.
Acceptance: revoking the session from `settings/sessions` on a second device logs the first device out to the login screen within one failed request, with the reason shown; a plain 401 from a guest-reachable screen still renders `SignInPrompt`, not a teardown loop.

**W4 — Campaign surface: enforce the D4 hold** — **S** (implementation) + **decision** (§5)
Files: `app/projects/campaign/[campaignId].tsx`, `app/projects/unit/[unitTypeId].tsx`, `src/features/projects/campaigns.ts`.
Until the group-buy re-decision: keep the campaign screen readable (name, status, member counts, dates) but remove the join/exit/payment-proof actions behind a flag defaulting to off, and stop linking to the campaign screen from the unit screen. This matches the web's current posture (renders nothing) while preserving mobile's superior wiring for the day the mechanic ships.
Acceptance: no mobile path lets a user join or pay into a campaign while the flag is off; the screens compile and the flag flips them back on without further work.

### P1 — major journeys behind the current product

**W5 — Projects render pack** (PA-5) — **XL**
Files: `app/projects/[id].tsx`, new components under `src/features/projects/components/`, `src/types/backend/project.ts`.
Port the behavior (not the markup) of the Aug-22 web render pack: location map with connectivity chips (blocked on W11's WebView map foundation; ship the connectivity chips + "open in maps" link first, embed the map when W11 lands), RERA number linked to the state register, construction-updates timeline (reverse-chronological, photos + % complete), documents section (brochure, CC, OC, approvals), bank approvals, developer profile block (never render builder phone/email; the web has a test asserting this, mobile should too), master plan full-bleed `contain` viewer with zoom, walkthrough video as a link.
Acceptance: every field the admin fills and the web renders is rendered or deliberately excluded with a comment; builder phone/email absent; sections hide cleanly when data is absent (admin-authored partial drafts are intended).

**W6 — Unit page depth** (PA-6) — **L**
Files: `app/projects/unit/[unitTypeId].tsx`, `src/features/projects/`.
All-inclusive cost sheet (base + GST% + stamp% + registration, hidden when all zero; taxes stay out of `effectivePrice`), price breakdown from `additionalCharges` + `viewPremium`, specs sections from `specifications` (flooring/kitchen/bathroom/doors/electrical), brochure link, inventory (available/booked/total) + tower allocation, interior photos grouped by `photos[].room`, video tour link.
Acceptance: numbers reconcile with the web for the same unit type; nothing is computed that the server provides.

**W7 — Types and registry catch-up** (PA-7, §7–8 of the audit) — **S**
Files: `src/types/backend/project.ts`, `src/api/endpoints/{projects,rewards,misc}.ts`.
Add `Project.publication{...}` + `views`; `ProjectBooking.source|contactHistory|assignedTo`; `pagination.limit`; fix `conversionRate` to `string | number`. Delete the dead declarations (`/rewards/store`, `/rewards/redeem`, `/subcategories/list`, `/properties/filter`). Correct the stale "active-only view" comments to the `publication.status` model.
Acceptance: `tsc --noEmit` clean; the registry contains no endpoint the backend does not mount.

**W8 — Guest guards on authenticated routes** (§9) — **S**
Files: the seven routes listed in the audit + `src/features/projects/bookings` hook.
Give `useMyBookings` an `enabled: authenticated` guard and render `SignInPrompt` on `projects/bookings`, `projects/booking/[bookingId]`, `settings/*`, `claim-reward/[verificationId]` when signed out (claim-reward should prompt, then resume the claim after login).
Acceptance: no guest ever sees a 401 `ErrorState` on these routes.

**W9 — Crash and error reporting** (§11) — **M**
Add `@sentry/react-native` mirroring the web's working-tree posture: `sendDefaultPii: false`, user = `{id, role}` only, set/cleared from `AuthProvider`, breadcrumbs scrubbed of cookies/headers. Wire release + `X-App-Version` correlation.
Acceptance: a forced test error arrives in a mobile-specific Sentry project with no PII; nothing is reported for expected 4xx kinds.

**W10 — Deploy sequencing for `listingType`** (PA-8) — **ops, not code**
Confirm whether `backend.dealdirect.in` has the 2026-08-03 `searchProperties` change. If not, the backend deploy must precede any mobile store build that advertises rent/sale filtering; until then mobile's results screen silently no-ops the toggle. Track in the release checklist, per the Hostinger per-app deploy model.

### P2 — product parity gaps

**W11 — Property location map screen** (the last placeholder) — **L**
Per `docs/MAP_IMPLEMENTATION.md`: Leaflet in a WebView, dev-client rebuild required. The WebView must never carry an API call (the no-`Origin` constraint). Degrade to locality text when coordinates are absent or (0,0). Link it from the detail screen; delete `src/dev/Placeholder.tsx` usage.
**W12 — Blog article rendering** — **M**. Replace the paragraph-stripper with a proper HTML renderer (`react-native-render-html` or equivalent): links, emphasis, inline images. Keep entity decoding.
**W13 — Listing form completion** (PA-11) — **L**. A zod schema for the whole form, final pre-submit validation, a date picker for `availableFrom`, per-step gates on all 7 steps, upload progress via the existing `onUploadProgress` hook, and field-parity pass against web (video URL; the commercial field matrix only where the backend schema actually persists it — several web fields are silently dropped by Mongoose, port none of those).
**W14 — Leads export + date filter** (PA-12) — **M**. Wire `GET /leads/export` (Blob download with `sessionHeaders()`, share sheet) and a 7-day range filter mirroring web's cap.
**W15 — Home request dedupe** (§12) — **S**. One shared `newest-100` pool query feeding popular/city-counts/related.
**W16 — Projects list filters** (§10) — **M**. City + status filters; bookmarks only if product wants them on mobile (web's are localStorage-only).
**W17 — Pull-to-refresh gaps** (§10) — **S**. Profile, Settings, Owner Analytics.
**W18 — `LEGACY_BUILDER_LISTING` redirect** (PA-9) — **S**. On that code, route to `/projects` with a toast instead of a generic error.
**W19 — Change-password parity** (PA-13) — **S**. Reuse `passwordSchema` on `settings/change-password`.
**W20 — Transactions pagination** (§10) — **S**. "Load more" on `/rewards` using the existing `pagination.totalPages`.

### P3 — polish

**W21** — Reward reveal theatre: port the spin-wheel/door split keyed on `rewardCategory` (PA-14). **M**
**W22** — Design-vocabulary alignment with the working tree: `basics.status` icon+colour map, tier icons (Medal/Trophy), highlight-chip length filter, reduced-motion audit. **S**
**W23** — Rewards marketing surface (pools/tiers explainer) or a deliberate decision to keep linking out. **M / decision**
**W24** — Universal links (`associatedDomains`, `intentFilters`, AASA) — folds into store readiness. **M**
**W25** — Contact form: wire `POST /contact` or confirm mailto is the intended terminal state. **S / decision**

---

## 2. Dependency order

```
W7 (types/registry)  ──►  W1 (booking)  ──►  W6 (unit depth)
                                        └──►  W4 (campaign gate)
W2 (delete-account)       independent
W3 (session teardown) ──►  W8 (guest guards)     [W8 reuses the teardown-vs-prompt distinction]
W9 (Sentry)               independent, wanted before any store build
W11 (WebView map) ──►  W5 map section            [W5 ships without the embed first]
W13 (listing form) after W7                       [shares the form types]
W10 (deploy check) gates any store release that advertises rent/sale
Phase 5 (tests) consumes the backend integration harness as its fixture source
```

## 2b. Status — 2026-08-22

| Item | State |
|---|---|
| W1 booking contract catch-up | **Done.** `intent:'enquiry'` CTA, `POST /bookings/:id/cancel`, actionable copy for `NO_INVENTORY` / `BOOKING_NOT_CONFIGURED` / `DUPLICATE_ENQUIRY`, `source` typed and read |
| W2 delete-account password | **Done.** Password sent, `INVALID_PASSWORD` as a field error, `retainedListings` surfaced |
| W3 global session teardown | **Done.** `setSessionFatalObserver`, guarded on status + auth-owned paths |
| W4 campaign gate | **Done.** `GROUP_BUY_ENABLED=false`, applied at the data layer |
| W7 types/registry catch-up | **Done.** Plus a defect found in passing: `UnitType.inventory` is `{totalUnits, availableUnits, …}`, not `{total, available}` — both read sites were permanently `undefined` |
| W8 guest guards | **Done.** New `RequireAuth` on `settings/sessions`, `settings/change-password`, `settings/delete-account`, `claim-reward/[verificationId]`; `useMyBookings` auth-gated for the two booking routes |
| W10 `listingType` deploy check | **Done — no risk.** Measured on production: 21 rent + 10 sale = 31 baseline. The param is live; the constraint is withdrawn |
| W9 crash reporting | **Not started.** Adds a native module, so it needs a rebuild and a mobile Sentry DSN |

Everything above is `dealdirect-mobile/` only, verified by `tsc --noEmit`, `expo lint` (0 errors) and `expo export`. **No flow has been exercised on a device or against a live API.**

## 3. Phases

**Phase 1 — Stop the bleeding (P0): W7, W1, W2, W3, W4.** ~1.5 weeks.
Exit: the audit's PA-1..PA-4 are closed; every booking/enquiry/cancel path verified against the local backend's integration-tested behavior; no join/exit reachable.

**Phase 2 — Guards, telemetry, deploy alignment (P1): W8, W9, W10.** ~0.5 week.
Exit: no guest 401 screens; Sentry live; release checklist carries the backend-first ordering note.

**Phase 3 — Projects render parity (P1): W5, W6.** ~1.5–2 weeks.
Exit: a buyer sees the same facts about a project and unit on mobile as on web, in mobile-native layout; builder contact info provably absent.

**Phase 4 — Owner tools and content quality (P2): W11–W20.** ~2 weeks.
Exit: no placeholder routes; blog readable; listing form validated end-to-end; leads exportable.

**Phase 5 — Verification and store readiness (M14): tests + device pass + W24 + P3 as capacity allows.** ~1.5 weeks.
Test requirements, in priority order:
1. **Contract suite** (jest + msw or fetch-mock): for every endpoint in `src/api/endpoints/*`, assert the request shape (method, path, params/body field names) and that the adapter parses a recorded fixture of the real envelope. Fixtures generated from the backend integration harness's known-good responses so the two suites cannot drift apart silently.
2. **Logic units**: refusal-code handling (W1), session teardown triggering rules (W3), `adaptPropertyDetail` normalization, `resolveNotificationTarget`, affordability math.
3. **One device smoke** (Maestro): login → search → detail → interest → owner lead appears → book/enquire → cancel. Run on a physical Android before every store submission.
4. **The HANDOFF §2.14 device checklist** executed once and recorded: payment screenshot round trip, offline cold start, permission chain, session survival across kill / WiFi↔cellular / version bump.

---

## 4. Reducing web↔mobile drift (lowest-risk path)

The repo has four apps, no monorepo tooling, and hand-duplicated types. A shared-package rewrite is not justified by the current failure mode, which is *silent contract drift after backend changes*, not duplicated effort. Three cheap mechanisms address it directly:

1. **A drift-check script in CI** (`backend/scripts/check-client-contracts.mjs`): parse the enum arrays out of `backend/models/*` and the route strings out of `backend/routes/*`, diff them against `dealdirect-mobile/src/api/endpoints/*` + `src/types/backend/*` (and optionally `client-next/src/utils/api.js`). Fail the build on a mismatch. Mobile's registry is string-literal and typed, so this is a few hundred lines of grep-and-compare, no runtime coupling, no deploy coupling.
2. **Fixture sharing**: the backend integration harness already produces real response bodies; export a `contracts/fixtures/` directory from a test run and point the mobile contract suite at it (Phase 5.1). One source of truth for envelope shapes.
3. **Process**: every `AI/CHANGELOG_AI.md` entry that changes an endpoint contract gains a mandatory line: `Mobile absorbed: yes/no/N-A`. The Aug-13→22 drift happened because nothing forced the question.

Explicitly not recommended now: npm workspace/monorepo consolidation (four independent Hostinger deploy repos make it operationally risky), runtime schema validation of every response (zod-parsing hot paths on low-end Android), and OpenAPI generation (the backend's six envelope shapes would fight the tooling more than help).

---

## 5. Decisions needed from Chirag

1. **Group buy (re-opens D4).** Web renders nothing; mobile has working membership. Options: (a) gate mobile's actions off until the mechanic's completion engine exists (W4, recommended — reversible, honest); (b) delete mobile's campaign surface to match web exactly; (c) accelerate the website group-buy redesign and treat mobile's wiring as the head start. W4 implements (a) either way.
2. **Contact**: wire `POST /contact` on mobile or keep mailto (W25).
3. **Rewards marketing surface** on mobile, or keep linking out (W23).
4. **Projects bookmarks** on mobile (web's are localStorage-only; parity may not be wanted) (W16).
5. **Store timeline**: if a submission is planned before Phase 3 completes, Phase 2's W9/W10 and the Phase 5 smoke become the minimum bar.

---

## 6. Target state

After Phases 1–5 the scorecard in the audit's §15 moves to: completion 9, logic parity 9, API parity 9.5, data model 9.5, navigation 8.5, UX 8.5, auth 9, security 8.5, performance 8, testing 6, error handling 9 — **overall 9 / 10**, with the remaining distance being the deliberately held features (chat, group buy, redemption) and deeper test coverage, each awaiting its own product decision rather than engineering effort.
