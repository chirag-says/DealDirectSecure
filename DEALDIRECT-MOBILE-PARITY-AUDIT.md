# DealDirect Mobile Parity Audit

Date: 2026-08-22. Code state: commit `b722dc3` plus the uncommitted working tree.
Reference implementation: `client-next/` as it stands today. Mobile under audit: `dealdirect-mobile/` (last mobile commit `982b85d`, 2026-08-15).
Method: four parallel read-only sweeps (client-next surface, mobile surface, backend contracts from `backend/routes/` + controllers + models, and the post-Aug-13 commit delta), then direct source verification of every disputed claim. No code, database, or environment was modified.

Companion documents: `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md` (the work items) and `DEALDIRECT-MOBILE-PAGE-MATRIX.csv` (one row per surface).

---

> **Status update, 2026-08-22 (later the same day).** Phase 1 (PA-1 to PA-4) and Phase 2 items W8/W10 have since been implemented in `dealdirect-mobile/` only. PA-8 was measured against production and disproved. The findings below are preserved as written — read them together with the top entry of [`AI/CHANGELOG_AI.md`](AI/CHANGELOG_AI.md), which records what changed. Device verification is still outstanding.

## 1. Verdict

The mobile app is not scaffolding. The `AI/` docs' "M1–M2 stubs" claim is stale by three months: mobile has ~30 routes, a typed endpoint registry mirroring the backend, careful cookie-session handling, drafts, offline read cache, and exactly one placeholder screen left (`property/[id]/map`). A full parity pass (waves W1–W5) landed 2026-08-13/14 and honored the four product decisions D1–D4.

The problem is what happened after. Seven backend/web commits since 2026-08-13 changed the projects and bookings contracts and rebuilt the project/unit pages, and **none of them touched a single mobile source file**. The drift is one-directional and entirely unabsorbed. On top of that, this audit found one mobile flow that is broken outright against the current backend (account deletion), one that will be refused on a large share of inventory (unit booking), and zero automated tests of any kind.

**Current mobile score: 6.5 / 10. Target after the roadmap: 9 / 10.** Full scorecard in §15.

The four highest-consequence findings:

| ID | Finding | Severity |
|---|---|---|
| PA-1 | `DELETE /users/me` requires `{password}`; mobile sends no body. Account deletion always returns 400 `PASSWORD_REQUIRED`. App Store review requires a working deletion path. | P0 |
| PA-2 | `POST /bookings` grew an `intent:"enquiry"` path and three new refusals (`BOOKING_NOT_CONFIGURED`, `NO_INVENTORY`, 409 `DUPLICATE_ENQUIRY`). Mobile sends no intent, has no enquiry CTA, and handles none of the refusals; on unit types with no `paymentTerms.bookingAmount` every mobile booking is refused where web now offers a working enquiry. `POST /bookings/:id/cancel` exists and is wired on web; mobile has no cancel at all. | P0 |
| PA-3 | No global 401 handling on mobile. A revoked session surfaces as scattered `ErrorState`s while the app keeps rendering as signed-in. | P0 |
| PA-4 | The web deleted every group-buy render (commit `79461c3`) because no code honors the discount; mobile still exposes campaign join/exit and payment-proof upload. Mobile is the only client offering group-buy membership. Held on decision D4. | P0 decision |

---

## 2. Product decisions that frame this audit

These are locked decisions (Chirag, 2026-08-13, recorded in `dealdirect-mobile/docs/HANDOFF.md` §9 and `AI/CHANGELOG_AI.md`). Divergences that implement them are classified INTENTIONAL, not gaps.

- **D1 — Agreements withdrawn** on both platforms. Web `/agreements` calls `notFound()`, backend mount commented out, mobile deleted its routes. Both clients keep dead API clients on disk with explanatory headers. Aligned.
- **D2 — Chat unmounted** on both platforms, code kept on disk. The backend now additionally gates `/api/chat/*` and every Socket.IO handler on `CHAT_ENABLED`, which no env file sets: sockets connect and receive nothing. Both clients must treat chat as absent. Aligned (mobile's `chat` tab is registered with `href: null`; `SocketProvider`/`PushBridge` are not mounted).
- **D3 — Rewards redemption is a separate workstream.** Mobile is display-only and links out to the website for redemption. Aligned.
- **D4 — Group buy on hold** until the website's own group-buy work settles. See PA-4: the two clients have since diverged in opposite directions and the hold needs a re-decision.

Two operational facts also frame everything:

- **Deploys are per-app Hostinger git imports of `origin/main`**, so backend, web, and mobile ship independently and deploy order matters. The `listingType` search param mobile already sends is committed locally but its deployment state on `backend.dealdirect.in` must be confirmed before the mobile rent/sale toggles mean anything in production.
- **Mobile auth is cookie-only by construction.** The backend mints no API bearer token; sessions are fingerprinted from the User-Agent and revoked on OS-family or device-type drift. Mobile correctly pins a constant UA per platform, puts the app version in `X-App-Version`, and never sends an `Origin` header (which is also what exempts it from the 16 CSRF-guarded routes, bookings included). These are invariants; do not "fix" them.

---

## 3. Client-next product inventory (the reference)

28 reachable routes (29 `page.js` files; `/agreements` 404s by design). Protection is edge `middleware.js` + per-page guards; there is no `ProtectedRoute` component.

| Route | Purpose | Access | Primary API calls |
|---|---|---|---|
| `/` | Landing: hero search, popular properties, builder projects, cities, blog teasers | public | SSR: `/properties/property-list`, `/categories/list-category`, `/propertyTypes/list-propertytype`, `/blogs?limit=3`, `/projects?limit=8`. Client: `/properties/suggestions` |
| `/properties` | Canonical browse/search/filter, list + Leaflet map view, compare (max 3, same type), save-search | public | `/properties/search` (param `search`, `categoryName`/`propertyTypeName`, `listingType`, price bounds), `/properties/suggestions`, `POST/DELETE /properties/interested/:id`, `POST /saved-searches` |
| `/properties/[id]` | Conversion screen: gallery, EMI calc (sale only), interest, report, share | public (actions auth-gated) | SSR `/properties/:id` (bare object). Client: `interested/:id/check`, `POST/DELETE interested/:id`, `POST /:id/report` |
| `/add-property` | 6-step listing creation, categorized images, Leaflet location picker | owner/agent (buyer → upgrade modal) | `POST /properties/add` multipart, taxonomy lists, Nominatim |
| `/edit-property/[id]` | 6-step edit via owner-scoped read | owner/agent | `GET/PUT /properties/my-properties/:id` |
| `/my-properties` | Owner hub: listings, leads (7-day range filter, XLSX export), analytics, close-deal | owner/agent | `/properties/my-properties`, `/leads`, `/leads/analytics`, `/leads/export`, `PUT /leads/:id/status`, `POST /leads/:id/contact`, `POST /properties/:id/close-deal` |
| `/saved-properties` | The interested list (there is no separate favorites concept) | protected | `GET /properties/saved`, `DELETE /properties/saved/:id` |
| `/projects` | Builder project cards, city/status/search filters, localStorage bookmarks, Group Buy badge on cards | public | SSR + client `GET /projects` |
| `/projects/[id]` | Project detail with the Aug-22 render pack: Leaflet map + connectivity chips, RERA number linked to the state register, construction-updates timeline, documents (CC/OC/approvals), bank approvals, developer profile, master-plan viewer | public | SSR `/projects/:id`, `/unit-types/project/:id`, `/campaigns/project/:id` (campaigns fetched, deliberately unrendered) |
| `/projects/[id]/units/[unitTypeId]` | Unit detail: cost sheet (GST/stamp/registration), specs tabs, floor plans, video tour link, brochure, inventory + tower allocation; **two CTAs**: Book This Unit (4-step UPI flow) and Enquire (no payment, `intent:'enquiry'`) | public (CTAs auth-gated) | SSR unit/campaigns/project. Client: `/bookings/payment-config`, `POST /bookings`, `POST /bookings/:id/payment` |
| `/my-bookings` | Booking list, 3-step progress, resubmit after rejection, **self-cancel** from `enquiry`/`payment_submitted` | protected | `GET /bookings/my`, `POST /bookings/:id/payment`, `POST /bookings/:id/cancel` |
| `/rewards` | Marketing page: pools, tiers, FAQs (hardcoded economics matching the backend) | public | none |
| `/rewards/dashboard` | Wallet, tiers, referrals, transactions, Hubble redemption iframe | protected | `/rewards/wallet`, `/rewards/referral-code`, `/rewards/transactions`, `/rewards/hubble/config` + `/token` |
| `/rewards/terms` | Static terms | public | none |
| `/notifications` | List, mark read/all, inline deal-reward claim → reveal game | protected | `GET /notifications`, `PATCH /:id/read`, `PATCH /mark-all/read`, `POST /properties/claim-deal-reward/:verificationId` |
| `/profile` | Profile edit (image crop), change password, delete account (`DELETE-<email>` phrase + password) | protected | `GET/PUT /users/profile`, `PUT /users/change-password`, `DELETE /users/me` |
| `/login` | Login + forgot/reset (phone OTP) + pending-interest completion | public | `POST /users/login`, `/users/forgot-password {phone}`, `/users/reset-password` |
| `/register` | Buyer (`register-direct`, instant session) vs owner (`register` → SMS OTP keyed by email) | public | `POST /users/register-direct` or `/users/register` + `/users/verify-otp` |
| `/blog`, `/blog/[slug]` | API-driven blog, markdown rendering, TOC, related, JSON-LD | public | `GET /blogs`, `GET /blogs/:slug` |
| `/contact` | Auth-gated inquiry form | protected in practice | `POST /contact {subject, message, category}` |
| `/about` `/why-us` `/privacy` `/terms` `/faq` `/press-impressions` `/coming-soon` | Static content | public | none |

Cross-cutting web features: `EmailVerificationModal` (phone-OTP buyer→owner upgrade), `RewardRevealRouter` (spin wheel for posting/enquiry pools, door game for sale pool), `CloseDealModal`, compare, save-search creation (no management UI), press marquee. Chat and agreements exist as dead code.

---

## 4. Mobile product inventory

~30 routes under expo-router. Guarding is per-screen (`OwnerOnly` on the six owner routes, `SignInPrompt` in-screen elsewhere); there is no route-level auth guard and no global 401 teardown. Stack: TanStack Query 5 with MMKV persistence (24 h, chat excluded), zod schemas mirroring backend validation character-for-character, SecureStore cookie mirror, FlashList, Reanimated.

| Route | Purpose | State |
|---|---|---|
| `/(tabs)` Home | Discovery surface: hero search, popular rail, project rail, collections, city grid, tools; deferred mounting (`Reveal`) as rate-limit defence | Complete |
| `/(tabs)/properties` | Canonical search: infinite feed on `/properties/search`, client-only filters for city/type/furnishing/possession/BHK (documented workarounds for corrupt taxonomy refs), compare mode, save-search sheet | Complete (no map view) |
| `/(tabs)/saved` | Interested segment + saved-searches management (toggle alerts, delete, run) | Complete; ahead of web |
| `/(tabs)/profile` | Account hub, wallet teaser, owner cards, upgrade sheet, theme | Complete |
| `/property/[id]` (+ `gallery`) | Detail with section nav, EMI, enquiry sheet with consequence copy, report, reward reveal; `staleTime: Infinity` to avoid inflating the view counter | Complete |
| `/property/[id]/map` | Location map | **Placeholder** (only one left; nothing links to it) |
| `/projects`, `/projects/[id]` | List with search + category chips; detail with gallery, basics, amenities, unit rows | Complete against the pre-Aug-22 web; far behind the render pack |
| `/projects/unit/[unitTypeId]` | Unit detail + booking sheet (auth-gated, prefilled) | Works only where `bookingAmount` is configured; see PA-2 |
| `/projects/booking/[bookingId]`, `/projects/bookings` | Payment submit (UTR + screenshot, resubmit after rejection), list | No cancel; guest sees a 401 error, not a sign-in prompt |
| `/projects/campaign/[campaignId]` | Group-buy membership: join/exit, payment proof, member counts. Deliberately does not render `discountPerBuyer`/`minBuyers`/perks (D4 hold) | Held; see PA-4 |
| `/owner/properties`, `/owner/property/new`, `/owner/property/[id]/edit` | Listing management: 7-step form, per-keystroke draft, image compression (1600 px / q0.7), close-deal sheet with derived closing type | Complete; field set narrower than web |
| `/owner/leads`, `/owner/leads/[id]`, `/owner/analytics` | Lead pipeline, status transitions, contact logging, 30-day analytics | Complete; no date filter, no XLSX export |
| `/rewards`, `/claim-reward/[verificationId]` | Wallet, tier progress, transactions (one page of 50), referrals, auto-claim screen | Complete display-only (D3) |
| `/notifications` | List, optimistic read, hardened target resolution (never follows `actionUrl` blindly) | Complete |
| `/settings` + `sessions` / `change-password` / `delete-account` | Inline profile editor, session revocation, password change, deletion | Deletion broken (PA-1) |
| `/blog`, `/blog/[slug]` | Infinite list; detail strips HTML to plain paragraphs | Complete; detail loses formatting |
| `/tools/emi`, `/tools/affordability` | Local calculators; affordability deep-links into search by price band | Complete; mobile-only |
| `/support` | Static FAQ, mailto/tel, legal links to the website | Complete |
| `/chat/*` | Fully built, deliberately dark (D2) | Withheld |

Tests: none (no test dependency, no config, no test script beyond `tsc --noEmit`). Everything from M7 onward is untested on a physical device per `HANDOFF.md` §2.14.

---

## 5. Master parity matrix

Coverage is against the **current** client-next working tree. "INTENTIONAL" marks decided divergence, not debt. Full per-column detail is in the CSV; this table is the judgment.

| ID | Client-next surface | Mobile equivalent | Coverage | Classification | Priority |
|---|---|---|---|---|---|
| 01 | `/` home | `/(tabs)` | 80–99% | MATCHED (deliberate mobile-native redesign) | P3 |
| 02 | `/properties` list + map | `/(tabs)/properties` | 80–99% | PARTIAL (no map view, no pin-drop radius) | P2 |
| 03 | `/properties/[id]` | `/property/[id]` | 80–99% | MATCHED (location map is the one gap; mobile's report flow works, web's is broken) | P2 |
| 04 | `/add-property` | `/owner/property/new` | 50–79% | PARTIAL (narrower field set, no commercial field matrix, no location picker, no video URL) | P1 |
| 05 | `/edit-property/[id]` | `/owner/property/[id]/edit` | 50–79% | PARTIAL (same gaps; address line/state/pincode uneditable is a server limitation both share) | P2 |
| 06 | `/my-properties` (3 tabs) | `/owner/properties` + `/owner/leads` + `/owner/analytics` | 80–99% | MATCHED (no lead date filter, no XLSX export) | P2 |
| 07 | `/saved-properties` | `/(tabs)/saved` | 100% | MATCHED — mobile is ahead (saved-search management web lacks) | — |
| 08 | `/projects` | `/projects` | 50–79% | PARTIAL (no city/status filters, no bookmarks, no Group Buy badge) | P2 |
| 09 | `/projects/[id]` | `/projects/[id]` | 1–49% | INCORRECT vs current web (entire Aug-22 render pack missing: map, RERA number, construction timeline, documents, bank approvals, developer block, master plan) | P1 |
| 10 | `/projects/[id]/units/[unitTypeId]` | `/projects/unit/[unitTypeId]` | 1–49% | INCORRECT (no enquiry CTA, no cost sheet, no specs/brochure/inventory/tower/video; booking refused where web enquires) | **P0** |
| 11 | `/my-bookings` | `/projects/bookings` + `booking/[bookingId]` | 50–79% | PARTIAL (no self-cancel, new refusal codes unhandled, guest guard missing) | **P0** |
| 12 | `/agreements` | — | — | INTENTIONALLY WITHDRAWN (D1, both platforms) | — |
| 13 | `/rewards` marketing | — (links out) | 0% | WEB-ONLY | P3 |
| 14 | `/rewards/dashboard` | `/rewards` | 80–99% | MATCHED (display-only per D3; no spin-wheel port; single transactions page) | P3 |
| 15 | `/rewards/terms` | web link from `/support` | — | INTENTIONALLY DIFFERENT | — |
| 16 | `/notifications` | `/notifications` | 100% | MATCHED (mobile's target resolution is safer) | — |
| 17 | `/profile` | `/(tabs)/profile` + `/settings/*` | 80–99% | PARTIAL (**deletion broken** PA-1; no image crop; DOB free text) | **P0** |
| 18 | `/login` (+forgot/reset) | `/(auth)/login` etc. | 100% | MATCHED (mobile error taxonomy is better) | — |
| 19 | `/register` (+OTP) | `/(auth)/register` + `verify-otp` | 100% | MATCHED | — |
| 20 | `/blog`, `/blog/[slug]` | `/blog`, `/blog/[slug]` | 50–79% | PARTIAL (detail strips HTML: links, emphasis, inline images lost) | P2 |
| 21 | `/contact` | `/support` (mailto) | 0% | INTENTIONALLY DIFFERENT — needs a confirmation that mailto is the intended terminal state (`POST /contact` is declared and unwired on mobile) | P3 |
| 22 | Static pages (about/why-us/privacy/terms/faq/press/coming-soon) | `/support` + web links | — | INTENTIONALLY DIFFERENT | — |
| 23 | Chat (dark on web) | Chat (dark on mobile) | — | INTENTIONALLY WITHHELD (D2) | — |
| 24 | Group-buy (web: deleted renders) | `/projects/campaign/[campaignId]` (join/exit live) | — | **MOBILE-ONLY, CONTRADICTS WEB** — needs decision (D4) | **P0 decision** |
| 25 | EMI inline on detail | `/tools/emi` + `/tools/affordability` | — | MOBILE-ONLY (superset; good) | — |
| 26 | Claim reward (inline in notifications) | `/claim-reward/[verificationId]` | 100% | MATCHED (different mechanics, same contract) | — |

Tally: 6 at 100%, 6 at 80–99%, 5 at 50–79%, 2 at 1–49%, 2 at 0% (both intentional), 4 intentionally withheld/different, 2 mobile-only surfaces.

---

## 6. Logic parity findings (the register)

Severity marks the user-visible consequence today, against the current backend.

### Broken or refused flows

- **PA-1 (P0) — Account deletion always fails.** `app/settings/delete-account.tsx` collects only the typed word `DELETE`; `useDeleteAccount` (`src/features/profile/hooks.ts:146`) calls `DELETE /users/me` with no body. `userController.deleteAccount` requires `{password}` and returns 400 `PASSWORD_REQUIRED`, then 401 `INVALID_PASSWORD` on a wrong one. The web collects the phrase and the password. Mobile must add a password field (and should adopt the web's `DELETE-<email>` phrase for consistency).
- **PA-2 (P0) — Booking flow is behind the contract.** Four sub-findings:
  1. Mobile `POST /bookings` (`src/features/projects/*`) sends no `intent`; every submission is `source:"booking"` and is refused with 400 `BOOKING_NOT_CONFIGURED` on any unit type without `paymentTerms.bookingAmount > 0`. Web offers "Enquire — no payment needed" on exactly those units.
  2. No handling for 400 `NO_INVENTORY` or 409 `DUPLICATE_ENQUIRY` (one open booking per user per unit type across `enquiry|payment_submitted`); the user sees a raw error with no path forward.
  3. `POST /bookings/:id/cancel` (user self-withdraw from `enquiry`/`payment_submitted`, response carries `refundMayBeDue`) is absent from the mobile endpoint registry entirely. Web wires it with a two-step confirm and refund warning.
  4. The create response now carries `source`; mobile does not read it, and `ProjectBooking.source`/`contactHistory`/`assignedTo` are missing from mobile types (§8).
- **PA-3 (P0) — No global session teardown.** `src/api/client.ts` installs only a cookie-mirroring observer. Session-fatal 401s are handled inside `AuthProvider` for `fetchMe`/`restore`/`establishSession`/`refreshUser` only. A session revoked mid-run (password change elsewhere, fingerprint revocation, admin block) leaves the app rendering as signed-in with every authenticated screen showing a generic `ErrorState`. Web centralizes this in an axios interceptor → `onAuthError`.
- **PA-4 (P0 decision) — Group buy: the clients now contradict each other.** Web (commit `79461c3`) deleted the campaign banner, `CampaignCard`, the discounted price, and the progress bar because nothing applies the discount. Mobile kept a live membership surface: join, exit (with `CAMPAIGN_MEMBER_PAYMENT_PROTECTED` handling), payment-proof upload, member counts. To mobile's credit it deliberately renders no `discountPerBuyer`, no `minBuyers` progress, and no perks (so it advertises no price promise), but it still lets users join and pay into a mechanic with no completion engine. D4 said hold; the hold has decayed into divergence. Options in the plan (§5 of the plan doc).

### Behavioral divergences (working, but different)

- **PA-5 (P1) — Projects render pack.** Everything in commit `d5c25aa` exists only on web: location map + connectivity chips, RERA number linked to the state register (a ratified compliance decision, 2026-08-22), construction-updates timeline (called "the single strongest trust feature" in the authoring-pipeline doc), documents incl. CC/OC, bank approvals, developer profile (with the enforced rule that builder phone/email never render), master-plan `object-contain` viewer, unit video-tour link. Mobile's project detail predates all of it.
- **PA-6 (P1) — Unit page depth.** Web renders an all-inclusive cost sheet (GST + stamp duty + registration, additive, never folded into `effectivePrice`), specs tabs, brochure, inventory/tower allocation, price breakdown with `additionalCharges`. Mobile renders price, floor plan, sold-out state, booking sheet.
- **PA-7 (P1) — Project visibility semantics changed under mobile.** Public reads are now filtered by `publication.status === "published"` (with a legacy fallback); new projects default to draft and are invisible. Mobile still works (the filter is server-side) but its code comments claim "active-only view", its types have no `publication`, and any cached draft-turned-unpublished project will 404 on refetch with no special copy. Also `GET /projects` `limit` is now clamped to 60 (mobile sends 10/20, fine; web's own `limit=100/200` requests silently truncate, a web bug).
- **PA-8 — RESOLVED 2026-08-22, no action needed.** The concern was that mobile sends `listingType` on every Buy/Rent search while the param might not be deployed. Measured directly against production (`GET /api/properties/search`, read-only): baseline **31**, `listingType=rent` **21**, `listingType=sale` **10**, `listingType=nonsense` **31**. 21 + 10 = 31 is an exact partition, and an unrecognised value degrades to "no filter" rather than "no results". **The param is live on `backend.dealdirect.in`** and mobile's rent/sale toggle works in production today. No deploy ordering constraint remains.
- **PA-9 (P2) — Interest on legacy builder listings.** `POST /properties/interested/:id` now returns 400 `LEGACY_BUILDER_LISTING` with `redirectTo:"/projects"`. Mobile's feed excludes builder listings so the path is deep-link-only, but the code shows a generic error instead of routing to projects.
- **PA-10 (P2) — Property `status:'inactive'` now genuinely hides listings** (the hidden-status list changed to `['pending','inactive']`). Mobile's 24 h persisted cache can hold items that 404 on refetch; the detail screen's "Listing no longer available" empty state covers it, but recently-viewed and saved rails will render stale cards until tapped.
- **PA-11 (P2) — Listing form validation is thinner than web.** Web's add flow validates per step (BHK requirements, exterior-photo minimum, finite price); mobile gates only 4 of 7 steps, has no final pre-submit validation, `availableFrom` is unvalidated free text, and there is no zod schema for the form. Neither client compensates for the backend's commented-out `validatePropertyCreate` (B13), so mobile must validate values itself.
- **PA-12 (P2) — Owner leads: no date-range filter, no XLSX export** (`GET /leads/export` is declared, never called; it must send `sessionHeaders()` if wired). Web caps the range filter at 7 days and offers the 3-month export.
- **PA-13 (P3) — Change-password validation weaker than backend on both clients**, differently: mobile checks length ≥8 + match (missing the four character classes); web's profile page checks length ≥6. Backend enforces 8 + four classes. Mobile already owns the correct `passwordSchema` (used in register/reset); reuse it.
- **PA-14 (P3) — Reward reveal is minimum-viable on mobile.** Web routes `rewardCategory` to a spin wheel (posting/enquiry pools) or a three-door game (sale pool); mobile shows a single `RewardReveal`. Same contract, less theatre. Deliberate scope cut (F11), now a polish item.

---

## 7. API parity

Mobile's endpoint registry (`src/api/endpoints/*`) was verified string-by-string against `backend/routes/`. It is the most accurate client contract in the repository: methods correct (PATCH for notifications where web's dead helper still says PUT), `search` vs `q` correct per endpoint, envelope kinds annotated per endpoint (the backend has six incompatible shapes; per-endpoint adapters are the right and only strategy, as both the mobile plan and the backend audit concluded independently).

Gaps and staleness:

| Item | Detail |
|---|---|
| Missing endpoint | `POST /bookings/:id/cancel` — not declared (PA-2) |
| Missing request field | `POST /bookings` `intent` — not sent (PA-2) |
| Missing request field | `DELETE /users/me` `{password}` (PA-1) |
| Unhandled refusals | `NO_INVENTORY`, `BOOKING_NOT_CONFIGURED`, `DUPLICATE_ENQUIRY`, `LEGACY_BUILDER_LISTING` (+`redirectTo`), `CAMPAIGN_HAS_PAID_MEMBERS` (admin-facing, low) |
| Dead declarations | `GET /rewards/store` and `POST /rewards/redeem` (removed server-side 2026-08-01), `GET /subcategories/list` (unmounted), `GET /properties/filter` (410 retired). None are called; delete the declarations so the registry stays truthful |
| Response drift | `GET /projects` pagination gained `limit`; create-booking response gained `source`. Harmless today, type them |
| Envelope trap honored | `GET /properties/:id` bare object, `/search` no `success` key, `/list` bare array — all correctly adapted on mobile |

Web-side API debt recorded for completeness (not mobile's problem, but parity means both clients against one backend): `propertyApi.search` still sends `q` (B19) and `notificationApi` still uses PUT paths (B20); both helpers are unused but misleading; the Navbar autocomplete fetches the entire `property-list` per keystroke instead of `/properties/suggestions`.

---

## 8. Data-model parity

Mobile types (`src/types/backend/*`) verified against `backend/models/`:

**Correct and current:** lead statuses and the transition table, booking `payment.status`, campaign member semantics, property status/listingType (all six spellings normalized to a two-value intent), rewards wallet shape (six keys, no `balance` — the F1 fix), suggestion objects, saved-search filter whitelist (five persisted keys, dead ends documented), the 22-value `BackendErrorCode` union, user roles (`user`/`buyer` equivalence).

**Stale or missing:**

| Entity | Missing on mobile | Consequence |
|---|---|---|
| `Project` | `publication{status, publishedAt, publishedBy, checklistAtPublish}`, `views` | Type-only today (public API pre-filters); blocks any future "draft" badge and leaves stale comments |
| `ProjectBooking` | `source ("enquiry"|"booking")`, `contactHistory[]`, `assignedTo` | Cannot distinguish an enquiry from a booking in `My bookings`; web now can |
| `GroupBuyCampaign` | `discountPerBuyer` typed `unknown`, statuses typed `string` | Loose by choice during the D4 hold; tighten when decided |
| `LeadAnalytics` | `conversionRate` typed `number`, arrives as a string (`toFixed(1)`) | Coerced at the call site; fix the type |

Web's data-model errors mobile must not import: `PropertyJsonLd` passes an object as `floorSize.value`; the deleted `normalizePrice` multiplied rupees by 1e5 on `priceUnit:"Lac"` (B29; both clients now treat `price` as rupees, keep it that way); ObjectId taxonomy filters are banned on both clients until the production refs are backfilled (B28) — mobile's client-side `categoryName` matching is the documented workaround.

---

## 9. Navigation parity

- **Unguarded authenticated routes (mobile):** `settings/sessions`, `settings/change-password`, `settings/delete-account`, `projects/bookings`, `projects/booking/[bookingId]`, `claim-reward/[verificationId]`, `chat/[conversationId]`. All render for a guest and fail at the request; `projects/bookings` shows a 401 `ErrorState` instead of a `SignInPrompt`. The owner routes are properly wrapped (`OwnerOnly`, documented as usability not security, which is correct since the server enforces ownership).
- **Deep links:** scheme `dealdirect://` covers every filesystem route, including the dark `chat/*` (accepted residue per D2) and `(dev)/gallery` (renders nothing in release). No universal links (`associatedDomains`/`intentFilters` absent) — M12's unfinished half. Notification routing never follows server `actionUrl` blindly (24-hex validation + path extraction), which is stricter than web.
- **Back behavior:** `ScreenHeader` falls back to `/(tabs)` when the stack is empty; five routes ship no `backTo` (notifications, three settings screens, claim-reward), acceptable but worth an audit pass when adding universal links.
- **Web navigation defects (do not copy):** `/settings` in `PROTECTED_ROUTES` with no such route; `/rewards/dashboard` redirects with `?redirect=` while everything reads `from` (return-to-page lost); `logout()`'s redirect list omits `/my-bookings` and `/rewards/dashboard`; `/why-us` and `/rewards` reachable only from the footer.

---

## 10. UX parity

Where mobile is deliberately different and better: consequence-before-action enquiry sheet, geometry-matched skeletons, section-registry jump nav on property detail, deferred below-fold mounting, safe notification routing, the affordability tool feeding search by price band, draft resume on the listing form, derived close-deal outcome (a sale listing cannot be closed as "rented" — web derives it too).

Where mobile reads as unfinished against the web:

| Surface | Gap |
|---|---|
| Project detail | The entire render pack (PA-5); this is now the widest visual gap in the product |
| Unit detail | Cost sheet, specs, brochure, inventory (PA-6) |
| Blog article | HTML stripped to plain paragraphs: links, bold, inline images gone |
| Property location | Map screen is the last placeholder; web shows an embedded map |
| Pull-to-refresh | Missing on Profile, Settings, Owner Analytics (`Refreshable` mounted with no `onRefresh`) |
| Transactions | One page of 50, no pagination control (web paginates) |
| Projects list | No bookmarks, no city/status filters |
| Design vocabulary | The working tree's status-icon system (icon + colour per `basics.status`), reduced-motion CSS, and highlight-chip length filtering are web-only; mobile should mirror the vocabulary, not the markup |

Offline/network: mobile is ahead of web (offline banner, 24 h read cache, retry taxonomy, rate-limit-aware copy with `retryAfterSeconds`, per-feature duplicate-tap guards). No offline write queue, mutations never retry (correct: the backend has no idempotency keys).

---

## 11. Security

- Mobile's posture is sound: SecureStore-only session cookie (`WHEN_UNLOCKED_THIS_DEVICE_ONLY`), no token in logs or JS-readable storage, constant User-Agent per platform (fingerprinting invariant), version in `X-App-Version`, no `Origin` header ever (the binding constraint documented in `client.ts`: no API call may originate from a WebView, or the 16 CSRF-guarded routes 403). The map implementation (Leaflet in WebView) must keep its WebView strictly non-API.
- `OwnerOnly` being advisory is fine; every owner mutation re-checks ownership server-side.
- Missing: any crash/error reporting. Web ships Sentry with a PII-scrubbed user (`id` + `role` only, working-tree change); mobile has nothing. A store release with zero telemetry repeats the mistake that let B2 sit broken unnoticed.
- Web-side items surfaced in passing (recorded, not mobile scope): `.env.production` contains a committed `SENTRY_AUTH_TOKEN` (rotate, move to CI); the Hubble `appSecret` travels to the browser in a URL query string; chat's stored-XSS in `lastMessage.text` (B3) must be fixed before `CHAT_ENABLED` is ever set.

---

## 12. Performance

- Home fires three byte-identical `GET /properties/search?limit=100&sort=newest` requests under three cache keys (`popular`, `city-counts`, `related-pool`); the detail screen's similar-rail shares the third. One shared pool query would remove two requests per cold home view against a 20/min rate limit.
- The `limit=100` bounded-pool pattern (client-only filters, related, city counts) is the honest response to "only `/search` is paginated"; it is O(corpus) and will need revisiting past ~500 live listings — same ceiling the web hits with `property-list`.
- Good: deferred section mounting, MMKV rehydration before first paint, FlashList, `staleTime: Infinity` on detail to keep the view counter honest, prefix invalidation on refresh.
- Web-side: SSR list payload is fetched then immediately discarded by the client refetch on `/properties`; Navbar suggestions fetch the full corpus per keystroke; `console.log` ships in the list render path.

---

## 13. Testing

| Surface | State |
|---|---|
| Backend | Real coverage since Phase 3A: 471 unit tests, 30+ integration suites on an in-memory replica set (publish gate, funnel/inventory, booking hardening incl. CSRF scope and UTR reuse, media lifecycle), mutation harnesses reporting 0 survivors |
| client-next | Source-text assertion suites only (with comment stripping); nothing renders a component tree |
| Admin | Zero |
| **Mobile** | **Zero. No framework, no config, no script.** Verification to date: `tsc --noEmit`, `expo lint`, `expo export`. Device verification: none since M7 (HANDOFF §2.14 lists the untested surfaces: payment round trip, cache rehydration offline, permission chain, session survival across kill/network-switch/version bump) |

The backend integration harness is the contract oracle mobile lacks. The plan (§Phase 5) specifies a mobile contract-test layer that asserts request shapes and envelope parsing per endpoint against recorded fixtures, plus one end-to-end smoke on a device farm. Until then every mobile release is verified by hand or not at all.

---

## 14. Web defects mobile must not copy (and web should fix)

Recorded so the "reference implementation" is not treated as gospel:

1. Report-property modal unreachable on most listings (`PropertyDetailsContent.jsx:1455` nested inside the `address?.nearby` conditional). Mobile's report sheet works.
2. `/rewards/dashboard` login redirect uses `?redirect=`, everything reads `from`.
3. Hero `types`/`possession`/`furnishing` filters parsed and never forwarded (silent no-ops).
4. Profile password change validates ≥6 chars against a backend requiring 8 + four classes.
5. `logout()` redirect list omits `/my-bookings` and `/rewards/dashboard`.
6. `GET /bookings/payment-config` called for guests (silent 401 per visitor).
7. `imageCategoryMap` has two incompatible shapes between add (object) and edit (array), with different file field names. Mobile mirrors this faithfully because the backend demands it; the backend is the right place to unify.
8. Stale `utils/api.js` helpers: `q` param (B19), PUT notification paths (B20), `forgotPassword {email}` vs the real `{phone}` flow, six dead agreement helpers.
9. `PropertyJsonLd` object-valued `floorSize`; Organization `sameAs` URLs disagree with the footer's socials.
10. Navbar suggestions fetch the entire property list per keystroke.
11. `/projects` requests `limit=100/200` against a backend now clamping to 60 (silent truncation of the SSR SEO block and the client list).
12. Committed `SENTRY_AUTH_TOKEN` in `client-next/.env.production`.

---

## 15. Scorecard

| Dimension | Score /10 | Basis |
|---|---|---|
| Overall mobile completion | 6.5 | One placeholder screen, two broken flows, one contract wave unabsorbed |
| Page coverage | 8 | 24 of 28 web surfaces represented; the intentional absences are decided, not forgotten |
| Business logic parity | 6 | PA-1..PA-4 outstanding; everything else traced and matching |
| API parity | 6.5 | Registry accurate but missing the Aug-22 wave (cancel, intent, refusal codes) |
| Data-model parity | 7 | Typed and mostly current; `publication`/`source`/`contactHistory` missing |
| Navigation | 6.5 | Sound structure; seven unguarded routes, no universal links |
| UX | 7 | Strong system; projects vertical and blog detail visibly behind |
| Authentication | 7.5 | Careful cookie lifecycle; no global 401 teardown (PA-3) |
| Security | 8 | Correct invariants throughout; no telemetry |
| Performance | 6.5 | Good discipline; triple-fetch on home; O(corpus) pool pattern |
| Testing | 0.5 | Zero automated tests; typecheck and lint only |
| Error handling | 7 | Best error taxonomy of the three clients; new refusal codes unhandled |

**Current mobile score: 6.5 / 10.**
**Target after the roadmap in `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md`: 9 / 10** (testing rises to ~6 with the contract suite and one device smoke; logic and API parity to 9+; the residual gap is the deliberately held features: chat, group buy, redemption).
