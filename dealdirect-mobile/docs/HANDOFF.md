# Mobile app — handoff

Written 2026-08-05, updated 2026-08-07 (M7-M9), updated 2026-08-07 (M11-M13,
M10 skipped for now), updated 2026-08-08 (M15-M22 scoped from a feature-parity
audit against the website, same day M15–M17 were implemented — see §8),
**updated 2026-08-13 (§9: four product decisions D1–D4, the full defect
register from a four-way source sweep, and the wave roadmap that supersedes
§4's and §8's ordering)**, updated 2026-08-14 (§10: the portal-parity UI pass —
what was measured on Housing.com, Square Yards and 99acres, what changed on
search, the card, detail and home, and what was deliberately not copied).
Point a new session at this file first, then
[`../README.md`](../README.md) and [`API_CONTRACT.md`](API_CONTRACT.md).

> **Read [`HANDOFF_AUDIT_2026-08-09.md`](HANDOFF_AUDIT_2026-08-09.md) before
> trusting anything below about auth, agreements, or rewards redemption.** An
> auth-flow audit on 2026-08-09 found that password reset, the OTP-delivery
> copy, buyer registration and referral attribution were all built from
> `client-next/src/utils/api.js`'s **unused** helpers rather than from the pages
> that actually run, and are broken on the wire. It also found that the backend
> in this working tree differs from the one deployed at `origin/main` on three
> surfaces the app depends on. Where that file disagrees with this one, it is
> right; the corrections it lists are inlined below at each affected claim.

The plan of record is [`../../MOBILE_APP_ARCHITECTURE_PLAN.md`](../../MOBILE_APP_ARCHITECTURE_PLAN.md),
which defines milestones M0–M14. This file says where we actually are against
it. **M15–M22 (below, §8) are not in that document** — they were scoped
2026-08-08 from a direct website-vs-mobile feature audit and extend the plan
rather than amend it. Treat §8 as the plan of record for that range until it
is folded into the architecture doc. **M15, M16 and M17 are done** (M16/M17
each minus one map-related item still blocked on the M4 dev-client rebuild,
§5.1); M18–M22 remain scope only.

---

## 1. Status in one table

| Milestone | Scope | State |
|---|---|---|
| M0 | Contract lock, tokens, toolchain | **done** |
| M1 | App shell, navigation, design system | **done** |
| M2 | Transport + authentication | **done** |
| M3 | Property discovery (search, filters, infinite scroll) | **done** |
| M4 | Property detail, gallery, map | **detail, gallery, attributes done. Map held** (§2.5) |
| M5 | Favorites, saved searches, notifications | **done** (§2.6) |
| M6 | Chat | **built; entry points being unmounted** — product decision 2026-08-13, §9.1 D2 |
| M7 | Profile, settings, rewards | **done** (§2.9) |
| M8 | Owner mode: listings and uploads | **done** (§2.10) |
| M9 | Leads and analytics | **done** (§2.11) |
| M10 | Agreements | **withdrawn from the product**, not merely skipped — see audit §4.2 |
| M11 | Projects, units, campaigns, bookings | **done** (§2.12) |
| M12 | Deep linking, offline, performance | **core pieces done** (§2.13) |
| M13 | Push notifications | **client-side/local done, server push still blocked** (§2.14) |
| M14 | Store readiness and release | not started |

**Working screens today:** Home, Search, property detail + gallery, Saved
(interested list + saved searches), notifications, the four auth screens, the
tab shell, profile/settings/rewards, the full owner surface (my listing,
add/edit, leads, analytics), and the full projects vertical (list, detail,
unit types, group-buy campaigns, bookings, my bookings). Messages (list +
thread) is built and working but is being unmounted per §9.1 D2, matching the
website, which mounts no chat UI at all. The property detail locator map and
M14 are still `Placeholder` stubs. **M10 (agreements) is the only milestone in M4–M13 not started.**
Corrected 2026-08-09: it is not merely "skipped by instruction." The backend
mount `app.use("/api/agreements", agreementRoutes)` is **commented out** in this
working tree (`backend/server.js:869`) under a comment recording a client
decision on 2026-08-01 to withdraw the agreement generator, alongside the
website's own `agreements/page.js` returning 404 and three navbar links removed.
It is still mounted on `origin/main`, i.e. live in production today, so the next
deploy is what closes it. Building a mobile client for it would ship a feature
the website deliberately hides. See audit §4.2.

---

## 2. What exists in the codebase right now

### 2.1 Foundation (M0–M2, complete and stable)

- `src/api/` — typed endpoint registry (`endpoints/_contract.ts` + one file per
  domain), axios client, error normalisation, TanStack Query setup, query keys.
  **Every backend route the app will ever call is already typed here.** Wiring a
  feature means writing a hook, not discovering an API.
- `src/auth/` — `AuthProvider`, cookie capture/restore via
  `@react-native-cookies/cookies` + SecureStore, zod schemas for every auth form.
- `src/theme/` — colors (semantic roles, light/dark), typography, spacing/radius/
  elevation, motion (springs, not durations), scrim gradients.
- `src/ui/` — 22 primitives. Screen, Text, Button, Input, Select, Sheet, Card,
  Badge, Avatar, Image, Skeleton, EmptyState, ErrorState, Chip, PriceLabel,
  RangeSlider, plus four Home-era additions (§2.8).
- `src/storage/` — three MMKV instances (cache / prefs / drafts) with a
  logout-scoped clear that deliberately spares preferences.

### 2.2 Property discovery (M3, complete)

- `features/properties/` — `adapters.ts` (80-field backend model → flat
  `PropertySummary`), `api.ts`, `hooks.ts` (`usePropertyFeed`, infinite +
  deduped), `PropertyCard`, `PropertyList`, `PropertyStrip`.
- `features/search/` — `filters.ts` (verified param mapping, price bands),
  `SearchBar`, `FilterSheet`, `SuggestionList`, MMKV recent searches.

### 2.3 Builder projects (early M11, new this session)

`src/features/projects/` is a **complete data layer** for the project list:

- `types.ts` — `ProjectSummary`
- `adapters.ts` — `adaptProject`, cover-image fallback chain, builder narrowing
- `api.ts` — `fetchProjects` against `GET /projects` (same call the website makes)
- `hooks.ts` — `useRecentProjects`
- `components/ProjectCard.tsx`, `components/ProjectRail.tsx`

**Not done for M11:** project detail, unit types, floor plans, group-buy
campaigns (join/exit + the 10-per-15-min limiter), bookings, payment-proof
upload. All five `app/projects/*` screens are still stubs.

### 2.5 Property detail (M4, done except the map)

`app/property/[id]/index.tsx` and `app/property/[id]/gallery.tsx`, built on
`features/properties/`:

- `types.ts` / `adapters.ts` — `PropertyDetail` extends `PropertySummary`
  rather than mirroring the ~80 backend fields; it carries `raw: Property` for
  the field map to read declaratively (below), and lifts only what needs real
  decisions: gallery flattening, owner contact, address lines.
- `fieldMap.ts` + `DetailAttributes.tsx` — the declarative attribute table, 8
  sections / ~60 fields. **Presence decides what renders, not `categoryName`**:
  the taxonomy refs are corrupt (§3.4), so a mislabelled listing would render
  the wrong half of its data if category picked the field set. A section with
  no fillable rows disappears rather than rendering empty.
- `DetailHero.tsx` — paged `FlatList` carousel (not a mapped `ScrollView`: a
  listing can carry up to 65 images across `images[]` and every
  `categorizedImages` bucket), tapping through to `gallery.tsx`'s full-screen
  pinch-zoom viewer (`ZoomableImage.tsx`). The gallery route reads through the
  same cached query the detail screen already populated, so opening it costs
  no extra request and — this is the one that matters — no extra view count.
- `hooks.ts`'s `usePropertyDetail` disables every automatic refetch
  (`staleTime: Infinity`, `refetchOnMount/Reconnect: false`) because
  `GET /properties/:id` **increments `views` on every call**. `refresh()`
  stays available for a deliberate pull.
- `interest.ts` + `DetailActions.tsx` — see §3.2. No heart icon; a labelled
  button with a consequence line, optimistic with rollback, surfaces the
  backend's own 400 message (five-listing cap, own listing, already marked)
  rather than trying to predict it client-side.
- `ReportSheet.tsx` — preset reasons that satisfy the backend's 10-character
  minimum, editable.

**Redesigned 2026-08-09**, structure only — no data, query or endpoint changed:

- `DetailHeader.tsx` (new) — the nav bar. The back button used to live in the
  hero and scroll away with it, leaving a several-thousand-pixel page with no
  way out. It now stays, cross-fading from a dark disc over the photo to an
  opaque bar carrying the listing's location, driven by the scroll offset as a
  shared value. It also owns the status-bar style flip, which is the one part
  of the transition that is discrete rather than continuous. **Opaque, not
  blurred** — `expo-blur` is a native module and `ui/Gradient.tsx` explains what
  adding one costs; the collapsed bar is what iOS itself falls back to under
  Reduce Transparency.
- `DetailHero.tsx` — parallax on scroll, top-anchored stretch on overscroll,
  both off under Reduce Motion. The content block below is opaque and paints
  after it, which is what lets the photo grow underneath without a clipping
  container.
- `ExpandableText.tsx` (new) — descriptions clamp to six lines. Line count is
  measured with a hidden unclamped copy because `onTextLayout` on a clamped
  `Text` does not report the same thing on both platforms.
- Surfaces (`DetailFacts`, `DetailAttributes`, `DetailOwner`) dropped their
  outlines for `Card bordered={false} radius="xl"` plus hairline separators
  inset from the row's leading edge. The page background sits one step down the
  neutral ramp from `surface` precisely so this works — see `theme/colors.ts`.
- `DetailActions.tsx` lost Share (now in the nav bar) and Report (now a quiet
  footer link, after the thing it refers to). Four equal-weight icons beside the
  primary button read as a toolbar of options rather than as one decision. The
  bar reports its own height so the scroll content ends clear of it instead of
  guessing at a constant.
- `ui/Tag.tsx` (new) — amenities and nearby places were rendered with `Chip`,
  which is a `Pressable` with `accessibilityRole="button"`, so VoiceOver
  announced twenty dead controls per listing. `Tag` is the same visual family
  with no role. `Card` gained `bordered` and `radius`; both default to the old
  behaviour, so no other call site moved.

**Unverified on device.** Typecheck and lint pass; the parallax, the header
cross-fade and the expand animation have not been run on hardware.

**Not done:** the locator map (§1.17, C1). Held for a dev-client rebuild —
`react-native-webview` and `expo-location` are native modules, and Chirag's
device workflow runs on `expo start --tunnel`, which ships JS only (§5.1).
Chirag confirmed "keep the locator" for C1 when asked.

**Untested on a device:** the gallery's pinch/pan gesture handoff (pan is
disabled while at rest so the carousel can still page beneath it; enabled once
zoomed) and the property detail action bar's layout. Both are reasoned
through, not observed running.

### 2.6 Saved, saved searches, and notifications (M5, done)

`features/saved/`, `features/savedSearches/`, `features/notifications/`;
`app/(tabs)/saved.tsx`, `app/notifications.tsx`.

- **Saved is "Interested," not "Favourites."** See §3.2 — one backend list,
  two names. The tab's first segment is labelled Interested; the count line
  ("3 of 5 used") is functional, since the cap makes this screen where a user
  comes to make room, not decoration.
- **Saved searches only expose city, price band, and rent/sale.** The alert
  matcher (`propertyController.js:484`) reads five stored filter fields but
  only three actually match anything, and `availableFor` silently misses every
  "Sell"-spelled listing when saved as "sale" (§3.4's spelling problem, a
  second time). Offering a control that quietly fails half the time is worse
  than not offering it. `isInert` on a saved search (no filter the matcher
  reads) disables its alert switch and says why, rather than promising alerts
  that can never fire.
- **The backend's `isActive` toggle is deliberately wired to nothing.**
  `GET /saved-searches/mine` filters to `isActive: true`, so flipping a search
  off would drop it from the only endpoint that can ever list it again — a
  delete with extra steps. `PUT .../notifyEmail|notifyInApp` is the reversible
  control actually exposed.
- **Notifications badge is counted from the list**, not from
  `GET /notifications/unread-count` — no such endpoint exists; `unreadCount`
  is summed client-side from the same rows the screen renders, capped at
  "99+" since the list itself is hard-capped at the 100 most recent. Read
  routes are PATCH (`/notifications/:id/read`, `/notifications/mark-all/read`)
  — the website's own helper calls PUT paths that 404.

`src/lib/htmlEntities.ts` — extracted here because chat (§2.7) needed the
identical decode a second time: two backend code paths (`express-validator`'s
`.escape()` on saved-search names, `chatController`'s hand-rolled `escapeHtml`
on message text) both produce the same five HTML entities.

### 2.7 Chat (M6, done)

`src/socket/` (the transport) and `features/chat/`; `app/(tabs)/chat.tsx`,
`app/chat/[conversationId].tsx`. `socket.io-client@4.8.3` added — pure JS, no
native module, so this did **not** need a dev-client rebuild.

- **`socketManager.ts` is a plain module, not a hook or context value** — one
  socket for the whole app, matching architecture plan §1.8. `SocketProvider`
  (mounted in `app/_layout.tsx`, inside `AuthProvider`) only drives lifecycle:
  connect on `authenticated` + foreground, disconnect on `guest` + background.
  Every screen reads the connection through `useSocketStatus` /
  `useOnlineUserIds` / `useIsUserOnline`, which work with no provider present.
- **The handshake re-runs on every `connect`, not just the first one.** The
  socket JWT (`GET /chat/socket-token`) lives 5 minutes, so caching it across a
  background/foreground cycle would mean authenticating with an almost-certainly-
  expired token. Socket.IO's own reconnection (capped exponential backoff) is
  left on for transport drops; the app-level handshake hooks into its
  `connect` event every time, first or reconnect alike.
- **`auth_error` gets exactly one retry, then a session failure** — per the
  plan's "do not retry blindly." A second consecutive failure calls
  `socket.disconnect()` (which also halts Socket.IO's own reconnect loop) and
  hands off to `refreshUser()`, the only way to learn whether the real session
  cookie is still good.
- **`useMessageThread` merges three sources into one list**: REST history
  (`GET /chat/messages/:id`, paginated OLDER by increasing page number, each
  page oldest-first internally — assembling one oldest-first list means
  reversing PAGE order, not item order), a live tail from `receive_message`
  scoped by room membership, and this device's own optimistic sends. Send is
  REST-then-emit exactly per the plan: persist first, then fan out the
  server's own saved object over the socket — never the other way around.
- **`visit_request` / `visit_confirmation` render as a distinct card**, not a
  bubble with a button bolted on (the website's actual treatment). The Accept
  action also tracks whether a later `visit_confirmation` already exists in
  the thread and hides itself once one does — the website's own `canAcceptVisit`
  has no such memory and would offer Accept on the same request forever.
- **Property detail's "Message owner" now calls `useStartConversation`**,
  wired into `DetailActions.tsx` from §2.5, closing the loop the plan
  describes ("M4 for entry from property detail").
- **Corrected in `types/backend/chat.ts`:** `StartConversationRequest`
  declared `ownerId` as required; the controller never reads it (derives the
  owner from the property, by explicit design, to prevent IDOR) — dropped.

**Flagged, not fixed:** `send_message`, `typing`, and `stop_typing` on the
backend trust client-supplied identity fields (`data.message.sender`,
`data.userId`) instead of verifying them against the authenticated socket,
unlike `join_conversation`, which does check DB participation. Blast radius is
limited to conversations an attacker is already a genuine participant in, but
within that room they could forge a message appearing to come from the other
participant. This app only ever emits its own REST-validated data, so it isn't
exploitable from here — it's a backend hardening item, spun off separately
rather than fixed in this session.

**Untested on a device:** the whole feature. Socket lifecycle across a real
background/foreground cycle, the inverted `FlatList`'s footer-is-visually-top
behaviour, and the keyboard-avoidance offset (`HEADER_HEIGHT` in the thread
screen is a measured estimate) all need verification on a physical device
before this is called solid.

### 2.8 Home screen + design system

New UI primitives, all generic and reusable:

| File | Purpose |
|---|---|
| `src/ui/Gradient.tsx` | Linear gradients via RN's `experimental_backgroundImage`. **No native module** — deliberately, see §5.1 |
| `src/ui/Scrim.tsx` | Gradient overlay for text on photos |
| `src/ui/PressableScale.tsx` | Press feedback as scale, not opacity |
| `src/ui/Rail.tsx` | The one horizontal scroller: peek, snap, gutters |
| `src/lib/scrollReveal.tsx` | Deferred mounting — the rate-limit mechanism, §5.2 |

Home feature (`src/features/home/`):

- `Hero.tsx` — full-bleed photo, colour-graded scrim, search trigger, Buy/Rent/Post
- `usePopularListings.ts` — ranks by `views`, client-side (§3.3)
- `cities.ts` + `useCityCounts.ts` — 12 city tiles, **live counts**, spelling
  variants merged client-side (§3.5)
- `CityGrid.tsx`, `AboutDealDirect.tsx`, `CtaBanner.tsx`
- `collections.ts` + `useCollection.ts` + `CollectionRail.tsx` — **built, tested,
  and NOT currently rendered.** A registry of 15 curated rails (Luxury, Starter
  Homes, Sea View…), each gated on live result count so a rail that cannot fill
  itself renders nothing. One `COLLECTIONS.map()` away from being live. Do not
  delete it without asking.

`features/properties/recentlyViewed.ts` — MMKV history, snapshots the card
fields rather than storing ids, **because refetching would inflate the backend's
view counter** (the same counter Popular Listings ranks on).

Current Home order: Hero → Popular Listings → Builder Projects → Why DealDirect
→ Explore by City → CTA.

### 2.9 Profile, settings, rewards (M7, done)

`features/profile/`, `features/rewards/`; `app/(tabs)/profile.tsx`,
`app/settings/*`, `app/rewards/index.tsx`.

- **No `useProfile` query.** `AuthProvider` already holds the current user
  from its cold-start `GET /users/me` probe; every mutation here calls
  `refreshUser()` on success instead of maintaining a second cache of the same
  document.
- **Edit profile lives inline on the Settings screen**, not on its own route.
  No such route was scaffolded in M0, the form is four fields (name, phone,
  bio, photo) plus an email-notifications toggle, and a save button that is
  visibly dirty-or-not reads better than a navigation round trip for that.
  `preferences` goes over as a JSON string field on the same multipart
  request — `updateProfile` (userController.js:922) reads it that way; it is
  not in the `updateProfile` endpoint's doc comment because that comment only
  covers the file field.
- **The owner-upgrade OTP flow is a `Sheet`, not a route**, opened from the
  buyer/user role's card on the Profile tab. Two-step (`send-upgrade-otp` /
  `verify-upgrade-otp`), gated client-side on `user.isVerified` since the
  backend's `requireVerified` would 400 first anyway — this just saves the
  round trip.
- **`transactions` and `referrals` are read defensively.** Both controllers
  spread a service result directly into the envelope (see
  `types/backend/rewards.ts`), so the exact key names were not confirmed
  against a live response this session. The hooks try the plausible key names
  and fall back to an empty list/zero rather than crash if the real key
  differs — pin this down against production data before trusting the
  Activity section's completeness.
- **`referralLink` is shared as-is**, never rewritten into a deep link — it
  points at the website by backend design (built from `CLIENT_URL`), and
  rewriting it would break attribution for a recipient without the app.
- **Delete account requires typing `DELETE`** rather than a single
  confirmation tap, given App Store policy requires this screen exist at all
  but says nothing about how easy reaching it should be.

### 2.10 Owner mode: listings and uploads (M8, done)

`features/listings/`; `app/owner/properties.tsx`,
`app/owner/property/new.tsx`, `app/owner/property/[id]/edit.tsx`.

Added `expo-image-picker` and `expo-image-manipulator` — both native modules,
so **this milestone also needs the dev-client rebuild** already pending for
the M4 map (§5.1). Neither works in the JS-only `--tunnel` bundle.

- **`add` and `edit` are NOT the same contract.** `POST /properties/add`
  sanitises through a strict field-name whitelist
  (`PROPERTY_ALLOWED_FIELDS`, propertyController.js:42) before
  `Property.create`; `PUT /properties/my-properties/:id`
  (`updateMyProperty`, propertyController.js:1258) has **no whitelist at
  all** and writes whatever reaches `req.body` through Mongoose schema
  binding directly. `src/features/listings/formData.ts` has the full
  field-by-field reasoning; the short version is two separate builders,
  `buildAddFormData` and `buildEditFormData`, and they are not
  interchangeable.
- **Several whitelist entries do not correspond to any real schema path** —
  `floor` (schema: `floorNo`), `age`/`availability` (schema has neither),
  flat `builtUpArea`/`carpetArea`/etc. (schema wants them nested under
  `area`), `parkingCovered`/`parkingOpen` as flats (schema wants `parking`
  nested). Mongoose's default strict mode drops these silently — no error,
  no save. The form only offers fields that are confirmed to reach the
  document: the intersection of the whitelist and
  `backend/models/Property.js`, not the whitelist alone.
- **Editing `address.line`/`state`/`pincode` is not possible through this
  backend.** `updateMyProperty` unconditionally rebuilds `data.address` from
  flat top-level `city`/`locality`/`landmark`/`latitude`/`longitude` and
  stuffs anything sent as a nested `address` object into a non-schema
  `address.full` string. This is a server limitation, not a client one — the
  edit form does not offer those three fields, and does not silently drop a
  user's edit to them because it never asks.
- **Edit-flow images are a real landmine, handled, not just documented.**
  `updateMyProperty` rebuilds `categorizedImages` from
  `existingCategorizedImages` (JSON) plus any newly uploaded files on *every*
  call, then rebuilds the flat `images` array from that. Omitting
  `existingCategorizedImages` reads to the controller as "this listing now
  has zero photos" and wipes the gallery. `buildEditFormData` always sends
  the full current photo set back under that key. This app has no per-room
  categorisation UI, so every photo — existing or newly added — lives in a
  single `other` bucket key within whichever of `residential`/`commercial`
  the listing's `categoryName` selects.
- **An owner account is capped at one listing, server-side** (the atomic
  check-and-create in `addProperty`). `useMyProperties` is written against
  the list response anyway so a future cap relaxation needs no client change,
  but `app/owner/properties.tsx` in practice renders zero or one card.
- **Edit reads from `useMyProperties`, never `GET /properties/:id`** — that
  endpoint increments the view counter on every call (§2.5), and an owner
  opening their own listing to edit it should not count as a view. An owner
  has at most one listing, so searching the cached list by id is cheap.
- **Draft autosave is add-only.** `draftStorage` (MMKV, pre-provisioned in M0
  for exactly this) writes on every field change; a resumed draft is offered
  once on mount via a confirm dialog rather than silently applied, so a stale
  abandoned draft cannot clobber a fresh start. Editing an existing listing
  has no local-only state worth protecting the same way.
- **Client-side compression, not just a picker.** `expo-image-manipulator`
  resizes to a 1600px long edge and re-encodes at JPEG quality 0.7 before
  upload — the backend's 10 MB per-file cap is easy to exceed with an
  uncompressed modern camera photo, especially with several picked at once.
- **Only a flat photo gallery is offered**, not the backend's per-room
  categorisation (`categorizedImages.residential.kitchen`, etc.). Building
  that UI was out of scope for this pass; see the image-landmine note above
  for why "no categorisation UI" and "images survive an edit" are not in
  tension.
- **Category and property type are closed choices** (`Residential` /
  `Commercial`, and a fixed list per category in `features/listings/types.ts`)
  rather than free text or the corrupt taxonomy refs (§3.4). `categoryName`
  and `propertyTypeName` are stored as denormalised strings on the schema
  either way, so this loses nothing the backend would have used.

### 2.11 Leads and analytics (M9, done)

`features/leads/`; `app/owner/leads/index.tsx`, `app/owner/leads/[id].tsx`,
`app/owner/analytics.tsx`.

- **Lead detail has no endpoint of its own.** `GET /leads` (paginated) is the
  only read path; the detail screen finds its lead in the same infinite-query
  cache the list screen already populated rather than issuing a second
  request the backend cannot serve.
- **`stats` (on `GET /leads`) and the shape from `GET /leads/analytics` are
  two different, unrelated objects** — the list's stats block is
  `{new,contacted,...,total,today}` from `leadController.js:484`, typed
  locally in `app/owner/leads/index.tsx` since the shared contract types it
  as `unknown`; the analytics screen uses the separately-typed
  `LeadAnalyticsResponse`. Do not assume one can stand in for the other.
- **No chart library was added.** The mobile app has none installed, and five
  summary numbers plus a status breakdown did not justify a new dependency —
  `app/owner/analytics.tsx`'s bars are plain `View`s sized by proportion.
- **Marking a lead viewed happens on open**, once, guarded by `lead.isViewed`
  so revisiting an already-read lead does not re-fire the mutation.

### 2.12 Projects, units, campaigns, bookings (M11, done)

`features/projects/*` (extended: `projectDetail.ts`, `campaigns.ts`,
`bookings.ts`, `components/ProjectList.tsx`, `components/ProjectListCard.tsx`
new this session); `app/projects/index.tsx`, `app/projects/[id].tsx`,
`app/projects/unit/[unitTypeId].tsx`, `app/projects/campaign/[campaignId].tsx`,
`app/projects/booking/[bookingId].tsx`, `app/projects/bookings.tsx`.

- **`app/projects/bookings.tsx` ("My bookings") was not in the M0 route
  scaffold.** Screen #42 in the architecture plan's build order, added here
  since `bookingsEndpoints.mine` already existed with no screen calling it.
  Linked from the Profile tab, alongside a new "Projects" row — both reachable
  by any signed-in user, not owner-gated, since booking a unit is a buyer
  action.
- **There is no "am I already a member" endpoint for a group-buy campaign.**
  `join`, `exit` and `detail` are the only three calls; `detail` carries no
  per-user membership flag. `app/projects/campaign/[campaignId].tsx` therefore
  tracks join/exit only for what happens in the CURRENT session (component
  state, not persisted) and otherwise lets the backend's own 400
  ("already a member" / "not a member") surface as the error message rather
  than guessing membership client-side. A user who joined in an earlier
  session sees "Join" as the enabled button here, same as before joining —
  tapping it gets the backend's real answer.
- **Booking detail has no GET-by-id endpoint either.** `bookingsEndpoints` only
  has `mine` (list) and the two write routes, so
  `app/projects/booking/[bookingId].tsx` finds its booking in the
  `useMyBookings()` cache — populated already, since `useCreateBooking`
  invalidates that same query key on success and the booking sheet navigates
  straight here afterward.
- **Join/exit are declared with `rateLimit: 'groupBuy'`, but that limiter does
  not actually reach them.** Corrected 2026-08-09: `groupBuyLimiter` is mounted
  at `/api/group-buy/projects/:id/join|exit` (`backend/server.js:705-706`) and
  campaigns are mounted at `/api/campaigns` (`:880`). No `/api/group-buy` path
  exists, so join/exit are covered only by the 500-per-15-min global limiter.
  The campaign screen's handling of `ApiError.retryAfterSeconds` is still
  correct and worth keeping — it just fires on the global tier, far less often
  than the annotation implies.
- **Payment proof upload (campaign) and payment screenshot (booking) are two
  separate flows on two separate models**, not one shared component — a
  campaign's `paymentProof` field and a booking's `payment.screenshotUrl`
  are unrelated data on unrelated documents, even though both are "upload a
  payment screenshot" from a user's point of view.

### 2.13 Deep linking, offline, performance (M12, core pieces done)

`src/api/persistence.ts`, `src/lib/useNetworkStatus.ts`,
`src/ui/OfflineBanner.tsx`, `src/features/notifications/targets.ts` (extended).

- **Scheme-based deep linking (`dealdirect://property/123` etc.) needed no new
  code.** Expo Router resolves a URL against the file-based route tree
  automatically once `scheme` is set in `app.config.js` (already was, M0), so
  a cold start into a shared link lands directly on that screen without
  passing through `app/index.tsx`'s bootstrap gate at all.
- **Universal links (`https://dealdirect.in/property/123` opening the app
  instead of a browser) are NOT done, and nothing was added toward them this
  session.** That needs `ios.associatedDomains` / `android.intentFilters` in
  `app.config.js` AND a hosted `apple-app-site-association` file (requires the
  Apple Developer Team ID) plus `assetlinks.json` (requires the Android
  signing certificate's SHA-256 fingerprint) on the production web domain.
  Neither credential is available from this session, and a wrong or
  placeholder value in either file is actively worse than absent — it fails
  silently and is hard to debug later. Left undone rather than faked.
- **Query cache persistence** (`PersistQueryClientProvider` in
  `app/_layout.tsx`, backed by the `cacheStorage` MMKV instance M0 already
  provisioned) means a cold start with no connectivity still shows
  properties/projects/leads/rewards/etc. from the last successful fetch,
  capped at 24 hours old. **Chat is deliberately excluded** — see
  `shouldPersistQuery`'s doc comment: a socket-fed conversation shown as
  "current" after being disconnected for hours is a worse read than an empty
  state.
- **FlashList migration covers the genuinely long, unbounded lists**:
  property search results, the new projects list, leads, saved/interested,
  saved searches, and notifications. Chat's inverted thread list, the gallery
  carousel, and short bounded lists (sessions, my bookings) were left on
  `FlatList` — FlashList v2 (New Architecture only, which this app runs)
  buys nothing on a list capped at a handful of rows, and the chat thread's
  pagination/keyboard behaviour is already flagged untested on a device;
  changing its list implementation in the same pass it is unverified in was
  not worth the risk.
- **Offline is a banner, not a sync engine.** `OfflineBanner` (mounted once in
  `app/_layout.tsx`) tells the user before they tap something that a write
  will fail; the persisted query cache handles the read side; every write
  already produces the existing `network`-kind `ApiError` message
  ("No connection. Check your network and try again.", `src/api/errors.ts`).
  No offline write queue, no optimistic-then-reconcile beyond what individual
  features (like `useRemoveInterest`) already did on their own.
- **Not done: Sentry, a memoisation pass, and device performance
  verification.** No Sentry DSN is configured anywhere in this repo, so
  wiring the SDK now would be dead code with nowhere to report to — skipped
  rather than half-built. A repo-wide memoisation audit was judged lower
  value than the concrete items above and was not attempted. "Performance
  budgets met on a mid-range Android device" cannot be verified without a
  device, same as everything else this session.

### 2.14 Push notifications (M13, client-side/local done; server push still blocked)

`src/notifications/*` (new), `src/features/chat/activeConversation.ts` (new).

- **Read this before assuming more works than does.** `SocketProvider`
  disconnects the socket on background BY DESIGN (M6, for session-token
  reasons unrelated to push). That means the socket-driven local notification
  built here — a banner for a new chat message — can only ever fire while the
  app is in the FOREGROUND. There is no live connection to receive an event
  from otherwise. This is not a bug to fix later; it is the actual ceiling of
  what "push" can mean without the backend addition below.
- **True server-initiated push (notification arrives with the app closed) is
  UNCHANGED from the architecture plan's original finding: blocked.** No FCM/
  APNs device-token model, no push credentials, no registration route exist
  on this backend (`MOBILE_APP_ARCHITECTURE_PLAN.md` §0 finding #6). Nothing
  in this session added one, and nothing here pretends to — nowhere in the UI
  claims a notification will arrive while the app is closed or killed.
- **What was built:** a permission request (asked once ever, on first opening
  the Messages tab — not on launch — tracked in `prefsStorage` so it never
  re-prompts after the first answer either way), a foreground local
  notification for `receive_message` when the sender isn't you and the
  message isn't for the conversation currently open on screen (tracked via
  `setActiveConversationId`/`getActiveConversationId`, set by the chat thread
  screen on focus/blur), and tap-to-navigate back into that conversation.
- **`resolveNotificationTarget` (`features/notifications/targets.ts`) gained a
  `leads` target.** "New Interest on Your Property" notifications
  (`type: "interest"`, propertyController.js:1599) carry a `propertyId` but
  NO lead id — routing an owner to the public property page for their own
  listing was the wrong destination for this one type; it now routes to the
  leads list instead. This also means `resolveNotificationTarget` is now the
  one place both the notifications screen AND (if a future session adds a
  data-carrying local notification for something other than chat) any local
  tap handler would resolve a destination through — kept as one function
  rather than two.
- **`expo-notifications` is a THIRD new native module this session**, after
  `expo-image-picker`/`expo-image-manipulator` (M8). All three need the same
  dev-client rebuild — see the consolidated note in §5.1.

**Untested on a device, everything in this update (M7–M9, M11–M13).** This
pass verified with `tsc --noEmit`, `expo lint`, and
`expo export --platform android` only — no dev client was available to run
it. Beyond the M8 items already flagged: the group-buy join/exit rate-limit
messaging, the booking payment-screenshot round trip, query cache
rehydration on an actual cold start with no connectivity, and the entire
local-notification permission/foreground-banner/tap-routing chain all need
verification on a physical device before any of them are called solid.

---

## 3. Backend blockers found by measurement

These were all found by probing production, not by reading code. Every one is
recorded with evidence in the file that depends on it.

### 3.1 `listingType` filter is written but NOT DEPLOYED — highest priority

`backend/controllers/propertyController.js` correctly expands rent/sale across
all six schema spellings. Corrected 2026-08-09: it is **committed** (`ab5ec1b`,
"feat(search): honour listingType on /properties/search") but **not deployed** —
`main` is 4 commits ahead of `origin/main`, and deploy is a Hostinger git import
from `origin/main`. The conclusion is unchanged: the live API ignores the param,
and `?listingType=sale`, `Sell`, `rent` and `Rent` all return the same 36
results. Only the stated reason was stale.

**Effect:** the Buy and Rent buttons — the primary CTA — open unfiltered results.
Home is correct because `useCollection` and the rails guard intent client-side;
the browse screen is not.

**Fix:** deploy the existing change. No new code.

### 3.2 There is no PRIVATE save — corrected 2026-08-05

**The earlier version of this section was wrong** and said no endpoint could add
to the saved list. Read `getSavedProperties` (propertyController.js:1726): it
queries `{ "interestedUsers.user": userId }` — the same array `markInterested`
pushes to. **Saved and interested are one list under two names.**
`DELETE /saved/:id` and `DELETE /interested/:id` are the same operation written
twice.

So the write path exists: `POST /properties/interested/:id`. What does not exist
is a *private* one. Adding to this list creates a `Lead`, emails the owner, and
hands over the user's name, email and phone. The backend also caps it at **five
listings per user**, rejecting the sixth with a 400.

**Effect:** no heart icon, for a different reason than previously recorded. A
heart means private, free, unlimited and quietly undoable, and this action is
none of those. M4 ships it as a labelled button with a consequence line
(`DetailActions.tsx`). Undo works, but does not unsend the notification or
delete the lead.

**Still worth a backend change request** if a genuine private bookmark is
wanted, since the current list cannot serve both purposes. M5's saved tab is
NOT blocked: it can render this list today.

### 3.3 No `sort=views`

`/properties/search` accepts `newest`, `priceAsc`, `priceDesc` only. `views` is
real data with a real spread (166 down to 5 across 36 listings) and is now
carried on `PropertySummary`.

**Current workaround:** `usePopularListings` fetches one page of 100 and sorts
locally. Exact today; degrades to "most viewed among the newest 100" later, and
the section subtitle changes itself to say so.

**Fix:** one line in the controller's sort map. Collapses that whole file into an
ordinary query.

### 3.4 Taxonomy refs are corrupt (known since M3)

`category` / `subcategory` / `propertyType` are null on 15 of 36 listings and
point at the wrong document on the other 21. The app therefore ships **no
category or property-type filter** and uses free-text terms instead.

**Fix:** backfill from the correct `categoryName` / `propertyTypeName` columns.
Makes all three filters work with zero client change.

### 3.5 `address.city` is not normalised on write

Live values include `Bangalore` (9) and `Bengaluru` (6) for one city, `Kolkata`
and `kolkata`, `Howrah ` with a trailing space, and `Ahamdabad`.

**Current workaround:** `cities.ts` carries an alias table and merges them
client-side, which is the only place the join can happen (the `city` param is
exact and case-sensitive; `search` is escaped server-side so no alternation gets
through).

---

## 4. Recommended order for core logic

> **Superseded 2026-08-13.** The ordering below predates the §9 decisions.
> Item 1 (M10, agreements) is dead: the withdrawal stands (§9.1 D1). Items
> 2–4 survive unchanged and are folded into §9.4's wave plan as held/blocked
> items. Follow §9.4, not this list.

M4 through M9 and M11 through M13 are done (§2.5–§2.14), except the
property-detail map (held for a dev-client rebuild, §5.1) and true
server-initiated push (blocked on a backend change request, §2.14). What was
left, in the pre-§9 ordering:

1. ~~**M10 — agreements.**~~ Withdrawn from the product; see §9.1 D1.
2. **The map phase**, whenever a dev-client rebuild is scheduled: property
   detail's locator (§2.5) plus M8's add/edit picker, both against
   `docs/MAP_IMPLEMENTATION.md`.
3. **The universal-links half of M12** (§2.13) — needs the Apple Team ID and
   the Android signing cert's SHA-256 fingerprint, neither available from a
   coding session; someone with access to both has to produce
   `apple-app-site-association` and `assetlinks.json` and this app's
   `associatedDomains`/`intentFilters` config together.
4. **M14** — store readiness, once everything above is settled.

---

## 5. Decisions a new session must not accidentally undo

### 5.1 No new native modules without a very good reason

I added `expo-linear-gradient`, then removed it and rebuilt gradients on RN's
built-in `experimental_backgroundImage` (`src/ui/Gradient.tsx`). Reason: a native
module invalidates every installed dev client, and `expo start --tunnel` ships
**JavaScript only**, so it silently serves a bundle the installed binary cannot
run. Chirag's device workflow depends on this. Native additions must be
deliberate and announced.

**M8 added two more, deliberately: `expo-image-picker` and
`expo-image-manipulator`.** There was no way to build listing photo upload
without a native picker, and no way to keep uploads under the backend's 10 MB
per-file cap without client-side compression. Both are registered in
`app.config.js`'s `plugins` array.

**M12 added `@react-native-community/netinfo`** for the offline banner
(§2.13) — connectivity state needs a listener-based API, which `expo-network`
does not provide.

**M13 added `expo-notifications`**, for the local-notification permission and
presentation calls (§2.14). No push-credential config needed on the client
side for what this milestone actually built (local only), but the module
itself is still native.

**This means the installed dev client is now stale for FOUR independent
reasons**: the M4 map's `react-native-webview`/`expo-location`, M8's
`expo-image-picker`/`expo-image-manipulator`, M12's
`@react-native-community/netinfo`, and M13's `expo-notifications`. One
rebuild covers all four — do them together, not one at a time.

### 5.2 The 20-req/min search limiter is a real design constraint

`/properties/search`, `/suggestions` and `/filter` are capped at **20 requests
per minute per IP**, and on Indian mobile networks that IP is a carrier NAT
gateway shared with strangers. This is why:

- Home sections below the fold are wrapped in `Reveal` (`src/lib/scrollReveal.tsx`),
  which withholds the **mount**, and therefore the query, until the section
  approaches the viewport.
- Collections cache for 10 minutes, city counts for 15.
- City counts come from **one** request counted locally, not 12 requests.

Do not add an eager query to Home.

### 5.3 One browsing implementation

Home owns no feed, no filters, no sort, no pagination. Every affordance does
`router.push({ pathname: '/search', params })`. A rent feed, a sale feed and a
search-results screen are the same screen three times and they drift.

### 5.4 Nothing claims what the data cannot support

No fabricated stats. The ported production home screen carried "₹50 Cr+
Brokerage Saved", "10k+ Happy Families" and city tiles reading "Mumbai 5000+"
against a live corpus of **36 listings**, where Mumbai has 9. All of it is gone
or computed. "Popular Listings" is real view counts; city tiles are real counts;
"Featured" was renamed because no curation flag exists.

Related: a section with no data **unmounts** rather than rendering an empty
state. See `CollectionRail`.

### 5.5 Live corpus is small — verify before assuming

36 approved properties, 5 builder projects. 25 of 36 properties have real
`address.latitude`/`longitude`. Probe endpoints before building against assumed
volume; several "obvious" features return zero rows.

---

## 6. Verification commands

```bash
cd dealdirect-mobile
npx tsc --noEmit          # currently clean
npx expo lint             # currently 0 errors, 11 pre-existing warnings
npx expo export --platform android   # currently succeeds
```

Device: `adb reverse tcp:8081 tcp:8081` then
`npx expo start --dev-client --localhost`. `--tunnel` is currently broken
because `@expo/ngrok@4.1.3` bundles an ngrok v2-era agent that ngrok has
retired server-side; there is no newer version.

---

## 7. UI work deliberately deferred

Chirag's call, 2026-08-05: core logic first, UI later. Outstanding UI items,
none of them blocking:

- Hero artwork is unresolved. Four images tried; current one is the website's
  `herokaback.png` (Dubai, 2752×1085 panorama, ~40% visible after crop).
- The **photo-band hero** was proposed and not built: photo in a ~260pt band
  fading into solid dark, with the search and buttons on the solid part. Removes
  the scrim entirely, shows ~78% of any image, and means the scrim never needs
  retuning per image. This is the right fix and it is still open.
- Collections rails are built but not rendered (§2.8).
- `assets/home/brand/hero.png` (558 KB) is unused; delete or use.

---

## 8. M15–M22 — feature-parity scope (2026-08-08, M15–M17 done same day)

A direct file-by-file audit of `client-next/` against `dealdirect-mobile/`
turned up features the website ships that mobile doesn't. Chirag reviewed the
full list and selected what to build next. **M15, M16 and M17 were
implemented in the same session that wrote this scope** — see the "Done"
notes under each below for what actually shipped and where it diverged from
the scope as first written. M18–M22 remain scope only, no code yet. Two items
were surfaced and explicitly declined; they're listed at the end so a future
session doesn't "rediscover" and re-propose them.

> ### COMPULSORY — the backend is live in production. Do not touch it.
>
> `backend/` is running in production today, serving the website and the
> admin panel as well as this app. Every feature in M15–M22 below is
> **frontend-only, mobile-side work** — proven by the fact that the website
> already renders all of it against this exact same backend, unchanged. If
> M15–M22 ever seems to need a new route, a new field, a schema change, or
> any edit under `backend/`, that is a signal the scope was misread, not a
> green light to add one. Stop and re-check against the website's own
> implementation before writing a single line of backend code.
>
> This extends `MOBILE_APP_ARCHITECTURE_PLAN.md` §7 ("Things that MUST NEVER
> be changed", rules 1–15) to the whole of M15–M22, with no exceptions listed
> here — unlike M13's push-notification change request, nothing in this
> range has been pre-approved for a backend change. Specifically, for the
> items below:
>
> - **Close Deal + Claim Reward, brochure/RERA links, video/nearby fields,
>   reward tiers** — all already returned by the live API today (the website
>   reads `wallet.tier`, `project.media.brochureUrl`, `property.videoUrl`,
>   `property.nearby`, and calls the close-deal endpoint against this same
>   backend right now). Mobile is missing the client code, not the data.
> - **Advanced search filters** — the underlying city/category/type data
>   quality problem (§3.4, §3.5) is a known, pre-existing backend condition.
>   Build the filters to tolerate it the way the website does. Do not "fix"
>   the taxonomy or city normalisation in `backend/` to make the filters
>   behave better — that is a backend change, and it is out of scope here
>   regardless of how small it looks.
> - **Content pages (M20)** — confirm each page's copy/data source (static
>   copy, or an existing `GET /api/blogs`-style endpoint already used by the
>   website) before assuming a new backend endpoint is needed. It isn't; the
>   website is already fetching this content from something that exists.
>
> If a future session genuinely believes a backend change is required for
> anything in M15–M22, that is a decision for Chirag to make explicitly, the
> same way M13's push-notification change request was raised and approved on
> its own merits before any code was written — not something to decide and
> proceed on mid-implementation.

| Milestone | Scope | State |
|---|---|---|
| M15 | Advanced search filters + profile depth | **done** |
| M16 | Property detail completion (map, video, nearby, EMI, compare, related) | **done except the locator map** — still blocked, §5.1 |
| M17 | Owner transaction completion (close deal, photo categorisation, location picker) | **done except the location picker** — still blocked, §5.1 |
| M18 | Rewards depth (tiers, terms page) | not started — **re-scoped 2026-08-13**: display only; redemption is a separate workstream, §9.1 D3 |
| M19 | Project extras (brochure, RERA download) | not started |
| M20 | Content & marketing pages (blog, about, why-us, faq, contact, press, privacy, terms) | not started |
| M21 | Platform polish (collections rails, Sentry) | not started |
| M22 | Store readiness | not started (this **is** the original plan's M14, reactivated) |

**Verification for M15–M17:** `npx tsc --noEmit` and `npx expo lint` both
clean — 0 errors, the same 11 pre-existing warnings §6 already documents,
nothing new added. **Untested on a device or in Expo Go/dev-client**, same
caveat every prior milestone in this document carries: this pass verified
with the type checker and linter only.

**Order followed:** M15 and M16 depended only on existing data layers and
were pure mobile-side work, so they went first, as planned. M17's close-deal
piece shipped the same way; its photo-categorisation piece turned out to
share nothing with the map's native-module dependency (§5.1) and shipped
too — only the location picker itself stayed blocked, alongside M16's
locator map, both on the same pending dev-client rebuild. **Remaining order,
unchanged from the original plan:** M18/M19 are additive, no shared
dependency, can run in any order or in parallel. M20 is entirely new route
scaffolding, zero overlap with anything else — safe to parallelise. M21's
Sentry item needs a DSN from Chirag before it can start; the collections-rails
item is a few minutes of work (already built, just needs mounting, §2.8).
**M22 last**, once everything above is settled — matches the original plan's
own ordering logic (§4).

### M15 — Advanced search filters + profile depth (done)

**Done 2026-08-08.** Both pieces shipped; the search filters piece resolved
the "which trade-off" question this section originally left open, rather than
picking one blindly:

- **Search filters — resolved by filtering client-side over an already-fetched
  page, not by fixing the backend or accepting broken results.**
  `usePopularListings`'s existing pattern (fetch one bounded page from
  `/properties/search`, `limit=100`, then work over rows already in hand) is
  reused wholesale: `usePropertySearchFeed` (`features/search/hooks.ts`)
  switches into that mode only when a city/category/furnishing/construction
  filter is active, and delegates to the untouched, unchanged
  `usePropertyFeed` infinite-scroll path otherwise. Category and city filters
  are genuinely safe now — `categoryName` and `matchCity`'s alias table (the
  same one `features/home/cities.ts` already built) are both correct data,
  the earlier write-up's concern was only ever about the corrupt `category`/
  `propertyType` **ObjectId refs**, which this never touches. Furnishing
  turned out to be a real, closed-enum field (`Property.furnishing`) the
  website's OWN filter doesn't even read correctly (it checks a
  `furnishingStatus` field that doesn't exist in the schema at all) — mobile's
  version is the first one that actually works. Construction status is
  genuinely free text with no enum, so it's a best-effort keyword match
  (`ready` / `construction`), documented as such in `filters.ts` rather than
  presented as exact. "Posted by" (owners vs. partner agents) was dropped —
  no backing field exists on the schema for it; it appears to be decorative
  UI on the website with nothing behind it. Full reasoning:
  `src/features/search/filters.ts`'s updated header comment.
- **Rich profile fields — shipped exactly as scoped.** All five fields plus
  the SMS toggle are now in `UpdateProfileValues`, the settings form
  (`app/settings/index.tsx`), and the multipart payload, matching the field
  names `userController.js:922` already reads
  (`alternatePhone`, `address` as a JSON object, `dateOfBirth`, `gender`,
  `preferences.smsNotifications`). Date of birth is a `YYYY-MM-DD` text field
  rather than a native date picker — no date-picker module is installed, and
  adding one is its own native-module decision (§5.1), not a default this
  form should force.

*Original scope write-up below, kept for the reasoning it recorded before
implementation started — the "Done" note above is what actually shipped.*

- **Search filters.** Website (`client-next/src/app/properties/PropertyListContent.jsx`
  filter bar, `client-next/src/components/HeroSection/*Filter.jsx`,
  `filterConfig.js`) exposes city, property type (category-scoped
  residential/commercial sub-types), 33-tier budget bands, possession status
  (ready-to-move / under-construction), furnishing (furnished / semi /
  unfurnished / gated community), and posted-by (owners / partner agents).
  Mobile's `src/features/search/filters.ts` + `FilterSheet.tsx` deliberately
  ship only free text, rent/sale, a 5-tier price band, and sort — the file's
  own header comment explains why (city/type/category data is unreliable
  against live production data, §3.4/§3.5 of this document). Building this
  means either accepting that unreliability the same way the website does, or
  fixing the underlying taxonomy/city-normalisation issues first. Decide
  which before starting — do not silently re-introduce the bug the current
  code was written to avoid.
- **Rich profile fields.** Website (`client-next/src/app/profile/ProfileContent.jsx`,
  Profile Info tab) collects alternate phone, date of birth, gender, and a
  5-field address block (line1, line2, city, state, pincode), plus separate
  email and SMS notification toggles. Mobile's `useUpdateProfile`
  (`src/features/profile/hooks.ts`) and its form on `app/settings/index.tsx`
  send only `name`, `phone`, `bio`, `emailNotifications`, and photo — the
  other fields aren't in the payload builder at all, not even as unused UI.
  Add the fields to `UpdateProfileValues`, the form, and the multipart
  payload; confirm the backend's `updateProfile`
  (`userController.js:922`) actually persists all of them before trusting the
  UI.

### M16 — Property detail completion (done except the locator map)

**Done 2026-08-08**, except the locator map, which stays blocked exactly as
scoped — nothing changed there:

- **Video walkthrough + Nearby chips** shipped as pure render-layer additions,
  as scoped — `VideoWalkthrough.tsx` and `NearbyPlaces.tsx`
  (`features/properties/components/`), wired into
  `app/property/[id]/index.tsx`. Video opens externally via `Linking.openURL`
  rather than an embedded YouTube iframe — embedding needs a WebView, which is
  the exact native module the locator map is blocked on (§5.1); adding it for
  this smaller feature would trigger the same dev-client rebuild for a much
  smaller payoff. `PropertyDetail.nearby` and `PropertySummary.furnishing`/
  `.constructionStatus` were added to `features/properties/types.ts` and
  `adapters.ts` to carry the fields these needed — the same two fields M15's
  filters also ended up needing, so they only had to be added once.
- **EMI calculator** shipped as scoped, arithmetic ported 1:1 from the
  website's `useEffect` in `PropertyDetailsContent.jsx` (`EmiCalculator.tsx`).
- **Compare properties** shipped, but comparing `PropertySummary` fields
  (already in memory from the search results being browsed), never
  `PropertyDetail` — seeing `GET /properties/:id` increments the listing's
  view counter on every call, fetching 2–3 listings' full detail just to
  populate a comparison table would have silently inflated their view counts
  for an action that isn't a real view. The row set is correspondingly
  smaller than the website's (no amenities/parking/facing — those live only
  on `PropertyDetail.raw`). `features/search/compare.ts` has the full
  reasoning. UI: `CompareBar.tsx` (sticky selection bar) and
  `CompareSheet.tsx` (side-by-side table), both in
  `features/search/components/`; `PropertyCard` gained an optional `compare`
  prop so every other screen that renders one is unaffected.
- **Related properties** shipped, scored against a bounded 100-listing pool
  (`RELATED_POOL_SIZE` in `features/search/related.ts`) rather than the
  website's unbounded `/property-list` fetch — same reasoning as M15's filter
  pool. Shown as a footer rail (`PropertyList` gained an optional `footer`
  prop) below search results once the direct match count drops under 6.

*Original scope write-up below, kept for the reasoning it recorded before
implementation started.*

- **Locator map.** `app/property/[id]/map.tsx` is currently an 11-line
  `Placeholder` stub. Needs the dev-client rebuild (§5.1) for
  `react-native-webview` + `expo-location`. Full spec already exists at
  `docs/MAP_IMPLEMENTATION.md`.
- **Video walkthrough embed.** `videoUrl` is already typed and adapted
  (`src/features/properties/types.ts:149`, `adapters.ts:335`) but never
  rendered anywhere. Website renders it via `getVideoEmbedUrl` as a YouTube
  iframe / external-link fallback (`PropertyDetailsContent.jsx`). Pure
  render-layer work — no new data plumbing needed.
- **Nearby places chips.** Same situation: `nearby`/`nearbyPlaces`
  (`src/types/backend/property.ts:57`) is typed, never rendered. Website
  shows it as chips near the amenities section. Also pure render-layer work.
- **EMI / loan calculator.** New UI + arithmetic, no backend dependency.
  Website version (`PropertyDetailsContent.jsx`, state ~L567–753, UI
  ~L1398–1409): editable loan amount (defaults to 80% of listing price),
  interest rate, tenure → live monthly EMI. No shared dependency with the
  map — build it independently of the M17 native-module rebuild.
- **Compare properties.** Largest of this group. Website
  (`PropertyListContent.jsx` L310–539, L2221–2521): pick up to 3 same-type
  listings, sticky compare bar, side-by-side spec modal. Needs new
  cross-screen state (selection persists while browsing search results) —
  design that before writing UI.
- **Related/similar properties.** Website backfills a scored "related
  properties" grid when a filtered search returns under 6 results
  (`PropertyListContent.jsx` L901–1021, L2039–2076). Port the same scoring
  logic; verify it still makes sense against the live 36-listing corpus
  (§5.5) before assuming it'll ever have enough data to show anything.

### M17 — Owner transaction completion (done except the location picker)

**Done 2026-08-08**, except the location picker, which stays blocked exactly
as scoped — same native-module dependency as M16's locator map, nothing
changed there:

- **Close Deal + Claim Reward** shipped end to end, including a gap the
  original scope note didn't catch: `claimDealReward` has no "my
  verifications" list to be reached from, and the `deal_reward` notification
  that announces an approved deal carries a `verificationId`, not a
  `propertyId` — `resolveNotificationTarget`
  (`features/notifications/targets.ts`) had no case for that type, so the
  notification was previously unnavigable, dead in the list. Added a
  `dealReward` target and a new route,
  `app/claim-reward/[verificationId].tsx`, which claims automatically on open
  (the notification tap was already the confirmation step) and handles
  `alreadyClaimed: true` as the normal repeat-tap outcome it is, not an error.
  Close-deal itself is `CloseDealSheet.tsx`
  (`features/listings/components/`), opened from a new "Close deal" button on
  `app/owner/properties.tsx`, gated on the exact same status set the backend
  itself rejects (`pending_verification`/`sold`/`rented`) so the button never
  offers an action the server would 400. Proof documents are photos via
  `expo-image-picker` (already installed since M8), not arbitrary PDF upload —
  adding `expo-document-picker` for this one screen would be a fourth native
  module stacked on the pending rebuild for a feature photographing the same
  paperwork already serves. `CloseDealResponse`/`ClaimDealRewardResponse` were
  added to `types/backend/property.ts`, replacing the placeholder `OkEnvelope`
  typing on both endpoints — the real payloads carry `verification`/`reward`
  objects the UI actually needs.
- **Per-room categorised photo upload** shipped, and turned out to need
  matching two DIFFERENT wire formats, not one — `addProperty` and
  `updateMyProperty` disagree on both the file field name for new categorised
  photos (`categorizedImages` vs `images`) AND the shape of
  `imageCategoryMap` (an object keyed by category vs. a position-matched
  array) — see the expanded module doc in `features/listings/formData.ts`
  for the exact mechanics, confirmed by reading both controller functions
  directly rather than assuming they matched. `existingCategorizedPhotos`
  (`editAdapter.ts`, replacing the old flatten-everything-to-`other`
  `existingPhotoUrls`) now preserves each existing photo's real category
  through an edit, rather than silently re-bucketing the whole gallery into
  `other` the way the pre-M17 code did. `ListingForm.tsx` gained a
  per-tile "which room is this?" sheet, category options scoped to
  Residential/Commercial via `photoCategoriesFor` (`features/listings/types.ts`).
- **Location picker**: unchanged, still blocked. `react-native-webview` and
  `expo-location` are still not in `package.json` — checked again at the
  start of this work, not assumed from the earlier note.

*Original scope write-up below, kept for the reasoning it recorded before
implementation started.*

- **Close Deal + Claim Reward.** The single biggest functional hole in owner
  mode. `POST` endpoint is already typed in
  `src/api/endpoints/properties.ts` but nothing calls it. Website's
  `components/Properties/CloseDealModal.jsx` is the reference: owner picks
  closing type (sold/rented, defaulted from listing type), uploads closing
  documents, selects the buyer from `interestedUsers`, submits. This is what
  triggers the reward payout — until this exists, an owner on mobile has no
  way to ever claim a reward.
- **Add/edit property location picker.** Not built at all today (distinct
  from the detail-page locator map above). Shares the same native-module
  dependency (§5.1).
- **Per-room categorised photo upload.** Website buckets photos into
  `categorizedImages.residential.kitchen` / `.bedroom` / etc. Mobile
  (`src/features/listings/formData.ts`) only offers one flat `other` bucket
  today — deliberately descoped in M8, not a technical blocker. Re-read
  `buildEditFormData`'s reasoning (§2.10) before touching this: the edit-flow
  image landmine (omitting `existingCategorizedImages` wipes the gallery) is
  still real and must stay handled once per-room UI is added.

### M18 — Rewards depth

- **Reward tiers.** Website (`client-next/src/app/rewards/dashboard/RewardsDashboardContent.jsx`,
  `TIER_CONFIG`) has Bronze/Silver/Gold/Diamond. Mobile's
  `app/rewards/index.tsx` shows balance + referral link + store/redeem only
  (already built, §2.9) — no tier system.
- **Rewards Terms page.** Website has a dedicated 127-line subpage
  (`client-next/src/app/rewards/terms/RewardsTermsContent.jsx`). New mobile
  route, static content, no data layer needed.

### M19 — Project extras

- **Brochure + RERA certificate download.** Website
  (`client-next/src/app/projects/[id]/ProjectDetailContent.jsx` L319–324,
  `.../units/[unitTypeId]/UnitDetailContent.jsx` L362–368) links
  `project.media.brochureUrl` and a RERA cert URL. Mobile's project/unit type
  layer doesn't carry these fields yet — add to `types.ts`/`adapters.ts` in
  `src/features/projects/` before the screens can render them.

### M20 — Content & marketing pages

None of these exist in mobile as routes today — no stubs, nothing. All are
static-to-mostly-static content, low risk, no shared state with the rest of
the app. Website sources:

| Page | Website route |
|---|---|
| Blog list + post | `client-next/src/app/blog/`, `blog/[slug]/` |
| About | `client-next/src/app/about/` |
| Why DealDirect | `client-next/src/app/why-us/` |
| FAQ | `client-next/src/app/faq/` |
| Contact / Support | `client-next/src/app/contact/` |
| Press & Impressions | `client-next/src/app/press-impressions/` |
| Privacy Policy | `client-next/src/app/privacy/` |
| Terms of Service | `client-next/src/app/terms/` |

Matches screens #43–44 in the original architecture plan's screen order
(§4 of that document), which anticipated blog/contact but not the other six —
those are new scope from the 2026-08-08 audit.

### M21 — Platform polish

- **Enable collections rails.** Already built and tested
  (`src/features/home/collections.ts`, `CollectionRail.tsx`) — 15 curated
  rails (Luxury, Sea View, Starter Homes, …), each gated on live result count.
  Not currently mounted on Home. One `COLLECTIONS.map()` call away (§2.8).
  Do this first in this milestone — it's minutes of work, not days.
- **Sentry.** Website has it wired; mobile has no DSN configured anywhere.
  Blocked on Chirag supplying a DSN — flag this rather than guessing one.

### M22 — Store readiness

This is the original plan's **M14**, reactivated rather than redefined. See
`MOBILE_APP_ARCHITECTURE_PLAN.md` §M14 and §1.27–1.28 for the App Store /
Play Store requirements already documented there. Sequence last, once M15–M21
are settled — a store listing for a half-finished feature set is wasted
effort.

### Explicitly declined — do not re-propose

Two items came up in the audit and Chirag turned them down. Don't rebuild
them without asking again:

- **WhatsApp contact/share buttons** — website has them on project/unit
  detail, my-properties, and blog (`wa.me` links). Declined for mobile.
- **Newsletter signup** — website's footer version is itself a non-functional
  stub (`Footer.jsx`, `handleSubscribe` just simulates success via
  `setTimeout`, no real API call). Not worth porting a fake feature.

**Agreements (M10 of the original plan): the withdrawal stands.** Resolved
2026-08-13 (§9.1 D1) — Chirag confirmed agreements are out of the product,
matching the website's own removal (page 404s, navbar links commented out,
backend mount commented out in the working tree). It is no longer "the
biggest open item"; it is a withdrawn feature. Do not re-propose it.

---

## 9. 2026-08-13 — Decisions, defect register, wave roadmap (PLAN OF RECORD)

Produced from a four-way sweep: the website's reachable surface (every navbar,
footer, and in-page link followed), the mobile app's real wiring (every route,
entry point, and dead affordance), the original architecture plan, and a
business-logic parity pass reading website page components against mobile
feature modules, with the backend controller settling every disagreement.
Where this section disagrees with §1–§8, this section wins. It also folds in
the still-open items from `HANDOFF_AUDIT_2026-08-09.md` §6, which remains the
authority for the auth details it documents.

**Backend rule, restated and non-negotiable:** every fix below is mobile-side
client code. The backend is live in production and is not touched. If an item
below ever seems to need a backend change, the scope was misread; stop and
re-check the website's implementation (the website ships all of this against
the same backend today).

### 9.1 Product decisions (Chirag, 2026-08-13)

**D1 — Agreements: withdrawal stands.** Delete the three placeholder routes
(`app/agreements/index.tsx`, `generate.tsx`, `[id].tsx`; nothing navigates to
them and the backend mount is commented out at `backend/server.js:869`). Keep
`src/api/endpoints/agreements.ts` and `src/types/backend/agreement.ts` on
disk with a header stating the feature is withdrawn (audit §4.2 asked for
exactly this), so the six typed endpoints are never read as an invitation.

**D2 — Messages/chat: unmount entry points, keep the code.** The website's
own pattern: chat is fully built there too (`ChatContext.jsx`,
`ChatWidget.jsx`) and mounted nowhere. Mobile mirrors it:

- Remove the Hero header Messages icon and its unread badge
  (`Hero.tsx:114-127`, `app/(tabs)/index.tsx:86,147-149`, the
  `useChatUnreadCount` import at `index.tsx:7`).
- Remove the "Message owner" action from property detail
  (`DetailActions.tsx:142-144` and its `onMessage` prop;
  `app/property/[id]/index.tsx:9,128,137-147`).
- Stop mounting `<SocketProvider>` and `<PushBridge />`
  (`app/_layout.tsx:21-22,77-78`). Both exist solely for chat; leaving them
  mounted keeps a live socket connection and a notification permission prompt
  serving a feature with no UI.
- Remove the `chat` `Tabs.Screen` registration (`app/(tabs)/_layout.tsx:35-44`,
  already `href: null`) and update `src/ui/TabBar.tsx:26-38`, whose "WHERE
  MESSAGES WENT" comment becomes wrong.
- Everything else stays on disk untouched: `app/(tabs)/chat.tsx`,
  `app/chat/[conversationId].tsx`, `src/features/chat/`, `src/socket/`,
  `src/notifications/`, the endpoint declarations, and the
  `socket.io-client` / `expo-notifications` dependencies.
- Known residue, accepted: expo-router registers routes from files, so
  `dealdirect://chat` deep links still resolve. No in-app path reaches them.
  If that ever matters, add a redirect guard; do not delete the screens.

**D3 — Rewards redemption: separate workstream, real money involved.** Not
part of this plan. No redemption UI ships from this roadmap: the in-house
store/redeem endpoints are deleted in the working tree (the website already
has zero callers of either; its Redeem tab is the Hubble SDK iframe,
`RewardsDashboardContent.jsx:373-375`), and the Hubble question (WebView,
token handoff, the no-Origin CSRF constraint from `API_CONTRACT.md` §1.2)
gets its own plan document and its own approval before any code. What this
plan does do to the rewards screen is display-only honesty (W3 below).

**D4 — Group buy: HELD.** Group buy is still being worked out on the website
itself. No campaign feature work (offer display, join/exit changes, campaign
payment-proof changes) until the website settles. Existing campaign screens
stay as they are. The parity findings are parked in §9.5 so they are not lost.
Booking wire-correctness fixes (F5–F8) proceed anyway: they are objectively
wrong against the current backend regardless of where group buy lands.

### 9.2 Search and Home IA — the rebuild spec

Decision: **the home bar becomes the real search; the Search tab is the
results surface; one implementation.** This is the website's own model (hero
input with live suggestions submitting to `/properties`; the website has no
separate `/search` route at all).

What is wrong today, precisely:

- The home "search bar" is a fake: a `PressableScale` with static grey text
  (`Hero.tsx:224-249`, admitted in its own comment at `:218-223`). Tapping it
  opens `SearchSheet`, a full-screen modal users read as "it redirected me".
- The filter icon inside it (`Hero.tsx:248`) does nothing, and `SearchSheet`
  has no filter UI at all.
- `Hero`'s `onSearch` prop is dead (declared `Hero.tsx:76,90`, passed at
  `index.tsx:141`, never called), as is its `SearchBar` import (`Hero.tsx:7`).
- "View all" and the CTA banner navigate to the Search tab but their params
  are discarded by the early return at `app/(tabs)/search.tsx:81` (it only
  proceeds on `search` or `listingType`), so both land on an empty screen.
  `sort` is dropped even when the effect does run (`search.tsx:75-78`).
- On the Search tab, typing shows suggestions only; results render solely
  after an explicit commit (`search.tsx:95`). Deliberate (`search.tsx:32-48`)
  and correct under the 20/min limiter, but combined with the fake home bar it
  reads as "search doesn't work".

The spec:

1. **Hero search becomes a real `TextInput`** with the existing suggestion
   machinery (`useSuggestions`: 450 ms debounce, 2-char minimum — keep both,
   §5.2's limiter is why) and recent searches beneath, rendered on Home, not
   in a modal. Committing (keyboard search key, suggestion tap, recent tap)
   routes to the Search tab with the chosen params and `editing` off.
2. **The Search tab accepts and applies every route param it can honour**:
   `search`, `listingType`, `sort`, and the client-side filter params. Fix the
   `search.tsx:81` early return so "View all" (sends `sort`) and the CTA
   banner (sends nothing: land in browse-all state showing newest, not an
   empty prompt) both arrive on a live results screen.
3. **The filter icon opens the existing `FilterSheet`** (built in M3/M15),
   from both the hero bar and the Search tab.
4. **Delete `SearchSheet.tsx`** and the dead `onSearch` prop and `SearchBar`
   import in `Hero.tsx`. One search implementation, per §5.3.
5. **Buy/Rent keep pushing `listingType`** (verified end-to-end into the
   controller's `$in` expansion). Until the deploy in §9.6 happens, the live
   API ignores the param and Buy/Rent open unfiltered results (§3.1). The
   rebuild does not fix that; only the deploy does.
6. **No per-keystroke result queries.** Suggestions per keystroke are the
   budgeted affordance; results on commit, same as the website. §5.2 stands.

### 9.3 Defect register — fix these, no decisions needed

IDs are stable; strike them through here when fixed. Severity: **wire** =
silently wrong data or guaranteed failure, **ux** = works but reads broken,
**parity** = website has it, mobile doesn't, **hygiene** = dead/stale code or
copy.

| ID | Sev | Where | Defect → fix |
|---|---|---|---|
| F1 | wire | `features/rewards/hooks.ts:35`, `types/backend/rewards.ts:14-19`, `app/rewards/index.tsx:76` | Reads `wallet.balance`; the service returns `{totalPoints, availablePoints, tier, tierMultiplier, nextTierProgress, recentTransactions}` (`rewardService.js:314-329`). The `?? 0` fallback means **every user sees 0 points, always**. Read `availablePoints`; retype the wallet. |
| F2 | wire | audit §1.3, §6.1 | Password reset is 100% broken: built from a dead website helper (email + link fiction). Rebuild phone-based: `{phone}` → SMS OTP → new `reset-password` screen with `{phone, otp, newPassword}`. Five files, listed in the audit. |
| F3 | wire | audit §1.5, §6.2 | Buyers are sent through OTP registration the website never asks of them. Branch on the role chip: `user` → `POST /users/register-direct` (session immediately), `owner` → `register` + `verify-otp`. Declare the missing endpoint. |
| F4 | wire | audit §1.6, §6.3 | Referral codes silently dropped on both registration paths. Owner path: carry the code to `verify-otp` (that is where attribution happens, `userController.js:456-458`). Buyer path: fixed by F3, `register-direct` reads it directly. |
| F5 | wire | `features/projects/bookings.ts:66` | Sends `utr`; the controller destructures `utrNumber` (`bookingController.js:161`). The typed reference number is discarded and the admin gets "screenshot only". Rename the field. |
| F6 | wire | `types/backend/project.ts:181-187`, `app/projects/booking/[bookingId].tsx:111,118` | Types `payment.utr`/`payment.verified`; the model has `utrNumber`, `status: pending\|submitted\|verified\|rejected`, `rejectionReason` (`ProjectBooking.js:80-94`). Both reads are permanently `undefined`, so the screen re-offers the submit form forever and can never show verified/rejected. Retype; render status + rejection reason + resubmit, as `MyBookingsContent.jsx:120-227` does. |
| F7 | wire | `app/projects/unit/[unitTypeId].tsx:129-134` | Booking sheet never checks auth; a guest fills the whole form and 401s at submit (route is `authMiddleware`-gated, `bookingRoutes.js:22`). Gate before opening, as `UnitDetailContent.jsx:233-240` does. |
| F8 | wire | `app/projects/booking/[bookingId].tsx:60,177` | Demands UTR **and** screenshot; backend and website accept either (`bookingController.js:164-166`). Loosen to either. |
| F9 | ux | §9.2 | The whole search/IA rebuild (home bar fake, params dropped, filter icon dead, SearchSheet duplicate). |
| F10 | ux | audit §1.4, §6.4 | OTP arrives by SMS; `verify-otp.tsx:84,101` and `endpoints/users.ts:33` say email. Pass the phone through as a display param; fix three strings. |
| F11 | parity | `features/properties/interest.ts:82-117` | The interest/post-property reward is earned but never shown: the mutation's `reward` return is discarded, where the website routes it to a reveal (`PropertyDetailsContent.jsx:917-919`, `RewardRevealRouter.jsx`). Minimum viable: a result sheet/toast showing points won on interest, add-property, and edit paths. No spin-wheel port required. |
| F12 | parity | `app/rewards/index.tsx`, `features/rewards/hooks.ts:90-99` | No tier, multiplier, next-tier progress, referral breakdown, or transaction pagination; the service returns all of it (`rewardService.js:340-346,466-489`). Display-only (D3). Also retire `pickTransactions`' multi-key guess: the key is confirmed `transactions`. |
| F13 | parity | `features/listings/formData.ts`, `features/listings/types.ts:44-89` | Add-listing fields the website sends and mobile cannot: `area.superBuiltUpSqft`/`plotSqft`/`pricePerSqft`, `availableFrom`, `legal.occupancyCertificate`/`tradeLicense`/`fireNoc`, `address.nearby`, `imagesToRemove` on edit. All verified to reach the document. (`latitude`/`longitude` wait for the map/dev-client rebuild; `videoUrl` is edit-path-only by whitelist and stays out until a URL field is worth it.) |
| F14 | parity | `CloseDealSheet.tsx:41-42,96-103` | Mobile offers Sold/Rented chips; the website derives `closingType` from `listingType` and shows it read-only, so an owner here can mark a sale "rented". Derive and display, don't ask. Also add the website's 15 MB per-file cap (`CloseDealModal.jsx:64`) next to the existing count cap. |
| F15 | hygiene | `app/(dev)/gallery.tsx:35` | Claims "excluded from production builds"; no exclusion exists (no dev-route filtering anywhere). Exclude it for real (env-gate the route or move it out of `app/`) or delete the claim and accept it ships. |
| F16 | hygiene | `app/(tabs)/_layout.tsx:29` | The tab bar's Post button pushes `/owner/property/new` for guests and buyers with no gate at the navigation site. Gate on auth + role, mirroring the owner surface. |
| F17 | hygiene | `features/search/filters.ts:97-99`, `src/api/client.ts:14-16`, `CloseDealSheet.tsx:23-26`, `features/projects/campaigns.ts:47-51` | Four stale comments that contradict verified reality (listingType "doesn't exist" (it does), CSRF "no route enforces it" (twelve do, app exempt via no-Origin), an interested-users gate the website doesn't have, a group-buy limiter that doesn't reach campaigns). Fix the comments; each one is a future bug factory. |
| F18 | hygiene | `features/notifications/targets.ts:24-29` | No target for chat-type notifications; moot once D2 lands, but confirm notification rows for conversations degrade gracefully (no dead tap). |

### 9.4 Waves — the order of work

> **STATUS 2026-08-13: W1–W5 are all implemented.** Verified with
> `npx tsc --noEmit` (clean), `npx expo lint` (0 errors; pre-existing warnings
> down from 13 to 11) and `npx expo export --platform android` (succeeds).
> **Untested on a device**, the same caveat every milestone in this document
> carries. What each wave actually shipped, and where it diverged from the
> scope below, is recorded in §9.9.

Each wave is independently shippable and verified with the §6 commands plus,
finally, a device pass (nothing from M7 onward has ever run on hardware; see
the standing caveat in §2.14).

- **W1 — Correctness on the wire.** F1–F8, F10. Auth first (F2, F3, F4, F10:
  the audit's own fix order), then the rewards balance (F1), then the booking
  trio (F5, F6, F7, F8). Nothing here changes IA; it makes existing screens
  tell the truth.
- **W2 — Search/IA rebuild + unmounts.** F9 per the §9.2 spec, D1 (delete the
  agreement stubs), D2 (unmount chat), F15, F16, F17, F18.
- **W3 — Rewards honesty (display only, per D3).** F11, F12, plus the M18
  terms page (static). The store/redeem sections come off the screen
  (`app/rewards/index.tsx:90,143-222`) and their hooks are retired; the
  endpoint declarations get a header noting the backend routes are deleted in
  the working tree.
- **W4 — Owner parity.** F13, F14.
- **W5 — Content, polish, store.** M20 pages (unchanged from §8), M21
  (mount the collections rails, one `COLLECTIONS.map()`; Sentry still blocked
  on a DSN from Chirag), then M22/M14 store readiness last.

**Held / blocked (unchanged owners):** group buy feature work (D4, §9.5);
rewards redemption (D3, separate workstream); the map bundle (locator +
location picker, blocked on the one dev-client rebuild covering all four
pending native modules, §5.1); universal links (needs Apple Team ID + Android
signing SHA-256, §2.13); true server push (needs a backend change request,
§2.14).

### 9.5 Parked group-buy findings (do not lose, do not build yet — D4)

- The campaign screen never shows the offer: no `discountPerBuyer`, no
  `buyerTargets.minBuyers/maxBuyers` progress, no `perks[]`
  (`app/projects/campaign/[campaignId].tsx:163-167`); users are asked to join
  terms that aren't on screen.
- The two products currently have different group-buy semantics: the website's
  "Join Now" opens the unit **booking** modal and never calls the campaign
  API; mobile built real join/exit membership against
  `/campaigns/:id/join|exit` (endpoints are real and correctly wired). Which
  semantics win is part of the website's in-progress group-buy work; decide
  there first.
- The website's campaign cards read `c.name`/`c.endDate`; the model stores
  `basics.name`/`duration.endDate`, so mobile is right and the website is
  wrong (§9.7). Do not "fix" mobile to match.

### 9.6 Deploy and repo state — the prerequisite everything sits on

Production is `origin/main`. `main` is 4 commits ahead, and effectively all of
M7–M17, this document, and the backend's agreements/rewards removal exist
only as **uncommitted working-tree changes**. Two consequences:

1. **Commit locally in coherent units** (mobile milestones, backend removals,
   docs) so the working tree stops being the only copy of six weeks of work.
   Local commits are fine; **pushing is deploying** (Hostinger imports
   `origin/main`) and needs Chirag's explicit go, per standing instruction.
2. **The next push changes the API under the app**: `listingType` starts
   working (Buy/Rent become real: the highest-leverage single change for the
   app), agreements go 404 (harmless once D1 lands), store/redeem go 404
   (harmless once W3 lands). Sequence W2/W3 before or with the deploy so
   nothing user-visible breaks on deploy day.

### 9.7 Website defects found in passing (not mobile scope)

For a separate website pass; recorded so they aren't rediscovered:

- `profile/ProfileContent.jsx:1155` still links "Rent Agreements" →
  `/agreements`, which 404s. The one surviving link to the withdrawn feature,
  reachable from the navbar's Settings entry.
- `HomeContent.jsx:455`: the "Why Choose" tile promises "Chat directly with
  owners"; no chat is mounted anywhere on the site.
- Hero search discards the BHK chips (`subFilters.bhk` is written,
  `buildSearchParams` never emits it) and `commercialSubTypes`; it emits
  `status`/`possession`/`furnishing` params no UI can set.
- The scrolled-navbar search is a third, divergent implementation: it fetches
  the entire unbounded `/properties/property-list` client-side to score
  suggestions and drops city/intent/budget on submit.
- Campaign cards read `c.name`/`c.endDate` instead of
  `basics.name`/`duration.endDate` (`UnitDetailContent.jsx:168,172`).
- `sitemap.js` omits live public routes: `/projects`, `/faq`, `/coming-soon`,
  `/press-impressions`, `/rewards`.
- Already recorded elsewhere, listed for completeness: the login page's
  phone-field lockout (audit §7.4), `normalizePrice` inflating Lac rows in
  the website's own filter/sort (`API_CONTRACT.md` §8 #5), the fake footer
  newsletter (§8 "Explicitly declined").

### 9.9 What W1–W5 actually shipped (2026-08-13)

Implementation notes, in the order the work happened. Where the code diverged
from §9.3's scope, the reason is here and the code carries it too.

**W1 — correctness on the wire.**

- **F2, F3, F4, F10 were already fixed** in the uncommitted working tree by an
  earlier session: forgot/reset-password is phone-and-SMS with a real
  `app/(auth)/reset-password.tsx`, `registerDirect` exists on `AuthProvider`
  and `register.tsx` branches on role, `verifyOtp` carries `referralCode`, and
  the verify screen displays the phone. The audit's fix list read as pending
  and was not. One thing genuinely remained: the register screen promised
  every signup "a 6-digit code" including buyers who never get one — now
  role-aware.
- **F1** — `rewards.ts` types were rewritten against the service functions
  that produce them, not guessed: the wallet is
  `{totalPoints, availablePoints, tier, tierMultiplier, nextTierProgress,
  recentTransactions}`. `useWallet` reads `availablePoints` and now also
  exposes tier, multiplier and progress. `pickTransactions`' multi-key guess is
  retired — the key is `transactions`, with a `pagination` block beside it.
- **F5, F6, F8** — `utr` → `utrNumber`; `payment` retyped against
  `ProjectBooking.js` (`status` enum, `rejectionReason`, no `verified`
  boolean); the booking screen now renders verified / awaiting / rejected
  states with the reference number and a resubmit path; either proof suffices.
- **F7** — the unit screen gates on auth before opening the booking sheet, and
  the button reads "Sign in to book" for guests.

**W2 — search rebuild and unmounts.**

- **F9** — `HeroSearchField` (new) replaces the fake bar: a real `TextInput`
  with the existing debounced suggestions and recent searches in a panel
  anchored under the field. `SearchSheet.tsx` deleted. The filter icon opens
  the real `FilterSheet` via `openFilters=1`. The Search tab now accepts
  `search`, `listingType`, `sort`, `browse` and `openFilters`, and a new
  `browsing` state makes "show me everything" a real results state — which is
  what fixes "View all" and the CTA banner landing on an empty screen.
- **D2** — chat unmounted: Hero's Messages icon, property detail's "Message
  owner" (and `DetailActions`' `onMessage` prop), `SocketProvider` and
  `PushBridge` in `app/_layout.tsx`. The `chat` route stays registered with
  `href: null`; **deleting that declaration would put Messages back in the tab
  bar**, which is why it is still there. All feature code, the socket layer
  and both dependencies remain on disk.
- **D1** — `app/agreements/` deleted. `endpoints/agreements.ts` keeps a header
  stating the withdrawal and the HMAC precondition for any future restore.
- **F15** — the dev gallery's "excluded from production" claim is now enforced
  with a `__DEV__` guard instead of asserted. Metro still bundles the module;
  this is a reachability guard, not a size win.
- **F16** — the tab bar's Post button routes guests to login.
- **F17** — four stale comments corrected. The `client.ts` one became the
  no-WebView-may-call-this-API constraint rather than just a fact.

**W3 — rewards.**

- **F12** — the rewards screen shows tier, tier multiplier, a next-tier
  progress bar and the referral milestone breakdown. Store and redeem sections
  are gone (D3); a card states plainly that redemption happens on the website
  and links there. `useRewardsStore`/`useRedeemReward` deleted from the
  feature's exports with a note not to re-add them.
- **F11** — `useInterest` now surfaces the `reward` it used to discard, via
  `lastReward`/`clearReward`, and invalidates the wallet when points land.
  `RewardReveal` (new) is mounted on property detail and on add-listing, where
  it is shown BEFORE navigating away (navigating first would unmount the
  reveal, which is how the award went unseen). **Not a spin wheel**: the points
  are decided server-side before the response arrives, so the animation is
  theatre over a settled number — the component doc says so, and is the one
  place to change if that judgement is revisited.

**W4 — owner parity.**

- **F13** — added `area.superBuiltUpSqft`, `area.plotSqft`, `availableFrom`,
  the three `legal.*` compliance booleans and `address.nearby`, all verified
  against both the add whitelist and the schema. `area.pricePerSqft` is
  **derived** from price and area rather than asked for, the way the website
  derives it, and deliberately not read back on edit so it cannot go stale
  against a changed price. The legal booleans are sent only when true: an
  unticked box means "not stated", not "does not have one". `latitude` and
  `longitude` still wait on the map/dev-client rebuild; `videoUrl` stays out.
- **F14** — the close-deal outcome is derived from `listingType` and shown
  read-only, so an owner can no longer mark a sale listing "rented". The
  website's dead-end case (a listing type matching neither, which its own modal
  blocks with no selector to satisfy) gets a sane answer here.
- **The 15 MB file cap was NOT added**, deliberately. Every picked photo goes
  through `compress` (1600px, JPEG 0.7), which lands far under both the
  website's 15 MB and the backend's 10 MB, so the check could never fire. The
  reasoning is recorded at the call site; if arbitrary file upload is ever
  added, the cap has to come with it.

**W5 — content and rails.**

- **Collections rails mounted**, but three of fifteen, not all. `/properties/search`
  allows 20 requests per minute per IP and Home already spends three; fifteen
  more would put a single scroll over budget and fail as a 429 on the next
  screen. `HOME_COLLECTION_IDS` is the list and carries that reasoning; the
  other twelve stay resolvable via `findCollection`.
- **Blog** — `app/blog/index.tsx` and `app/blog/[slug].tsx`, on the real
  `/blogs` endpoints (free-text param is `q`, addressed by **slug**, `related`
  alongside `data`). Post content is HTML from the admin editor and is rendered
  as **text**: block tags become paragraph breaks, the rest is stripped,
  entities decoded with the existing helper. Faithful rendering needs a WebView
  or an HTML renderer — a native module or a dependency for one screen. What is
  lost is inline emphasis, links and embedded images.
- **`app/support.tsx`** — one Help & about screen instead of the website's
  seven content routes. Carries the FAQ (ported from the website, with the
  redemption answer amended because the website's copy still describes a store
  it no longer ships), support email and phone from the website footer, and
  links out to About / Why DealDirect / Privacy / Terms.
- **Privacy and Terms are links, not screens, on purpose.** Legal text needs
  one source of truth: a copy baked into a shipped binary drifts silently and
  cannot be corrected until the next release is adopted. The links are omitted
  entirely when no `WEB_URL` is configured rather than built against a guessed
  origin. **Press & impressions was not ported** — it targets journalists and
  does not belong in a buyer's app.
- Both new destinations are reachable from the Profile tab.

**Still open, unchanged:** everything in §9.4's held/blocked list — group buy
(D4), rewards redemption (D3), the map bundle, universal links, server push —
plus the device pass and the deploy (§9.6).

### 9.10 The UI pass (2026-08-13/14) — what changed and the rules that follow

Chirag's brief: "except home page the complete app's UI/UX is shit." Correct,
and the causes were structural rather than a matter of taste. Home had been
redesigned; nothing else had, and four systemic faults made that gap look
worse than it was.

**The four root causes, all fixed.**

1. **The app rendered in two typefaces.** `FontOverrideProvider` was mounted at
   Home's root only, so Home was DM Sans and every other screen was the
   platform system face. Moving between tabs looked like moving between two
   products. The provider now sits in `app/_layout.tsx`. The trade is real and
   recorded in `theme/fonts.ts`: system faces ship optical sizing that one
   bundled webfont does not, and we take that hit to make the app look like
   itself.
2. **`global.css` and `colors.ts` disagreed, and the CSS side won.**
   `--color-background` and `--color-surface` were both bound to pure white,
   while `colors.ts` had already dropped the page a step down the ramp and
   written a long comment explaining why. `Screen` renders
   `className="bg-background"`, so it read the CSS: every screen was a white
   card on a white page, which is why cards needed borders and the app read as
   an admin panel. Both files now bind `palette.canvas`, and `Card`'s
   `bordered` default flipped to `false`.
3. **Twenty screens hand-rolled the same header**, no two agreeing on padding,
   title size, or the back button's fallback. Now one `ScreenHeader`. The
   conversion is in `scripts/adopt-screen-header.mjs`, kept in the repo: it
   rewrote 13 files mechanically and REPORTED the 7 variants (trailing
   actions, close icons, floating discs) for hand-work rather than mangling
   them.
4. **Headers padded at 20 while content padded at 16.** On nearly every screen
   the title sat 4pt outside the content beneath it, and several screens padded
   their skeleton at 20 and their loaded list at 16 — so content jumped
   sideways the moment data arrived. `screenPadding` is now a token and
   everything reads it.

**New primitives** (`src/ui/`): `ScreenHeader` + `HeaderAction`;
`ListGroup`/`ListRow`/`SectionLabel` (the grouped list, with separators inset
to the row's text — the detail that most separates a native list from a web
one); `Stat`/`StatRow`/`ProgressBar`/`Segmented` (each of which previously
existed twice under two names); and `Toast`.

**Toast matters more than it looks.** The app had no non-blocking notification
surface, so every "saved", "removed" and "sent" was an `Alert.alert` — a modal
with a button, to confirm the thing the user just asked for. Eleven screens did
this. `Alert.alert` stays for destructive confirmations and errors that must be
acknowledged; everything else should move to `useToast()`.

**Two real bugs found while in there.** `Button`'s disabled state never
rendered — its animated `style` returned `opacity: 1` unconditionally and
merges after NativeWind's compiled classes, silently overriding `opacity-50`,
so every disabled button in the app looked enabled. And `Card`'s press
feedback dimmed, which is the language of *disabled*; it springs now, like
everything else.

**Rules that follow, for anyone adding a screen:**

- Never hand-roll a header. `ScreenHeader`, always, and pass `backTo` — a
  screen entered by deep link has no history and `router.back()` strands the
  user.
- Never hard-code a horizontal page margin. `screenPadding`. The skeleton and
  the loaded content must use the same one.
- A list of options is `ListGroup` + `ListRow`, not a `Card` with hand-built
  rows and full-bleed separators.
- Press feedback is scale (`PressableScale`), never opacity. Opacity means
  disabled.
- A tab screen uses `edges={['top']}` — `TabBar` already pays the bottom
  inset, and the default `['top','bottom']` pays it twice.
- Confirmations are toasts. Modals are for questions.

**The auth screens and the alert sweep — done 2026-08-14.**

*Auth.* All five screens now share `AuthShell` (`src/auth/components/`). What
it fixed: four centred their content and register did not, so the title jumped
vertically between screens; all five padded at 24 against the app's 16; and
each carried a different way back (a ghost Button, a bare Pressable, nothing).
Centring is now a prop rather than a habit — `center={false}` on register and
reset-password, because `justifyContent: 'center'` on a scroll view whose
content exceeds the viewport clips the TOP, putting the title out of reach.

Their four bespoke terminal states ("Code sent", "Password updated", "Session
expired", "Missing details") were `EmptyState`'s layout hand-written four
times with three different spacings. They are now `AuthResult`, which adds the
thing all four lacked: an icon, so success and failure no longer render
identically apart from their words. `EmptyState` gained one prop
(`actionVariant`) so its action can be primary when it *is* the screen.

*Alerts.* Thirteen down to eight, and the eight that remain are correct. The
rule applied: **a modal is for a question, a toast is for an answer.** Every
surviving `Alert.alert` is a destructive confirmation ("Delete listing",
"Leave this group buy?", "Log out") or a real question ("Resume draft?"), and
each now fires a toast on completion rather than leaving the user to infer it
worked. Converted to toasts: the close-deal submission notice, the OTP resend
confirmation, the photo-permission explanation, and the invalid-video error.

One deliberate exception, documented at the call site: "Cannot place calls"
stays a modal because it carries the number the user must now dial by hand,
and a toast that vanishes in 2.6 seconds is not long enough to read and
transcribe ten digits.

**The off-centre button — a one-line cause with an app-wide effect (2026-08-14).**

Reported as "the sign-in button is shifted right, not centred". The cause was
`Button` hard-coding `self-start` whenever `fullWidth` was false, with no way
to override it. **`alignSelf` beats the parent's `alignItems`**, so every
button inside a centred container was dragged to the leading edge —
`EmptyState`'s action, `ErrorState`'s retry, and every guest gate in the app.
Those are the most-seen screens for a signed-out user, and all of them looked
broken.

`Button` now takes an `align` prop. `start` remains the default, because a
button with no alignment inherits RN's `alignItems: 'stretch'` and grows to
fill its row, which is worse — but it is a default now rather than a decree,
and `EmptyState`/`ErrorState` pass `center`.

**Guest gates, rebuilt as `SignInPrompt` (`src/auth/components/`).** Six
screens rendered a bare `EmptyState` with one button, and they shared two
faults beyond the alignment bug:

- **They offered no way to create an account.** A brand-new user — the person
  most likely to be looking at a signed-out screen — could only "Sign in".
  They had to find that screen, read it, and notice the create-account link at
  the bottom. `SignInPrompt` offers both paths.
- **They were undifferentiated**: identical title-over-button on all six,
  which reads as a wall rather than an invitation. Each now carries a tinted
  icon well naming what is behind the gate, and the title names the *thing*
  ("Your rewards") rather than the act ("Sign in to see your rewards").

**Also swept:** the last three off-token greys (`#9AA0A6`, `#94a3b8`) replaced
with `theme.colors.textMuted`; and two project rows that wrapped a `Card` in a
bare `Pressable` with no `style` callback — they acknowledged a touch with
nothing at all, and now use `Card`'s own springing `onPress`.

**Still outstanding:** `chat/[conversationId]` keeps a hand-rolled header with
a magic `HEADER_HEIGHT = 56` keyboard offset — left alone deliberately, since
chat is unmounted (§9.1 D2) and touching an unreachable screen's layout is
work with no way to verify it.

### 9.11 The five-surface redesign (2026-08-14) — references and decisions

Chirag asked for premium real-estate app references and five surfaces built
against them. The references, and what was taken from each:

| Source | What it settled |
|---|---|
| [UX Planet — bottom tab bar practices](https://uxplanet.org/bottom-tab-bar-design-best-practices-ef3ee71de0fc) | 3–5 destinations max; ~49pt bar; min 3:1 contrast; no scrollable bar; standard icons only if going icon-only |
| [Mobbin — real estate](https://mobbin.com/explore/mobile/app-categories/real-estate) and [tab bar](https://mobbin.com/explore/mobile/ui-elements/tab-bar) | Shipped patterns rather than concept work; floating/curved docks as the emerging convention |
| [Airbnb design notes](https://github.com/VoltAgent/awesome-design-md/blob/main/design-md/airbnb/DESIGN.md) | 14px property-card radius; fixed card aspect with column count changing, never reflowing rows |
| [Zillow/Redfin patterns](https://www.designmonks.co/blog/real-estate-website-ux-design-examples) | Progressive filtering — location and price first, then the rest; results update instantly |
| [Real estate UI trends 2026](https://techlancersme.com/blogs/ui-ux-design-tips-for-real-estate-apps-2026/) | Sticky thumb-reachable CTAs; restraint over density |

**1. The dock (`ui/TabBar.tsx`) — a floating pill.** The old bar was
edge-to-edge on a hairline with four icons, four labels and a 2pt rule under
the active one: legible, and completely forgettable. It floats now, so content
scrolls visibly beneath it and it becomes an object with a shape that can
carry a shadow.

The active tab **expands** to show its label; the others are icon-only. Four
permanent labels at 11pt is four pieces of text competing, and "Properties"
either truncates or drags every other label smaller with it. Showing the label
only for the current tab also produces the strongest possible active state —
the selected tab is a different SHAPE, which survives low contrast and colour
blindness in a way a colour swap does not. The trade is named in the file:
this is only acceptable because the four glyphs are home, magnifier, heart and
person. A domain-specific icon would need its label back.

Post stays in the dock, against the "destinations only" rule, and the file
says so. Posting is the single thing an owner opens this app to do; the rule
costs more than it is worth here. It is marked as an action by being the only
filled circular element and never taking the selected state.

**2. Search → Properties (`app/(tabs)/properties.tsx`).** Renamed because the
old name described the ACT rather than the destination — three nouns and a
verb in one tab bar — and because arriving from Home's "View all" lands here
with no query at all, which is not searching. Three rows of chrome (filters,
result count, intent chips) collapsed into one scrolling control strip plus a
result bar that only exists once there is a result. Added a **density toggle**:
cards when the photo is deciding for you, compact rows when price and size
are what you are comparing. That toggle is also the cheapest accessibility win
on the screen — the compact row fits roughly 3× as many results, which matters
most to users on large text who see fewest.

**3. Property card.** Now a real surface card at radius 14, which only became
possible when the page background moved to `canvas` (§9.10). The old file
argued *against* a container and was right at the time; that reasoning is kept
rather than deleted, because it says what to revisit if the background ever
goes back up the ramp. **Still no heart** — saving here creates a Lead, emails
the owner and is capped at five, so a heart would promise private, free and
unlimited and be none of them.

**4. Profile.** Rebuilt as the app's only complete index. Home shows
discovery, the dock shows four tabs, and everything else is reachable from
here or nowhere — so the test for this list is coverage, not brevity. Three
groups (yours / the product / your account), then log out alone at the bottom.

**5. Saved and My Properties.** Saved's interest cap became a **meter** rather
than a sentence: "3 of 5 used" states the limit, a filled bar shows how close
the wall is, and it turns danger-toned at the cap where it stops being
information and starts being the reason the next tap will fail. My Properties
gained the two numbers an owner actually opens it for — enquiries and views,
enquiries first because a view is attention and an enquiry is a person — and
Delete moved out of the primary row, where it had been an equal-width danger
button a thumb-width from Edit.

**New tokens:** `brandMuted` (a tinted brand fill for selected states that
must not read as alerts) and `tabBarClearance` (the floating dock means no
scroll view can rely on its own bounds any more).

**6. Home rails and property detail (same pass).**

*Rails.* `PropertyRailCard` and `ProjectCard` both drew a hairline border and
no shadow, while the new browse card draws a shadow and no border — the same
object built two ways depending on which screen it appeared on. Both moved to
the shadow. The rail card's original note argued for the border and was right
when the page was near-white; that reasoning is preserved rather than deleted,
because it records what to revisit if the background moves back up the ramp.

`Section` padded its heading at 20 while `Rail` padded its cards at 16, so
every section title on Home sat 4pt outside the first card it introduced. Both
read `screenPadding` now. Its "View all" was bare coloured text with a chevron
— which reads as part of the heading rather than as a control, and painted
about 18pt tall against a 44pt minimum. It is a tinted pill with a real edge
and a real target.

*Property detail.* The intent chip moved above the price rather than beside
it. "For rent" and "₹45,000" on one line makes the eye choose between them at
equal height; stacked, the chip is read first, which is what tells you whether
the number below is monthly or a purchase price — the difference between a
₹45,000 flat and a ₹45,000 mistake. Section headings gained a rule above them:
the page runs to several thousand pixels of one neutral colour, so the
headings are the only structure the eye has, and `title3` alone was doing that
at the same weight as a card title three lines up.

The sticky action bar gained an **upward** shadow. A hairline alone says "the
page ends here"; the shadow is what makes the last attribute row read as
passing *under* the bar rather than being cut off by it.

**7. The heart is gone from Home's rails — Chirag's decision, 2026-08-14.**

`PropertyRailCard` used to render a heart when the caller passed
`onToggleSave`, and Home passed it. A tap there created a Lead, emailed the
owner, handed over the user's name, email and phone, and silently spent one of
five enquiries — from a thumb brushing the corner of a photo, on the app's
busiest screen.

Removed end to end rather than hidden: the control and both props are out of
`PropertyRailCard`, the pass-through props are out of `PropertyRail`, and Home
no longer reads the interest list at all. `useSavedIds` — the hook that existed
solely to drive it — was deleted with them, since leaving 60 lines of working
toggle logic behind is an invitation to re-mount the control. Nothing lost
capability: the Saved screen uses `useSavedProperties` + `useRemoveInterest`,
and property detail uses `useInterest`.

**Every surface now offers this action the same way**: a labelled button with
a consequence line under it, on the detail screen where there is room for that
sentence. That last part is the real argument, and it is recorded at the top of
`PropertyRailCard` so the next person to reach for a heart on a property card
finds out why there isn't one: *a rail card has no room to say what the action
does.*

### 9.8 Documentation discipline

- **This file is the plan of record.** `HANDOFF_AUDIT_2026-08-09.md` stays
  authoritative for the auth details it documents. `API_CONTRACT.md` is the
  wire truth. `MOBILE_APP_ARCHITECTURE_PLAN.md` is historical design context
  only (it now carries a banner saying so); do not scope work from it.
- Every backend claim in any doc states which backend: `origin/main` (live),
  `HEAD`, or working tree.
- The website's `client-next/src/utils/api.js` is partly dead code. Parity
  work reads page components, never that file. If a helper and a page
  disagree, the page ships; if both disagree with the controller, the
  controller wins.

---

## 10. 2026-08-14 — The portal-parity UI pass

Scope: `dealdirect-mobile` only. Nothing in `backend/`, `client-next/` or
`Admin/` was touched, and no endpoint, param or model changed. Every figure the
new UI shows is either a field already on the row or arithmetic over two of
them.

### 10.1 What was measured, and how

Housing.com, Square Yards and 99acres were opened in a 375×812 viewport and
read through the DOM: computed styles, sticky/fixed element geometry, card
subtree structure, type scale and radius histograms. MagicBricks is blocked by
browsing policy and was not read. NoBroker serves a no-JS shell to that browser,
so only its filter taxonomy came through — which was the useful part.

The findings that drove the work:

| | Housing | Square Yards | 99acres |
|---|---|---|---|
| Sticky pill rail on results | search + bottom nav | Filters · Sort, 52pt | **Sort · Owner · Budget · BHK · Type · Verified · Ready**, 53pt |
| Photo count on card | yes | dark pill, r7, bottom-left | yes |
| ₹/sqft on card | yes | in attribute grid | `₹34,992 /sqyd` |
| Attribute presentation | — | icon + label + value grid | labelled key-facts row |
| Social proof | — | — | "3 people already contacted since last week" |
| Detail sticky CTA | — | 72pt, WhatsApp + Call Back | 54pt, WhatsApp + View Number |
| Detail section nav | — | **yes**, 14 jump links | — |
| Similar rail on detail | — | yes | two of them |
| Research tools on home | **6 calculators** | — | — |

Brand values for reference: Housing `#5E23DC` / Rubik / radii 8·5·10·24;
99acres `#0056B8` / Inter / pills at 1000px; Square Yards Arial / 8px cards,
100px pills.

### 10.2 What changed

**Search results** (`app/(tabs)/properties.tsx`, `features/search`)

- `QuickFilterBar` — the 99acres pill rail. Filters, a compact `Segmented` for
  rent/sale, then facet pills for Sort, Budget, Rooms, Type, Furnishing, and a
  direct possession toggle. A pill shows its facet NAME unset and its VALUE set.
- `FacetSheet` — one facet, applied on tap, no Apply button. `FilterSheet` keeps
  its draft-and-commit model; the note at the top of `FacetSheet` says why the
  two differ rather than one wrapping the other.
- **BHK is a filter for the first time.** Client-only, reconciling the string
  `bhk` and numeric `bedrooms` fields; `'4'` is an open 4-and-up bucket. `1 RK`
  is matched before the digit scan, or the `1` in it reads as a 1 BHK.
- The result count moved into the list as its header, so it scrolls. Fixed
  chrome is still two rows after gaining six facets.
- The rail is NOT inside the screen's horizontal padding, deliberately — a
  horizontal scroll view inside one is clipped short of both edges.
- `priceBand` is now an accepted route param, validated against the table.

**Listing card** (`features/properties/components/PropertyCard.tsx`)

Photo count over the image, ₹/sqft beside the price, an icon fact row replacing
the dot-joined grey spec line, and a "Posted 3 days ago · 142 views" line. Both
densities. `formatRatePerSqft` returns null far more often than it returns a
string — read its guards before loosening them; a wrong rate costs more than a
missing one.

**Property detail** (`app/property/[id]/index.tsx`)

- ₹/sqft under the price, the provenance line under the facts strip.
- `DetailSectionNav` — Square Yards' jump strip. Sections MEASURE themselves in
  through `SectionRegistryContext`; a declared list would scroll people to
  nothing on the many listings that omit a section. Shares the header's
  collapse interpolation via the new exported `useHeaderProgress`.
- A "Similar properties" rail, with its own scorer in `search/related.ts`. It
  shares the search rail's pool query and key, so a user who searches and then
  opens a listing pays for one fetch.

**Home** (`app/(tabs)/index.tsx`, new `features/tools`)

Housing's research-tools section, at two calculators rather than six. The
affordability one models both ceilings Indian lenders apply — FOIR on income and
the LTV cap on the deposit — reports which one bound the answer, and ends in a
search rather than a figure.

### 10.3 What was deliberately NOT copied

- **Verified / RERA badges** (99acres, Square Yards). The backend has no
  verification state for a listing. An unearned trust badge is worse than none.
  It goes in the day the field does.
- **Locality reviews, price insights, commute time** (99acres, Square Yards).
  No data, and the last needs the map phase that is still held on a dev-client
  rebuild (§5.1).
- **Eligibility, Valuation, Rent Value, Area calculators** (Housing). Three need
  a model or data we do not have; Eligibility is Affordability backwards.
- **A heart on the card.** Unchanged and still correct — see §9.7.

### 10.4 Verification status

`tsc --noEmit` and `eslint` are clean across the app; the 14 remaining warnings
all predate this work. **Nothing here has been seen running.** There is no test
runner in this package and no web target (`react-native-web` is not installed),
so a device or emulator pass is the first thing the next session should do.
Highest-risk items to look at first, in order:

1. `DetailSectionNav` — offset measurement, the jump landing point, and that it
   does not eat taps meant for the hero while transparent.
2. `FacetSheet` heights — derived from an 812pt reference, so a small phone will
   scroll where a large one will not.
3. The quick-filter rail's width on a small screen, and that the segmented
   control does not squash.

### 10.5 Second pass — Saved and Profile (same day)

Their shortlist and account surfaces are login-gated on all three portals, so
this pass had no reference to measure against and is not parity work. It is
what going through the two screens carefully turned up.

**Three defects, all previously invisible:**

1. **Tapping a saved search did nothing.** `run()` pushed `{ city }`, a param
   `app/(tabs)/properties.tsx` has never read, and that screen returns early
   from its route effect when none of its known params are present. The tap
   switched tab and left the previous search in place. Fixed by translating the
   stored city STRING through `matchCity` into the `City.id` the results
   filter is keyed by, with a free-text fallback for cities not in the table,
   plus a new validated `city` route param. **The saved-search price band is
   still deliberately not carried** — its three buckets do not line up with the
   results screen's five, and running a subtly different search from the one
   the alert watches would let a user draw false conclusions about their alert.
2. **The Searches tab loaded behind `PropertyListSkeleton`** — three 300pt
   property cards standing in for 90pt text rows, so the list collapsed upward
   when data arrived. It has `SavedSearchListSkeleton` now.
3. **Profile's signed-out header was missing `tight`**, so signing in shifted
   the screen 12pt.

**Two things mounted that already existed:**

- `recentlyViewed.ts` has been complete since M12 and rendered nowhere; its own
  docstring refers to a Home row that did not exist. It is now the first row on
  Home and the **only one not wrapped in `Reveal`** — `Reveal` defers a
  section's query, and this row makes no request, so there is nothing to defer.
  Read that module before changing it: it stores a snapshot rather than ids
  specifically because `GET /properties/:id` increments the view counter, and
  refetching to draw the row would corrupt the one behavioural signal the
  backend collects.
- The two calculators are now in Profile's index, which documents itself as the
  app's only complete index.

**One structural change:** Profile's signed-out state was a full-height sign-in
wall. Five of the eight destinations it indexes need no account — listings,
projects, blog, both calculators, help — so a guest now gets a compact prompt
and the public half of the index. Both branches render the same
`PublicSections`, so a route added there cannot appear for one kind of user and
not the other. `SignInPrompt` gained a `compact` prop for this; the other five
screens that use it have genuinely nothing to show a guest and keep the
full-height default.

### 10.6 Text fields — a real clipping bug, and phone entry

**Reported:** text cut off along the bottom on login and register.

**Cause, and it was app-wide rather than screen-specific.** `Input` and
`SearchBar` styled their `TextInput` with `text-body` — the NativeWind class
every paragraph uses. That class is a SET: size, tracking, weight and **line
height**. React Native honours a `lineHeight` on a `TextInput` by laying the
text out in a box of exactly that height and does NOT grow it for the font's
own ascent and descent. `body` declares 16/24, DM Sans at 16pt needs more than
24pt to clear its descenders, so `g y p j q` and the comma were sliced off
everywhere those two components appeared. It is not fixable with padding — the
clipping happens inside the line box.

**Fix:** `src/ui/textInputStyle.ts`. One hook, used by all four `TextInput`s in
the app (`Input`, `SearchBar`, `HeroSearchField`, `ChatComposer`), which
previously held four different ideas of what an input's text looks like. It
takes size, tracking and weight from a typography token and **deliberately
omits `lineHeight`**. If you add one back, the bug comes back.

Two things to know before touching that file:

- **`includeFontPadding` is left alone on purpose.** The usual advice for
  tightening Android text is to disable it. That is exactly backwards here:
  that padding is derived from the font's ascent and descent and is what stops
  descenders being clipped. Turning it off is a known way to cause this bug.
- It also sets `fontFamily`, which fixed a second bug nobody had reported.
  `FontOverrideProvider` is a context `ui/Text.tsx` reads, and a `TextInput` is
  not a `Text` — so every field in the app rendered in the platform system face
  while every label around it rendered in DM Sans. That is the one place the
  app-wide typeface decision in `theme/fonts.ts` had never reached, and it
  compounded the clipping, since the declared 24pt box was being measured
  against whichever face happened to render.

**Phone entry.** Register always had a mobile field. It now shows `+91` as a
fixed prefix that is never sent — the backend validates `/^[6-9]\d{9}$/`, ten
digits and no country code, and without the prefix a user has to guess between
`9876543210`, `09876543210` and `+919876543210`, two of which that regex
rejects without explaining itself. `normalizeIndianMobile` (beside
`phoneSchema`, since the two encode the same fact from opposite ends) reduces a
pasted number to those ten digits instead of failing it for its formatting.
Forgot-password uses the same helper and prefix. `Input` gained a `prefix` prop
for this, separated by a hairline so the fixed part reads as fixed.

**Open, and NOT a mobile-app change: login accepts email only.**
`userController.loginUser` does `User.findOne({ email: normalizedEmail })` and
there is no phone-login route — lines 683 and 802 look users up by phone, but
those are the reset flows. Chirag's call on 2026-08-14 was to leave login
email-only for now; forgot-password is the phone-based route into an account.
Adding mobile login means extending `loginUser` first, then a single
accepts-either field on the login screen.

### 10.7 Motion audit

Audited against the eight-category bar (purpose/frequency, easing/duration,
physicality, interruptibility, performance, accessibility, cohesion, missed
opportunities). **The result was short, and that is the finding**: the motion
system in `theme/motion.ts` is genuinely good — tokens describe BEHAVIOUR
rather than fixed timings, anything touchable gets a spring, and reduced-motion
substitution is defined centrally. `PressableScale`, `Sheet`, `ExpandableText`,
`DetailHero` and `Image` were all checked and left alone.

Four things changed:

| Location | Was | Now |
|---|---|---|
| `DetailSectionNav` | slides `translateY -8 → 0`, and scrolls its rail sideways, with no reduced-motion gate | fade only under reduce-motion; rail jumps rather than glides |
| `ui/Toast.tsx` | `FadeInDown` / `FadeOutDown`, ungated | plain fade under reduce-motion |
| `ui/Metrics.tsx` `ProgressBar` | `width: '${pct}%'`, teleports | springs on `scaleX` with `transformOrigin: left` |
| `tools/affordability`, `tools/emi` | result card popped into existence | rises once on mount |

Two of those are the same bug — a component animating movement without reading
the OS setting, when eight others in the app already do. `DetailSectionNav` was
added earlier the same day and simply missed it.

**`ProgressBar` is the one worth reading before changing.** It animates
`scaleX` rather than `width` deliberately: width re-runs layout every frame on
the main thread, a transform composites on the UI thread for free. The fill is
laid out at full width once and scaled down, origin pinned left. It springs
rather than times because the value can change again mid-flight (removing two
interests in a row on the Saved screen), and `spring.standard` is critically
damped because a progress bar that overshoots is briefly showing a number that
is not true.

**Deliberately NOT animated**, so nobody adds it later thinking it was missed:

- **Quick-filter pills and the segmented control.** Hit tens of times a day.
  The playbook's own rule for that frequency is remove or reduce, not add.
- **Search-result rows.** Entrance animations on a virtualised infinite list
  fire on every scroll-in, which is motion the user did not ask for, repeatedly.
- **The card/row density swap.** It teleports, and animating a FlashList
  re-layout costs more than the jump does.
- **Screen transitions.** Expo Router's native stack already provides the
  platform animation; overriding it would make the app feel non-native.
- **Input focus borders.** Feedback on a direct manipulation should be
  immediate, not eased.

**Unverified by eye.** As with the rest of §10, none of this has been seen
running. Feel-check on a device: the progress bar under a rapid double-remove
on Saved (it should retarget, not restart), and the tools card entrance while
editing an input (it must NOT re-enter on each keystroke).

---

### 10.8 The navigator's own background was light in dark mode

Reported from a device: on Saved and Properties in dark mode, a pale band sat
along the bottom edge under the floating dock. It was on every screen with a
tab bar, not those two.

**Cause.** React Navigation paints a background behind every navigator, taken
from `theme.colors.background`. Expo Router mounts its `NavigationContainer`
with `DefaultTheme` and never consults the colour scheme, so that value was
`rgb(242, 242, 242)` in both schemes, always.

Nothing showed it while a screen covered it — `ui/Screen` paints
`bg-background` across the whole scene. But the tab bar is a SIBLING of the
scene rather than a child: `BottomTabView` lays the screen container and the
tab bar out in a column. Our dock is a floating pill (§ `ui/TabBar.tsx`) with
transparent 16pt gutters and a transparent safe-area strip beneath it, so every
transparent pixel around the pill was showing that grey through a black app.
The pill's shadow (radius 20) darkened the gutters enough to hide it there,
which is why it read as a band along the bottom rather than as a frame.

**Fix.** `src/theme/navigationTheme.ts` projects our colour tokens into React
Navigation's theme shape for both schemes, and `app/_layout.tsx` wraps the
`Stack` in `ThemeProvider` from `@react-navigation/native`. That also corrects
the native stack's scene background and the modal backdrop, which were reading
the same wrong value.

`@react-navigation/native` is imported directly and is deliberately NOT added
to `package.json`. It arrives as a dependency of `expo-router`, which owns its
version; declaring it separately would let the two drift.

**Status bar.** `style="auto"` reads the OS appearance, not the app's resolved
scheme, so forcing Dark on a Light phone gave black glyphs on a black header.
Both remaining `auto` uses are now driven from `theme.scheme` — the root layout
and `DetailHeader`'s collapsed state. `gallery.tsx` and `DetailHeader`'s
expanded state stay hard-forced to `light`: those sit on a photograph, where
the scheme is irrelevant.

**Not covered.** Android's system navigation bar under `edgeToEdgeEnabled`.
Setting its button colour needs `expo-navigation-bar`, which is not installed;
that is a native-module decision, not part of this fix.

### 10.9 Theme switch on Profile

`Appearance` group at the foot of `PublicSections` in `app/(tabs)/profile.tsx`:
a three-option segmented control, System / Light / Dark, on
`useThemePreference()`. The runtime already existed and persisted to MMKV; the
only surface exposing it was the dev-only gallery, so a shipped build had no
way to reach it.

Three decisions worth keeping:

- **In `PublicSections`, so signed-out users get it too.** A colour scheme is a
  device preference, not account data — `ThemeProvider` already persists it
  across logout for that reason.
- **Three options, not a switch.** A two-state toggle cannot express "follow
  the phone", so picking either would silently opt the user out of their
  phone's schedule with no way back.
- **Inside a `ListGroup`.** `Segmented` draws its track in `surfaceMuted`,
  which is within 2% of the page background in light mode and would vanish on
  it; on a card it separates.

---

### 10.10 A function-valued `style` is silently discarded — read this before writing one

The single highest-value finding in this pass, because it fails quietly and it
had already shipped in several places.

React Native lets a `Pressable` take `style={({ pressed }) => …}`. **This app
cannot use that form.** `babel.config.js` sets NativeWind's `jsxImportSource`,
which routes every JSX element through `react-native-css-interop`'s `wrapJSX`;
that swaps `Pressable` for its interop component whether or not the element has
a `className`. The interop treats `style` as a source of inline CSS rules: it
spreads it (`{...style}` — for a function, `{}`), assigns the empty object over
`props.style`, and renders `{...props, ...computed}` with the computed value
last. The function is never called.

What that cost, in ascending order of visibility:

| Where | What was lost |
|---|---|
| ~20 sites carrying layout in `className` | the pressed fade only — invisible in a screenshot, but every press in the app was unacknowledged |
| `home/IntentCards` | the two hero cards' background tint and corner radius |
| `home/HeroSearchField` rows | all layout: row direction and padding |
| `search/QuickFilterBar` `Pill` | **everything** — padding, border, fill, pill radius, and `flexDirection`, which fell back to `column` |

That last row is what "the filters at the top of the Properties page are not
properly placed" was. Each pill painted as a bare `View`, so every chevron
stacked under its own label and the whole rail read as loose text.

**The rule.** Layout goes in a plain style OBJECT or in `className`. The press
state goes in an `active:` class, or use `ui/PressableScale`, which takes an
object and is the app's standard press treatment anyway. `eslint.config.js`
now fails the build on a function-valued `style` in any `app/**` or `src/**`
`.tsx`, with the explanation attached to the rule.

All 26 sites were converted. Nothing else in the app uses the form.

### 10.11 Properties opened blank, and the rail was rebalanced

**Blank on arrival.** Reported as "no properties visible on the All filter". On
a fresh install the tab rendered the search field, the filter rail, and nothing
else. It started in `editing` with an empty field, which renders the
recent-searches panel, and that panel returns `null` when there is no history —
true for every first visit.

Fixed in two moves, and the second is what retires the class of bug:

1. The tab opens in results mode. `/properties/search` with no criteria returns
   the whole corpus, so browsing everything is a real answer. The `browsing`
   flag that used to distinguish "no criteria on purpose" from "no criteria by
   accident" is gone, along with `StartPrompt`, because the accidental state is
   no longer reachable. `clear()` now lands on the unfiltered corpus too.
2. Editing mode only COVERS the screen when the panel has something in it —
   suggestions for what is typed, or a history to offer. Focusing an empty
   field with no history leaves the results visible behind it.

**The rail.** Filters moved off it and now sits beside the search field, as a
pill carrying the active count. It opens a surface rather than setting a value
— the module doc always said so — and moving it returned 93pt to a strip that
had eight controls competing for 393pt. The right edge now fades into the page
background instead of chopping, so the pill under it reads as continuing rather
than as broken. The rail still scrolls; eight legible controls will not fit
across a phone and no arrangement of them will.

### 10.12 Saved — the empty and signed-out states

Both rendered one centred box and nothing else, on the same premise Profile was
corrected for in §10.5: that a screen about saved things has nothing for a user
with none. It is false. Recently viewed is device-local, so a guest has one; it
costs no request, because `recentlyViewed.ts` replays a disk snapshot rather
than refetching (which would inflate every listing's view counter); and with
enquiring capped at five and emailing the owner, the listing someone returns
for is far more often one they merely opened.

So `NothingSavedYet` wraps both branches: the prompt goes `compact` at the top
of a scroll with the recently-viewed rail under it, and falls back to the old
full-height centred prompt when the history is empty too. `EmptyState` gained
the `compact` prop `SignInPrompt` already had, for the same reason and with the
same meaning.

---

## 11. 2026-08-15 — The card system rebuild

Brief: the property cards, saved-property interactions, list/grid layout,
spacing and button placement "feel amateur and visually inconsistent". Keep the
light minimal language; fix the structure. Reviewed against `ios-visual`,
`ux-foundations` and `interaction-design`.

### 11.1 What was structurally wrong

Not styling. Four architectural facts produced every symptom:

1. **`Card` had no padding.** Of 49 `<Card>`s in the app, 41 supplied none, so
   their content sat flush against all four edges. The Profile header was the
   clearest casualty — avatar against the corner, and the rewards card touching
   it with no gap.
2. **The compact row was the feed card at a smaller size.** A fixed 108pt
   square thumbnail inside a text-sized row meant image height and row height
   varied independently down the list; 108pt was 29% of a 375pt screen and 25%
   of a 430pt one; the intent chip was absolutely positioned over the *text*
   column where it cost a line; the photo count sat in the opposite corner from
   the feed card's.
3. **The three cards shared no parts.** Each redeclared its own photo
   container, badge and count chip at different sizes and insets. That is why
   the list and the feed read as two apps.
4. **The Saved screen's Remove was a sibling of the card, not part of it.**

### 11.2 The component set

| File | Responsibility |
|---|---|
| `properties/components/cardParts.tsx` | **new** — what a signal looks like, once: `Cover`, `IntentBadge`, `PhotoCount`, `SaveControl`, `CompareControl`, `SpecRow`, and the geometry constants |
| `properties/components/PropertyCard.tsx` | rewritten — the feed card, 3:2 photo, four content groups |
| `properties/components/PropertyListItem.tsx` | **new** — the compact row, purpose-built |
| `properties/components/SavedPropertyCard.tsx` | **new** — four lines; `PropertyCard` with the heart wired to remove |
| `properties/components/PropertyCardSkeleton.tsx` | rewritten — both shapes, derived from `cardParts` |
| `search/components/ResultsToolbar.tsx` | **new** — count + save-search + compare + density |
| `saved/components/EnquiryMeter.tsx` | **new** — the 4-of-5 counter as one object |

`PropertyRow`, `COVER_HEIGHT`, `ROW_HEIGHT` and `PropertyCompareProps` are
gone. `PropertyList` takes `getSaveProps` and `getCompareProps`.

### 11.3 Geometry, stated once

- **Cover is a RATIO (3:2), never a height.** A fixed 210pt cover was 1.72:1 on
  a 375pt phone and 2.1:1 on a 430pt one. The compact thumbnail is a *share* of
  row width (32%) at 1:1, and the row is `alignItems: 'stretch'` so the photo
  takes the row's height rather than the row taking the photo's. That one word
  is most of the list-view fix.
- **Radius is a function of surface size**: `xl` (20) for a full-width card and
  anything sitting in that column, `lg` (14) for a 96pt row. Content padding is
  16 on both, which makes each inner box concentric with its outer radius.
- **Overlay corners are assigned, not negotiated**: intent top-left, the one
  action top-right, photo count bottom-right, bottom-left deliberately empty.
  `OVERLAY_INSET` is 12 and `CONTROL_INSET` is *computed* from it — a 44pt
  target around a 34pt disc has to sit 5pt closer to the edge for the two
  visible objects to line up rather than the two boxes.
- **The list owns the gap; no card carries a margin.** 16 between cards, 12
  between rows.

### 13.4 Save/unsave — the heart, and why it is honest now

`features/properties/interest.ts` argued at length that a heart would be a lie
on this backend: marking interest creates a `Lead`, emails the owner, hands over
name/email/phone, and is capped at five. Every word still true.

What changed is the resolution. Refusing the control did not make the
consequence visible — it made the *action* invisible, and left the corner where
every user looks for a save control occupied by a bare unlabelled circle (the
compare checkbox). A discoverability failure traded for an honesty one.

The control ships and the **confirmation** carries the truth: the toast says the
owner can now contact you, states how many of the five remain, and carries an
**Undo**. `ui/Toast.tsx` gained an optional action for this, and only becomes
interactive when one is present.

`useSaveToggle` (`features/saved/hooks.ts`) is the single implementation — one
hook per screen, per-card props derived from it, membership read from the
shared `useSavedProperties` query rather than one `check` request per card.
Reading the cache *without* subscribing was tried first and was wrong: on a
signed-in session that had not opened the Saved tab, every heart rendered empty
including on already-enquired listings.

Residue, stated rather than hidden: undo frees the slot and removes the user
from the owner's interested list, but does **not** unsend the email or delete
the `Lead`. That is why the toast says "can now contact you" rather than
implying full reversal.

### 11.5 The Saved screen's Remove

Was: card, then a small red "⊗ Remove" in the gap **below** it, then the next
card — putting the control nearer the listing it does not act on than the one it
does. Norman's mapping, Cooper's "keep actions near the object they affect", and
plain Gestalt proximity all say the same thing, and the layout violated all
three identically. Worst case was not confusion; it was removing the wrong
listing off a list capped at five.

Now the filled heart on the card, with Undo. The `Alert.alert` confirmation went
with it: a confirmation dialog is an admission that an action cannot be taken
back, and four taps to remove one listing on the screen whose job is making room
is the interaction cost of that admission. Undo is the same safety at a quarter
of the cost and also covers the case the dialog never did — a mis-tap on the
feed.

### 11.6 Compare became a mode

It was permanently on: an unlabelled circle over every photo in the feed for a
feature most sessions never use. It is now behind the toolbar's Compare toggle,
paid for with three simultaneous signals (filled toggle, checkboxes replace
hearts, compare bar appears). Entering it forces card density, because the
compact row has no free corner and a mode that is on with no visible effect is
the worst kind.

### 11.7 The dock

The reported symptom was that the post button "competes with the navigation". It
was not the button — it was that nothing distinguished it. The selected tab had
a `brandMuted` pill with a brand-red icon and label, so the dock held two red
objects side by side, one a destination and one an action. `colors.ts` already
says which is which: brand is "not an action colour", accent is "the primary
action colour". The selected tab now takes the accent, a hairline separates the
four destinations from the one action, and red means exactly one thing in that
bar.

### 11.8 Unverified

None of §11 has been seen running. Feel-check on a device, in order: the compact
list's row heights (every row should now be identical); the heart's 44pt target
against the card's own press target; the Undo toast's timing (5s) against how
long it takes to notice one; and whether `Card`'s new default padding
double-pads anywhere the grep for `p-*`/`px-*`/`py-*` classes missed.

---

## 12. 2026-08-15 — Production correction pass

Device review of §11. Four real defects, one of them semantic.

### 12.1 🔴 The heart was firing an irreversible disclosure, and calling it undoable

**Audited against the controller**, not inferred. `markInterested`
(`backend/controllers/propertyController.js:1505`), one tap:

| Step | Effect |
|---|---|
| 1 | rejects if the user already holds 5 interests app-wide |
| 2 | rejects their own listing, and duplicates |
| 3 | pushes to `Property.interestedUsers`, `$inc likes` |
| 4 | **creates a `Lead`** with a `userSnapshot`: name, email, phone, photo |
| 5 | creates a `Notification` for the owner |
| 6 | **sends the owner a WhatsApp** carrying name, email and phone |
| 7 | awards reward points |

`removeInterest` (`:1660`) reverses **step 3 only**. The lead, the
notification, the WhatsApp and the points all survive. The quota IS restored,
because the cap counts `interestedUsers` rather than leads.

No email is sent. The claim in `features/properties/interest.ts` that this
"notifies them by email" is wrong; it is an in-app document plus WhatsApp.

So §11 shipped two lies at once: a heart icon promising a private, free,
unlimited, reversible bookmark, and an "Undo" in the toast for an action that
had already disclosed a phone number to a stranger.

**Fixed without touching the backend.** `features/saved/saveToggle.ts` now
raises `EnquirySheet` before an add — three lines stating what the owner
receives, plus the quota — and the Undo is gone. Withdrawing is immediate,
unconfirmed, and its toast says "Enquiry withdrawn" and nothing more, because
offering Undo there would re-fire the notification and the WhatsApp, which is
the opposite of undoing.

A confirmation is normally the wrong answer. Three conditions make it right
here and all three must hold or it should go back to one tap: the action is
genuinely irreversible; the consequence cannot be inferred from the control;
and it is rare (capped at five, so at most five sheets ever).

**The product model the user wants is Save ≠ Enquire, and this backend cannot
express it.** There is one array. `GET /properties/saved` reads the same
`interestedUsers` that `POST /properties/interested/:id` writes.

Minimum backend change, NOT made, awaiting a decision:

- `User.savedProperties: [ObjectId]` (or a `SavedProperty` collection)
- `POST/DELETE /properties/save/:id` — array write only, no lead, no
  notification, no WhatsApp, no reward, **no cap**
- `GET /properties/saved` split into `/saved` (the new bookmark) and
  `/enquiries` (the existing interest list)

UI change that would follow: the heart becomes the bookmark and loses the
sheet; `Enquire` becomes a labelled button on the card and the detail screen;
Saved gains a third segment or renames Interested to Enquiries.

### 12.2 🔴 Cards touched because `gap` is inert under FlashList

`contentContainerStyle={{ gap: 16 }}` did nothing. FlashList v2 positions every
cell absolutely — its own `CellRendererComponent` documentation says `position`
"will be `absolute` as that's how `FlashList` positions elements" — and flex
`gap` has no effect on absolutely positioned children. `paddingHorizontal` and
`paddingBottom` on the same object DO apply, which is what made it look like a
value that was merely too small.

`ItemSeparatorComponent` is the supported mechanism, is measured into the
layout, and renders between items only — never above the first or below the
last. 16 between cards, 12 between rows, matching header gaps via
`ListHeaderComponentStyle`. No card carries a margin.

### 12.3 🟠 Compare mode had no visible state at zero selected

`CompareBar` returned null at zero items, so entering the mode gave a lit
toolbar icon, checkboxes where the hearts were, and no explanation or exit. The
bar now renders on the mode rather than the count, states what to do at zero,
and always carries the way out. The toolbar toggle carries the count.

### 12.4 🟠 The active filter pill was 2pt taller than its neighbours

The label switched from `footnote` (13) to `subhead` (15) on selection, so a
set pill stood taller and the rail lost its baseline. Fixed height, constant
variant, weight and colour carry the state.

### 12.5 🟠 Two hooks returned fresh objects, re-rendering every visible row

`useSaveToggle` and `useCompareSelection` returned object literals, so the
screens' `useCallback`-wrapped per-card prop builders changed identity on every
render — including on every keystroke in the search field — which changed
`renderItem` and re-rendered every visible row. Both memoised.

### 12.6 Unverified

Feel-check on device: the enquiry sheet at the largest accessibility text sizes
on a 667pt screen (it does not scroll); the busy lock on a slow connection; and
whether the 36pt filter pill needs its `hitSlop` widened on small phones.

---

## 13. 2026-08-15 — Property Detail and Gallery

Scoped to two screens. Nothing else was touched.

### 13.1 The call button is gone, and what that does and does not achieve

Removed on instruction from `DetailActions`, along with `Linking`, the `tel:`
handler and the `IconAction` helper. Nothing phone-shaped replaces it; the bar
carries one action.

**Recorded so nobody restores it thinking it was an oversight.** The button read
`property.owner.phone`, which arrives from `GET /properties/:id` — a PUBLIC
endpoint that populates the owner's phone and email into every response. So
removing the button removes the encouragement, not the exposure: the number is
still readable by anyone who calls the API directly. If it should not be
reachable, the fix is what the endpoint returns, not what this bar draws. Not
changed here — that is a backend decision.

### 13.2 The enquiry now confirms before the side effect

The detail screen's CTA called `interest.toggle()` directly, which posts to
`/properties/interested/:id` and creates the lead, the notification and the
WhatsApp message in one tap. It now raises `EnquirySheet` first and only calls
`toggle` from the sheet's confirm. Withdrawing still goes straight through —
cheap, frees the slot, nothing to warn about.

`EnquirySheet` took plain props for this rather than being bound to
`useSaveToggle`. Two hooks reach the same endpoint (`useSaveToggle` on the feed
and Saved, `useInterest` on detail); binding the sheet to either would have
meant a second copy for the other, which is how two confirmations end up
wording the same consequence differently.

The screen reads `useSavedProperties` for the true remaining count — the same
query the feed's hearts already run, deduplicated, so no extra request. It
feeds both the sheet's quota line and a disabled CTA with an explanation when
the cap is reached, instead of a press that gets refused.

### 13.3 Hero

- **Height is `heroHeight(width)`, not a flat 320.** A fixed height is a fixed
  CROP over a variable width, so the same listing showed more sky on a 430pt
  phone than on a 375pt one. `HERO_HEIGHT` is gone; `DetailHeader` and the
  skeleton call the function.
- **Two indicators that say different things**, never both saying the same one:
  dots bottom-centre for POSITION (up to 8, then dropped), and a button
  bottom-right for COUNT and for opening the viewer. Past 8 the button takes
  the position back as "3 / 24".
- The old chip was drawn inside the content sheet's 20pt overlap and was
  visibly clipped. Everything now sits at `20 + lg` from the photo's edge.
- The counter chip went from `black/55` at caption size to `black/72` at
  footnote/600 in a 32pt pill with a 44pt hit slop — it was reported as too
  easy to miss.

**A next-image peek was rejected.** It needs horizontal gutters, and gutters end
the full-bleed treatment that makes the hero read as a photograph rather than a
card. On a 375pt screen the peek would be about 16pt: not enough to be legible
as an image, plenty to look accidentally misaligned.

### 13.4 Gallery: black was not the problem, empty black was

A 3:2 photograph on a 19.5:9 phone leaves roughly 40% of the screen empty, and
the old layout put a 12pt "1 of 6" in it. Stretching distorts; cropping to fill
throws away what the owner chose to include. The third answer is to use the
space.

A **thumbnail filmstrip** occupies the lower band and earns it three times: it
shows the neighbouring images (§10's ask, without shrinking the current one by a
point), it makes the set's size visible, and it is a direct jump rather than N
swipes. The band is reserved out of the pager's height rather than overlaid, so
the thumbnails can never land on the photograph on a short device.

One pagination system: the selected thumbnail IS the position. "3 of 6" beside
it is a count, not a second set of dots. The strip is dropped entirely at one
image — no filmstrip of one, no "1 of 1".

Close button: `white/15` → a 36pt `black/55` disc inside a 44pt target. The old
fill was invisible against a pale photograph, which is exactly when a close
button has to be findable.

### 13.5 Unverified

- The filmstrip's `scrollToIndex` on a fast swipe through 60 photos — FlatList
  can throw `scrollToIndex out of range` if the strip has not rendered that far;
  `getItemLayout` should prevent it but it has not been seen.
- `pagerHeight` on a landscape rotation.
- The enquiry sheet at the largest accessibility text sizes (still not
  scrollable — carried over from §12.6).

---

## 14. 2026-08-16 — Audit remediation

Implements the confirmed findings of the two-pass source-level audit (§13 and
the route inventory). Scope was the audit's list; no screen classified 🟢 was
touched.

### 14.1 🔴 `Card`'s default padding double-padded the attribute table

`DetailAttributes` renders its rows inside a `Card` and each row supplies its
own `px-base py-md`. When `Card` gained `padded = true` by default (§11), those
rows went to 16 + 16 = 32pt from the card edge, and the separator's
`marginLeft: 16` inset — written assuming the row's own 16 was the only one —
stopped landing under the label it insets to.

My own Card audit in §12 missed it: the grep looked two lines past `<Card` and
the padded child is four lines down inside a `.map`. Fixed with
`padded={false}`; a deeper scan found no other real instance (the two other
hits are inner boxes inside padded cards, which is intentional).

### 14.2 🔴 `projects/[id]`

Three independent defects, all structural:

- **`Dimensions.get('window').width` at module scope** — captured once at
  import, so every gallery page was sized from the width at app start and never
  updated on rotation or split-screen. Now `useWindowDimensions`.
- **Fixed `GALLERY_HEIGHT = 260`** — a fixed height over a variable width is a
  fixed crop over a variable one. Now `galleryHeight(width)`, same derivation
  `DetailHero` uses.
- **Mapped `ScrollView` gallery** — every image mounted and decoded at once,
  which is exactly what `DetailHero`'s doc argues against. Now a windowed
  `FlatList` (`windowSize={3}`, `removeClippedSubviews`, `getItemLayout`).
- **`refreshing={false}` hardcoded** — the pull gesture fired the request and
  showed nothing. The screen owns the flag now.
- Amenities moved from `Badge` to `Tag`, matching property detail, where the
  reason is documented: `Chip`/`Badge`-as-control announces dead buttons.

### 14.3 🔴 `projects/unit/[unitTypeId]` action bar had no safe-area inset

`px-lg py-md` with no `insets.bottom`, so the CTA sat under the home indicator.
Now inset, `fullWidth`, on `screenPadding`, with its height measured by
`onLayout` instead of the scroll view clearing it with a hardcoded 100. The
sold-out disabled state gained the caption that explains it.

### 14.4 🔴 `forgot-password` was an account-enumeration oracle

The file's own docstring said the success state must not confirm whether the
phone exists, "would turn this endpoint into an account-enumeration oracle" —
and the error branch printed the backend's `No account found with this phone
number` verbatim. The protection was worthless: anyone could test any Indian
mobile, ten digits at a time.

A 404 now lands on the same "code sent" screen as a success. Rate limiting is
still surfaced, because a user who must wait needs to know how long and it
reveals nothing about the account.

### 14.5 🔴 Six owner routes had no client-side role guard

`auth/components/OwnerOnly.tsx` — signed out gets `SignInPrompt`, signed-in
non-owner gets an `EmptyState` routed at Profile, where the buyer-to-owner
upgrade sheet lives. `restoring` renders through, so a real owner never sees a
flash of refusal on cold start.

**It is not security and must not be read as one.** Every route stays gated
server-side. This changes what a legitimate user is TOLD: before it, a buyer
who deep-linked `/owner/leads` got a titled screen that spun and then said
"Could not load leads" — an access decision presented as a fault.

### 14.6 🟠 Interaction fixes

| Where | Was | Now |
|---|---|---|
| `unit`, `campaign`, `booking/[bookingId]` | `backTo` skipped one or two levels (or defaulted to `/(tabs)`) | back to the screen the user came from |
| `campaign` Join/Leave | equal-width side by side, Leave always enabled | Join is the only button; Leave demoted below it and offered only once joined, matching how `owner/properties` demoted Delete |
| `projects/bookings`, `owner/leads/index` rows | `<Pressable><Card>` — no press feedback, no accessible name | `Card`'s own `onPress`, the correction two sibling files already document |
| `owner/leads/[id]` contact buttons | one `isAddingContact` flag spun all four | per-action pending state |
| `rewards` referral pill | a `View` with a share glyph that did nothing | the control it looked like |
| `projects/index` chips | fixed row, clipped at large text sizes | scrolling rail |

### 14.7 🟠 `Card`'s accessible name landed on the wrong node

`Card extends ViewProps`, so a caller's `accessibilityLabel` typechecked and
then went onto the inner `View` — one node below the `PressableScale` a screen
reader actually focuses. It read as a correctly labelled control and was not
one. Hoisted onto the pressable, along with `accessibilityHint`.

### 14.8 🟡 Also fixed

`px-lg` → `screenPadding` in `projects/index`, `projects/[id]`,
`unit/[unitTypeId]`, `campaign/[campaignId]`, `owner/leads/index` · `key={index}`
→ a stable key in lead contact history · `rewards` pull-spinner no longer fires
on first load · chat's online dot got an accessible name (it was colour-only
state whenever a property title was present) · `projects/index` clear-search
target raised to `gesture.hitSlop`.

### 14.9 Not done, needs your call

- **`app/property/[id]/map.tsx`** — an M4 `Placeholder` stub on a live but
  unreachable route. Deleting it was declined as out of scope; it is still
  there and a deep link still lands on scaffolding.
- The `Save ≠ Enquire` backend split (§12.1) remains open and untouched.

---

## 15. 2026-08-16 — Owner Analytics and Leads

Two screens taken from "four numbers and a status chart" and "a database list"
to a CRM an owner can triage from. Scope was these two plus the lead-detail
consistency they imply; nothing else was touched.

### 15.1 What the analytics endpoint actually returns

Read from `leadController.js:348`. The shape of the screen follows from it, and
three things were NOT built because of it:

| Field | Period |
|---|---|
| `statusStats` | **all time** — the aggregate has no date match |
| `dailyLeads` | within `days` — the only period-scoped series |
| `totalLeads`, `convertedLeads`, `conversionRate`, `unreadLeads` | all time |
| `newLeadsThisWeek` | last 7 days, **hard-coded**, not derived from `days` |
| `leadsByProperty` | top 10 listings |

**No period selector.** `days` scopes exactly one field. A "Last 30 days"
control that changes a sparkline while five numbers above it hold still states
that the numbers are scoped when they are not. Every figure is labelled with
its own true period instead.

**No trend arrows.** There is no previous-period figure anywhere in the
response. Computing one would mean inventing it.

**No leads-by-property table.** Real, unused data — but an owner account is
capped at one listing server-side, so today that table is one row restating the
total. First thing to add if the cap is lifted.

### 15.2 Analytics composition

Attention → scale → pipeline → activity → bridge.

The old screen was four equal `Stat` cards and an unlabelled bar chart, which
reads as four equally important facts, so none of them led. Now: an accent
banner for unread leads (the only actionable figure, hidden entirely at zero),
one emphasised primary `Stat` for the total, four subordinate ones each
carrying its own period, then the pipeline, then the chart.

The chart kept its plain-`View` bars — no chart library for fourteen numbers —
and gained what it was missing: a total, a peak value, first and last dates,
and a hairline for zero days so a gap reads as "no enquiries" rather than as
missing data.

### 15.3 🔴 The Leads whitespace was `flexGrow`, not padding

The filter rail was a horizontal `FlatList`. React Native applies
`baseHorizontal` to those — `{ flexGrow: 1, flexShrink: 1, ... }`
(`ScrollView.js:1867`) — so in a column parent it claimed every remaining point
of vertical space and pushed the list off screen. The chips drew at the top of
that space, which is why it read as a gap beneath them.

Fixed by capping it in a plain `View`, which is exactly what `QuickFilterBar`
does on Properties. No negative margins.

### 15.4 The lead card

`LeadCard` answers who / what / when / where. What it replaced showed the
status **twice** — a "New" badge beside the name and a status badge under the
price — which cost the slot where recency belonged.

Unread is now a left rail plus a heavier name, the convention every mail client
uses, rather than a second competing pill. That frees the top-right for one
badge (the stage) and the footer for `relativeDay(createdAt)` plus whether any
contact has been logged. No scoring, no priority, no "hot" — the backend gives
`isViewed`, `status`, `createdAt` and `contactHistory`, and the owner ranks.

The three stat pills above the rail became one line in `ScreenHeader`'s
subtitle. It switches to describing the filtered view when a filter is on,
because `getLeads` computes `stats` over every lead regardless of the query — a
subtitle reading "18 leads" above a list of one would be quietly wrong.

### 15.5 The bridge

`LeadPipeline` rows are routes: tapping a stage opens `/owner/leads?status=…`,
validated against `LEAD_STATUSES` on arrival. Before it, the only way from "4
negotiating" to those four leads was to leave, open Leads, and find the chip.

Stage order, not count order — sorting by count would reshuffle the pipeline
whenever a status changed and break the one thing the shape is good at. Counts
and labels are always text; strip the colour and nothing becomes unreadable.

### 15.6 Lead detail

Not redesigned. Three consistency changes so the row and the detail say the
same things in the same order: the identity card gained the recency line, the
listing card gained the price and became a real `Card onPress` (it was a bare
`Pressable` around the title with no accessible name), and the status block was
relabelled "Move to stage" — a verb, because it is the editor rather than a
second statement of a fact the chips already carry.

### 15.7 Two things worth knowing

- `Stat`'s body is `flex: 1`, so it needs a row parent. The primary tile is
  wrapped in a one-child `StatRow` rather than a plain `View`, where it would
  collapse to zero height.
- `Chip`'s selected state swaps `callout` (16) for `bodyEmphasis` (17), so a
  selected chip is 1pt taller. `alignItems: stretch` in the rail equalises them
  so nothing jumps, but the rail's own height shifts by a point. Left alone —
  changing `Chip` is a global change and this pass was scoped to composition.
