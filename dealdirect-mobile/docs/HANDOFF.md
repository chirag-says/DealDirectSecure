# Mobile app — handoff

Written 2026-08-05. Point a new session at this file first, then
[`../README.md`](../README.md) and [`API_CONTRACT.md`](API_CONTRACT.md).

The plan of record is [`../../MOBILE_APP_ARCHITECTURE_PLAN.md`](../../MOBILE_APP_ARCHITECTURE_PLAN.md),
which defines milestones M0–M14. This file says where we actually are against it.

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
| M6 | Chat | **done** (§2.7) |
| M7 | Profile, settings, rewards | not started ← next |
| M8 | Owner mode: listings and uploads | not started |
| M9 | Leads and analytics | not started |
| M10 | Agreements | not started |
| M11 | Projects, units, campaigns, bookings | **~15% done** (§2.3) |
| M12 | Deep linking, offline, performance | not started |
| M13 | Push notifications | not started, backend CR needed |
| M14 | Store readiness and release | not started |

**Working screens today:** Home, Search, property detail + gallery, Saved
(interested list + saved searches), Messages (list + thread), notifications,
the four auth screens, and the tab shell. The property detail locator map,
M7–M10, M12–M14, and the remaining M11 screens are still `Placeholder` stubs.

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

---

## 3. Backend blockers found by measurement

These were all found by probing production, not by reading code. Every one is
recorded with evidence in the file that depends on it.

### 3.1 `listingType` filter is written but NOT DEPLOYED — highest priority

`backend/controllers/propertyController.js:1862` correctly expands rent/sale
across all six schema spellings. It is **uncommitted in the working tree**. The
live API ignores the param: `?listingType=sale`, `Sell`, `rent` and `Rent` all
return the same 36 results.

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

M4, M5 and M6 are done (§2.5–§2.7), except the property-detail map, which is
held for a dev-client rebuild (native modules, §5.1) whenever that is
convenient. What's left, in order:

1. **M7 — profile, settings, rewards.** Next up. Self-contained, no blockers,
   nothing else in the plan depends on it.
2. **M11 — finish projects.** The data layer is already done; this is screens
   plus unit types, campaigns and bookings.
3. **M8 → M9 → M10** — owner mode, then leads, then agreements. M8 is the
   largest and most failure-prone item in the whole plan (10 days) and is the
   first thing that **writes** to production.
4. **The map phase**, whenever a dev-client rebuild is scheduled: property
   detail's locator (§2.5) plus M8's add/edit picker, both against
   `docs/MAP_IMPLEMENTATION.md`.
5. **M12 → M13 → M14** — offline/perf, push notifications (blocked on a
   backend change request, §1.16), then store readiness.

---

## 5. Decisions a new session must not accidentally undo

### 5.1 No new native modules without a very good reason

I added `expo-linear-gradient`, then removed it and rebuilt gradients on RN's
built-in `experimental_backgroundImage` (`src/ui/Gradient.tsx`). Reason: a native
module invalidates every installed dev client, and `expo start --tunnel` ships
**JavaScript only**, so it silently serves a bundle the installed binary cannot
run. Chirag's device workflow depends on this. Native additions must be
deliberate and announced.

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
