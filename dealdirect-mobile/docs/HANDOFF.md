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
| M4 | Property detail, gallery, map | **not started** ← next |
| M5 | Favorites, saved searches, notifications | not started (partly blocked, §3.2) |
| M6 | Chat | not started |
| M7 | Profile, settings, rewards | not started |
| M8 | Owner mode: listings and uploads | not started |
| M9 | Leads and analytics | not started |
| M10 | Agreements | not started |
| M11 | Projects, units, campaigns, bookings | **~15% done** (§2.3) |
| M12 | Deep linking, offline, performance | not started |
| M13 | Push notifications | not started, backend CR needed |
| M14 | Store readiness and release | not started |

**28 of 39 screens are still `Placeholder` stubs.** Each stub names the
milestone that replaces it. Working screens today: Home, Search, the four auth
screens, and the tab shell.

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
  RangeSlider, plus the four added this session (§2.4).
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

### 2.4 Home screen + design system (this session)

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

M4 first, and not only because the plan says so. **Almost everything else
depends on it:** it is the screen every card in the app taps into, it is where
`recordView()` must be called for Recently Viewed to ever populate, and it is
the entry point M6 (chat) and M10 (agreements) both hang off.

1. **M4 — property detail, gallery, map.** Biggest single unblock. Note
   `GET /properties/:id` **increments `views` on every call**, so it must not
   refetch on focus. Implements `docs/MAP_IMPLEMENTATION.md` (bundled Leaflet in
   a WebView, matching the website's tiles and markers).
2. **M11 — finish projects.** The data layer is already done; this is screens
   plus unit types, campaigns and bookings.
3. **M7 — profile, settings, rewards.** Self-contained, no blockers.
4. **M5 — favourites and notifications.** Do notifications and saved searches
   now; favourites waits on §3.2.
5. **M6 — chat.** Two-step socket handshake, the trickiest transport work left.
6. **M8 → M9 → M10** — owner mode, then leads, then agreements. M8 is the
   largest and most failure-prone item in the whole plan (10 days) and is the
   first thing that **writes** to production.

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
- Collections rails are built but not rendered (§2.4).
- `assets/home/brand/hero.png` (558 KB) is unused; delete or use.
