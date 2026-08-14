# DealDirect Mobile

React Native + Expo SDK 54 + TypeScript client for the existing DealDirect
backend.

This app is **additive**. It introduces no backend route, no backend change and
no website change. The backend is the single source of truth and the app adapts
to it.

Architecture of record: [`../MOBILE_APP_ARCHITECTURE_PLAN.md`](../MOBILE_APP_ARCHITECTURE_PLAN.md).
Backend contract of record: [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md).
Map behaviour of record: [`docs/MAP_IMPLEMENTATION.md`](docs/MAP_IMPLEMENTATION.md).

**Starting a new session? Read [`docs/HANDOFF.md`](docs/HANDOFF.md) first.** It
records what is actually built against the milestone plan, the backend blockers
found by measuring production, and the decisions that must not be accidentally
undone.

## Status

**M3 complete — property discovery.** Explore feed and search both run on
`GET /properties/search` with infinite scroll, debounced autocomplete, recent
searches and a filter sheet. Remaining feature screens are still labelled stubs
naming the milestone that replaces them.

| Milestone | Scope | State |
|---|---|---|
| M0 | contract lock, tokens, toolchain | done |
| M1 | app shell, navigation, design system | done |
| M2 | transport + authentication | done |
| M3 | property discovery | done |
| M4 | property detail, gallery, map | not started |

Milestones run one at a time, in order, each reviewed before the next starts.

### Screen responsibilities

One browsing implementation, reused everywhere. This is a hard rule, not a
preference: a rent feed, a sale feed and a search-results screen are the same
screen three times, and they drift until one has pull-to-refresh, another has
the new empty state and a third still formats prices the old way.

| Screen | Owns |
|---|---|
| **Home** (`(tabs)/index`) | Discovery and navigation only. No feed, no filters, no sort, no pagination. Every affordance pushes to the browse screen with params. |
| **Search** (`(tabs)/search`) | The canonical browse experience: infinite scroll, free text, filters, sort, pull-to-refresh. Map arrives in M4. |

Home routes in via `router.push({ pathname: '/search', params })`, carrying
`search` and/or `listingType`. The browse screen applies incoming params once
per distinct navigation, so returning to the tab does not stamp a stale filter
over what the user just changed.

### Two backend findings from M3 that need a decision

Both are recorded in [`docs/API_CONTRACT.md`](docs/API_CONTRACT.md) §4.1 with the
measurements behind them. Neither blocks M4.

1. **Taxonomy refs are corrupt in production data.** `category`, `subcategory`
   and `propertyType` are null on 15 of 36 listings and point at the wrong
   document on the other 21, so all three `/search` filters return nothing or
   the wrong set. The app therefore ships **no category or property-type
   filter**. A backfill from the (correct) `categoryName` / `propertyTypeName`
   columns would make them work with no client change.
2. ~~There is no rent-versus-sale filter.~~ **Resolved 2026-08-03.**
   `listingType` was added to `/properties/search` by explicit approval, and is
   additive and backward-compatible. **It is not deployed to
   `backend.dealdirect.in` yet**, so a build pointed at production sends the
   param and production ignores it — the rent/sale cards land on an unfiltered
   list until the backend ships.

### Frozen configuration

| Setting | Value |
|---|---|
| iOS bundle identifier | `in.dealdirect.mobile` |
| Android package | `in.dealdirect.mobile` |
| Production API | `https://backend.dealdirect.in/api` |
| Production Socket.IO | `https://backend.dealdirect.in` |

Both URLs stay configurable through `EXPO_PUBLIC_API_URL` and
`EXPO_PUBLIC_SOCKET_URL`; the values above are the production defaults, baked
into the `preview` and `production` EAS profiles. The identifiers are frozen and
cannot change once a build reaches a store.

The primitive gallery is at **`/gallery`** in development. It renders every
primitive in its real states and carries the light/dark toggle, which is the
quickest way to check a theme change across the whole system at once.

### Carried forward

- **`src/dev/` is scaffolding.** `Placeholder.tsx` and the `(dev)` route group
  are deleted once the last stub is replaced.
- **Haptics are not wired.** Press feedback is visual only. `expo-haptics` is
  not in the approved stack, so adding it needs a decision rather than a commit.
- **Query cache is not persisted to MMKV yet.** The storage instance exists;
  wiring the persister is the offline strategy, scoped to M12. Doing it before
  the query keys settle would persist a shape we then have to migrate.
- **Session behaviour needs on-device verification.** Survival across app kill,
  a WiFi-to-cellular switch and a version bump cannot be checked from a bundler.
  See the M2 completion criteria in the architecture plan.
- **Lists are `FlatList`, not `FlashList`.** The migration is scoped to M12 and
  `@shopify/flash-list` is not a dependency yet. Stable keys, memoised rows and
  hoisted props are already in place, so the swap is a component-name change.
- **`RangeSlider` is unused.** Price filtering ships as bands rather than a
  slider, because one linear axis has to span ₹8,000 rentals and ₹5 crore sales
  and the backend has no `listingType` param to separate them.
- **Offset paging can duplicate a row.** A listing approved mid-scroll shifts
  every later page by one. The feed dedupes by `_id`, which hides the duplicate
  but cannot recover the row the shift pushed past a page boundary. Cursor
  paging would fix it and does not exist on this backend.

Resolved in M2: theme preference now persists to MMKV.
Corrected in M3: `PriceLabel` no longer multiplies by `priceUnit`. The M1
version would have shown a ₹65,000 rental as "₹650 Crore" on real listings.

## Setup

Requires Node 20+.

```bash
npm install
```

Then create `.env` from the template:

```bash
cp .env.example .env
```

Both values are public and are inlined into the bundle. Only non-secret values
belong there.

## Commands

```bash
npm run typecheck
```

```bash
npm start
```

`npm start` launches with `--dev-client`. Expo Go cannot run this app past M4,
because the map WebView, location and notifications all need native modules, so
development builds are used from the start rather than switching mid-project.

## Maps

The app uses **Leaflet inside a WebView**, matching the website's stack:
`leaflet@1.9.4` on OpenStreetMap raster tiles with Nominatim geocoding. There is
no Google Maps SDK and **no map API key of any kind** — both services are
keyless.

Read [`docs/MAP_IMPLEMENTATION.md`](docs/MAP_IMPLEMENTATION.md) before touching
anything map-related. It records the website's exact marker formats, popup
contents, pin-drop radius search and geocoding parameters, plus the six
behaviours (C1–C6) that could not carry over unchanged.

## Layout

```
app/          Expo Router routes. Composition only, no data fetching.
src/api/      Transport. The only layer that knows endpoint paths.
src/theme/    Design tokens: color, type, motion, spacing.
src/types/    Backend contract types, mirroring the Mongoose schemas.
docs/         The verified API contract.
```

## Rules that are not negotiable

These come from the approved plan and from backend behaviour. Breaking any of
them causes user-visible failure, not just untidy code.

1. **The User-Agent constant never varies** by app version, device model or
   build type. The backend derives a session fingerprint from it and revokes the
   session when the derived OS or device type changes. Version belongs in
   `X-App-Version`. See `docs/API_CONTRACT.md` §1.1.
2. **The session cookie lives in SecureStore**, never MMKV, never AsyncStorage,
   never a log line.
3. **No screen calls** `/properties/property-list` or `/properties/filter`. Both
   are unbounded. They are absent from the endpoint registry on purpose.
4. **No CSRF plumbing.** It is disabled server-side; adding it would be dead
   code that later reads as load-bearing.
5. **The socket token is fetched per connection**, never cached or persisted. It
   expires in five minutes.
6. **`POST /chat/message/send` always precedes the socket emit.** REST persists;
   the socket only fans out.
7. **Verify endpoints against the backend controller**, never against
   `client-next/src/utils/api.js`. Four known helper discrepancies are recorded
   in `docs/API_CONTRACT.md` §8.
8. **No Google Maps, and no mapping stack other than Leaflet.** The map must
   match the website's behaviour; `docs/MAP_IMPLEMENTATION.md` is the spec.
   Tile and geocoding hosts stay out of `src/api/endpoints/`, which is reserved
   for the DealDirect API.
#   d e a l d i r e c r - m o b i l e  
 