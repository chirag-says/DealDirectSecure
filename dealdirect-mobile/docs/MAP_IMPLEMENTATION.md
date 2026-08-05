# Map implementation reference

Verified against `client-next/` on 2026-07-31. This document is the specification
M4 implements against. The website is the source of truth for map behaviour, the
same way the backend is for API behaviour.

Supersedes the `react-native-maps` + Google provider decision in the original
architecture plan §1.17, per the approved change of 2026-07-31.

---

## 1. What the website actually uses

| Concern | Implementation |
|---|---|
| Library | `leaflet@^1.9.4` + `react-leaflet@^5.0.0` |
| Tiles | `https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png` (OSM raster) |
| Attribution | `© OpenStreetMap contributors` |
| Geocoding | Nominatim (`nominatim.openstreetmap.org`), forward and reverse |
| Geolocation | browser `navigator.geolocation.getCurrentPosition` |
| Google Maps | **not used anywhere** |
| Mappls / MapmyIndia | `NEXT_PUBLIC_MAPPLES_API_KEY` is set in env but **no code reads it** |

The Mappls key is dead configuration. It is not a second mapping stack and must
not be treated as one.

### Where maps appear

Three surfaces, and **only** three:

| Surface | File | Purpose |
|---|---|---|
| Search results map | `src/app/properties/PropertyListContent.jsx` | browse, pin-drop radius search |
| Add-property picker | `src/app/add-property/AddPropertyContent.jsx` | set listing coordinates |
| Edit-property picker | `src/app/edit-property/[id]/EditPropertyContent.jsx` | amend listing coordinates |

**The property detail page has no map.** See contradiction C1 in section 5.

---

## 2. Search-results map behaviour

`MapContainer`: `zoom={11}`, `scrollWheelZoom`, `zoomControl={false}`,
`attributionControl={false}`, with an explicit `<ZoomControl position="bottomright" />`.

### Coordinates

Read from the top-level `lat` / `lng` that `withPublicImages` promotes, and only
when **both** `address.latitude` and `address.longitude` exist on the document.
Listings without coordinates are filtered out of `propertiesWithCoords` and the
map shows a "No Location Data" panel when the filtered set is empty.

No backend geospatial query exists. Everything below is client-side over the
current result set.

### Markers

Price-pill `L.divIcon`s, not image pins:

```
price >= 1e7  →  ₹{(price/1e7).toFixed(1)}Cr
price >= 1e5  →  ₹{(price/1e5).toFixed(0)}L
otherwise     →  ₹{price.toLocaleString()}
```

Note this pill formatter is **not** the same as `formatPrice`: it uses `Cr`/`L`
abbreviations and one decimal for crore, where `formatPrice` produces
`₹7 Crore` / `₹50 Lakh`. Both exist on the website and must both be ported.

Default pill is white on `#1e293b` text; highlighted is `#dc2626` with white
text. On `mouseover` the marker is swapped for a larger "detailed" marker and
raised with `zIndexOffset: 1000`.

Image-based `L.Icon` markers also exist for the dropped pin (green) and a
highlighted state (red), sourced from `cdnjs` and
`raw.githubusercontent.com/pointhi/leaflet-color-markers`.

### Popups

Image (first of `images[]`, with a fallback), title, `address.city` +
`address.locality || address.state`, distance from pin when present, price via
`formatPrice`, `area.superBuiltUp`, and a "View Details" button.

Popup styling overrides: `border-radius: 12px`, zero wrapper padding, 12px
content margin.

### Pin-drop radius search

The distinguishing feature of this map.

1. User toggles `pinDropMode`; the cursor becomes a crosshair.
2. A map click drops a pin (`MapClickHandler` via `useMapEvents`).
3. A `<Circle>` is drawn at `searchRadius * 1000` metres, stroke and fill
   `#22c55e`, `fillOpacity: 0.1`, `weight: 2`.
4. Properties are filtered to those within the radius using a **client-side
   Haversine** calculation (`R = 6371 km`), and each keeps its `distance`.
5. Radius slider ranges **0.5 km to 10 km**, default **2 km**.

### Auto-fit

`MapBoundsUpdater` calls `map.fitBounds(bounds, { padding: [50, 50], maxZoom: 14 })`
over whichever set is active (all properties, or the nearby subset once a pin
is dropped).

---

## 3. Add / edit property picker behaviour

- Default centre `[20.5937, 78.9629]` (centre of India), `zoom` 5 with no
  position, 15 once a position exists.
- Tap the map to set the position (`useMapEvents.click`), which writes
  `latitude` / `longitude` as strings fixed to **6 decimal places**.
- `RecenterMap` calls `map.setView(position, 15)` whenever the position changes.
- Coordinates remain manually editable in text fields alongside the map.
- **Reverse geocode** on pin placement:
  `GET nominatim.openstreetmap.org/reverse?format=json&lat=&lon=&addressdetails=1&zoom=18`,
  header `Accept-Language: en`. Fills city from
  `city || town || village || state_district || county`, locality from
  `suburb || neighbourhood || hamlet || residential || quarter`, landmark from
  `amenity || building || shop || tourism || leisure`, and composes an address
  line from house number, road, locality, city, state, postcode.
- **Forward geocode** as the user types (min 3 characters):
  `GET nominatim.openstreetmap.org/search?format=json&q=&addressdetails=1&limit=1`.
  The edit page uses a variant that appends `, India` and `limit=5`.
- **Use my location** via `navigator.geolocation.getCurrentPosition`, then
  reverse geocode.

The backend stores these as `Number` (`address.latitude`, `address.longitude`);
the 6-decimal strings are cast by Mongoose on write. Nothing changes.

---

## 4. React Native approach

**`react-native-webview` hosting Leaflet 1.9.4**, with the map HTML, CSS, JS and
marker images bundled as local assets and a typed message bridge between the
WebView and React Native.

### Why this rather than the alternatives

| Option | Verdict |
|---|---|
| WebView + Leaflet (chosen) | Preserves the tile provider, `divIcon` price pills, popup markup, `Circle`, `fitBounds` and click handling exactly. The same Leaflet version the website runs. |
| `react-native-leaflet-view` / `expo-leaflet` | These are WebView wrappers too, so they buy nothing architecturally, but they pin older Leaflet builds, are effectively unmaintained, and have known New Architecture problems. We would inherit their bugs and still hand-write the custom `divIcon`s. |
| MapLibre native | A genuinely different stack: vector tiles, different styling model, no Leaflet API. Would not preserve behaviour. |
| Google Maps | Excluded by the approved change, and unnecessary since no product or backend requirement calls for it. |

### Bridge surface (to be built in M4)

React Native → WebView: set properties, set centre and zoom, toggle pin-drop
mode, set radius, fit bounds, set the selected marker.

WebView → React Native: marker tapped, "View Details" tapped, map tapped (with
lat/lng), pin dropped, map ready, tile error.

### What moves to the native side

- **Geolocation** uses `expo-location`, not WebView `navigator.geolocation`.
  WebView geolocation permissions are unreliable on Android and would need a
  second permission prompt. The resolved coordinate is passed into the WebView.
- **Geocoding calls** are issued from React Native rather than inside the
  WebView, so they share the app's networking, can be debounced centrally, and
  carry a proper identifying header.
- **Marker and popup assets** are bundled locally instead of fetched from cdnjs
  and raw.githubusercontent.com, so the map renders offline-first and does not
  depend on third-party CDN availability. Appearance is unchanged.

---

## 5. Limitations that cannot be replicated, and decisions needed

Per the standing instruction, these are raised rather than resolved unilaterally.

### C1 — The website has no property-detail map, the architecture specifies one

Architecture plan §1.17 states two surfaces: "a locator map on property detail,
and a map view over search results". The website has a map on the search results
page and on the add/edit pickers, and **none on property detail**.

*Smallest change:* keep the detail-page map, since a property detail screen
without a location is a genuine gap on mobile where opening a separate map tab
is more costly than on desktop. Implement it as a small, non-interactive Leaflet
view centred on the listing with a single marker, tapping through to the full
map. It reuses the same component and adds no new dependency.

*Alternative:* drop it, to mirror the website exactly.

**Needs your decision.** I have assumed "keep" in the updated M4 scope and
marked it clearly.

### C2 — Hover has no touch equivalent

The website swaps to a larger detailed marker on `mouseover`, scales the pill
1.1× on CSS hover, and raises `zIndexOffset`. Touch devices have no hover state,
so this behaviour cannot be reproduced.

*Smallest change:* map hover onto **tap-to-select**. First tap on a marker
selects it, swapping in the detailed marker and opening the popup; the popup's
"View Details" button navigates. This preserves both visual states and both
outcomes, and only changes what triggers them.

Consequence worth naming: on the website, a marker click navigates straight to
the property (`click: () => viewDetails(p)`) while hover shows the popup. On
touch those must merge, so the first tap will show the popup rather than
navigating immediately. This is a deliberate, unavoidable divergence.

### C3 — OSM tile usage policy

The OSM Foundation's tile policy is aimed at modest, attributed use and requires
a valid identifying User-Agent. A store-distributed app can generate far more
tile traffic than a website, and heavy consumers are asked to run or pay for
their own tile infrastructure. Existing app blocks over this are not rare.

This is a pre-existing risk the website already carries; the app changes its
scale, not its nature.

*Smallest change:* ship on OSM tiles exactly as the website does, send a proper
identifying User-Agent, cache tiles on device to cut repeat requests, and keep
the tile URL in one constant so switching to a paid provider later is a
one-line change. **No provider change is proposed now.**

**Flagging, not requesting a decision** — unless you want a tile provider lined
up before store submission.

### C4 — Nominatim usage policy

Nominatim's public instance permits at most 1 request per second, requires an
identifying User-Agent, and forbids heavy or automated use. The website's
add-property forward geocode fires as the user types.

*Smallest change:* debounce to at least 1100 ms in the app, require the existing
3-character minimum, cache results per query, and send an identifying
User-Agent. Same endpoint, same parameters, disciplined call rate.

### C5 — Gesture conflict inside a scrolling screen

A WebView map placed inside a scrolling screen competes with the parent scroll
view for pan gestures. On the website the map is a full-height panel, so the
question does not arise.

*Smallest change:* the full map is its own full-screen route
(`/property/[id]/map` and the search map view), where it owns all gestures. The
detail-page locator from C1, if kept, is non-interactive and passes taps
straight through to a navigation action.

### C6 — Marker volume

Neither the website nor this plan uses clustering, and every property with
coordinates gets a `divIcon`. Rendering hundreds of DOM markers inside a WebView
degrades noticeably earlier than it does in a desktop browser.

*Smallest change:* the mobile map plots only the current search page (default
12 results) rather than an unbounded set, which is both faster and consistent
with the paginated `/properties/search` contract. Clustering is deferred until
there is evidence it is needed.

---

## 6. Backend impact

**None.** No route, contract, parameter or response shape changes.

The map reads `lat` / `lng` (promoted by `withPublicImages`), `address.city`,
`address.locality`, `address.state`, `images[]`, `price`, `priceUnit` and
`area` — all already frozen in `API_CONTRACT.md`.

Tiles and geocoding are **external third-party services**, not DealDirect
backend endpoints. They are deliberately absent from `src/api/endpoints/`, which
is reserved for the DealDirect API, and will live in the maps feature module
instead.

No geospatial query endpoint exists, so the app must not offer a "search this
area" affordance that the backend cannot honour. Adding one remains a future
backend change request, not part of this work.
