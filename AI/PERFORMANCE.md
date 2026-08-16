# PERFORMANCE.md — Optimisations, Costs, and Bottlenecks

Related: [DATABASE.md](DATABASE.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [DEPENDENCIES.md](DEPENDENCIES.md)

---

## 1. What Is Already Optimised

### Database indexes
`Property` carries 9 indexes covering the real query shapes (`owner`, `builder`, `{status,isApproved}`, `{city,status}`, `{listingType,status,createdAt:-1}`, `{address.city,address.state}`, `{categoryName,propertyTypeName}`, `price`, `createdAt:-1`). The commit comment marks this as an "H12 FIX": *"Without these, the most heavily queried collection does full scans."*

Other well-indexed collections: `Lead` (incl. the unique `{user,property}`), `AuditLog` (5 compound indexes), `Blog` (incl. a text index), `Project`/`UnitType`/`CampaignMember`.

**TTL indexes** on `UserSession.expiresAt`, `AdminSession.expiresAt`, and `PasswordResetToken.expiresAt` let Mongo expire rows without a cleanup job.

### Query-level
- `.lean()` used where documents are read-only (`Conversation` socket auth, reward/redemption listings, campaign reads).
- Field projections via `.select()` on most `populate()` calls (`"name email phone profileImage"`).
- `Promise.all` for independent queries — `getDashboardStats` batches 5 counts then 3 aggregations; `searchProperties` runs `countDocuments` and the find concurrently.
- `getSuggestions` uses a single `$facet` aggregation instead of three round trips.
- Atomic single-document operations replace read-modify-write in the hot paths: campaign join (`$inc` with `$expr` guard), booking inventory (`$inc` with `$gte:1` filter), interest (`$push` + `$inc`).

### Images
- Everything goes to Cloudinary with server-side transforms: properties `1400×900 crop:limit quality:auto`, profiles `400×400 crop:fill gravity:face`, projects additionally `fetch_format:auto` (WebP/AVIF negotiation).
- 6 MB chunked uploads with a 120 s Cloudinary timeout — added specifically to stop single-shot 499s on large files.
- `next.config.mjs` allows Cloudinary hosts through `next/image`.
- `layout.js` emits `dns-prefetch` + `preconnect` for `res.cloudinary.com`.

### Frontend
- **SSR + ISR** — `ssrFetch` passes `next: { revalidate }`: properties 120 s, taxonomy 3600 s, blogs 600 s, projects 120 s. Static content is cached hard; listings refresh every 2 minutes.
- **8-second SSR timeout** via `AbortController`. A slow backend degrades the page to empty state instead of hanging the render — the single best resilience decision in the frontend.
- `ssrFetchAll` uses `Promise.allSettled` so one failing endpoint doesn't blank the whole page.
- **Auth-check elision** — `AuthContext.checkAuth()` reads the `session_exists` cookie first and skips the `/users/me` request entirely for guests. Removes one round trip from every anonymous page load.
- `next/font` self-hosts Inter with `display: swap`.
- Sentry configured with `hideSourceMaps` and `disableLogger` (tree-shakes log statements).
- Admin splits three manual vendor chunks (`vendor`, `antd`, `charts`).
- `Navbar` uses `useMemo`/`useCallback`; `LogoLoop` is wrapped in `memo`.

### Uploads
`uploadConcurrencyGuard` caps in-flight upload requests at 10 process-wide, decrementing on both `finish` and `close` (so aborted requests don't leak the counter). Magic-byte validation happens **in memory before** any Cloudinary call, so invalid files cost nothing externally.

---

## 2. Bottlenecks — Ranked

### P1 — Notification email fan-out is synchronous and per-document
`Notification` has `post('save')` **and** `post('insertMany')` hooks that, for each document, do a `User.findById` and then an SMTP send.

`addProperty` loads **every** active `SavedSearch`, matches in JS, and `insertMany`s the matches. Listing one property in a popular city can trigger dozens of User lookups and dozens of Gmail SMTP connections, inside the request path.

*Fix:* move email out of the model hooks into a queue (BullMQ/Agenda), or at minimum batch the User lookups with a single `$in` query and fire sends without awaiting.

### P2 — Saved-search matching is O(all active searches) per listing
```js
const savedSearches = await SavedSearch.find({ isActive: true }).lean();
```
No index use, no filtering by city at the DB level, entire collection into memory, matched in a JS loop. Runs on every property creation (owner and builder paths both).

*Fix:* invert it — query `SavedSearch` with a filter derived from the new property (`{isActive: true, $or: [{'filters.city': ''}, {'filters.city': prop.city}]}`) and index `filters.city`.

### P3 — `GET /api/properties/filter` has no pagination
Loads the full matching set with three `populate()` calls, then filters **and** sorts in JavaScript. Cost grows linearly with the collection. This is why `searchLimiter` (20/min) covers it.

*Fix:* add pagination, or push the populated-field matching into an aggregation with `$lookup`.

### P4 — `Reward.transactions` is an unbounded embedded array
Every earn/redeem/adjustment pushes a subdocument. The whole document is rewritten on each `save()`. `getTransactionHistory` loads the entire array and paginates in JS. `awardPoints` also filters the array in JS for the daily enquiry cap.

A heavy user trends toward the 16 MB BSON limit, and write cost grows with history length.

*Fix:* move transactions to their own collection with `{user, createdAt}` indexed. This is the highest-value schema change available.

Same shape, lower volume: `Agreement.auditLog`, `Lead.contactHistory`.

### P5 — All rate limiting and caching is in-process
`express-rate-limit`'s default MemoryStore, two hand-rolled `authAttempts` Maps, `activeUploads`, the Hubble token Map, Socket.IO presence Maps, and `MemoryCache`. Nothing is shared. **The backend cannot run more than one instance without breaking correctness**, not just performance.

`config/redis.js` already ships an ioredis-shaped shim with the real client commented out — the migration path is written into the file.

### P6 — `cacheOrCompute` exists and is never called
`config/redis.js` exports a working cache helper. Grep finds no usage. Dashboard stats, taxonomy lists, and the rewards store are all recomputed on every request and are ideal candidates.

### P7 — Live aggregations on every dashboard load
`getDashboardStats` runs 5 counts, 2 regex counts, and 4 aggregations (three 6-month `$dateToString` series plus a `$lookup` for top owners) per request. `getLeadAnalytics` runs 3 aggregations plus 3 counts. No caching.

### P8 — Regex search cannot use indexes
All property search is `RegExp` without anchors, so `/mumbai/i` cannot use the `address.city` index. `Property` has **no text index** (unlike `Blog`, `Builder`, and `Project`, which all have one).

*Fix:* add a text index on `title`/`description`/`address.*` and use `$text` for the free-text portion, keeping regex only for prefix autocomplete.

### P9 — `views` increments on every property GET
`getPropertyById` does a second write (`$inc: {views: 1}`) on every request, uncached and undeduplicated. Doubles the DB ops for the most-hit endpoint and makes the metric meaningless.

### P10 — Bundle weight from duplicated libraries
Three icon libraries per frontend; Admin ships both recharts and chart.js; `client-next` ships an unused markdown editor (`@uiw/react-md-editor`) and the backend carries 7 unused packages. See [DEPENDENCIES.md](DEPENDENCIES.md).

### P11 — `getMyProperties` populates `interestedUsers.user`
For a listing with many interested buyers this is an N-document populate on a dashboard load. Acceptable today because of the 5-interests-per-buyer cap, but it scales with popularity, not with the cap.

### P12 — `Property.find()` without `.lean()` on list endpoints
`getProperties`, `getAllPropertiesList`, and `getAdminProperties` hydrate full Mongoose documents, then `withPublicImages` calls `.toObject()` on each — paying hydration cost for nothing.

---

## 3. Frontend Rendering Notes

**Not used anywhere:** `React.memo` (except `LogoLoop`), `useMemo`/`useCallback` outside `Navbar` and the contexts, virtualisation, code splitting beyond Next.js route-level defaults, `next/dynamic` for heavy components.

The largest client components — `PropertyListContent.jsx` (2 536 L), `AddPropertyContent.jsx` (2 040 L), `PropertyDetailsContent.jsx` (1 623 L), `AdminAddProperty.jsx` (2 013 L) — are single components holding large `useState` trees. Any state change re-renders the whole subtree. They are also all `'use client'`, so they ship entirely to the browser.

**Leaflet** must be `next/dynamic` with `ssr: false` — it touches `window` at module scope.

**ISR caveat:** `app/page.js` and `app/sitemap.js` set `export const dynamic = 'force-dynamic'` because the backend is unreachable during the Hostinger build. This disables static generation for the home page — the `revalidate` values inside `ssrFetch` still cache the *fetches*, but the page itself renders per request.

---

## 4. Measurement

There is **no performance instrumentation**: no APM, no slow-query logging, no `explain()` anywhere, no Lighthouse budget, no bundle analyzer.

Sentry is wired on the frontend only (`@sentry/nextjs`) and captures errors, not performance. `@sentry/node` is installed in the backend but **never initialised** — the backend has no error or performance reporting at all.

Available today:
- `X-Request-ID` on every response, correlating to the server log line
- `duration` recorded on `AuditLog` entries for admin writes
- `GET /health` for liveness

---

## 5. Recommended Order of Work

| # | Change | Effort | Payoff |
|---|---|---|---|
| 1 | Initialise `@sentry/node` in the backend | trivial | Visibility — everything else is guesswork without it |
| 2 | Fire notification emails without awaiting; batch the User lookups | low | Removes SMTP latency from the request path (P1) |
| 3 | Filter saved searches at the DB level + index `filters.city` | low | Kills an O(n) scan per listing (P2) |
| 4 | Add `.lean()` to the three list endpoints | trivial | Cheap win (P12) |
| 5 | Paginate `/api/properties/filter` | low | Bounds the worst endpoint (P3) |
| 6 | Wire real Redis into `config/redis.js`, use `cacheOrCompute` for dashboard + taxonomy | medium | P6, P7 — and unblocks P5 |
| 7 | Move rate limiting to the Redis store | low (after 6) | Correct limits under scale (P5) |
| 8 | Socket.IO Redis adapter | medium | Unblocks horizontal scale (P5) |
| 9 | Text index on `Property` + `$text` search | medium | P8 |
| 10 | Extract `Reward.transactions` to its own collection | **high** — needs migration | P4, and removes a hard document-size ceiling |
| 11 | Remove the 7 unused backend packages and consolidate icon/chart libraries | low | P10 |
| 12 | Split the four 1 500+ line components | high | P-frontend |

Items 6–8 are one project: introducing Redis is the prerequisite for scaling the backend past a single instance.
