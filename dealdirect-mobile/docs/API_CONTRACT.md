# DealDirect Backend Contract (mobile client reference)

Verified against backend source on 2026-07-31. Every row was read from the route
file and its controller, not from `client-next/src/utils/api.js`.

**Live-verified 2026-07-31** against `https://backend.dealdirect.in`:

| Check | Result |
|---|---|
| `GET /health` | `{success, status:"healthy", environment:"production", database:"connected"}` |
| `GET /api/properties/search?limit=1` | `{data, total, page, pages}` — **no `success` key**, as documented |
| top-level `lat` / `lng` | present on a listing that has coordinates |
| `parking.covered` | returned as the **string** `"0"`, confirming the `MixedValue` typing |
| `GET /api/categories/list-category` | `{success, data}`, with `propertyType` populated |
| `GET /api/users/me` unauthenticated | `401` with `code: "NO_SESSION"` |

**This document, and the types in `src/types/backend/`, are the only sanctioned
source for what the backend returns.** Where the website's API helpers disagree
with the backend, the backend wins and the discrepancy is recorded in section 8.
Neither the backend nor the website is modified.

Paths below omit the `/api` prefix, which `EXPO_PUBLIC_API_URL` already carries.

> **Which backend?** Corrected 2026-08-09. This repository's `backend/` is not
> what is deployed. Production runs `origin/main`; `main` is 4 commits ahead of
> it and 13 backend files are uncommitted on top of that. Three surfaces the app
> depends on differ between the two:
>
> | Surface | `origin/main` (live) | working tree |
> |---|---|---|
> | `/agreements/*` | mounted | **unmounted** (`server.js:869`) |
> | `/rewards/store`, `/rewards/redeem` | live | **deleted** |
> | `listingType` on `/properties/search` | absent | present |
>
> Every claim in this document should be read as describing the working tree
> unless it says otherwise. Full detail in
> [`HANDOFF_AUDIT_2026-08-09.md`](HANDOFF_AUDIT_2026-08-09.md) §0.

---

## 1. Authentication model

The session token is a **48-byte opaque random string** (`crypto.randomBytes(48).toString('base64url')`,
`models/UserSession.js`), stored server-side as a SHA-256 hash. It is **not a JWT**.

It is delivered **only** as a `Set-Cookie` header:

| Cookie | Flags | Purpose |
|---|---|---|
| `user_session` | HttpOnly, Secure (prod), SameSite=None (prod) / Lax (dev), 7 days, `domain=.dealdirect.in` | the credential |
| `session_exists` | readable by JS, same lifetime | a hint flag for the website; the app does not need it |

No response body ever contains the token. There is **no token endpoint and no
refresh endpoint**, so there is no refresh flow to implement. When the 7-day
session expires, the user logs in again.

A `Bearer` fallback exists in `middleware/authUser.js`, but it is only consulted
when **no cookie is present**, and nothing in the backend ever issues a user a
JWT that would satisfy it. It is not usable by the app.

### 1.1 Session fingerprinting — the load-bearing constraint

`UserSession.validateFingerprintLenient` compares each request against the
session's stored fingerprint and **revokes the session** on:

- a change in **OS family** (derived from the User-Agent), or
- a change in **device type** (derived from the User-Agent).

An IP change only refreshes the fingerprint; it does not revoke. Indian carrier
IP rotation is therefore safe.

Consequence: **every authenticated request must send a byte-identical
User-Agent.** A single request from a different HTTP client (a file download, a
second library) flips the fingerprint and silently logs the user out.

The app compiles in one constant per platform, containing no version number:

| Platform | Must parse to |
|---|---|
| Android | os `Android`, device `Mobile` |
| iOS phone | os `iOS`, device `Mobile` |
| iOS tablet | os `iOS`, device `Tablet` |

App version travels in `X-App-Version`, which the fingerprint ignores.
Implemented in M2 (`src/api/userAgent.ts`).

### 1.2 CSRF — the app is exempt, and that exemption is load-bearing

Corrected 2026-08-09. The original wording ("no route enforces CSRF") was true
of `origin/main` and is no longer true of this repository.

`validateCsrfToken` is indeed commented out (`backend/server.js:768`). But the
working tree adds a second guard, `requireCsrf`
(`backend/middleware/csrfProtection.js:246`), applied to **eleven named routes**
(`server.js:804-829`), including:

```
POST /properties/add          PUT  /properties/my-properties/:id
POST /properties/interested/:id    POST /properties/:id/report
POST /campaigns/:id/join      POST /campaigns/:id/exit
POST /chat/message/send       POST /chat/conversation/start
POST /contact                 POST /rewards/admin/adjust-points
```

The app still builds no CSRF plumbing, and that is still correct — but for a
different reason than "nothing enforces it." `requireCsrf` returns `next()`
immediately when the request carries **no `Origin` header**
(`csrfProtection.js:256-259`), on the explicit grounds that CSRF is a
browser-only attack and a native client has no ambient credentials to forge.
React Native's networking sends no `Origin`.

> **Constraint that follows:** no DealDirect API call may ever originate from a
> WebView, from `react-native-web`, or from any client that attaches `Origin`.
> Those eleven writes would 403 with `CSRF_ORIGIN_REJECTED`. This matters for
> the pending `react-native-webview` work (M4/M16 locator map, and any Hubble
> rewards WebView): map tiles and Nominatim are fine — different hosts, no
> cookie — but a WebView must not call this API. Fetch in the app, pass the
> result in.

An emergency off-switch exists: `CSRF_ENFORCE=false`.

---

## 2. Response envelopes

Six shapes across the API. There is no generic unwrapper.

| Kind | Shape | Example endpoint |
|---|---|---|
| `bare` | `[...]` or `{...}`, no wrapper | `GET /properties/list`, `GET /properties/:id` |
| `data` | `{ success, data }` | `GET /projects/:id` |
| `counted` | `{ success, data, count }` | `GET /properties/my-properties` |
| `paged` | `{ data, total, page, pages }` — **no `success` key** | `GET /properties/search` |
| `paginated` | `{ success, data, pagination: { total, page, pages } }` | `GET /projects`, `GET /leads`, `GET /blogs` |
| `keyed` | `{ success, <domainKey>: ... }` | `GET /chat/conversations` → `conversations` |

A truthiness check on `success` treats every successful `/properties/search`
response as a failure. Branch on the declared envelope, not on a guess.

---

## 3. Rate limits (per IP, `backend/server.js`)

| Tier | Budget | Applies to |
|---|---|---|
| global | 500 / 15 min | everything except `/health` |
| auth (express-rate-limit) | 5 / 15 min, successes **not** counted | `/users/login`, `/users/register`, `/users/forgot-password`, `/admin/login` |
| **auth (in-memory, second limiter)** | **10 / 15 min, successes ARE counted, one shared budget** | **`/users/register`, `/register-direct`, `/verify-otp`, `/resend-otp`, `/login`, `/forgot-password`, `/reset-password`** |
| search | 20 / min | `/properties/search`, `/suggestions`, `/filter` |
| transactional | 20 / hour | `/agreements/generate` |
| ~~group buy~~ | ~~10 / 15 min~~ | **does not apply — see below** |

Corrected 2026-08-09, two rows:

**The second auth limiter was missing.** `authRateLimit`
(`backend/middleware/authUser.js:512-546`) is a hand-rolled in-memory `Map`
keyed `auth:${ip}`, applied per-route in `backend/routes/userRoutes.js:59-70`. It
allows **10 requests per IP per 15 minutes across all seven public auth routes
combined**, and unlike `authLimiter` it counts successful requests. In practice
it is the stricter of the two. A test session that registers, resends an OTP
twice, verifies and logs in three times has already spent 7 of 10. It returns
429 with `retryAfter` in the body, which `src/api/errors.ts` reads.

**The group-buy limiter does not reach campaigns.** It is mounted at
`/api/group-buy/projects/:id/join` and `.../exit` (`backend/server.js:705-706`).
Campaigns are mounted at `/api/campaigns` (`:880`). No `/api/group-buy` path
exists anywhere in the app, so campaign join/exit fall under the global tier
only.

Keyed on **IP, not user**. On Indian carrier NAT many subscribers share one
address, so these budgets are effectively shared between unrelated users. The
client compensates with caching, a 400–500 ms search debounce, request dedupe,
no polling, and backoff honouring `RateLimit-Reset`.

---

## 4. Endpoints the app uses

Declared in `src/api/endpoints/`. `auth` column: `pub` = none, `opt` = optional,
`user` = `user_session` cookie.

### Users — `/users`

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| POST | `/users/register` | pub | keyed | 20 KB cap. Creates **unverified** user, sends OTP **by SMS only**. No session. **Ignores `referralCode`.** The website uses this for **owners only**. |
| POST | `/users/register-direct` | pub | keyed | **Added 2026-08-09 — was missing.** The path the website uses for **buyers**: no OTP, `isVerified: true`, session created immediately, 201 with the user. Reads `referralCode`. `userController.js:333-409`. |
| POST | `/users/verify-otp` | pub | keyed | 201. **Establishes the session.** Do not call login after. **This is where `referralCode` is attributed** (`:456-458`) — send it here, not to `/register`. |
| POST | `/users/resend-otp` | pub | ok | SMS, not email. |
| POST | `/users/login` | pub | keyed | 10 KB cap. Body is exactly `{ email, password }`. 401 bad creds / 423 `ACCOUNT_LOCKED` / 403 `ACCOUNT_BLOCKED` / 400 `EMAIL_NOT_VERIFIED` |
| POST | `/users/logout` | user | ok | |
| POST | `/users/logout-all` | user | ok | revokes the calling device too |
| POST | `/users/forgot-password` | pub | ok | **Corrected 2026-08-09.** Sends a 6-digit OTP **by SMS**. Body `{ phone }` (`{ email }` accepted as a lookup fallback, but delivery is still SMS). No email, no link, no token. Returns **404** when no account matches — it enumerates. `userController.js:670-743`. |
| POST | `/users/reset-password` | pub | ok | **Corrected 2026-08-09.** Body `{ phone \| email, otp, newPassword }`. Full password-strength rules apply. Revokes every session on success. `userController.js:782-868`. |
| GET | `/users/me` | user | keyed | cold-start session probe; 401 is the normal guest result |
| GET | `/users/profile` | user | keyed | alias of `/me` |
| PUT | `/users/profile` | user | keyed | multipart, file field `profileImage` |
| PUT | `/users/change-password` | user | ok | |
| DELETE | `/users/me` | user | ok | **App Store account-deletion requirement, already implemented** |
| GET | `/users/sessions` | user | keyed | reshaped rows, not raw documents |
| DELETE | `/users/sessions/:sessionId` | user | ok | |
| POST | `/users/send-upgrade-otp` | user | ok | buyer → owner, requires verified account |
| POST | `/users/verify-upgrade-otp` | user | ok | role becomes `owner`; refetch profile |

### Properties — `/properties`

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| GET | `/properties/search` | pub | paged | **the only paginated property endpoint.** Param is `search`, not `q`. Default limit 12. |
| GET | `/properties/suggestions` | pub | keyed | uses `q`. `<2` chars returns empty. Max 8. Rows are **objects**, see 4.1. |
| GET | `/properties/list` | pub | bare | **naked array** |
| GET | `/properties/:id` | pub | bare | **naked object.** Increments `views` per call. 404 (not 403) when hidden. |
| GET | `/properties/my-properties` | user | counted | |
| POST | `/properties/add` | user | data | owners only. multipart `images` (15) + `categorizedImages` (50) |
| PUT | `/properties/my-properties/:id` | user | data | owners only |
| DELETE | `/properties/:id` | user | ok | |
| GET | `/properties/saved` | user | data | **NOT a private bookmark** — corrected 2026-08-09 to match `HANDOFF.md` §3.2, which this table predates. `getSavedProperties` queries `{ "interestedUsers.user": userId }`, the same array `markInterested` pushes to. Saved and Interested are one list under two names, capped at 5. |
| DELETE | `/properties/saved/:id` | user | ok | |
| POST | `/properties/interested/:id` | user | keyed | **creates a Lead and notifies the owner.** Not a bookmark. |
| GET | `/properties/interested/:id/check` | user | keyed | |
| DELETE | `/properties/interested/:id` | user | ok | |
| POST | `/properties/:id/report` | user | ok | |
| POST | `/properties/:id/close-deal` | user | keyed | multipart `documents` (5) |
| POST | `/properties/claim-deal-reward/:verificationId` | user | keyed | after admin approval |

`search` params: `search, category, subcategory, propertyType, buildingType,
size, city, priceFrom, priceTo, listingType, page, limit, sort`. `sort` ∈
`newest | priceAsc | priceDesc`. `city=All` means no filter.

`listingType` was added by commit `ab5ec1b` and expands `rent` / `sale` across
all six schema spellings. It is **committed but not deployed** — `main` is ahead
of `origin/main`, which is what Hostinger imports. Against the live API the
param is ignored. See `HANDOFF.md` §3.1.

**Excluded on purpose** (see section 7): `/properties/property-list`,
`/properties/filter`.

Upload limits (`middleware/upload.js`): 10 MB per file, 50 files, mime ∈
jpeg/jpg/png/gif/webp, magic-byte validated. 503 when more than 10 uploads are
in flight server-wide.

### 4.1 Which `/properties/search` params actually work

Added 2026-08-03 during M3. Accepting a param and doing something useful with it
are different things, and five of the eleven turned out to be the second kind.
Measured against production (36 approved listings) on that date.

| Param | Verdict | Evidence |
|---|---|---|
| `search` | **works** | `Apartment` → 16, `Showroom` → 2, `Bengaluru` → 6 of 36. Regex over title, description, `address.city`, `address.area`. Case-insensitive. |
| `priceFrom` / `priceTo` | **works**, rupees | `priceTo=100000` → 21, `priceFrom=5000000` → 8. See the `priceUnit` warning below. |
| `sort`, `page`, `limit` | **works** | |
| `listingType` | **works** (added 2026-08-03) | `rent` → 24, `sale` → 12, baseline 36. Perfect partition. An unrecognised value is ignored, so `listingType=nonsense` → 36 rather than 0. |
| `category` | **useless** | 19 categories probed; 17 return 0. The 2 that match return the wrong listings. |
| `subcategory` | **useless** | same root cause |
| `propertyType` | **useless** | `Residential` → 0, `Commercial` → 0, `Plot` → 21 — and those 21 are apartments and penthouses. |
| `city` | **usable but sharp** | exact and **case-sensitive**: `Pune` → 3, `pune` → 0. No endpoint lists valid cities. |
| `buildingType` | **breaks the query** | field is not on the schema. Mongoose 8 defaults `strictQuery: false`, so it reaches Mongo and matches nothing. |
| `size` | **breaks the query** | same |

**Taxonomy refs are corrupt in the data, not the API.** On the live corpus,
`category` / `subcategory` / `propertyType` are `null` on 15 of 36 listings, and
the remaining 21 all carry the *same* `propertyType` id (the one for "Plot")
regardless of what they are. The denormalised `categoryName` and
`propertyTypeName` strings are correct on every row, but no param filters on
them. Backfilling the refs from those strings would make all three filters work
with no client change. Until then the app ships no category or type filter,
because a filter that returns an empty list reads as "no such property" rather
than "this is broken".

**`priceUnit` is not a multiplier.** It defaults to `"Lac"` in the schema
(`models/Property.js:23`) and holds that default on 15 of 36 listings whose
`price` is plainly in rupees (65000, 17800000, 36000, …). `price` is rupees;
render it as rupees. The website's `formatPrice` does exactly this and ignores
`priceUnit`; its separate `normalizePrice` helper *does* multiply, and is used
only for the website's own client-side sort and price filter, which are
therefore wrong on those rows. Mobile copies the display, not the filter. See
`src/ui/PriceLabel.tsx`.

**`listingType` — added 2026-08-03, by explicit approval.** Rent versus sale was
previously unfilterable server-side. `searchProperties` now reads an optional
`listingType` and expands it to an `$in` over every spelling that means the same
thing:

| Send | Matches |
|---|---|
| `rent` | `Rent`, `rent` |
| `sale` (or `sell`) | `Sell`, `Sale`, `sell`, `sale` |
| anything else | ignored — the filter is not applied |

The expansion is required, not defensive: the schema enum holds six spellings of
three meanings, so an equality match returns only the listings that happen to
share the caller's casing. Ignoring an unrecognised value rather than applying
it means a typo shows the unfiltered list instead of an empty one.

Backward-compatible by construction: omitting the param leaves the query exactly
as it was, and the response shape is untouched. The website sends nothing and is
unaffected.

### 4.2 `/properties/suggestions` response shape

M0 typed this as `string[]`. It is not. `getSuggestions`
(`propertyController.js:1911`) runs a three-way `$facet` and returns objects:

```jsonc
{ "suggestions": [
  { "type": "project",  "value": "3 BHK Independent House for Rent in Hebbal",
    "subtitle": "Bengaluru",
    "image": "https://res.cloudinary.com/…" },   // null when the listing has none
  { "type": "locality", "value": "Hebbal", "subtitle": "Bengaluru" },
  { "type": "city",     "value": "Bengaluru", "subtitle": "City" }
]}
```

`type` is `project | locality | city`, where `project` means a listing **title**
match, not a builder project. At most 8 rows: 5 titles, 5 localities, 3 cities,
deduped then sliced. Verified live 2026-08-03.

### Chat — `/chat` (all `user`)

> **Product status (2026-08-13):** messages/chat is unmounted from the mobile
> UI (HANDOFF §9.1 D2), matching the website, which mounts no chat anywhere.
> The endpoints below remain live on the backend and the client code remains
> on disk, dormant. This table stays for when/if the feature returns.

| Method | Path | Envelope | Notes |
|---|---|---|---|
| GET | `/chat/socket-token` | keyed | JWT, **5-minute** life. Fetch per socket connect. Never cache. |
| POST | `/chat/conversation/start` | keyed | idempotent; `isNew:false` + 200 when reused |
| GET | `/chat/conversations` | keyed | adds `otherParticipant`, `myUnreadCount`, `isOwner`. Not paginated. |
| GET | `/chat/messages/:conversationId` | keyed | **oldest-first**, default limit 50, **no total**. Marks read as a side effect. |
| POST | `/chat/message/send` | keyed | see the `message` warning below |
| GET | `/chat/unread-count` | keyed | |
| DELETE | `/chat/conversation/:conversationId` | ok | archives (`isActive=false`) |

Two traps:

1. `POST /chat/message/send` returns `{ success, message }` where on **success**
   `message` is a **Message object**, and on **error** `message` is a **string**.
   Narrow on `success` before touching it.
2. Message text is **HTML-escaped** before storage (`escapeHtml`), but
   `conversation.lastMessage.text` is stored **raw**. The bubble and the preview
   encode the same text differently. Decode entities when rendering bubbles.

`unreadCount` is a Mongoose `Map`, serialised as `Record<string, number>` keyed
by user id.

### Leads — `/leads` (all `user`, owner-facing)

| Method | Path | Envelope | Notes |
|---|---|---|---|
| GET | `/leads` | paginated | carries **both** `stats` and `pagination`. Default limit 20. |
| GET | `/leads/analytics` | data | default 30 days; `statusStats` is an object, not an array |
| GET | `/leads/property/:propertyId` | data | 403 when not the owner |
| PUT | `/leads/:id/status` | data | |
| PUT | `/leads/:id/viewed` | ok | bare `{success:true}` |
| POST | `/leads/:id/contact` | data | |
| GET | `/leads/export` | bare | **binary xlsx**; authenticated, so same User-Agent rule applies |

### Agreements — `/agreements`

> **WITHDRAWN from the product** (client decision 2026-08-01, confirmed
> 2026-08-13, HANDOFF §9.1 D1). The backend mount is commented out in the
> working tree (`server.js:869`); after the next deploy every route below
> 404s. The website's page already returns 404 and its navbar links are
> commented out. Do not build a client for these. The table stays only so the
> withdrawal is legible.

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| GET | `/agreements/templates` | pub | keyed | |
| GET | `/agreements/states` | pub | keyed | |
| POST | `/agreements/generate` | user | keyed | **20/hour**, 50 KB cap. Two success shapes (201 created, or 200 `isDuplicate:true`). Amounts read server-side from the Property. |
| GET | `/agreements/my-agreements` | user | keyed | strips `content` and `signature` |
| GET | `/agreements/:id` | user | keyed | IDOR-checked; returns an `integrity` block |
| POST | `/agreements/:id/sign` | user | keyed | `fullySigned` only once **both** parties sign |

**Role gate:** `requireUserRole('owner','user')`. An account whose role is
literally `buyer` gets 403 here, even though `authUser.js` accepts `buyer`
elsewhere. Hide the entry point for that role.

### Notifications — `/notifications` (all `user`)

| Method | Path | Envelope | Notes |
|---|---|---|---|
| GET | `/notifications` | keyed | **capped at 100**, newest first, **not paginated** |
| PATCH | `/notifications/:id/read` | keyed | **PATCH**, not PUT |
| PATCH | `/notifications/mark-all/read` | ok | **PATCH**, path is `/mark-all/read` |

Every saved Notification also emails the user via a `post('save')` hook, unless
`preferences.emailNotifications === false`. Out-of-app delivery already exists.

### Saved searches — `/saved-searches` (all `user`)

| Method | Path | Envelope | Notes |
|---|---|---|---|
| POST | `/saved-searches` | keyed | needs ≥1 non-empty filter; key is `savedSearch` |
| GET | `/saved-searches/mine` | keyed | key is **`searches`** |
| PATCH | `/saved-searches/:id/toggle` | keyed | key is `savedSearch` |
| PUT | `/saved-searches/:id` | keyed | |
| DELETE | `/saved-searches/:id` | ok | |

### Rewards — `/rewards`

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| GET | `/rewards/store` | pub | keyed | **DEAD — removed in working tree**; live only until the next deploy. The website has zero callers. Do not build against it. |
| GET | `/rewards/wallet` | user | keyed | see the shape warning below |
| GET | `/rewards/transactions` | user | keyed | key confirmed: `{ transactions, pagination }` (`rewardService.js:340-346`) |
| GET | `/rewards/referral-code` | user | keyed | `referralLink` points at the **website** |
| GET | `/rewards/referrals` | user | keyed | full shape: `{ totalReferred, signups, firstActions, dealClosures, totalPointsEarned, referrals[] }` (`rewardService.js:466-489`) |
| POST | `/rewards/redeem` | user | keyed | **DEAD — removed in working tree**, same as `/store`. Redemption is Hubble-only now; that is a separate workstream (HANDOFF §9.1 D3). |

**Wallet shape — corrected 2026-08-13.** `getWallet` returns
`{ totalPoints, availablePoints, tier, tierMultiplier, nextTierProgress,
recentTransactions }` (`rewardService.js:314-329`). There is **no `balance`
key**. The website renders `availablePoints`
(`RewardsDashboardContent.jsx:183`); mobile's `wallet.balance ?? 0` read is
defect F1 in HANDOFF §9.3 and shows every user zero points.

### Projects vertical

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| GET | `/projects` | opt | paginated | default limit 20; `search` is a Mongo `$text` query (whole words) |
| GET | `/projects/:id` | opt | data | |
| GET | `/projects/builder/:builderId` | opt | data | not paginated |
| GET | `/unit-types/project/:projectId` | opt | data | sorted **oldest-first** |
| GET | `/unit-types/:id` | opt | data | |
| GET | `/campaigns/unit-type/:unitTypeId` | pub | data | |
| GET | `/campaigns/project/:projectId` | pub | data | |
| GET | `/campaigns/:id` | pub | data | |
| POST | `/campaigns/:id/join` | user | data | 10/15 min; 201 with `memberId` |
| POST | `/campaigns/:id/exit` | user | ok | 10/15 min |
| POST | `/campaigns/:id/payment-proof` | user | ok | multipart `paymentProof`; no record echoed back |
| POST | `/bookings` | user | data | login required; needs `projectId, unitTypeId, clientName, clientPhone` |
| POST | `/bookings/:id/payment` | user | keyed | multipart: file field `screenshot`, text field **`utrNumber`** (not `utr` — defect F5). Backend accepts **either** one (`bookingController.js:164-166`). `payment` on the model is `{ utrNumber, screenshotUrl, submittedAt, verifiedAt, verifiedBy, status: pending\|submitted\|verified\|rejected, rejectionReason }` (`ProjectBooking.js:80-94`) — there is no `utr`, no `verified` boolean (defect F6). |
| GET | `/bookings/my` | user | data | |
| GET | `/bookings/payment-config` | user | data | UPI id + QR |

`attachAdminIfPresent` on the `opt` routes only widens visibility for an admin
session. The app never holds one, so it always sees the active-only view.

### Taxonomy, blogs, contact

| Method | Path | Auth | Envelope | Notes |
|---|---|---|---|---|
| GET | `/categories/list-category` | pub | data | non-REST path |
| GET | `/subcategories/list` | pub | data | different suffix from categories |
| GET | `/subcategories/byCategory/:categoryId` | pub | data | camelCase segment |
| GET | `/propertyTypes/list-propertytype` | pub | data | camelCase mount, lowercase segment |
| GET | `/blogs` | pub | paginated | free-text param is **`q`**, default limit 10 |
| GET | `/blogs/:slug` | pub | data | by **slug**; also returns `related` |
| GET | `/blogs/meta/categories` | pub | data | |
| GET | `/blogs/meta/tags` | pub | data | |
| POST | `/contact` | **user** | keyed | 20 KB cap; requires login despite reading as public |
| GET | `/contact/my-inquiries` | user | keyed | key is `inquiries` |

---

## 5. Socket.IO

Attaches at the **server root**, not under `/api`. Hence the separate
`EXPO_PUBLIC_SOCKET_URL`.

Handshake, from `backend/server.js`:

1. connect
2. `GET /chat/socket-token` → 5-minute JWT
3. emit `authenticate` `{ token }`
4. wait for `authenticated` `{ userId }` before emitting anything else

Client → server: `authenticate`, `join_conversation`, `leave_conversation`,
`send_message`, `typing`, `stop_typing`.

Server → client: `authenticated`, `auth_error`, `error`, `users_online`,
`receive_message`, `user_typing`, `user_stop_typing`.

- `join_conversation` verifies participation in the database; non-participants
  get `error` with code `ACCESS_DENIED`.
- `send_message` only **relays** an already-persisted message to the room. REST
  is the source of truth; always POST first, then emit the returned object.
- The legacy `user_online` handler was **removed** from the server. Do not emit
  it. The website still has a dead fallback that does; do not copy it.
- `pingTimeout` 60 s, `pingInterval` 25 s.

---

## 6. Error codes

Branch on `code`, never on `message`.

`NO_SESSION`, `INVALID_SESSION`, `SESSION_REVOKED`, `TOKEN_EXPIRED`,
`INVALID_TOKEN`, `USER_NOT_FOUND`, `AUTH_ERROR`, `NOT_AUTHENTICATED`,
`INVALID_ROLE`, `PASSWORD_CHANGED`, `ACCOUNT_BLOCKED`, `ACCOUNT_DEACTIVATED`,
`ACCOUNT_LOCKED`, `EMAIL_NOT_VERIFIED`, `FORBIDDEN`, `NOT_OWNER`, `NOT_FOUND`,
`OWNERSHIP_CHECK_ERROR`, `RATE_LIMITED`, `AUTH_RATE_LIMITED`,
`SEARCH_RATE_LIMITED`, `TRANSACTION_RATE_LIMITED`, `WEBHOOK_RATE_LIMITED`.

Session-fatal codes bypass the query layer and go straight to the auth store.
`ACCOUNT_BLOCKED` carries `blockReason`; show it rather than a generic message.

---

## 7. Endpoints deliberately not exposed to the app

| Endpoint | Reason |
|---|---|
| `GET /properties/property-list` | returns **every** approved property, unbounded |
| `GET /properties/filter` | unbounded, and post-filters in memory after loading everything |
| all `/admin/*` routes | require an admin session the app never holds |
| `/rewards/catalogue/*` | legacy RewardPort surface the website keeps for compatibility |
| `/rewards/hubble/*` | web-SDK integration with no native equivalent |
| `/agreements/webhook/payment` | payment-gateway callback, HMAC-signed, server-to-server |
| `/builders/*` | admin-only (`router.use(protectAdmin)`) |

Omission from `src/api/endpoints/` **is** the enforcement mechanism. A path that
is not in the registry cannot be called.

---

## 7b. External services (NOT DealDirect endpoints)

The map calls two third-party services directly. They are **not** part of the
DealDirect API, carry no session cookie, and are deliberately absent from
`src/api/endpoints/`. They live in `features/maps/` instead.

| Service | Host | Used for |
|---|---|---|
| OSM tiles | `{s}.tile.openstreetmap.org` | raster map tiles |
| Nominatim | `nominatim.openstreetmap.org` | forward and reverse geocoding |

Both are keyless, and both are the same services the website already uses. Their
usage policies expect an identifying User-Agent and modest request rates; see
`MAP_IMPLEMENTATION.md` C3 and C4.

The **session** User-Agent rule in §1.1 does not apply to these calls, because
they carry no cookie and hit no DealDirect host. Do not reuse the session
User-Agent constant for them, and do not let their headers leak into the
DealDirect axios instance.

Map data itself comes from the normal contract: `lat` / `lng` promoted by
`withPublicImages`, plus `address.*`, `images[]`, `price` and `area`. No
geospatial endpoint exists.

---

## 8. Website helper discrepancies (recorded, not fixed)

Found while verifying. In each case the **backend is correct** and the website
helper is wrong. The website's screens work because they mostly call endpoints
directly rather than through these helpers. Per the standing instruction,
neither side is modified.

| # | Website helper | Backend reality | Mobile does |
|---|---|---|---|
| 1 | `propertyApi.search` sends `params: { q }` | `searchProperties` destructures **`search`**; `q` is never read | sends `search` |
| 2 | `notificationApi.markRead` calls `PUT /notifications/:id/read` | route is **PATCH** | uses PATCH |
| 3 | `notificationApi.markAllRead` calls `PUT /notifications/read-all` | route is **PATCH `/notifications/mark-all/read`** | uses the mounted path |
| 4 | `ChatContext` falls back to emitting `user_online` | handler **removed** from the server | never emits it |
| 5 | `normalizePrice(price, priceUnit)` multiplies by 1e5 on `priceUnit: "Lac"` | `priceUnit` holds the schema default on rupee-denominated rows | treats `price` as rupees, matching the website's own `formatPrice` display path |
| 6 | `authApi.forgotPassword(email)` posts `{ email }`; `authApi.resetPassword(token, password)` posts `{ token, password }` | `forgotPassword` wants `{ phone }` and sends an **SMS OTP**; `resetPassword` wants `{ phone, otp, newPassword }` and reads neither `token` nor `password` | **was wrong — mobile copied these two helpers instead of the page.** Being fixed; see audit §1.3 |
| 7 | `AuthContext.verifyMfa` posts `/users/verify-mfa`; `changePasswordOnLogin` posts `/users/change-password-required` | **neither route exists** anywhere in `backend/`. `loginUser` never returns `requiresMfa` or `passwordChangeRequired`, so the branches never fire | implements neither, correctly. Do not "close this gap" — audit §1.7 |
| 8 | `LoginContent.jsx` requires a valid 10-digit Indian phone before submitting | `loginUser` destructures only `{ email, password }`; the phone is never transmitted | sends `{ email, password }`, which is the real contract. Audit §1.1 |

Rows 6–8 added 2026-08-09. Row 8's effect on the live site is a genuine lockout:
any account without a `[6-9]\d{9}` mobile number cannot log in through the
website, while the same credentials work through the API.

Effect of #1 on the live site: the search helper returns unfiltered, paginated
results rather than filtered ones. Worth telling the website owner about, as a
website bug, separate from this project.

Effect of #5 on the live site: the website's price-range filter and its
price sort inflate every `"Lac"` listing by 100,000×, so "Under ₹50 Lakh"
excludes listings that belong in it. Display is unaffected because display never
calls `normalizePrice`. Also a website bug, separate from this project.
