# ARCHITECTURE.md — System Architecture

Related: [MASTER_MEMORY.md](MASTER_MEMORY.md) · [DATABASE.md](DATABASE.md) · [AUTH_SYSTEM.md](AUTH_SYSTEM.md) · [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) · [FILE_MAP.md](FILE_MAP.md)

---

## 1. What DealDirect Is

An Indian real-estate marketplace whose product thesis is **removing the broker**. Property owners list directly; buyers contact them directly. Three revenue/engagement mechanics sit on top of that core:

1. **Rewards** — a gamified points economy that pays users (in points convertible to vouchers/cash at ₹0.05/point) for listing, enquiring, and closing deals.
2. **Builder projects** — admin-curated new-construction inventory from developers who have no login of their own.
3. **Group buy** — the stated USP: multiple buyers commit to the same unit type and each receives a pre-agreed flat ₹ discount once a minimum-buyer threshold is met.

Everything else (chat, agreements, leads, blog, saved searches) exists to support one of those three.

---

## 2. Deployment Topology

```
                    ┌──────────────────────────────────────────┐
   Browser ────────>│  dealdirect.in            (Next.js 16)   │
                    │  Node server, SSR + ISR + middleware      │
                    └───────────────┬──────────────────────────┘
                                    │ fetch (SSR: server→server)
                                    │ axios withCredentials (browser→API)
                    ┌───────────────v──────────────────────────┐
   Admin ──────────>│  backend.dealdirect.in    (Express 5)    │
   (admin.dealdirect.in, static Vite SPA)  port 9000            │
                    │  + Socket.IO on the same HTTP server      │
                    └───┬──────┬──────┬──────┬──────┬──────┬────┘
                        │      │      │      │      │      │
              MongoDB Atlas  Cloudinary  Gemini  Equence  WAHA  RewardPort
                                          AI      SMS   WhatsApp  + Hubble
                        │
                   (Gmail SMTP via nodemailer)
```

- **Host:** Hostinger. The `.htaccess` files and the `.env` → `.env.production` fallback in `server.js` exist purely for that environment.
- **Cross-origin by design.** Frontend and API are on different hosts, which is why every cookie is `SameSite=None; Secure` and `COOKIE_DOMAIN=.dealdirect.in`.
- **Single backend process.** Socket.IO presence maps and the Hubble SSO token store are in-process, so the backend **cannot be horizontally scaled as written**. See §8.
- **Mobile app** (`dealdirect-mobile/`) talks to the same API. It is pre-release scaffolding — see §7.

---

## 3. The Four Applications

| App | Stack | Port | Auth | State of completion |
|---|---|---|---|---|
| `backend/` | Express 5, Mongoose 8, ESM | 9000 | issues both cookies | Production |
| `client-next/` | Next.js 16 App Router, React 19, Tailwind 4 | 3000 | `user_session` cookie | Production |
| `Admin/` | Vite 6 + React 19 SPA, React Router 7, Tailwind 4 + antd | 5174 | `admin_session` cookie | Production |
| `dealdirect-mobile/` | Expo 54, expo-router 6, React Native 0.81, NativeWind | — | mirrors `user_session` into Keychain | **Scaffolding (M1–M2)** |

There is no shared package, no monorepo tool, no code sharing between apps. Each has its own `package.json` and `node_modules`. **Types, validation rules, and enum values are duplicated by hand across all four.** The mobile app's `src/types/backend/*.ts` is the only place where the API contract is written down as types, and it is a hand-maintained mirror, not generated.

`client/` (a legacy Vite client) is referenced in `CLAUDE.md` but no longer exists.

---

## 4. Backend Architecture

### Layering
```
server.js
  → env validation (exits on missing JWT_SECRET / MONGO_URI)
  → connectDB()
  → security middleware stack (see below)
  → routes/*.js          — routing + middleware composition only
     → controllers/*.js   — ALL business logic lives here
        → models/*.js     — schema + statics/methods
        → services/*.js   — external integrations + the reward engine
        → utils/*.js      — email templates
```

**There is no service/repository layer for domain logic.** Controllers query Mongoose directly. `services/` holds only third-party clients (SMS, WhatsApp, RewardPort, Hubble) plus `rewardService.js`, which is the one genuine domain service.

### Middleware order in `server.js` (order matters, do not reorder casually)
```
 1. /ping, /debug-startup (dev only) — BEFORE everything, for boot diagnostics
 2. trust proxy            (prod: TRUSTED_PROXIES or 'loopback'; dev: 1)
 3. helmet + CSP           (script-src 'self' only — no unsafe-inline/eval)
 4. HSTS + HTTP→HTTPS 301  (production only)
 5. request id             → req.requestId, X-Request-ID header
 6. hpp                    whitelist: sort, fields, page, limit, status, type
 7. globalLimiter          500 / 15 min, skips /health
 8. cors                   dynamic whitelist; no-Origin requests ALLOWED (SSR)
 9. Socket.IO server attach
10. cookie-parser
11. res.cookie override    forces httpOnly/secure/sameSite defaults
12. setCsrfToken           issues csrf_token cookie on every request
13. body parsers           10kb on login, 20kb register/contact, 50kb agreements, 100kb default
14. per-route rate limits  auth 5/15m · transactional 20/h · webhook 30/m · search 20/m · groupbuy 10/15m
15. blockRetiredRoles      global Agent-role kill switch
16. /, /health, /api/health, /api/csrf-token
17. (CSRF validation — COMMENTED OUT, line 763)
18. static /uploads
19. 20 route modules under /api/*
20. notFoundHandler → globalErrorHandler
```

Two subtleties:
- The strict payload limits at step 13 are registered with `app.use("/api/users/login", express.json({limit:"10kb"}))` **before** the general parser. Express runs the first matching parser, so the general 100 KB limit never applies to those paths.
- CORS allows requests with **no `Origin` header** (`if (!origin) return callback(null, true)`). This is required for Next.js SSR (`ssrFetch`) and for the mobile app, and it means CORS protects browsers only.

### Error handling
`middleware/errorHandler.js` is deliberately paranoid. `getSafeResponse` **always** returns a generic message, regardless of `NODE_ENV`, unless the error is `isOperational` **and** its message passes a regex gauntlet (no stack frames, no file paths, no `MongoServerError`, no `Cast to ObjectId`, < 200 chars). Full details go to the console with a request id the client can quote.

`process.on('uncaughtException')` **exits the process**; `unhandledRejection` only logs.

---

## 5. Frontend Architecture (client-next)

### The `page.js` / `*Content.jsx` split — the single most important convention

Every route directory contains exactly two files:

```
src/app/properties/
  page.js                  ← Server Component. metadata, SSR fetch, JSON-LD
  PropertyListContent.jsx  ← 'use client'. All interactivity
```

- `page.js` exports `metadata` (or `generateMetadata`), calls `ssrFetch`/`ssrFetchAll`, renders JSON-LD, and passes data down as `initial*` props.
- `*Content.jsx` starts with `'use client'`, seeds its `useState` from those `initial*` props, and takes over from there.

**When adding a route, follow this split.** Putting `'use client'` on `page.js` silently disables SSR and the SEO metadata pipeline.

Some routes add a third `*Wrapper.jsx` (e.g. `add-property/AddPropertyWrapper.jsx`) purely to wrap the content in `<ProtectedRoute>`.

### Data flow
```
Server render:  page.js → ssrFetch(path, {revalidate}) → backend
                  ↓ null on timeout/error (8s AbortController) — page still renders
                initial* props → Content component initial state

Client render:  Content → utils/api.js (axios, withCredentials, 90s timeout)
                  ↓ request interceptor attaches X-CSRF-Token from cookie
                  ↓ response interceptor sanitizes messages, routes 401/403
                     to the handler registered by AuthContext
```

`ssrFetch` **never throws**. A failed backend call returns `null` and the page renders with empty arrays. This is why `getHomeData()` uses `propsData?.data || []` everywhere.

### Global state
Only two contexts, both client-side:
- **`AuthContext`** (`ClientLayout` wraps the whole app) — user, loading, role helpers (`isOwner`, `isBuyer`, `canAddProperty`), login/logout/register, and `ProtectedRoute`.
- **`ChatContext`** — Socket.IO connection, conversations, messages, presence. **Not** in `ClientLayout`; mounted only where chat is used.

No Redux, Zustand, or React Query on web. Everything else is local `useState` + direct `api` calls.

### Edge middleware
`src/middleware.js` reads the non-HttpOnly `session_exists` cookie and redirects unauthenticated users away from six protected paths before render. It explicitly **does not validate the session** — that is the backend's job. It also sets a short-lived `auth_hint` cookie and an `x-auth-hint` header.

### Auth detection chain (three layers, by design)
1. **Edge** — `middleware.js` reads `session_exists`, redirects.
2. **Client bootstrap** — `AuthContext.checkAuth()` skips the `/users/me` call entirely when `session_exists` is absent, eliminating a 401 on every guest page load.
3. **Server** — `authMiddleware` validates the real `user_session` token against `UserSession`.

---

## 6. Admin Architecture

Plain Vite SPA — no SSR, no routing framework beyond React Router 7.

- `main.jsx` sets `axios.defaults.withCredentials = true` globally, then renders `<App/>`.
- `App.jsx` holds the entire route table (~30 routes) plus the layout shell (header + collapsible sidebar). Every non-auth route is wrapped in `<AdminProtectedRoute>`.
- `AdminContext` verifies the session by calling `GET /api/admin/profile` on mount — there is no cookie hint shortcut, so the admin app always makes that call.
- `api/adminApi.js` (641 lines) is the single API surface, mirroring `utils/api.js` on the client.
- Four auth routes are intentionally **outside** `AdminProtectedRoute` (`/admin/login`, `/admin/mfa-setup`, `/admin/mfa-verify`, `/admin/change-password`) because the backend gates them via partial sessions.
- Build splits three manual chunks: `vendor` (react + router), `antd`, `charts` (recharts + chart.js).

Notable: the admin app uses **both** antd and Tailwind 4, and **both** recharts and chart.js. See [DEPENDENCIES.md](DEPENDENCIES.md).

---

## 7. Mobile Architecture (pre-release)

`dealdirect-mobile/` is at milestone **M1–M2**: the navigation graph, design system, API contract types, and auth are built; **every feature screen is an 11-line `<Placeholder milestone="Mx"/>` stub.**

What is real and worth reading before touching it:
- `src/api/client.ts` — two axios instances (30 s JSON, 120 s upload). Comments explain why CSRF plumbing was deliberately omitted.
- `src/api/userAgent.ts` + `src/config/env.ts` — **the app version must never enter the User-Agent**, because the backend fingerprints sessions from it and a version bump would log out every user on release day. Version goes in `X-App-Version`.
- `src/auth/cookies.ts` — mirrors the `user_session` cookie from the native jar into Keychain/Keystore and re-injects on cold start, because Android's jar does not reliably survive process death.
- `src/types/backend/*.ts` — 13 files of hand-written types mirroring the API. The closest thing to a written API contract in this repo.
- `app.config.js` — bundle identifiers `in.dealdirect.mobile` are **frozen**; changing one after a store release orphans installed users.

Stack: expo-router (file-based), TanStack Query, react-hook-form + zod, MMKV + SecureStore, NativeWind.

---

## 8. Cross-Cutting Concerns & Constraints

### Single-instance constraints (blocking horizontal scale)
| What | Where | Effect if scaled |
|---|---|---|
| `onlineUsers` / `socketUserMap` | `server.js:475-477` | Wrong presence, dropped messages across instances |
| Hubble SSO token store | `services/hubbleService.js` | SSO fails when step 1 and step 3 hit different instances |
| `authAttempts` Map (×2) | `authUser.js`, `authAdmin.js` | Per-instance rate limits — N× the intended allowance |
| `activeUploads` counter | `middleware/upload.js` | Upload concurrency cap is per-instance |
| `express-rate-limit` default store | `server.js` | Same |
| `MemoryCache` | `config/redis.js` | Cache never shared |

`config/redis.js` already ships an ioredis-shaped `MemoryCache` with the real client commented out — the intended migration path is written into that file.

### Notification fan-out
`Notification` has `post('save')` and `post('insertMany')` hooks that send email. Every notification write is therefore a User lookup plus an SMTP send. Saved-search matching on property creation loads **all** active saved searches and can `insertMany` many notifications at once.

### The builder/owner property split
`Property` serves two feeds distinguished only by whether `builder` is null. **Every public property query filters on this.** Search, filter, suggestions, list, and property-list all repeat the same `$or: [{builder: null}, {builder: {$exists: false}}]` clause. Because `searchProperties` and `filterProperties` also add a `$search` `$or`, they perform an awkward dance: move the builder clause into `$and`, `delete filter.$or`, then re-push the builder clause. Modifying these queries without understanding that dance will leak builder inventory into the consumer feed.

### Auto-approval
`Property.isApproved` defaults to `true` and `addProperty` explicitly sets it to `true` ("Auto-publish for new properties (client requirement)"). Moderation is **reactive** — admins disapprove, they do not approve. Any change here must also update the Admin `AllProperty` UI, which is built around that assumption.

---

## 9. Request Lifecycle — Worked Example

**A buyer marks interest in a property.** This is the densest side-effect path in the codebase.

```
[Browser] PropertyDetailsContent.jsx — "I'm Interested"
   ↓ propertyApi.markInterested(id)  →  POST /api/properties/interested/:id
   ↓ axios: withCredentials, X-CSRF-Token header from cookie

[Express] globalLimiter → cors → cookieParser → setCsrfToken
   → express.json(100kb) → blockRetiredRoles
   → propertyRoutes: authMiddleware → validateMongoId('id') → markInterested

[authMiddleware]
   user_session cookie → sha256 → UserSession.findOne({tokenHash, active, unexpired})
   → validateFingerprintLenient (OS/device unchanged → pass)
   → session.lastActivity = now, save
   → req.user = sanitizeUser(session.user)      [throws if role invalid]

[markInterested — controllers/propertyController.js]
   1. ObjectId valid?                                    → 400
   2. Property.findById                                  → 404
   3. Property.countDocuments({"interestedUsers.user": userId}) >= 5 → 400
   4. property.owner === userId                          → 400 (own listing)
   5. already in interestedUsers                         → 400
   6. User.findById(userId)
   7. Property.findByIdAndUpdate: $push interestedUsers, $inc likes
   8. Lead.findOne({user, property}) — if absent, Lead.create with
      userSnapshot + propertySnapshot            [unique index is the backstop]
   9. Notification.create(owner, "New Interest…")
        └─ post('save') hook → User lookup → sendGeneralNotification (SMTP)
   10. User.findById(owner).select('phone') → sendNewLeadWhatsApp (fire & forget)
        └─ also fires an admin copy to WAHA_ADMIN_PHONE
   11. awardPoints(userId, "send_enquiry")
        ├─ daily cap: 5 send_enquiry txns/day → returns 0 points, still success
        ├─ getRandomReward('property_enquiry') — weighted random over 19 tiers
        ├─ × tier multiplier (bronze 1.0 … diamond 1.5)
        ├─ wallet.addTransaction + recalculateTier
        └─ wallet.save() — optimisticConcurrency; retries once on VersionError
   12. 200 { success, message, reward }

[Browser]
   reward != null → <RewardRevealRouter reward={...}/>
      rewardCategory 'property_enquiry' → <SpinWheelOverlay/>
      (property_sale → <PropertyHuntGame/> 3-door reveal)
```

Steps 9–11 are all non-blocking in intent, but 9 and 11 are `await`ed, so SMTP latency and wallet contention are on the response path.

---

## 10. Architectural Rules

1. **Never break the `page.js` / `*Content.jsx` split** in client-next.
2. **Never remove the builder-exclusion clause** from a public property query.
3. **Never `await` a new external-service call on a hot request path** — follow the existing `.catch(err => console.error(...))` fire-and-forget pattern.
4. **Never add in-process state** that a second instance would need to share.
5. **Controllers own business logic.** Do not put logic in routes; do not add a service layer for one function.
6. **Admin and user auth are separate.** A change to one is not a change to the other.
7. **Mongoose `strict` silently drops unknown fields.** If a controller writes a field, confirm it exists in the schema (several currently do not — see [KNOWN_BUGS.md](KNOWN_BUGS.md)).
8. **Reward mutations must go through `rewardService`**, never direct `Reward` writes — the optimistic-concurrency retry lives there.
