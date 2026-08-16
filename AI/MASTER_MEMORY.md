# MASTER_MEMORY.md — Start Here

> **You are an AI assistant with no memory of this repository. Read this file first.**
> It is the index and the orientation. Read the specific document for your area before changing code.

Generated 2026-08-01 by a full-repository audit. See [CHANGELOG_AI.md](CHANGELOG_AI.md) for how to keep this current.

---

## 1. What This Is

**DealDirect** — an Indian real-estate marketplace whose product thesis is **removing the broker**. Owners list directly, buyers contact them directly. Three mechanics sit on top:

1. **Rewards** — a gamified points economy (1 pt = ₹0.05) paying users for listing, enquiring, and closing deals, with weighted-random payouts and a spin-wheel/door-reveal UI.
2. **Builder projects** — admin-curated new-construction inventory from developers who have no login.
3. **Group buy** — the stated USP: N buyers commit to one unit type, each gets a pre-agreed **flat ₹ discount** once a minimum threshold is met.

Production, live at `dealdirect.in`. Hosted on Hostinger.

---

## 2. Tech Stack

| App | Directory | Stack | Port | State |
|---|---|---|---|---|
| API | `backend/` | Express **5**, Mongoose 8, Socket.IO 4, ESM | 9000 | Production |
| Public site | `client-next/` | Next.js **16** App Router, React 19, Tailwind **4** | 3000 | Production |
| Admin | `Admin/` | Vite 6 SPA, React 19, React Router 7, Tailwind 4 + antd | 5174 | Production |
| Mobile | `dealdirect-mobile/` | Expo 54, expo-router 6, RN 0.81, NativeWind | — | **Scaffolding (M1–M2 of 14)** |

Data: MongoDB Atlas. Files: Cloudinary. AI: Google Gemini. SMS: Equence. WhatsApp: WAHA. Rewards catalogue: RewardPort + Hubble. Email: Gmail SMTP.

**No monorepo tooling, no shared package, no code sharing between apps.** Types, enums, and validation rules are duplicated by hand in all four.

**No tests anywhere.** `backend/package.json` has the npm-init placeholder. Every change is verified manually.

---

## 3. Reading Order

**Always:** this file.

Then, by task:

| Task | Read |
|---|---|
| Any backend change | [ARCHITECTURE.md](ARCHITECTURE.md) → [API_REFERENCE.md](API_REFERENCE.md) |
| Schema / query work | [DATABASE.md](DATABASE.md) |
| Login, sessions, roles, MFA | [AUTH_SYSTEM.md](AUTH_SYSTEM.md) |
| A feature or workflow | [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) |
| Frontend component work | [COMPONENT_INDEX.md](COMPONENT_INDEX.md) → [STYLING_GUIDE.md](STYLING_GUIDE.md) |
| Anything security-adjacent | [SECURITY.md](SECURITY.md) |
| Slowness, scaling | [PERFORMANCE.md](PERFORMANCE.md) |
| Config, deploy, env vars | [ENVIRONMENT.md](ENVIRONMENT.md) |
| Adding/removing packages | [DEPENDENCIES.md](DEPENDENCIES.md) |
| "Where is X?" | [FILE_MAP.md](FILE_MAP.md) |
| **Before assuming anything works** | [KNOWN_BUGS.md](KNOWN_BUGS.md) |
| Planned work | [FUTURE_PLANS.md](FUTURE_PLANS.md) |
| **What to fix next** | [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md) |
| After you change something | [CHANGELOG_AI.md](CHANGELOG_AI.md) — append an entry |

---

## 4. The Twelve Things That Will Trip You Up

1. **There are two entirely separate auth systems.** User (`authUser.js`, `user_session` cookie, `UserSession`) and admin (`authAdmin.js`, `admin_session` cookie, `AdminSession`, mandatory TOTP). They share no code. Fixing one does not fix the other.

2. **`role: "user"` and `role: "buyer"` are the same role.** Both mean buyer. Every check must accept both. `role: "owner"` is the seller. The **Agent** role is permanently retired and actively blocked in four places.

3. **Every `client-next` route is two files.** `page.js` (server: metadata, `ssrFetch`, JSON-LD) + `*Content.jsx` (`'use client'`: everything else). Putting `'use client'` on `page.js` silently kills SSR and SEO.

4. **`Property` serves two feeds.** `owner != null` → consumer feed. `builder != null` → builder feed. **Every public query filters on this**, using an awkward `$and`/`$or` dance in search and filter. Break it and builder inventory leaks into the consumer feed.

5. **Route order matters.** Literal paths (`/search`, `/my-properties`, `/admin/all`) must be declared **before** `/:id`. Several route files depend on this.

6. **Mongoose `strict` silently drops undeclared fields.** Controllers currently write `isBanned`, `isActive`, `approvedAt`, `location`, and more to `Property` — none of which exist on the schema. Nothing errors; the data just vanishes.

7. **`Notification` post-save hooks send email.** Creating notifications in a loop fans out one User lookup and one SMTP connection per document, in the request path.

8. **Properties are auto-approved.** `isApproved` defaults `true` and is explicitly set `true` on create. Moderation is *reactive* — admins disapprove, never approve.

9. **The backend cannot run more than one instance.** Socket.IO presence, Hubble SSO tokens, all rate-limit counters, the upload-concurrency gate, and the cache are in-process. `config/redis.js` is a `MemoryCache` shim with the real client commented out.

10. **CSRF validation is disabled** at two independent points, while cookies are `SameSite=None`. Deliberate, documented, and a real gap — [SECURITY.md](SECURITY.md) H1.

11. **`utils/api.js` has drifted from the routes.** Two helpers call endpoints that don't exist or send the wrong parameter (B19, B20). Screens bypass the helpers, which is why nobody noticed. Verify against `backend/routes/` — the route files are authoritative.

12. **The chat feature is fully built and never mounted** (B17). ~1 900 lines across the stack that no user can reach.

---

## 5. Never Change These Without Explicit Instruction

| Thing | Why |
|---|---|
| `createSession` setting `mfaVerified: false` | Marked as a fixed vulnerability. Admin sessions must earn MFA |
| `sanitizeUser` throwing on an unknown role | Fail-closed by design. Do not default to `buyer` |
| Cookie-beats-bearer precedence in `authMiddleware` | Prevents forced-bearer-token injection |
| Lenient session fingerprinting (IP change allowed) | Reverted twice already; strict checks caused mass logouts on Indian mobile ISPs |
| Agreement money read from the `Property` document | Never trust client-supplied amounts |
| Aadhaar stored as last-4 only | Everywhere, no exceptions |
| Magic-byte validation before Cloudinary upload | Invalid files must never reach external storage |
| `blockRetiredRoles` global middleware | The Agent kill switch |
| Nothing `required` on `Project`/`UnitType` data fields | Admin-authored partial drafts are intended |
| GST/stamp duty/registration excluded from `effectivePrice` | Taxes, not list price |
| Atomic `$gte: 1` guard on inventory decrement | Prevents overselling |
| Campaign counters **recounted**, not incremented | Avoids drift under races |
| `in.dealdirect.mobile` bundle identifiers | Frozen; changing one after a store release orphans installed users |
| App version out of the mobile User-Agent | Would revoke every session on release day |

Source markers `SECURITY FIX:`, `H4`, `H5`, `H6`, `C2`, `C4`, `C6`, `H12` mark closed audit findings. **Reverting the pattern reopens the finding.** See the review documents listed in [FUTURE_PLANS.md](FUTURE_PLANS.md) §4.

---

## 6. Conventions

**Backend**
- Routes compose middleware; **controllers hold all business logic**. There is no service layer for domain logic — `services/` is third-party clients plus `rewardService.js`.
- Field whitelists, not blacklists (`sanitizePropertyData`, `whitelistFields`).
- IDOR guard = re-read the resource, compare ownership to `req.user._id`.
- External calls on a request path are fire-and-forget: `.catch(err => console.error(...))`.
- Every admin mutation writes an `AuditLog` entry.
- Escape user input before any `RegExp` (`escapeRegExp`).

**Frontend**
- `page.js` / `*Content.jsx` split; `*Wrapper.jsx` for `<ProtectedRoute>`.
- `ssrFetch` never throws — it returns `null`, so always guard with `?.data || []`.
- Tailwind utilities inline. **No custom theme exists** — stock values only.
- `lg` (1024 px), not `md`, is the desktop breakpoint.
- Reward reveals always go through `RewardRevealRouter`.
- Anything using `useSearchParams` must be inside `<Suspense>`; anything touching `window` at module scope must be `next/dynamic` with `ssr: false`.

**Naming:** components PascalCase · routes kebab-case · API groups `<domain>Api` · contexts `<Domain>Context` exporting `<Domain>Provider` + `use<Domain>` · admin pages PascalCase in `pages/`.

---

## 7. Response Shapes — Read Before Writing a Client Call

There is **no consistent envelope**. Verified forms:

```jsonc
{ "success": true, "data": [...] }                  // most endpoints
{ "success": true, "data": [...], "count": 12 }     // my-properties
{ "data": [...], "total", "page", "pages" }         // /properties/search
{ "suggestions": [...] }                            // /properties/suggestions
[ ... ]                                             // GET /properties/list — BARE ARRAY
```

`GET /api/properties/list` returning a bare array is the single most common source of frontend bugs here. A generic unwrapper is impossible — the mobile plan reached the same conclusion independently and mandates a typed adapter per endpoint.

Errors are always `{success: false, message, code?, requestId}` with aggressively genericised messages (in **all** environments — `getSafeResponse` does not trust `NODE_ENV`).

---

## 8. Common Pitfalls

| Symptom | Cause |
|---|---|
| Property field silently not saved | Not in the schema (see #6) or not in `PROPERTY_ALLOWED_FIELDS` |
| New route 404s | Declared after `/:id` |
| Registration returns 500 locally | Equence SMS not configured — required for `/register`. Use `/register-direct` |
| `POST /properties/add` fails locally | Uses a transaction; needs a replica set, not standalone `mongod` |
| Cross-origin auth broken | `NODE_ENV !== 'production'` → cookies fall back to `SameSite=lax` |
| Admin gets 403 `MFA_REQUIRED` | Correct — the session exists but MFA is unverified |
| Uploads return 503 | `CLOUDINARY_URL` missing or malformed |
| `useChat must be used within a ChatProvider` | B17 — `ChatProvider` is never mounted |
| Search returns everything | B19 — `propertyApi.search` sends `q`; backend reads `search` |
| Edited property loses its gallery | Client didn't send `existingCategorizedImages`; `images[]` is rebuilt from scratch |
| Email/WhatsApp/SMS silently not sent | Integration unconfigured — all fail silently except SMS on registration |

---

## 9. Quick Start

```bash
cd backend && npm install && npm run dev
```
```bash
cd client-next && npm install && npm run dev
```
```bash
cd Admin && npm install && npm run dev
```
```bash
curl http://localhost:9000/health
```

Requires: MongoDB Atlas (or a local replica set), `CLOUDINARY_URL`, and — for `/register` — Equence SMS credentials. Full matrix in [ENVIRONMENT.md](ENVIRONMENT.md).

---

## 10. Health of the Codebase — Honest Assessment

**Strong:** the security posture is genuinely above average for a project this size. Magic-byte upload validation, HMAC-signed agreements with tamper detection, structural prompt-injection defence, hashed session tokens and OTPs, consistent IDOR guards, a real audit trail, and an error handler that refuses to leak even when misconfigured. The comments explain *why*, which is rare and valuable — trust them.

**Weak:** no tests, no backend error reporting (`@sentry/node` installed but never initialised), no caching despite the helper existing, single-instance-only architecture, and 20 verified defects — four of which mean a shipped feature does not work at all.

**The pattern to watch:** several features are ~90 % built and then not wired up — chat (B17), deal verification (B2), referral milestones 2–3 (B11), the login streak (B12), the RBAC layer (5 of ~40 admin endpoints), Redis, backend Sentry. Before building something new, **check whether it already exists and is merely unmounted.**

---

## 11. Document Index

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Topology, the four apps, middleware order, request lifecycle, architectural rules |
| [DATABASE.md](DATABASE.md) | All 32 models, relationships, indexes, integrity warnings |
| [AUTH_SYSTEM.md](AUTH_SYSTEM.md) | Both auth systems, fingerprinting, CSRF, sockets, Hubble SSO, error codes |
| [API_REFERENCE.md](API_REFERENCE.md) | Every endpoint: auth, input, behaviour, rate limits |
| [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) | Every workflow and the reasoning behind it; the 14 business invariants |
| [COMPONENT_INDEX.md](COMPONENT_INDEX.md) | Components, props, usage graph, orphans, hooks, naming |
| [STYLING_GUIDE.md](STYLING_GUIDE.md) | Tailwind setup, colour, typography, breakpoints, dark mode |
| [FILE_MAP.md](FILE_MAP.md) | Every folder and significant file, one line each |
| [DEPENDENCIES.md](DEPENDENCIES.md) | Every package: why, where, replaceable, and 8 verified-unused |
| [SECURITY.md](SECURITY.md) | Controls, accepted risks, open weaknesses, review checklist |
| [PERFORMANCE.md](PERFORMANCE.md) | What's optimised, 12 ranked bottlenecks, work order |
| [ENVIRONMENT.md](ENVIRONMENT.md) | Every env var, failure modes, the `.env` drift, deployment |
| [KNOWN_BUGS.md](KNOWN_BUGS.md) | 20 verified defects with locations and fixes |
| [FUTURE_PLANS.md](FUTURE_PLANS.md) | Mobile milestones, feature plans, suggested priorities |
| [REMEDIATION_PLAN.md](REMEDIATION_PLAN.md) | **Verified findings + phased execution plan.** Start here for "what should we fix next" |
| [CHANGELOG_AI.md](CHANGELOG_AI.md) | **Append here after any architectural change** |
