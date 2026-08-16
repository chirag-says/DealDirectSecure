# SECURITY.md — Controls, Assumptions, and Weaknesses

This codebase has been through at least one formal security review — the source is dense with `SECURITY FIX:` comments and `H4`/`H5`/`H6`/`C2`/`C4`/`C6` markers referencing findings. This document records what is defended, what is deliberately accepted, and what is still open.

Related: [AUTH_SYSTEM.md](AUTH_SYSTEM.md) · [KNOWN_BUGS.md](KNOWN_BUGS.md) · [ENVIRONMENT.md](ENVIRONMENT.md)

---

## 1. Controls Actually in Place

### Transport & headers (`server.js`)
- Helmet with a **strict CSP**: `scriptSrc: ["'self'"]` — no `unsafe-inline`, no `unsafe-eval`. `frameSrc`/`frameAncestors`/`objectSrc`/`childSrc` all `'none'`. `imgSrc` limited to self, data:, blob:, Cloudinary.
- HSTS 1 year + `includeSubDomains` + `preload`, and a 301 HTTP→HTTPS redirect, both production-only.
- `x-powered-by` disabled on Express **and** `poweredByHeader: false` in Next.js.
- `hpp` with a 6-key whitelist against HTTP parameter pollution.
- Per-request `X-Request-ID` for correlating a client error report with a server log line.

### CORS
Explicit whitelist built from `CLIENT_URL` + `ADMIN_URL` (plus www/non-www variants, plus localhost in dev). `credentials: true`. Allowed headers are enumerated.
**Requests with no `Origin` header are allowed** — required for Next.js SSR and the mobile app. CORS therefore protects browsers only, which is correct but means it is not an authorization control.

### Input validation
- `express-validator` schemas in `middleware/validators/index.js` with a `whitelistFields()` helper that rebuilds `req.body` from an allowlist — mass-assignment defence.
- `propertyController` layers a second, stricter whitelist (`PROPERTY_ALLOWED_FIELDS`) plus an `ADMIN_ONLY_FIELDS` deny pass.
- ObjectId format validated before every parameterised query (`validateMongoId`, `mongoose.Types.ObjectId.isValid`).
- Lead status and saved-search enums are whitelist-validated specifically to block **NoSQL operator injection** (`H6 FIX` comments).

### ReDoS
`escapeRegExp()` escapes regex metacharacters before every user-supplied `RegExp` in `propertyController` and in the admin audit-log `action` filter.

### File uploads (`middleware/upload.js`) — the strongest area
1. `multer.memoryStorage()` — nothing touches disk.
2. MIME + extension pre-filter.
3. **Magic-byte validation on the in-memory buffer** against JPEG/PNG/GIF/WebP signatures (WebP additionally verifies `WEBP` at offset 8).
4. An explicit **blocklist**: MZ (EXE/DLL), ELF, `<?php`, `<script`, `<!DOCTYPE`, ZIP, RAR, 7Z.
5. Extension-vs-detected-type cross-check — a `.png` whose bytes say JPEG is rejected.
6. Only then is the buffer streamed to Cloudinary.
7. Total request size cap (200 MB), per-file caps (10 MB images / 15 MB with docs), file-count and multipart-part caps.
8. `uploadConcurrencyGuard` — max 10 in-flight upload requests process-wide, decremented on `finish` and `close`.

The code comment is explicit that invalid files "never touch external storage."

### Secrets & crypto
- OTPs stored as `sha256(otp + OTP_SECRET||JWT_SECRET)`, compared with `crypto.timingSafeEqual`.
- User session tokens stored as SHA-256 hashes.
- Passwords bcrypt cost 12 (users and admins).
- Agreements HMAC-SHA256 signed; `signature` is `select:false` **and** stripped in `toJSON`.
- Payment webhook signature compared with `timingSafeEqual`.
- CSRF tokens compared with `timingSafeEqual`.
- Ownership comparison in `roleGuard.requireOwnership` is written as a constant-time loop.

### Error handling
`getSafeResponse` **always** returns a generic message regardless of `NODE_ENV`, unless the message is operational, under 200 chars, and survives a regex gauntlet blocking stack frames, file paths, `node_modules`, `MongoServerError`, `CastError`, and duplicate-key text. Logs sanitize query params (token, otp, email, phone, …) and headers (authorization, cookie, x-forwarded-for). Request bodies are sanitized for passwords, Aadhaar, OTPs, card numbers.

### IDOR
Consistently defended by re-reading the resource and comparing ownership against `req.user._id`:
- Properties: `findOne({_id, owner: userId})`
- Leads: `lead.propertyOwner.toString() !== ownerId.toString()` with a `⚠️ IDOR attempt` log
- Agreements: `isPartyToAgreement()`
- Chat: participant check on every read/write; `startConversation` refuses a client-supplied `ownerId`
- Sessions: `findOne({_id, user: req.user._id})` before revoke

### Audit trail
Every admin mutation writes an `AuditLog` entry with sanitized body, client IP, result, severity, and an `isSecurityEvent` flag. Failed logins, permission denials, fingerprint revocations, MFA changes, and payment fraud are all recorded. Logging failures never break the request.

---

## 2. Deliberately Accepted Risks

These are documented decisions, not oversights. Do not "fix" them without understanding why they exist.

| Decision | Where | Stated reason |
|---|---|---|
| **CSRF validation disabled** | `server.js:763` commented out; `validateCsrfToken` also early-returns for `/api/*` | Cross-origin deployment. Compensating controls named in the code: CORS whitelist, HttpOnly cookies, preflight on state-changing requests |
| **`SameSite=None` cookies** | `authUser.js`, `authAdmin.js`, `csrfProtection.js` | Required for cross-origin frontend/backend |
| CORS allows no-Origin requests | `server.js:438` | Next.js SSR and mobile do not send `Origin` |
| Lenient session fingerprinting (IP change allowed) | both session models | Indian mobile ISPs and CDN edges rotate IPs; strict checks caused mass logouts. OS and device-type changes are still hard revokes |
| Memory-pressure upload check disabled | `upload.js:1212` | False positives on Hostinger shared hosting; the concurrency cap is retained |
| Properties auto-approved | `propertyController.addProperty` | Explicit client requirement |
| Admin registration endpoint unrouted | `adminRoutes.js` | "Eliminates the registration attack surface entirely" |

---

## 3. Open Weaknesses

Ordered by exploitability × impact.

### High

**H1 — ✅ MITIGATED 2026-08-01 (Phase 1).** `requireCsrf` now enforces Origin + double-submit token on **15 named state-changing routes** — rewards redeem/adjust, property create/edit, mark-interested, report, campaign join/exit, contact, chat send. Applied in `server.js` before the routers; `CSRF_ENFORCE=false` disables it without a redeploy. Verified: 4 attack shapes blocked with 403, legitimate requests unaffected.
**Still open:** every *other* authenticated mutation (account deletion, password change, session revocation, admin CRUD) remains unprotected pending Phase 2, which is gated on frontend regression testing and automated tests. Original analysis retained below.

**H1 (original) — CSRF is off while cookies are `SameSite=None`.**
`SameSite=None` removes the browser's built-in cross-site protection, and the double-submit implementation is disabled at two independent points. The only remaining control is the CORS whitelist. That is genuinely effective for XHR/fetch (preflighted, origin-checked), but a plain HTML `<form method="POST">` to a state-changing endpoint is **not** preflighted and CORS does not block the *request* — only the attacker's ability to read the response. Any endpoint that accepts `application/x-www-form-urlencoded` or `multipart/form-data` and performs a side effect is reachable this way. `express.urlencoded` is enabled globally.
*Fix:* re-enable CSRF (both the commented `app.use` and the `/api/` early-return) — the client already sends the header.

**H2 — ✅ CLOSED 2026-08-01.** The agreements module is hidden at the client's request and `/api/agreements` is unmounted in `server.js`, so this endpoint returns 404 and is unreachable. **The underlying flaw is unfixed** — re-enabling agreements re-opens it. Set `PAYMENT_WEBHOOK_SECRET`, or make the check fail closed, *before* restoring the route. Original analysis below.

**H2 (original) — Payment webhook is unauthenticated when `PAYMENT_WEBHOOK_SECRET` is unset.**
`agreementController.validatePaymentWebhook` wraps the entire signature check in `if (process.env.PAYMENT_WEBHOOK_SECRET)`. The variable is commented out in `.env.example` and absent from both `.env` and `.env.production`. Anyone who knows an `agreementId`, a `payerId`, and the correct amount can post a completed payment. Amount validation and the party check limit the damage but do not prevent forged payment records.
*Fix:* fail closed — 500 when the secret is missing, matching how `handleHubbleSSO` handles `HUBBLE_WEBHOOK_SECRET`.

**H3 — Account enumeration on password reset.**
`forgotPassword` returns 404 `"No account found with this phone number. Please register first."` The login endpoint is correctly generic; this one is not. It confirms which phone numbers are registered.
*Fix:* always return 200 with a neutral message.

### Medium

**M1 — Permission checks cover only 5 admin endpoints.**
`requirePermission` guards dashboard, leads, reports, verifications, and audit-logs. Properties, blogs, builders, projects, unit types, campaigns, bookings, categories, rewards, users, and contact inquiries are protected by `protectAdmin` alone. A `viewer`-role admin (level 10) can create projects, delete properties, adjust reward points, and block users. The RBAC model exists but is barely applied.

**M2 — `verifications` is not a valid Permission resource.**
`adminRoutes.js` requires `verifications:read` / `verifications:approve`, but `Permission.resource` is a closed enum that does not include `verifications`. Those Permission documents cannot be created through the schema, so `getPermissions()` can never return those codes and the deal-verification endpoints are **unreachable for every admin**. Either add `verifications` to the enum or change the required codes.

**M3 — Stored XSS in the chat inbox preview.**
`chatController.sendMessage` escapes `text` for the `Message` document but assigns the **raw** `text` to `conversation.lastMessage.text`. Anywhere the inbox preview is rendered without escaping, this is injectable.
*Fix:* one-word change — use `sanitizedText`.

**M4 — Unescaped regex in admin lead search.**
`leadController.getAllLeads` builds `new RegExp(search, 'i')` directly from a query parameter. Every other search path escapes. Admin-only, but it is a ReDoS vector.

**M5 — ❌ WITHDRAWN 2026-08-01, not a defect.** Verified no code path ever wrote `bankDetails`: the frontend sent only `rewardSlug`, `handleRedeem` was never invoked, and 0 `RedemptionRequest` documents existed. The entire pre-Hubble redemption layer has since been deleted. Original claim below, retained as a record of a false positive.

**M5 (original) — Bank details stored in plaintext.**
`RedemptionRequest.bankDetails` holds `accountNumber`, `ifscCode`, `upiId` with no encryption and no `select: false`, and is returned by `GET /api/rewards/admin/redemptions`.

**M6 — Socket-auth JWT is accepted as a REST bearer token.**
`GET /api/chat/socket-token` mints a 5-minute JWT `{id, purpose: 'socket_auth'}`. `handleJWTAuth` in `authUser.js` does not check `purpose`; a token without `sessionId` takes the legacy path and authenticates the user for REST. Impact is limited (5-minute window, only obtainable by an already-authenticated user), but the token is passed to a third-party socket layer and is not scoped as intended.
*Fix:* reject `decoded.purpose === 'socket_auth'` in `handleJWTAuth`.

**M7 — In-process rate limiting.**
Every limiter (`express-rate-limit` default store, two `authAttempts` Maps, `activeUploads`) is per-process. Any horizontal scaling multiplies the effective limits.

### Low / Informational

- **L1** — `/debug-startup` is dev-gated but still discloses which env vars are set, cwd, `__dirname`, and Node version.
- **L2** — `AuditLog` has no TTL and grows unbounded; `res.on('finish')` writes an entry for every admin write.
- **L3** — `Reward.transactions` and `Agreement.auditLog` are unbounded embedded arrays trending toward the 16 MB BSON cap.
- **L4** — `sessionVersion` exists on `User` with an `invalidateSessions()` method, but no middleware reads it. It is a no-op safeguard.
- **L5** — `getPropertyById` increments `views` on every request with no dedupe, so the counter is trivially inflated.
- **L6** — `reportProperty` awards 100 points; the only anti-farming control is one active report per user per property.
- **L7** — `Admin.role` is `Mixed`. A legacy string role silently degrades to three read-only permissions rather than failing loudly.
- **L8** — The Hubble SSO token store and Socket.IO presence maps are in-process; multi-instance breaks them (availability, not confidentiality).

---

## 4. Secrets Handling

**Git hygiene is correct for the files that matter.** `backend/.env`, `backend/.env.production`, `Admin/.env`, `client-next/.env.local`, and `client-next/.env.production` are all gitignored and untracked (verified with `git check-ignore` and `git ls-files`).

Two caveats:
- `client-next/.env.production` contains a live **`SENTRY_AUTH_TOKEN`** and the Mapples API key. It is gitignored, but it exists in the working tree and would be included by any naive `scp -r`/zip deployment. Sentry auth tokens permit source-map upload and project reads.
- `Admin/.env.production` **is tracked in git** — it contains only `VITE_API_BASE_URL`, which is public. Harmless, but be aware the pattern differs from the other apps.

Everything under `NEXT_PUBLIC_*` and `EXPO_PUBLIC_*` is compiled into client bundles by definition. The Mapples key is present in both. The mobile app's `src/config/env.ts` documents the correct posture: public keys must be restricted by bundle identifier at the provider, not hidden.

`JWT_SECRET` is validated at boot — production requires ≥32 chars or the process exits.

---

## 5. Threat Model Assumptions

The code assumes:
1. The backend runs behind a trusted reverse proxy configured via `TRUSTED_PROXIES`; `req.ip` is authoritative. **`TRUSTED_PROXIES` is not set in either env file**, so production falls back to `'loopback'` — correct for a same-host nginx, wrong behind a CDN (rate limits would then key on the CDN's IP).
2. MongoDB Atlas is network-restricted; there is no application-level encryption at rest.
3. Cloudinary URLs are public and unguessable. Property images, deal-closure proof documents, and payment screenshots are all publicly readable by URL — **there is no signed-URL usage anywhere**. A leaked URL exposes the document.
4. Gemini, Equence, WAHA, RewardPort, and Hubble are trusted with the data sent to them.
5. Admins are trusted; the RBAC layer is defence-in-depth, not a primary boundary (which is consistent with M1).

---

## 6. Checklist for New Code

Before merging anything that touches the backend:

- [ ] New route: is `authMiddleware` / `protectAdmin` applied? Is `requirePermission` warranted?
- [ ] Route ordering: literal paths declared **before** `/:id`?
- [ ] Any resource fetched by an id from params: is ownership re-verified from the DB?
- [ ] Any user string used in a `RegExp`: is it passed through `escapeRegExp`?
- [ ] Any user value used in a Mongo query field position: is it whitelist-validated?
- [ ] New request body fields: added to the relevant whitelist, and confirmed absent from `ADMIN_ONLY_FIELDS`?
- [ ] New file upload: does it go through `memoryUpload` + `validateAndUploadToCloudinary` (or `documentUpload` + `uploadDocumentsToCloudinary`)?
- [ ] New error path: does the message survive the `getSafeResponse` gauntlet, or will it be genericised?
- [ ] New admin mutation: is there an `AuditLog.log` call?
- [ ] New external call on a request path: is it fire-and-forget with `.catch()`?
- [ ] New secret: added to `.env.example` **and** to [ENVIRONMENT.md](ENVIRONMENT.md), with a documented fail-closed behaviour when absent?
