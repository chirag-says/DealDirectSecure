# AUTH_SYSTEM.md — Authentication & Authorization

> There are **two completely independent auth systems** in this codebase: end-user auth and admin auth. They share no code, no cookie, no session store, and no middleware. Never assume a fix in one applies to the other.

Related: [SECURITY.md](SECURITY.md) · [DATABASE.md](DATABASE.md) · [API_REFERENCE.md](API_REFERENCE.md) · [ARCHITECTURE.md](ARCHITECTURE.md)

---

## 1. The Two Systems at a Glance

| | **End User** | **Admin** |
|---|---|---|
| Middleware | `middleware/authUser.js` → `authMiddleware` | `middleware/authAdmin.js` → `protectAdmin` |
| Cookie | `user_session` (HttpOnly) + `session_exists` (JS-readable flag) | `admin_session` (HttpOnly) |
| Session model | `UserSession` | `AdminSession` |
| Token stored in DB | **SHA-256 hash** of a 48-byte base64url token | **Raw** 64-byte hex token |
| Lifetime | 7 days | 24 hours |
| MFA | none | **TOTP required for every session** |
| Password hashing | bcrypt cost 12, done **in the controller** | bcrypt cost 12, done in a **pre-save hook** |
| Password policy | ≥8, upper+lower+digit+special | ≥12, upper+lower+digit+special |
| Lockout | 5 fails → 15 min | 5 fails → 30 min |
| Audit logging | none | every mutation → `AuditLog` |
| Attaches | `req.user`, `req.userSession` | `req.admin`, `req.adminSession`, `req.clientIp` |
| Registration | public | **removed — DB seeding only** |

---

## 2. End-User Registration

Two distinct paths exist. Which one the client calls determines whether OTP is required.

### 2a. `POST /api/users/register` — OTP path (used for owners, and by the main register form)

```
Client submits { name, email, password, phone, role, referralCode? }
  ↓ authRateLimit (in-memory, 10/15min per IP) + authLimiter (express-rate-limit, 5/15min)
  ↓ express.json({ limit: "20kb" })
  ↓ validate: all four required fields present
  ↓ validate: phone matches /^[6-9]\d{9}$/
  ↓ validate: password strength (8+, a-z, A-Z, 0-9, special)
  ↓ reject if a VERIFIED user exists with this email OR phone
  ↓ REUSE an existing UNVERIFIED user with this email OR phone (overwrite it)
  ↓ otp = crypto.randomInt(100000, 999999)
  ↓ store SHA-256(otp + OTP_SECRET) in user.otp, 10-min expiry
  ↓ bcrypt.hash(password, 12)
  ↓ role normalized: "owner" → "owner", anything else → "user"
  ↓ send OTP via Equence SMS  ← HARD DEPENDENCY: 500 if SMS not configured or send fails
  ↓ 200 { success, message, email }        ← NO session yet
```

Then `POST /api/users/verify-otp { email, otp, referralCode? }`:
```
find user (+otp +otpExpires)
  ↓ reject if already verified
  ↓ reject if otp missing or otpExpires < now
  ↓ verifyOTPHash: timingSafeEqual(sha256(provided+secret), stored)
  ↓ isVerified = true, clear otp fields
  ↓ UserSession.createSession(user, req) → setSessionCookie
  ↓ side effects (all non-blocking, errors swallowed):
      getOrCreateWallet · createReferralFromCode · sendNewUserWhatsApp · sendWelcomeEmail
  ↓ 201 { user: sanitizeUserResponse(user) }
```

**Registration cannot complete without working SMS.** If `EQUENCE_*` env vars are missing, `registerUser` returns 500 with "SMS service is not configured".

### 2b. `POST /api/users/register-direct` — no OTP (buyers)
Same validation, but: **deletes** any existing unverified user with that email, creates the user with `isVerified: true`, and issues a session immediately. Role is hardcoded `"user"`.

> Note the asymmetry: `register` reuses an unverified record; `register-direct` deletes it. Both then create fresh. Duplicate-phone is *not* checked in `register-direct` — it relies on the DB's sparse unique index, which surfaces as a generic 500.

---

## 3. End-User Login & Session Validation

### Login — `POST /api/users/login`
```
{ email, password }
  ↓ authRateLimit + authLimiter (skipSuccessfulRequests: true)
  ↓ User.findOne(email).select(+password +failedLoginAttempts +lockoutUntil +blockReason)
  ↓ 401 generic "Invalid email or password" if not found   ← no user enumeration
  ↓ 423 if user.isLocked()      (lockoutUntil in future)
  ↓ 403 if user.isBlocked       (returns blockReason)
  ↓ 400 if !user.isVerified
  ↓ bcrypt.compare → on fail: incrementFailedLogins() then 401 generic
  ↓ resetFailedLogins() + updateLastLogin(req.ip)
  ↓ UserSession.createSession() → setSessionCookie
  ↓ trackDailyLogin() (non-blocking)
  ↓ 200 { user }
```

### `UserSession.createSession(user, req, expirationHours = 168)`
1. `sessionToken = crypto.randomBytes(48).toString("base64url")` — the **raw** value.
2. `tokenHash = sha256(sessionToken)`.
3. Stores `sessionToken: tokenHash` **and** `tokenHash: tokenHash` — the raw token is never persisted.
4. Computes `fingerprint` and `fingerprintData`.
5. Returns `{ session, sessionToken }`; the **raw** token goes into the cookie.

### `setSessionCookie(res, sessionToken)`
Sets two cookies:
- `user_session` — HttpOnly, `secure` in prod, `sameSite: 'none'` in prod / `'lax'` in dev, 7 days, `domain: COOKIE_DOMAIN`.
- `session_exists = "1"` — **intentionally `httpOnly: false`** so client JS can detect "probably logged in" without reading the token. The frontend `AuthContext` uses this to decide whether to attempt a `/profile` fetch.

> `server.js` also wraps `res.cookie` globally to force `httpOnly` (default true), `secure` (prod), and a `sameSite` default. `session_exists` survives because it explicitly passes `httpOnly: false`.

### Per-request validation — `authMiddleware`
```
1. read req.cookies.user_session
2. IF NO COOKIE → fall back to `Authorization: Bearer <jwt>` (handleJWTAuth)
   IF COOKIE EXISTS → the Authorization header is IGNORED ENTIRELY
      ↑ deliberate: prevents an attacker forcing a stolen bearer token
        onto a browser that already holds a valid cookie
3. UserSession.validateSession(rawToken, req):
     tokenHash = sha256(raw)
     findOne({ tokenHash, isActive: true, expiresAt > now }).populate('user')
     → validateFingerprintLenient(req)   [see §4]
     → on pass: lastActivity = now, session.save()
4. 401 + clear cookie if no session
5. 401 if session.user missing → revoke
6. 403 if user.isBlocked → revoke session
7. 403 if user.isActive === false → revoke session
8. req.user = sanitizeUser(user); req.userSession = session
```

**`sanitizeUser` throws `INVALID_USER_ROLE`** if `user.role` is not one of `user` | `buyer` | `owner`. This is a deliberate fail-closed: a malformed record gets 403 rather than silently defaulting to `buyer`. The middleware catches this specific error and returns `code: "INVALID_ROLE"`.

### Bearer-token fallback (`handleJWTAuth`)
Only reachable when there is **no** cookie. Verifies the JWT, then:
- If the payload contains `sessionId`, it looks up that `UserSession` and enforces revocation/blocked/inactive — so logout genuinely kills bearer tokens.
- If there is **no `sessionId`** (legacy token), it logs a warning and falls back to loading the User directly, checking `isBlocked`, `isActive`, and `changedPasswordAfter(iat)`.

> Nothing in the codebase currently *issues* a JWT with `sessionId`. The only JWTs minted are the 5-minute socket tokens (`GET /api/chat/socket-token`), which contain `{ id, purpose: 'socket_auth' }`. A socket token presented as a Bearer header would therefore take the **legacy** path and authenticate the user for REST calls. See [KNOWN_BUGS.md](KNOWN_BUGS.md).

### `optionalAuth`
Never blocks. Sets `req.user` to the sanitized user or `null`. Used where a page renders for both anonymous and logged-in visitors.

---

## 4. Session Fingerprinting

Both session models compute a fingerprint from **User-Agent + truncated IP** (first 3 IPv4 octets / first 4 IPv6 groups). The full IP is deliberately not used.

`validateFingerprintLenient(req)` is the validator actually wired in:

| Change detected | Action | Rationale (from code comments) |
|---|---|---|
| **OS family changed** (Windows10 → macOS…) | **REVOKE** | An OS does not change mid-session; this is hijacking |
| **Device type changed** (Desktop ↔ Mobile) | **REVOKE** | Same |
| IP prefix changed | allow + refresh | Indian mobile ISPs (Jio/Airtel/Vi) and CDN edges rotate IPs constantly; revoking caused mass logouts |
| Browser family changed | allow + refresh, log warning | e.g. Chrome ↔ Chrome Canary |
| UA string changed (same family) | allow + refresh | browser auto-updates |

"Refresh" rewrites `fingerprintData` and `fingerprint` on the document; the caller must save. `UserSession.validateSession` saves; `protectAdmin` saves via `session.touch()`.

`AdminSession` additionally defines `validateFingerprintStrict` (exact UA match + subnet check) — **defined but never called**. Do not wire it in without understanding that it will revoke on every browser update.

A previous version hard-revoked admin sessions on IP-prefix change; the code comment records that this caused false 401s on every project-create POST while GETs (which use `attachAdminIfPresent`, no fingerprint check) kept working.

---

## 5. Password Reset (User)

**The implemented flow is OTP-over-SMS, not the token model.**

```
POST /api/users/forgot-password { phone }   (email accepted as fallback)
  ↓ authLimiter (5/15min)
  ↓ find user by phone, else by email
  ↓ 404 "No account found…"                 ← LEAKS ACCOUNT EXISTENCE (see SECURITY.md)
  ↓ 60-second cooldown check derived from resetPasswordOtpExpires
  ↓ otp = randomInt(6 digits); store sha256(otp+secret) in user.resetPasswordOtp, 10-min expiry
  ↓ sendPasswordResetSms  ← 500 if SMS unavailable
  ↓ 200

POST /api/users/reset-password { phone, otp, newPassword }
  ↓ password strength validation
  ↓ load user with +resetPasswordOtp +resetPasswordOtpExpires
  ↓ 400 if no OTP on record / expired (expired OTP is $unset)
  ↓ verifyOTPHash (timingSafeEqual)
  ↓ atomic findByIdAndUpdate: set password (bcrypt 12), isVerified = true,
    security.passwordChangedAt = now; $unset both OTP fields
  ↓ UserSession.revokeAllUserSessions(user, "password_reset")
  ↓ 200
```

> `resetPassword` sets `isVerified = true` as a side effect — an unverified account can be verified by completing a password reset.

**Dead path:** `PasswordResetToken` (model) + `GET /api/users/reset-password/validate/:token` implement a proper hashed single-use token with a 3-per-hour rate limit and 5-attempt cap. Nothing creates these tokens, so the validate endpoint always returns "Invalid or expired reset link".

### Change password (authenticated)
`PUT /api/users/change-password` verifies the current password, re-hashes, sets `passwordChangedAt`, then calls `revokeOtherSessions(user, currentSessionId)` — **the current session survives**, all others die.

---

## 6. Role Upgrade: Buyer → Owner

There is no self-serve role field. Upgrading requires proving phone ownership:

```
POST /api/users/send-upgrade-otp     (authMiddleware + requireVerified)
  → 400 if already role "owner"
  → writes hashed OTP to user.otp, sends SMS
POST /api/users/verify-upgrade-otp { otp }
  → verifyOTPHash
  → user.role = "owner"; user.isVerified = true; clear OTP
```

Consequence: `Property.owner` listings and the one-listing-per-owner rule only apply after this upgrade.

---

## 7. Admin Authentication

### Admin accounts are not self-service
`registerAdmin` still exists in `adminController.js` but **is not routed**. `adminRoutes.js` documents this: *"Admins are now created via database seeding only… This eliminates the registration attack surface entirely."* New admins come from a seed script (`seedAdmin.js`, referenced in comments but not present in the repo).

New admins are created with `security.mustChangePassword: true` and `mfa.required: true`.

### Login — `POST /api/admin/login`
```
{ email, password }
  ↓ authRateLimit (in-memory, 10/15min per IP) + authLimiter (5/15min)
  ↓ Admin.findOne(email).select(+password)     ← role deliberately NOT populated
  ↓ 401 generic if not found (+ AuditLog login_failed)
  ↓ 403 if isActive === false
  ↓ 403 if isLocked (returns remaining minutes)
  ↓ bcrypt.compare → on fail: incrementLoginAttempts() + audit, 401 generic
  ↓ clearAuthRateLimit(req)
  ↓ createSession(admin, req)   ← mfaVerified: false ALWAYS
  ↓ branch:
      A) mfa.enabled === true
           → setMfaPendingCookie(admin_mfa_pending, 10 min)
           → 200 { requiresMfa: true, mfaType: "totp" }     ← NO admin_session cookie yet
      B) mfa.required && !mfa.enabled   (first login)
           → session.mfaSetupPending = true, mfaVerified = false
           → setSessionCookie (limited-access session)
           → 200 { requiresMfaSetup: true, mfaSetupPending: true }
      C) neither
           → session.mfaVerified = true
           → setSessionCookie
           → 200 { admin }
```

Branch C is reachable only for a legacy admin whose `mfa.required` is false. The schema default is `required: true`, so in practice every admin lands in A or B.

### MFA verification — `POST /api/admin/mfa/verify`
Reads the `admin_mfa_pending` cookie (not the session cookie), finds the session with `mfaVerified: false`, then:
- TOTP: `speakeasy.totp.verify({ secret, encoding: 'base32', token: code, window: 1 })` — ±1 step (±30 s) tolerance.
- Backup code: `admin.verifyBackupCode(code)` — bcrypt-compares against the hashed list and **splices out the used code**.

On success: `session.mfaVerified = true`, clear the MFA cookie, set `admin_session` to the **same token**, reset login attempts, audit `mfa_success`.

### MFA setup — `POST /api/admin/mfa/setup` → `POST /api/admin/mfa/confirm`
`setup` generates a 32-byte Speakeasy secret, renders a QR data-URL via `qrcode`, generates **10 backup codes** (4-byte hex, uppercased), bcrypt-hashes them for storage, and returns the plaintext codes **once**. MFA is not yet enabled.
`confirm` verifies a TOTP code, sets `mfa.enabled = true`, and — importantly — flips the *current* session's `mfaVerified = true` / `mfaSetupPending = false` so the admin isn't stuck in a setup loop.

### Per-request — `protectAdmin`
```
1. token from admin_session cookie, else Authorization: Bearer (fallback kept for migration)
2. no token → AuditLog(access_denied, severity medium, security event) → 401
3. AdminSession.findOne({ sessionToken, isActive, expiresAt > now })
   → not found: clear cookie, audit invalid_session, 401
4. session.validateFingerprintLenient(req)
   → fail: session.revoke(), audit CRITICAL session_revoked_fingerprint, 401
5. MFA gate:
     !mfaVerified && mfaSetupPending → allow ONLY paths containing
         /mfa/setup, /mfa/verify-setup, /mfa/generate-secret, /mfa/confirm
         else 403 MFA_SETUP_REQUIRED
     !mfaVerified && !mfaSetupPending → 403 MFA_REQUIRED
6. Admin.findById(session.admin).populate('role')
7. 401 if admin missing (revoke session)
8. 403 if isActive === false (revoke + audit high)
9. 403 if isLocked
10. mustChangePassword → allow only /change-password and the MFA endpoints
11. session.touch()
12. req.admin, req.adminSession, req.clientIp
13. res.on('finish'): for POST/PUT/PATCH/DELETE → AuditLog data_access entry
```

Step 5 is the load-bearing control: **an admin session is worthless until MFA is verified.**

### `attachAdminIfPresent` — read-only admin detection
Used on *public* GET routes for projects and unit types (`projectRoutes.js`, `unitTypeRoutes.js`). Never blocks. Requires an active, unexpired, **MFA-verified** session and an active, unlocked admin, then sets `req.isAdminViewer = true`.

Controllers use it to widen visibility only:
```js
if (req.isAdminViewer === true) { /* may see isActive:false records */ }
else { filter.isActive = true; }
```
It grants **read** visibility, never mutation rights. It performs **no fingerprint check and no audit logging** — that asymmetry is deliberate (see §4).

---

## 8. Authorization Layers

### User-side RBAC (`middleware/roleGuard.js` + `authUser.js`)

| Guard | Behavior |
|---|---|
| `blockRetiredRoles` | **Applied globally in `server.js`.** 400 if `req.body.role` is not in `['user','buyer','owner']`; 403 if the authenticated user's role is not. Kills the retired **Agent** role platform-wide |
| `requireUserRole(...roles)` | Throws at *module load* if you pass an invalid role name — a wiring mistake fails at boot, not at request time |
| `ownerOnlyListingAccess` | 403 unless `role === 'owner'`. Gates property create/update |
| `requireRole(...)` (authUser) | Same idea, returns `requiredRoles` in the error body |
| `requireVerified` | 403 unless `user.isVerified` |
| `requireOwnership(fn, param, field)` (roleGuard) | Validates ObjectId format → fetches resource → **constant-time** owner comparison → attaches `req.resource` |

> Two different `requireOwnership` implementations exist — one in `authUser.js` (takes an async id-getter) and one in `roleGuard.js` (takes a finder + field names). Neither is currently used by any route; controllers do ownership checks inline instead (`Property.findOne({ _id, owner: userId })`, `lead.propertyOwner.toString() !== ownerId.toString()`).

### Admin-side RBAC (`middleware/authAdmin.js`)

| Guard | Behavior |
|---|---|
| `requirePermission(...codes)` | `admin.getPermissions()` then **OR** match — having *any* listed code passes. Denials are audited |
| `requireRoleLevel(n)` | `admin.role?.level >= n`, else audited 403 |
| `requireSuperAdmin` | `requireRoleLevel(100)` |

Permission enforcement is **inconsistent by design gap**: only a handful of admin routes carry `requirePermission` (dashboard, leads, reports, verifications, audit-logs). Every other admin route — properties, blogs, builders, projects, unit types, campaigns, bookings, categories, rewards, contact inquiries — is protected by `protectAdmin` alone, meaning **any MFA-verified admin of any role level can perform them**. See [SECURITY.md](SECURITY.md) §Authorization.

---

## 9. CSRF

`middleware/csrfProtection.js` implements the double-submit-cookie pattern:
- `setCsrfToken` runs on **every** request (wired in `server.js`), issuing/refreshing a non-HttpOnly `csrf_token` cookie.
- `GET /api/csrf-token` mints a fresh token. **It deliberately does not return the token in the JSON body** — the client must read the cookie.
- `validateCsrfToken` compares the `csrf_token` cookie against the `X-CSRF-Token` header using `crypto.timingSafeEqual`.

**Validation is disabled.** Two independent reasons:
1. `server.js:763` — `app.use('/api', validateCsrfToken)` is commented out.
2. Even if re-enabled, `validateCsrfToken` early-returns for any path starting with `/api/`.

The stated compensating controls are: strict CORS whitelist, HttpOnly cookies with `SameSite=None; Secure`, and preflight on all state-changing requests. Note that `SameSite=None` is precisely the setting that *removes* the browser's built-in CSRF protection, so CORS is doing the entire job. See [SECURITY.md](SECURITY.md).

To re-enable, you must fix **both** the commented line and the `/api/` early-return, and ensure every frontend mutation sends the header (`client-next/src/utils/api.js` already reads the cookie and attaches it).

---

## 10. Socket.io Authentication

Real-time chat is authenticated separately from REST.

```
Client: GET /api/chat/socket-token        (authMiddleware — cookie required)
        → JWT { id, purpose: 'socket_auth', iat }, expiresIn: '5m'

Client: socket.emit('authenticate', { token })
Server (server.js:487):
        jwt.verify(token, JWT_SECRET)
        userId = decoded.id || decoded.userId || decoded._id
        socketUserMap.set(socket.id, userId)
        onlineUsers.set(userId, socket.id)
        emit('authenticated'); broadcast('users_online')

Client: socket.emit('join_conversation', conversationId)
Server: reject if length > 100 or not a string
        reject if socket not in socketUserMap  → 'NOT_AUTHENTICATED'
        Conversation.findOne({ _id, participants: userId, isActive: true })
        not found → 'ACCESS_DENIED'   ← the real authorization check
        socket.join(conversationId)

Client: socket.emit('send_message', { conversationId, message })
Server: reject if socket not authenticated
        relay to room only: socket.to(conversationId).emit('receive_message', …)
```

Points to know:
- The legacy `user_online` handler (which trusted a client-supplied user id) was **removed**. `authenticate` with a JWT is the only path.
- `socket.on('send_message')` only **relays**; it does not persist. Persistence happens over REST via `POST /api/chat/message/send`. The frontend does both.
- `typing` / `stop_typing` echo `data.userId` back unverified — cosmetic only.
- `onlineUsers` / `socketUserMap` are **in-process Maps**. Horizontal scaling requires a Socket.io Redis adapter; today a second instance would show wrong presence and drop cross-instance messages.
- The 5-minute socket token never expires the socket — once `authenticate` succeeds, the mapping lives until disconnect.

---

## 11. Hubble Third-Party Auth (Gift Cards)

A separate, server-to-server SSO used by the Hubble gift-card SDK. See `services/hubbleService.js` + `controllers/hubbleController.js`.

```
1. Frontend (authenticated): GET /api/rewards/hubble/token
   → crypto.randomBytes(32) token stored in an IN-MEMORY Map with a 5-min expiry
     alongside { userId, name, email, phone }
2. Frontend loads the Hubble SDK iframe with that token
3. Hubble's backend: POST /api/rewards/hubble/sso
     Header X-Hubble-Secret must equal HUBBLE_WEBHOOK_SECRET
     Body { token }
   → validateHubbleToken deletes the token (single use) and returns user details
4. Coin economy (all gated on X-Hubble-Secret, all public routes):
     GET  /api/rewards/hubble/balance?userId=  → { totalCoins: availablePoints }
     POST /api/rewards/hubble/debit   { userId, coins, referenceId, note }
     POST /api/rewards/hubble/reverse { userId, referenceId, note }
```

Both `debit` and `reverse` are **idempotent by `referenceId`** — they scan `reward.transactions` for a matching `metadata.referenceId` and short-circuit.

⚠️ Two operational risks:
- The token store is a process-local `Map` with a `setInterval` sweeper. **Multi-instance deployments will fail SSO** whenever step 3 lands on a different instance than step 1.
- If `HUBBLE_WEBHOOK_SECRET` is unset, `/sso` returns 500 (fails closed) — but check `verifyHubbleSecret` in `hubbleController.js` before assuming the coin endpoints behave identically.

---

## 12. Quick Reference: Error Codes

| Code | HTTP | Meaning |
|---|---|---|
| `NO_SESSION` | 401 | No cookie and no bearer token |
| `INVALID_SESSION` | 401 | Session not found / expired / fingerprint anomaly |
| `SESSION_REVOKED` | 401 | Bearer JWT references a revoked session |
| `TOKEN_EXPIRED` / `INVALID_TOKEN` | 401 | JWT problems |
| `PASSWORD_CHANGED` | 401 | Legacy JWT issued before a password change |
| `INVALID_ROLE` | 403 | `sanitizeUser` rejected the user's role |
| `RETIRED_ROLE` | 403 | `blockRetiredRoles` caught an Agent-era role |
| `ACCOUNT_BLOCKED` / `ACCOUNT_DEACTIVATED` / `ACCOUNT_LOCKED` | 403 / 423 | Account state |
| `EMAIL_NOT_VERIFIED` | 400 | Login before OTP verification |
| `MFA_REQUIRED` | 403 | Admin session exists but MFA not verified |
| `MFA_SETUP_REQUIRED` | 403 | Admin must enrol TOTP first |
| `PASSWORD_CHANGE_REQUIRED` | 403 | `admin.security.mustChangePassword` |
| `SESSION_FINGERPRINT_MISMATCH` | 401 | OS or device-type change |
| `PERMISSION_DENIED` | 403 | `requirePermission` miss |
| `INSUFFICIENT_ROLE_LEVEL` | 403 | `requireRoleLevel` miss |
| `NOT_OWNER` / `NOT_PARTY` | 403 | IDOR guard |
| `CSRF_*` | 403 | Only reachable if CSRF validation is re-enabled |

---

## 13. Rules for Modifying Auth

1. **Never default a missing role.** `sanitizeUser` throwing is intentional.
2. **Never set `mfaVerified: true` at session creation.** `createSession` hardcodes `false`; the comment marks this as a fixed vulnerability.
3. **Cookie beats bearer.** Do not "helpfully" check the Authorization header when a cookie exists.
4. **Do not tighten fingerprinting to IP equality.** It was already reverted twice for causing mass logouts on Indian mobile networks.
5. **Do not add `requireRole` to a route without checking both `user` and `buyer`** — they are the same role in different spellings.
6. Password reset, OTP, and upgrade OTP all share the single `user.otp` field family. Two concurrent flows for one user will clobber each other.
7. Admin password changes go through `admin.password = plaintext; await admin.save()` — the pre-save hook hashes. Assigning an already-hashed value would double-hash.
