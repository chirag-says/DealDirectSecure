# Mobile Handover — Verified Corrections (2026-08-09, updated 2026-08-11)

This document supersedes specific claims in `HANDOFF.md` and `API_CONTRACT.md`.
Where it disagrees with either, **this file is right** — every statement below
was read out of the source file cited, in this repository.

**Method.** Backend controllers and routes read directly. Website behaviour read
from the page components that actually run, not from `client-next/src/utils/api.js`
(several helpers in that file are dead code and disagree with the pages — see
§2.2). Deployment state read from `git diff origin/main`. Nothing here was
verified against a running device or the live API; items that need that are
marked **UNVERIFIED** and say exactly what to run.

**Confidence key.** `CONFIRMED` = read in source. `UNVERIFIED` = reasoned from
source, needs a device or a live call to settle.

---

## 0. The thing that reframes everything else

`git status` says `main` is **4 commits ahead of `origin/main`**, and there are
13 modified backend files that are not committed at all. Deploy is a Hostinger
git import from `origin/main`, so **the backend running in production is
`origin/main`, not what is in this working tree.**

That means the mobile app is being built against three different backends
depending on which one a given session happens to look at:

| Surface | `origin/main` (live) | `HEAD` (local commits) | working tree (uncommitted) |
|---|---|---|---|
| `/api/agreements/*` | **mounted, live** | mounted | **unmounted** (`server.js:869`) |
| `/api/rewards/store`, `/api/rewards/redeem` | **live** | live | **removed** (`routes/rewardsRoutes.js`) |
| `listingType` on `/properties/search` | **absent** | present (`ab5ec1b`) | present |
| delete-account session cascade | **broken** (wrong field names) | broken | fixed |
| `requireCsrf` guard | absent | absent | **present** (`server.js:804-829`) |
| Sentry error reporting | absent | absent | **present** (`server.js:887-900`) |

`CONFIRMED` — `git diff origin/main -- backend/`, and `git show origin/main:backend/server.js | grep agreements` returns the **uncommented** mount at line 791.

Two consequences the handover has to carry, because neither is currently written
down anywhere:

1. **A mobile session reading `backend/` in this repo is reading the future, not
   production.** Every "the backend does X" claim needs to say *which* backend.
2. **The next `git push` changes the API under the app.** Agreements go from
   live to 404. The rewards store goes from live to 404. `listingType` starts
   working. Nothing in `dealdirect-mobile/` is prepared for any of those three.

### 0.1 What this does to the milestone table

| Claim in `HANDOFF.md` | Reality |
|---|---|
| §1: "M10 (agreements) — **skipped by explicit instruction, not blocked**" | Against production it is buildable **today**. Against the working tree it is 404 on every route. It was withdrawn by a client decision on 2026-08-01 (`server.js:848-868`) that has not shipped yet. It is not "the largest remaining gap"; it is a feature the client removed. **Do not build it without asking Chirag whether the withdrawal still stands.** |
| §3.1: "the `listingType` filter is **uncommitted in the working tree**" | It was committed as `ab5ec1b`. It is still **not deployed** (unpushed). The conclusion — Buy/Rent buttons open unfiltered results in production — is unchanged and still correct. Only the stated reason is stale. |
| §2.9: rewards "store/redeem only (already built)" | Built against `GET /rewards/store` and `POST /rewards/redeem`, which the working tree **deletes**. See §4.1. |
| §4.3: `POST /bookings` "optionally authenticated" | The route is `authMiddleware`-gated (`bookingRoutes.js:22`). The dead helper in `client-next/src/utils/api.js` is wrong; so is the mobile `src/api/endpoints/bookings.ts` if it declares `auth: 'optional'`. Verify against the actual route. |

---

## 1. Authentication, end to end

### 1.1 Login — the cookie is now checked (FIXED since audit)

`CONFIRMED` — `src/auth/AuthProvider.tsx:207-213`.

```ts
const login = useCallback(
  async (values: LoginValues): Promise<User> => {
    const response = await call(usersEndpoints.login, { data: values });
    return establishSession(response.user);   // ← probes /users/me
  },
);
```

`establishSession` (lines 162-205) mirrors the cookie via `captureSessionCookie()`,
then calls `fetchMe()` to prove the session took. If the probe fails with a
fatal error (401/403), it calls `endSession` and throws `"Signed in, but this
device could not keep you signed in."`

**The audit's §1.2a diagnosis (discarded cookie return value) was accurate at
the time but the code has since been corrected.** The login flow now matches the
backend contract exactly: sends `{ email, password }`, proves the session with
a real `/users/me` call.

### 1.2 What can actually make mobile login fail

**(a) The `authRateLimit` limiter is stricter than documented and counts successes.**
`CONFIRMED` — `backend/middleware/authUser.js:512-546`, `backend/routes/userRoutes.js:59-70`.

Two limiters stack on `/users/login`:

| Limiter | Where | Budget | Counts successes? | Scope |
|---|---|---|---|---|
| `authLimiter` (express-rate-limit) | `server.js:373-385`, applied `:681` | 5 / 15 min | **no** (`skipSuccessfulRequests: true`) | `/users/login`, `/users/register`, `/users/forgot-password` |
| `authRateLimit` (in-memory `Map`) | `authUser.js:512` | **10 / 15 min** | **yes** | **shared key `auth:${ip}` across** register, register-direct, verify-otp, resend-otp, login, forgot-password, reset-password |

`API_CONTRACT.md` §3 documents only the first one. The second is the one that
bites during development: ten *combined* auth calls per IP per 15 minutes,
successes included. A testing session that registers, resends an OTP twice,
verifies, and logs in three times is already at 7. On carrier NAT it is shared
with strangers.

The mobile login screen does handle this (`app/(auth)/login.tsx:66-70`) and the
in-memory limiter does return `retryAfter`, which `errors.ts:102` reads. So it
surfaces correctly — but "Too many attempts, try again in about 15 minutes"
after two taps reads as a broken login unless you know why.

**(b) `EMAIL_NOT_VERIFIED` routes to an OTP screen the user cannot complete.**
`CONFIRMED` — see §1.4. A registered-but-unverified account gets 400
`EMAIL_NOT_VERIFIED` (`userController.js:577-582`), and `login.tsx:49-55` pushes
to `/(auth)/verify-otp`, which tells the user to check their **email**. The OTP
was sent by **SMS**. The user waits for an email that does not exist and reports
that login is broken.

**(c) Cookie jar behaviour on a cold start.** `UNVERIFIED`.
`src/auth/cookies.ts` mirrors `user_session` into SecureStore and re-injects it
with `CookieManager.set`. The reasoning in that file is sound, but whether
`@react-native-cookies/cookies` reads and writes the *same* jar that RN's
networking stack uses for XHR has not been checked on a device on either
platform. Test: log in, force-quit, relaunch, confirm the app comes back
authenticated without a second login. If (a) is fixed first, a failure here
becomes visible instead of silent.

**(d) CSRF — not a problem, but the code comment is wrong.** `CONFIRMED`.
`src/api/client.ts:14-16` says *"`validateCsrfToken` is commented out at
backend/server.js:763 and no route enforces it."* Half true and about to be
wrong. `validateCsrfToken` is indeed commented out (`server.js:768`), but the
working tree adds `requireCsrf` (`middleware/csrfProtection.js:246`) and applies
it to twelve named routes (`server.js:807-829`), including
`POST /properties/interested/:id`, `POST /properties/add`,
`PUT /properties/my-properties/:id`, `POST /campaigns/:id/join`,
`POST /campaigns/:id/exit`.

Requests without an `Origin` header (mobile app, Next.js SSR, webhooks) pass
through — CSRF is a browser-only attack. The mobile app is exempt.

**Fix the comment in `client.ts` to say this instead of "no route enforces it."**

This matters for the pending map work: `react-native-webview` is on the M4/M16
shopping list. Tiles and Nominatim are fine (different hosts, no cookie), but
nothing in a WebView may call the DealDirect API.

### 1.3 Forgot password is wired to a contract that does not exist

`CONFIRMED`. This is the clearest case of the app copying a website helper
instead of the website's behaviour.

**What the backend does** (`userController.js:620-720`):

| | Request | Effect |
|---|---|---|
| `POST /users/forgot-password` | `{ phone }` preferred, `{ email }` accepted as fallback | looks up the user, generates a 6-digit OTP, **sends it by SMS**. Returns 500 if the user has no phone or SMS is unconfigured (`:731-734`). Returns **404** — not a generic 200 — when no account matches (`:690-694`). |
| `POST /users/reset-password` | `{ phone \| email, otp, newPassword }` | verifies the hashed OTP, applies the full password-strength rules, revokes every session |

There is no email, no link, and no token. `validateResetToken` (`:748`) exists
for a token flow that `forgotPassword` never creates.

**What the website does** (`LoginContent.jsx:259-311`): a three-step modal —
phone → OTP + new password → success. It posts `{ phone }` then
`{ phone, otp, newPassword }`. Correct.

**What `client-next/src/utils/api.js` claims** (`:318-328`):

```js
forgotPassword: async (email) => api.post('/users/forgot-password', { email }),
resetPassword: async (token, password) =>
    api.post('/users/reset-password', { token, password }),
```

Dead code. Nothing on the website calls either. `resetPassword` would fail
outright — the controller requires `otp` and `newPassword`, and reads neither
`token` nor `password`.

**What mobile built** — from the dead helper, not from the page:

| File | Problem |
|---|---|
| `src/auth/schemas.ts:71-73` | `forgotPasswordSchema` asks for **email** |
| `app/(auth)/forgot-password.tsx:37` | posts `{ email }` |
| `app/(auth)/forgot-password.tsx:53-60` | success screen says *"Check your email… we have sent a reset link. Open it in your browser."* No email and no link are ever sent. |
| `src/api/endpoints/users.ts:89-92` | endpoint note repeats the same fiction |
| `src/types/backend/user.ts:100-107` | `ForgotPasswordRequest { email }`, `ResetPasswordRequest { token, password }` — both copied from the dead helper. Neither matches the controller. |
| — | **no in-app reset screen exists**, so even a user who receives the SMS has nowhere to type the OTP |

Net effect: password reset on mobile is 100% broken, and it fails in the worst
way — the request succeeds, the user gets an SMS, and the app tells them to look
in their inbox.

**Fix.** Port the website's three-step modal as a two-screen flow:

1. `forgotPasswordSchema` → `{ phone: phoneSchema }` (the regex already exists at
   `schemas.ts:38-41`).
2. `ForgotPasswordRequest` → `{ phone: string }`.
3. `ResetPasswordRequest` → `{ phone: string; otp: string; newPassword: string }`.
4. New screen `app/(auth)/reset-password.tsx`: OTP + new password + confirm,
   reusing `otpSchema` and `passwordSchema`, which already mirror the backend.
5. Rewrite both the success copy and the endpoint note to say **SMS**.
6. Handle the 404: the backend *does* enumerate accounts here
   (`"No account found with this phone number"`). Do not paper over it with a
   privacy-preserving generic message — that would leave the user staring at a
   success screen for an account that does not exist. Show the backend's message.

Note the mismatch to test for: `forgotPassword` matches on `phone` **exactly, as
stored** (`:682-683`), with no normalisation. A number saved with a country code
or a space will not be found.

### 1.4 The OTP goes by SMS. Three screens say email.

`CONFIRMED` — `userController.js:301-317` (register), `:512-523` (resend).

`registerUser` sends the OTP through `sendOtpSms` only, and **returns 500 if SMS
is unconfigured** (`:314-317`) — it does not fall back. `sendOTPEmail` is defined
at `:152` and never called from anywhere in the file. The website's own copy is
right: *"OTP sent to your phone number"* (`RegisterContent.jsx:210`).

Mobile says email in two places:

| File | Text |
|---|---|
| `app/(auth)/verify-otp.tsx:101` | "We sent a 6-digit code to **{email}**" |
| `app/(auth)/verify-otp.tsx:84` | `Alert.alert('Code sent', 'A new code is on its way to {email}.')` |
| `src/api/endpoints/users.ts:33` | "sends an OTP by SMS **and email**" |

`app/(auth)/register.tsx:90` and its phone-field hint (`:160`) are already
correct, which makes the verify screen contradicting them worse, not better.

The screen only receives `email` as a route param, because `verify-otp` is keyed
on email (`userController.js:416`). Pass the phone through as a second param for
display and keep sending `email` on the wire.

### 1.5 Buyers should not be going through OTP at all

`CONFIRMED` — `RegisterContent.jsx:148-213`.

The website has **two** registration paths and picks between them by role:

| Role | Endpoint | OTP? | Session |
|---|---|---|---|
| Buyer | `POST /users/register-direct` | **no** | created immediately (`userController.js:373-374`), 201 with the user |
| Owner | `POST /users/register` → `POST /users/verify-otp` | yes, by SMS | created at verify-otp (`:448-449`) |

`registerUserDirect` (`:333-409`) sets `isVerified: true`, creates the session,
creates the wallet, and applies `referralCode` — all in one call.

Mobile sends **every** registration to `/users/register`
(`src/auth/AuthProvider.tsx:215-219`), so a buyer signing up on the app gets an
SMS OTP the website never asks them for. It works, but it costs an SMS per
signup, adds a step, and burns two of the ten-per-IP auth budget (§1.2b) instead
of one.

`/users/register-direct` is **not** declared in `src/api/endpoints/users.ts` at all.

**Fix.** Branch on the role chip that `app/(auth)/register.tsx:96-107` already
collects: `role === 'user'` → `register-direct`, straight to `/(tabs)`;
`role === 'owner'` → `register` → `verify-otp`. This is the website's own logic,
against the same backend.

### 1.6 Referral codes are silently dropped on both paths

`CONFIRMED`. Four files, one broken chain:

**Owner path (OTP registration):**

- `registerUser` (`userController.js:232-328`) destructures `referralCode` at
  `:234` and **never uses it**. No `createReferralFromCode` call anywhere in the
  function.
- `verifyOtp` **is** where attribution happens: `if (req.body.referralCode)
  await createReferralFromCode(...)` (`:456-458`).
- The website knows this. `RegisterContent.jsx:275-279` passes `referralCode` to
  `/users/verify-otp`, not just to `/users/register`.

Mobile sends `referralCode` to `/users/register` (`app/(auth)/register.tsx:53-56`
→ `AuthProvider.register`), where it is discarded, and then calls
`verifyOtp(email, otp)` with **only those two fields**
(`AuthProvider.tsx:229`, `VerifyOtpRequest` at `types/backend/user.ts:86-89`).

**Buyer path (direct registration):**

- `registerUserDirect` (`:381-383`) reads `req.body.referralCode` directly.
- But mobile never calls this endpoint (§1.5).

So the referral field on the mobile registration form does nothing on both paths.

**Fix (owner path).** Carry the code from the register screen to the verify screen
as a route param, add `referralCode?: string` to `VerifyOtpRequest`, and pass it
through `verifyOtp`.

**Fix (buyer path).** Once §1.5's `register-direct` path is wired up, it handles
referral codes automatically since that controller reads `req.body.referralCode`
directly (`:381-383`).

### 1.7 MFA and forced password change do not exist. Do not port them.

`CONFIRMED` — no route or controller anywhere in `backend/` matches
`verify-mfa` or `change-password-required`.

`client-next/src/context/AuthContext.jsx` carries ~150 lines for both flows:
`verifyMfa` posts to `/users/verify-mfa` (`:262`), `changePasswordOnLogin` posts
to `/users/change-password-required` (`:293`), and `LoginContent.jsx:326-485`
renders two full-screen forms for them. Both endpoints **404**. The branches
never fire because `loginUser` never returns `requiresMfa` or
`passwordChangeRequired` — read `userController.js:538-616`; those keys do not
appear.

The mobile app correctly implements neither. Recording it here so a future
parity audit does not "discover the gap" and build a client for endpoints that
do not exist. (Admin MFA is real and TOTP-based, but that is `authAdmin.js` and
out of mobile scope.)

### 1.8 Smaller auth notes

- **`isValidPhoneNumber` accepts an empty string** — `userController.js:114-118`
  returns `true` for a blank phone. `registerUser` catches it separately at
  `:236`, so registration is safe, but do not rely on that helper as a
  presence check.
- **`sanitizeUserResponse` includes `blockReason`** (`:140`) on every login and
  profile response. Backend hygiene item, not a mobile bug.
- **Delete account session cascade — FIXED in working tree, still broken on `origin/main`.** The cascade now uses correct field names (`user` not `userId` for sessions, `userId` not `user` for LoginTracker, `reportedBy` not `reporter` for Reports, `referred` not `referredUser` for Referrals). `app/settings/delete-account.tsx` should not promise that other devices are signed out until that ships to production.

---

## 2. Where the copying went wrong, structurally

### 2.1 The pattern

Every defect in §1.3 through §1.6 has the same shape: **`client-next/src/utils/api.js`
was treated as the website's behaviour, when it is partly an unused wrapper.**

The website's pages mostly bypass that file's domain helpers and call
`api.post(...)` directly. So the helpers drifted and nobody noticed — they are
not on any code path. `API_CONTRACT.md` §8 already caught five of these. The
auth ones were missed because auth is the one area where the page *does* go
through a context, and the context's `login`/`register` are live while
`forgotPassword`/`resetPassword` sitting next to them in the same object are not.

**Rule for future parity work:** read the page component, not the helper. If a
helper and a page disagree, the page is what ships. If both disagree with the
controller, the controller wins.

### 2.2 Confirmed-dead helpers in `client-next/src/utils/api.js`

Do not port any of these:

| Helper | Line | Why it is dead |
|---|---|---|
| `authApi.forgotPassword(email)` | 319 | pages post `{ phone }` |
| `authApi.resetPassword(token, password)` | 325 | controller wants `{ phone, otp, newPassword }` |
| `propertyApi.search({ q })` | 343 | controller reads `search` (`API_CONTRACT.md` §8 #1) |
| `notificationApi.markRead` / `markAllRead` | 423, 428 | PUT paths that 404; routes are PATCH (§8 #2, #3) |
| `agreementApi.*` | 464-494 | see §4.2 |
| `rewardsApi.getStore` / `redeem` | — | already deleted from this file with a comment explaining why (§4.1) |

### 2.3 Mobile's own endpoint declarations that drift from the controller

These are in `dealdirect-mobile/src/api/endpoints/`:

| Endpoint file | Declaration | Backend reality | Impact |
|---|---|---|---|
| `users.ts:83-92` | `forgotPassword` takes `{ email }`, note says "emails a reset link" | Takes `{ phone }` (email fallback), sends SMS OTP | Wrong field, wrong UI copy, wrong success message |
| `users.ts:94-100` | `resetPassword` takes `{ token, password }` | Takes `{ phone\|email, otp, newPassword }` | Completely wrong body shape |
| `users.ts` (missing) | `registerDirect` not declared | Live endpoint at `POST /users/register-direct` | Buyer registration path unreachable |
| `users.ts:86-89` | `VerifyOtpRequest { email, otp }` | Controller reads `referralCode` from `req.body` too (`:456-458`) | Referral codes dropped on owner path |

---

## 3. Corrections to `API_CONTRACT.md`

| § | Claim | Correction |
|---|---|---|
| 1.2 | "`validateCsrfToken` is commented out… **No route enforces CSRF.**" | True on `origin/main`. The working tree adds `requireCsrf` on 12 named routes (`server.js:807-829`). The app is exempt only because it sends no `Origin`. Rewrite as a constraint, not an absence. |
| 3 | auth tier "5 / 15 min, successes not counted" | Incomplete. A second limiter, `authRateLimit` (`authUser.js:512`), is 10 / 15 min per IP, **counts successes**, and is **shared across all seven public auth routes**. |
| 3 | group buy "10 / 15 min — campaign join, campaign exit" | **Does not apply.** The limiter is mounted at `/api/group-buy/projects/:id/join\|exit` (`server.js:705-706`). Campaigns are mounted at `/api/campaigns` (`:880`). No such path exists; join/exit are covered only by the 500/15min global limiter. |
| 4 Users | forgot-password "emails a **website** link; app opens it externally" | Wrong. Sends a 6-digit OTP by **SMS**. Body is `{ phone }` (email accepted as fallback). See §1.3. |
| 4 Users | reset-password, no note | Body is `{ phone \| email, otp, newPassword }`. Full password-strength rules apply. Revokes all sessions. |
| 4 Users | table omits `/users/register-direct` | Real, live, and the path the website uses for buyers (§1.5). Add it. |
| 4 Users | login "body: `{ email, password }`" | Correct. But note the session proof: `establishSession` calls `/users/me` after login to confirm the cookie took. |
| 4 Properties | `/properties/saved` — "private bookmark" | Contradicts `HANDOFF.md` §3.2, which corrected this: saved and interested are **one list** (`getSavedProperties` queries `interestedUsers.user`). `API_CONTRACT.md` was never updated. |
| 4 Properties | search params list | Add `listingType` (`propertyController.js`, `ab5ec1b`) with the caveat that it is **not deployed**. |
| — | no reachability column | Add one. Agreements, `/rewards/store` and `/rewards/redeem` are live on `origin/main` and removed in the working tree (§0). |
| 4 Rewards | `/rewards/store` and `/rewards/redeem` | **Removed in working tree.** `origin/main` still serves them. After the next deploy they 404. |

Also worth adding to §8, as website bugs found in this pass:

- `authApi.forgotPassword` / `resetPassword` are unreachable and wrong (§1.3).
- `/users/verify-mfa` and `/users/change-password-required` do not exist; the
  website ships UI for both (§1.7).
- The login page requires a 10-digit Indian phone that is never transmitted
  (§1.1) — a real lockout for anyone without one.

---

## 4. Endpoints the app declares that do not survive the next deploy

### 4.1 Rewards store and redemption — `CONFIRMED`

`backend/routes/rewardsRoutes.js` in the working tree deletes:

```
- router.get("/store", getRewardsStore);
- router.post("/redeem", authMiddleware, redeemReward);
```

along with `RedemptionRequest.js` (deleted), 209 lines of `rewardService.js`, and
102 of `rewardsController.js`. The website already removed its own callers, with
a comment: *"they called the pre-Hubble in-house redemption store, which no
longer exists on the backend"* (`utils/api.js:558-562`). Redemption now happens
inside the **Hubble SDK iframe**, debited server-to-server via
`POST /api/rewards/hubble/debit`.

Mobile still declares and calls both:

| File | Line |
|---|---|
| `src/api/endpoints/rewards.ts` | `store` :26-32, `redeem` :68-76 |
| `src/features/rewards/hooks.ts` | `useRewardsStore` :102, `useRedeemReward` :126 |
| `app/rewards/index.tsx` | :28, :169 |

`src/api/endpoints/rewards.ts:5-10` explicitly puts Hubble out of scope
("a web-SDK integration with no native equivalent"). Taken together:
**after the next deploy, mobile has no working redemption path at all** — the
old one 404s and the new one was declined.

This is a product decision, not a coding one. Options, in the order I would
raise them:

1. Show balance, tier and referrals; route redemption to the website (deep link
   into the Hubble dashboard). Honest, small, ships now.
2. Ask whether Hubble's SDK has a React Native or hosted-page mode that a
   WebView could load — **but see §1.2d first**: a WebView must not call the
   DealDirect API, and Hubble's flow needs a token from
   `GET /rewards/hubble/token`. That token has to be fetched by the app and
   handed in, not fetched by the page.
3. Keep the store screen only if the removal is not going to ship.

Until this is decided, `app/rewards/index.tsx`'s store and redeem sections
should be gated behind a feature flag rather than left to 404 on release day.

### 4.2 Agreements — `CONFIRMED`, and the reverse of what the handover says

`server.js:848-868` (working tree) unmounts `/api/agreements` with a comment:
*"AGREEMENTS — HIDDEN (client decision, 2026-08-01) … withdrawn for now and
will return later."* It also lists the three places hidden together — the mount,
`client-next/src/app/agreements/page.js` (returns 404), and three navbar links.

`HANDOFF.md` §1 and §4 call M10 "the largest remaining buyer/owner-facing gap"
and "skipped by explicit instruction, not blocked." The accurate statement is:
**agreements were withdrawn from the product.** Building a mobile client for
them would ship a feature the website deliberately hides.

`src/api/endpoints/agreements.ts` should carry a header saying this, so nobody
reads six typed endpoints as an invitation.

If it is ever restored, note the security precondition already recorded at
`server.js:860-863`: `POST /api/agreements/webhook/payment` **skips HMAC
verification entirely when `PAYMENT_WEBHOOK_SECRET` is unset**. That must be
fixed before the mount comes back, and the mobile app must never be the reason
it comes back early.

### 4.3 Smaller declaration errors

- **`POST /bookings` requires auth.** `bookingRoutes.js:22` is
  `authMiddleware`-gated. `client-next/src/utils/api.js:723-726` describes it as
  *"optionally authenticated… auto-linked if the user is logged in."* Wrong.
  Check what `src/api/endpoints/*` declares and make sure the booking sheet
  prompts for login rather than failing at submit.

---

## 5. What is right, and should not be touched

Stated explicitly so a corrective pass does not churn working code:

- **Login request shape** — `{ email, password }` matches the controller exactly
  (§1.1).
- **Session model** — opaque 48-byte cookie, no JWT, no refresh endpoint, probe
  `/users/me` on cold start. `AuthProvider`'s treatment of a cold-start 401 as
  "guest" rather than as an error is correct.
- **The User-Agent constant** (`src/api/userAgent.ts`) — the fingerprint-drift
  reasoning is right and load-bearing. Every claim in that file's comment checks
  out against `authUser.js`. Do not interpolate the version into it.
- **Socket handshake** — `GET /chat/socket-token` then `emit('authenticate')`
  matches `server.js:492-526` and the website's own `ChatContext.jsx:78-98`.
  Re-running the handshake on every `connect` is correct: the token is
  short-lived. Not emitting `user_online` is correct: the handler is gone.
- **`verify-otp` establishes the session** and must not be followed by a login
  call — confirmed at `userController.js:448-449`, returns 201 with `Set-Cookie`.
- **Password rules in `src/auth/schemas.ts`** are character-for-character
  identical to `PASSWORD_REGEX` (`userController.js:92`). Verified.
- **`GET /properties/:id` increments `views` on every call.** Every place the
  handover works around this (detail `staleTime: Infinity`, gallery reading
  through cache, edit reading from `my-properties`, compare using
  `PropertySummary`, `recentlyViewed` snapshotting) is correct and should stay.
- **Cookie mirror to SecureStore** — the rationale in `src/auth/cookies.ts` is
  sound. Cold-start recovery through `restoreSessionCookie` + `GET /users/me` is
  the right pattern.
- **`pickTransactions` defensive read** (`hooks.ts:44-47`) — the service result
  is spread into the envelope and the actual key name is not yet pinned down.
  Reading `transactions ?? data ?? history` is the correct defensive pattern.
- **Delete-account cascade in working tree** — all four wrong field names are
  now fixed (`user` for sessions, `userId` for LoginTracker, `reportedBy` for
  Reports, `referred` for Referrals). Cloudinary assets are also cleaned up.

---

## 6. Fix order

Grouped by what unblocks what, not by size.

**Auth flows that are broken end to end.**

1. Forgot/reset password: phone-based, SMS OTP, new in-app reset screen, five
   files (§1.3). Largest single fix here. Also fixes the endpoint declaration
   drift in `src/api/endpoints/users.ts`.
2. Buyer registration via `/users/register-direct` (§1.5). Depends on adding
   the endpoint declaration.
3. Referral code carried through to `verify-otp` (§1.6). Depends on 1 (owner
   path needs verify-otp to work) and 2 (buyer path needs register-direct).
4. Verify-OTP copy: SMS not email, two strings + one alert (§1.4). Can be done
   any time, low risk.

**Then — stop the app from shipping against endpoints that are going away.**

5. Decide the rewards redemption question (§4.1). Product call, needed before
   M18 can be scoped at all.
6. Decide whether agreements stay withdrawn (§4.2). Closes or reopens M10.
7. Feature-flag or remove the store/redeem UI, per 5.

**Then — documentation, so the next session does not repeat this.**

8. Apply §3 to `API_CONTRACT.md`, including a reachability column.
9. Correct `HANDOFF.md` §1 (M10), §2.12 (group-buy limiter), §3.1 (listingType
   is committed, still undeployed).
10. Fix the CSRF comment in `src/api/client.ts` and turn it into the
    no-WebView-API-calls constraint (§1.2d).

**Ongoing.**

11. Add a "which backend?" line to every backend claim in the docs: `origin/main`
    (live), `HEAD`, or working tree (§0).
12. Pin down the transaction response shape against a live call (M7 task — see
    `hooks.ts:44`).

---

## 7. Open questions for Chirag

1. **Agreements** — does the 2026-08-01 withdrawal still stand? Answering this
   deletes or restores an entire milestone.
2. **Rewards redemption on mobile** — website-only for now, or is a Hubble
   WebView worth the native-module and CSRF cost?
3. **The four unpushed commits** — is the `listingType` fix waiting on something,
   or just not deployed yet? It is the single highest-leverage backend change for
   the app: it makes the Buy and Rent buttons work.
4. **The website login's phone field** — deliberate, or a leftover? As written it
   locks out any account without a 10-digit Indian mobile number, on the website
   only.
