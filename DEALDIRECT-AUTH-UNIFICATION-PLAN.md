# DealDirect Auth Unification — Google Sign-In + Just-In-Time Phone Verification

**Status:** Phase 1 (backend) built and tested. Phases 2 (mobile) and 3 (website) not started.
**Date:** 2026-09-10, updated 2026-09-11 with what implementation corrected
**Scope:** `backend/`, `dealdirect-mobile/`, `client-next/` — all three in one cutover
**Classification:** Arch + Feature + SecReview + Migration

---

## 1. What changes, in one paragraph

Registration stops asking "Buyer or Owner" and stops demanding an SMS OTP. One register page, one
login page, for everyone. Google becomes the fast path: tap the button, pick a Gmail, you are in,
with no password and no phone number. Email + password signup survives, minus the role picker and
minus the mandatory phone. The SMS OTP moves from being a signup toll to being a just-in-time check:
the first time an account tries to do something that needs a real person behind a real phone, a sheet
asks for the number, sends the OTP, links it permanently, and then **completes the action the user
was originally trying to do**. Role stops being declared and starts being earned: the account becomes
`owner` at the moment it first lists a property, which is the same moment the phone gate fires.

---

## 2. Current state (read from source, 2026-09-10)

| Fact | Where | Consequence for this plan |
|---|---|---|
| `POST /users/register` requires phone, sends SMS OTP, `verify-otp` finishes signup | `controllers/userController.js:236,420` | This becomes the legacy path; new signup does not send SMS |
| `POST /users/register-direct` creates the account with **`isVerified: true` and no OTP at all** | `userController.js:337` | `isVerified` is already not a phone proof. It cannot be reused as one |
| `isVerified` is labelled "Email verification required" in middleware but is set by *phone* OTP | `middleware/authUser.js:520` | The field's meaning is already muddled. New flags must be unambiguous |
| Email is **never verified** at registration on any path | `userController.js` | This is the precondition for account pre-hijacking. Drives decision D2 |
| Role picker on signup drives `owner` permissions | `roleGuard.js:122` `ownerOnlyListingAccess`, `agreementRoutes.js:74` | Removing the picker means promotion has to happen somewhere else |
| Buyer→owner upgrade already exists behind an SMS OTP | `userController.js:1103,1140` | This is the seed of the new gate. Generalise it, do not duplicate it |
| OTP is 6 digits, 10 minute window, **no attempt limiting** | `userController.js:64` + `verifyOtp` | ~900k space, unlimited guesses. Brute-forceable. Must be fixed here |
| `user.otp` is a single field shared by registration, upgrade **and** password reset | `userController.js:277,730,1117` | Concurrent flows overwrite each other. Phone-link needs its own storage |
| Session is an opaque 48-byte token in an HttpOnly cookie, Bearer as fallback | `authUser.js:26,69` | Google sign-in reuses this exactly. No JWT, no refresh, nothing new |
| Mobile stores/replays the cookie via SecureStore into the native jar | `dealdirect-mobile/src/auth/cookies.ts` | Google sign-in on mobile needs zero new session plumbing |
| CSRF is a named allowlist enforced in `server.js` | `server.js:877-915` | Every new mutating route must be added there or it is unguarded |
| No `google-auth-library`, no `next-auth`, no `expo-auth-session` anywhere | all three `package.json` | Three new deps, chosen in §5 |
| Website caps owners at one property: `canAddProperty = isOwner && isVerified && !ownerHasProperty` | `client-next/src/context/AuthContext.jsx:317` | Existing business rule. Preserve it, do not silently drop it |

---

## 3. Decisions

### D1 — `isVerified` is not reused. Three explicit flags replace one ambiguous one.

`isVerified` stays exactly where it is and keeps meaning "this account is usable", because a dozen
call sites depend on it and changing its meaning under them is how you create a silent authz hole.
Three new fields carry the real claims:

- `emailVerified` — true only when Google vouched for the inbox
- `phoneVerified` — true only when someone entered an OTP sent to that number
- `googleId` — Google's stable `sub`, unique + sparse

Every new gate reads `phoneVerified`. Nothing new reads `isVerified`.

### D2 — Google sign-in onto an existing password account requires the password. No silent merge.

Because email is never verified at registration, anyone can hold an account under your Gmail. Auto
-merging on email match would drop a legitimate Google user straight into an attacker's pre-made
account, where the attacker still knows the password and can watch everything. That is account
pre-hijacking, and this codebase has the exact precondition for it.

| Google sign-in finds | Response |
|---|---|
| No account with that email | Create account, `googleId` set, no password, `emailVerified: true`, sign in |
| Account whose `googleId` matches `sub` | Sign in |
| Account with that email, no `googleId` | **`409 GOOGLE_LINK_REQUIRED`.** Client asks for the existing password once, calls the link endpoint, then signs in |

Supporting rules, all non-negotiable:

- Look up by `googleId` (`sub`) **first**, email only as fallback. Workspace emails get reassigned; `sub` does not.
- Reject if the verified token payload has `email_verified !== true`.
- Verify the ID token server-side against Google's JWKS with `audience` set to all our client IDs. The email in the request body is never trusted.

**Residual risk, accepted and documented:** an attacker who squats your email can block you from
using Google sign-in (you cannot produce their password). They cannot get *into* your data, and this
squatting hole predates this change. The real fix is verifying email at registration, which is filed
as follow-up work in §9, not smuggled into this change.

### D3 — Phone collision refuses, it does not merge.

`phone` is `unique, sparse`. When the OTP sheet is handed a number already linked to another account,
return `409 PHONE_ALREADY_LINKED` with a plain message. Merging accounts on a shared identifier is
how data leaks between users.

### D4 — Existing users are grandfathered, behind a flag.

Backfill sets `phoneVerified: true` for every existing user who has a phone and `isVerified: true`.
This is imperfect: users who came through `register-direct` never proved their phone. But those users
can already perform every gated action today, so grandfathering is **status quo, not a regression**,
whereas forcing the entire live user base through a re-verification event is a real cost for a
problem they did not create. An env flag `FORCE_PHONE_REVERIFY=true` flips this later if you want the
clean sweep, without a code change.

### D5 — Role is derived from action, never from client input.

The client never sends a role. `POST /properties/add` runs `requirePhoneVerified` and then
`ensureOwnerRole`, which promotes `user`/`buyer` → `owner` in place. One code path, no trust in the
request body, and the promotion is atomic with the thing that justified it.

### D6 — Old endpoints stay alive through the cutover.

Old app builds are in the wild and cannot be forced to update. `register`, `register-direct`,
`verify-otp`, `send-upgrade-otp`, `verify-upgrade-otp` all keep working unchanged. They get retired
in Phase 5, after telemetry shows the old clients are gone.

---

## 4. The gated actions

Confirmed list. Everything not here stays open to an unverified account, including browsing,
searching, shortlisting, saved searches, and profile edits.

| Action | Endpoint | Guard added |
|---|---|---|
| List a property | `POST /properties/add` | `requirePhoneVerified` + `ensureOwnerRole` |
| Edit own listing | `PUT /properties/my-properties/:id` | `requirePhoneVerified` |
| Express interest / contact owner | `POST /properties/interested/:id` | `requirePhoneVerified` |
| Close a deal | `POST /properties/:id/close-deal` | `requirePhoneVerified` |
| Generate / sign an agreement | `POST /agreements/generate`, `POST /agreements/:id/sign` | `requirePhoneVerified` |
| Claim a reward | `POST /properties/claim-deal-reward/:verificationId` | `requirePhoneVerified` |

Three corrections the code forced on the draft above:

- `PUT /properties/edit/:id` is **admin-only** (`protectAdmin`), not an owner route. Gating it on a user's phone would have been meaningless. Dropped.
- The agreement routes are mounted only under `AGREEMENTS_ENABLED`, which is off — the feature is withdrawn. The gate is wired anyway so re-enabling cannot quietly re-enable it ungated, and the test asserts the wiring rather than driving a route that would 404 for the wrong reason.
- There is no rewards redemption endpoint; `/redeem` went with the pre-Hubble store. Claiming a deal reward is the only reward action, and it is listed.

Reads are never gated. `GET /agreements/my-agreements`, checking or removing your own interest, browsing, searching and shortlisting all stay open. Blocking a read would strand someone who verified on one device and opened the app on another, and harms nobody.

`requirePhoneVerified` returns exactly:

```json
{ "success": false, "code": "PHONE_VERIFICATION_REQUIRED", "message": "Verify your mobile number to continue." }
```

with HTTP 403. Both frontends key the sheet off `code`, never off the message string.

---

## 5. Dependencies (L14: breach → buy, bug → build)

| Where | Package | Why this one |
|---|---|---|
| backend | `google-auth-library` | ID token verification is a signature-check against a rotating JWKS. Failure mode is a breach. Google's own library, no alternative worth considering |
| mobile | `@react-native-google-signin/google-signin` | Native account picker sheet. Best UX by a wide margin. Needs a dev/release build, not Expo Go, which is already how this app is built (local Gradle + EAS) |
| website | Google Identity Services, script tag | No package. `google.accounts.id` renders the button and hands back a credential. Adding `next-auth` would mean running a second session system alongside the opaque-cookie one, for no gain |

Google Cloud Console needs four OAuth client IDs before any code runs: **Web** (for the website, and
as `serverClientId` for Android), **Android debug SHA-1**, **Android release SHA-1** including the
Play App Signing key, and **iOS**. All four go into the backend's `audience` array.

---

## 6. Backend changes

### 6.1 Schema — `models/userModel.js` (migration rung M2: additive + backfill)

```js
googleId:        { type: String, unique: true, sparse: true, index: true },
emailVerified:   { type: Boolean, default: false },
phoneVerified:   { type: Boolean, default: false },
phoneVerifiedAt: { type: Date },

// Phone-link OTP lives in its own subdocument, not in the shared `otp` field.
// The pending number is not on the account yet, so it needs somewhere to live,
// and sharing `otp` with password reset means one flow silently kills the other.
pendingPhone: {
  phone:    { type: String, select: false },
  otp:      { type: String, select: false },
  expires:  { type: Date,   select: false },
  attempts: { type: Number, default: 0, select: false },
  sentAt:   { type: Date,   select: false },
},
```

`password` becomes conditionally required:

```js
required: [function () { return !this.googleId; }, "Password is required"],
```

`phone` stays `unique, sparse` and simply stops being demanded at registration.

**Migration script** `backend/scripts/migrate-auth-flags.js`, with an explicit DOWN before the UP is
run, per L9:

- UP: `phoneVerified: true` where `isVerified: true` and `phone` exists; `false` everywhere else.
- DOWN: `$unset` the four new fields. No existing field is touched, so DOWN is total.
- Run against a backup. Confirm with Chirag before it touches production data.

### 6.2 New endpoints — `controllers/authGoogleController.js`, `controllers/phoneVerificationController.js`

```
POST /api/users/auth/google         { idToken }              → 200 session | 409 GOOGLE_LINK_REQUIRED
POST /api/users/auth/google/link    { idToken, password }    → 200 session | 401
POST /api/users/phone/send-otp      { phone }        [auth]  → 200 | 409 PHONE_ALREADY_LINKED | 429
POST /api/users/phone/verify-otp    { otp }          [auth]  → 200 { user } | 400 | 429
```

Both Google routes issue a session through the existing `UserSession.createSession` +
`setSessionCookie`. Nothing about session handling changes, so both clients keep working as they do.

New user creation through Google reuses the post-registration hooks that `register-direct` already
runs: wallet creation, referral code, WhatsApp admin notification, welcome email. Extracted into one
`completeRegistrationSideEffects(user, req)` helper rather than copy-pasted a third time.

### 6.3 New middleware — `middleware/requirePhoneVerified.js`, `middleware/ensureOwnerRole.js`

Small, single-purpose, applied at the route table. `ownerOnlyListingAccess` stays for any route not
in the §4 list so nothing loses a guard it currently has.

### 6.4 Security work that has to happen in the same change

These are not optional extras. The OTP is about to become the *only* thing standing between an
account and every high-value action on the platform, so it has to be worth that weight.

1. **OTP attempt limiting.** 5 wrong guesses burns the OTP. `pendingPhone.attempts` already exists in the schema above for this. Without it, a 6-digit code with unlimited guesses over 10 minutes is not a control. **Done.**
2. **Send throttling, per user and per phone.** 3 sends per 15 minutes. Every send costs real money at Equence, and an unthrottled authenticated endpoint that dials arbitrary numbers is an SMS-pumping bill waiting to happen. Enforced per account rather than per IP: an attacker changes IP at will on a phone network, and an office behind one NAT is not three abusers. **Done.**
3. **CSRF.** Add all four new routes to the `csrfGuard` list in `server.js`. The Google routes are pre-session, but login CSRF is real: an attacker who can force you into *their* session gets everything you do next. **Done.**
4. **`authRateLimit`** on both Google routes. `/link` also shares the password-login lockout counter, so it cannot be used as an unthrottled oracle for guessing the very password `loginUser` throttles. **Done.**
5. ~~Constant-time OTP comparison.~~ **Not needed.** The existing `verifyOTPHash` already uses `crypto.timingSafeEqual`; the draft was wrong about it. It was moved to `utils/otp.js` unchanged so both callers share one implementation.
6. ~~Audit log entries.~~ **Not done, deliberately.** `AuditLog` is admin-scoped: it requires an `admin` reference and an `adminSnapshot`, and its own source carries the line that an audit category which lies about what happened is worse than none. Writing user auth events into it would be exactly that. These four events are logged through the structured `console` prefixes the rest of the auth code already uses. A user-facing security log is worth building, as its own change.
7. **`sanitizeUserResponse`** must expose `phoneVerified` and `emailVerified` so clients can render state without a second call, and must never expose `pendingPhone`. **Done**, and `googleId`/`pendingPhone` are additionally stripped in `toJSON`, `getSafeFields` and `authUser.sanitizeUser`.

### 6.5 What implementation found that the plan missed

A user document can now exist with **no password**. Four controller paths called `bcrypt.compare(x, user.password)` with no check for the hash, and all four threw a 500 for a Google account:

- `loginUser` — now answers `401 USE_GOOGLE_SIGNIN`. A 500 here was not merely a crash: it distinguished "Google-only account" from "no such account" by status code alone, which is the exact thing a generic 401 exists to hide.
- `changePassword` — now answers `400 NO_PASSWORD_SET`.
- `forgotPassword` — reset delivery is SMS-only, and a Google account may have no number yet. Now answers `400 NO_PHONE_ON_ACCOUNT` instead of falling through to a generic 500.
- `deleteAccount` — the serious one. Requiring a password would have left Google accounts **permanently undeletable**, which fails both data-rights obligations and App Store review. It now accepts a freshly minted Google ID token instead, and requires that token's `sub` to match the account's own `googleId` — otherwise any valid Google token would delete whichever account the session happened to hold.

---

## 7. Mobile changes (`dealdirect-mobile/`)

| File | Change |
|---|---|
| `app/(auth)/register.tsx` | Delete the Buyer/Owner picker. Phone field removed. Google button added above the form |
| `app/(auth)/login.tsx` | Google button added above the form |
| `app/(auth)/verify-otp.tsx` | No longer part of signup. Kept only for legacy sessions mid-flow, then deleted in Phase 5 |
| `src/auth/AuthProvider.tsx` | `signInWithGoogle()`, `linkGoogle(password)`, `sendPhoneOtp()`, `verifyPhoneOtp()`. `register()` stops routing to the OTP screen |
| `src/auth/PhoneVerificationSheet.tsx` | **New.** Number entry → OTP entry → success. Follows the app's existing sheet + motion conventions |
| `src/auth/GoogleLinkPasswordSheet.tsx` | **New.** The one-time password prompt for D2 |
| `src/api/request.ts` | Intercept `403 PHONE_VERIFICATION_REQUIRED`, open the sheet, **replay the original request on success** |
| `src/api/endpoints/users.ts` | The four new endpoints |
| `app.config.ts` | `@react-native-google-signin/google-signin` config plugin, client IDs from env |

**The replay is the feature.** The user tapped "I'm interested". They should land back on that
property with the interest registered, not on the home screen wondering what happened. The existing
`setResponseObserver` hook in `src/api/request.ts` is the right place: it already sees every
response, so the retry queue lives there and every gated action gets the behaviour for free, with no
per-screen code.

Build note: `@react-native-google-signin` is a native module, so this needs a fresh dev client and a
release build. Per the existing APK build path, that means `SENTRY_DISABLE_AUTO_UPLOAD`, prod URLs,
`CI=1`, and the update channel present in `app.config` or OTA never arrives. Fingerprint changes, so
**this cannot ship as an OTA update** — it is a store build.

---

## 8. Website changes (`client-next/`)

| File | Change |
|---|---|
| `src/app/register/RegisterContent.jsx` | Delete the `userType` state, the two-card picker, the two-branch submit, and the `step === 2` OTP stage. One form, one submit |
| `src/app/login/LoginContent.jsx` | Google button |
| `src/components/AuthModal/AuthModal.jsx` | Same two changes, since it duplicates both forms |
| `src/context/AuthContext.jsx` | `signInWithGoogle`, `linkGoogle`, phone OTP methods. `canAddProperty` becomes `isAuthenticated && !ownerHasProperty` — the `isOwner && isVerified` half is now enforced server-side by the gate, and keeping it client-side would hide the "Add property" button from exactly the users the new flow is designed to let through |
| `src/components/PhoneVerificationModal.jsx` | **New.** Web twin of the mobile sheet |
| `src/lib/api` axios instance | Same `403 PHONE_VERIFICATION_REQUIRED` interceptor and replay |
| `src/app/layout.js` | GIS script, `afterInteractive` |

Note the one-property-per-owner cap is preserved deliberately. If that rule is meant to die, it dies
in its own change, not as a side effect of this one.

---

## 9. Phases

**Phase 0 — Console + env.** Chirag creates the four OAuth client IDs. Env vars land in all three
apps. Nothing else can start until the Android release SHA-1 is registered, because sign-in fails
silently without it and that failure is genuinely hard to diagnose.

**Phase 1 — Backend, additive only. ✅ Built.** Schema, migration script, six endpoints (the four
planned plus `GET /users/phone/status` and the delete-by-Google-token path), two middlewares, the
security items in §6.4, and §6.5's passwordless-account fixes. 753 unit and 1106 integration tests
pass, including two new suites (26 + 32 assertions). Every old endpoint still works, and with the
`GOOGLE_CLIENT_ID_*` variables unset the new ones answer 503 and change nothing — so this is
deployable on its own, today, with zero client impact. That property is what makes the rest safe.

Still to do before deploying it: run the migration dry run against a copy of production, then `--up`.

**Phase 2 — Mobile.** Screens, sheets, replay interceptor, native module, dev build, QA against the
existing mobile QA script.

**Phase 3 — Website.** Same feature set, web idioms.

**Phase 4 — Deploy.** Backend first, always. Each app folder is its own repo with its own Hostinger
hosting, so the order is enforced by hand, not by CI: **backend → website → store submission.** The
app is last because it is the only one with a review queue and a population of users who will not
update.

**Phase 5 — Retire.** Once telemetry shows old clients are gone: delete `register-direct`,
`send-upgrade-otp`, `verify-upgrade-otp`, the mobile `verify-otp` screen, and the role picker's dead
CSS. Not before.

---

## 10. Test plan

Each phase ships with its own tests, and Phase 1's are the ones that matter most because both clients
depend on the backend being right.

- New Google user → account created, `emailVerified: true`, no password, session issued
- Returning Google user matched by `sub` after their Gmail address changed → same account, not a new one
- Google onto an existing password account → `409`, and **no session is issued** (the whole point)
- Link with the correct password → linked, session issued. Wrong password → 401, still not linked
- `email_verified: false` in the token payload → rejected
- Forged / expired / wrong-audience ID token → rejected
- Each of the six §4 actions by an unverified account → `403 PHONE_VERIFICATION_REQUIRED`
- Phone OTP happy path → `phoneVerified: true`, phone stored, action replays and succeeds
- 6th wrong OTP guess → burned, not accepted
- 4th send inside 15 minutes → 429
- Phone already on another account → `409`, and the other account is untouched
- First `POST /properties/add` by a verified buyer → role becomes `owner`, listing created
- `role: "owner"` in a request body → ignored completely
- Migration UP then DOWN on a copy → schema identical to the start

---

## 11. Open items

1. **Name for Google users.** Google gives a display name; we take it. If the user later edits it, that is a normal profile edit. No decision needed unless you want the name locked to Google.
2. **Profile photo.** Google returns a picture URL. Cheap to adopt as the default `profileImage`, and it makes new accounts look populated instead of empty. Worth doing, say the word.
3. **Apple Sign-In.** Not in scope. But if this app goes to the iOS App Store with Google sign-in and no Apple sign-in, App Review rejects it under Guideline 4.8. That is not a maybe. Flagging it now because it changes the iOS timeline, not the Android one.
4. **Email verification at registration.** The real fix for the D2 residual risk. Deliberately out of scope here; it deserves its own change.
