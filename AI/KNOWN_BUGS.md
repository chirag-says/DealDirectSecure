# KNOWN_BUGS.md — Verified Defects & Dead Code

Every entry below was verified by reading the code, not inferred. Each gives the exact location, the mechanism, the observable effect, and the fix.

Status is tracked per finding. Fixes are logged in [CHANGELOG_AI.md](CHANGELOG_AI.md).

Related: [SECURITY.md](SECURITY.md) · [DATABASE.md](DATABASE.md) · [CHANGELOG_AI.md](CHANGELOG_AI.md)

---

## ✅ Resolved

| ID | Resolution | Date |
|---|---|---|
| **B2** | **FIXED** — `requirePermission` removed from the 3 verification routes, reverting regression `79ae3ab`. Confirmed working in production by the owner | 2026-08-01 |
| **B17** | **NOT A BUG** — chat is hidden by explicit client decision. Backend, context, and components are intact for later re-enablement. See "Reclassified" below | 2026-08-01 |
| **B21** | **FIXED** — broken email action links (`http:///notifications`) | 2026-08-01 |
| **B22** | **FIXED** — backend had no Sentry initialisation | 2026-08-01 |
| **B6** | **FIXED** — `extractCloudinaryPublicId()` + `deletePropertyAssets()`. Verified against 5 real production URLs: old method resolved 1/5, new 5/5 | 2026-08-01 |
| **B1** | **FIXED** — four cascade field names corrected; property images now destroyed during account deletion | 2026-08-01 |
| **M5** | **WITHDRAWN — not a defect.** "Bank details stored in plaintext" assumed a live redemption flow. Verified: nothing ever wrote `bankDetails`, and the whole pre-Hubble redemption layer was unreachable. Layer since deleted | 2026-08-01 |

### Reclassified: B17 (chat not mounted)
Originally rated High on the assumption it was an accidental regression. The owner confirmed the client asked for chat to be hidden and it may return later. `ChatProvider` is intentionally absent from `ClientLayout`, and `ChatWidget`/`ChatButton` are intentionally unimported.

**Consequences that follow, and are also intentional:**
- **B3** (unescaped `lastMessage.text`) is not reachable through the UI — downgraded to Low. Still worth the one-word fix before chat returns.
- **B7** (socket JWT as bearer) — `GET /api/chat/socket-token` is still live and callable by any authenticated user, so this stands independently of the UI. Unchanged at Medium.
- `VisitModal` is unreachable (only imported by `ChatWidget`), so site-visit requests cannot be created. The Admin "Site Visit Management" page has no new data by design.
- The Admin "Reported Messages" page can receive no new reports.

**Do not "fix" B17 by mounting chat.** Re-enabling is a product decision.

---

## Severity Index (open items)

| ID | Severity | Area | One line |
|---|---|---|---|
| [B28](#b28) | **High** | Property data | Taxonomy refs on `Property` are null or point at the wrong document — every category / type filter is broken |
| [B29](#b29) | **Medium** | Property data | `priceUnit` holds its schema default on rupee-priced listings; the website's price filter and sort inflate them 100,000× |
| [B30](#b30) | **Low** | Property search | `buildingType` and `size` are read from the query but exist on no schema — sending either empties the result set |
| [B23](#b23) | **Medium** | Data retention | Deal-closure documents are never deleted by anything — **accepted risk pending client discussion** |
| [B26](#b26) | **Medium** | Data retention | Cloudinary assets orphaned by past deletions still exist — cleanup not yet run |
| [B27](#b27) | **Medium** | Account deletion | Six collections referencing a deleted user are deliberately retained — needs a product decision |
| [B3](#b3) | ~~Medium~~ **Low** | Chat | Inbox preview stores unescaped HTML — not reachable while chat is hidden |
| [B4](#b4) | **Medium** | Property visibility | `isBanned` / `isActive` filters are vacuous — fields not in schema |
| [B5](#b5) | **Medium** | Rewards | `upload_5_photos` bonus never awards — ⚠️ reachability not yet proven |
| [B7](#b7) | **Medium** | Auth | Socket JWT usable as a REST bearer token |
| [B8](#b8) | **Low** | Password reset | `PasswordResetToken` model + endpoint are dead |
| [B9](#b9) | **Low** | Frontend auth | `verifyMfa` / `changePasswordOnLogin` call endpoints that don't exist |
| [B10](#b10) | **Low** | Frontend routes | `ProtectedRoute` redirects to three non-existent routes |
| [B11](#b11) | **Low** | Rewards | Referral milestones 2 and 3 are unreachable |
| [B12](#b12) | **Low** | Rewards | `LoginTracker` collection is never written |
| [B13](#b13) | **Low** | Validation | `validatePropertyCreate` is commented out of the route |
| [B14](#b14) | **Low** | Admin search | Unescaped `RegExp` in lead search |
| [B15](#b15) | **Low** | CSRF | `fetchCsrfToken()` reads a field the server deliberately removed |
| [B16](#b16) | **Info** | Chat | Socket fallback emits a handler that was deleted server-side |
| [B18](#b18) | **Low** | Frontend | Orphaned components never imported — count now lower after the redemption removal |
| [B19](#b19) | **Low** | Client API | `propertyApi.search` sends `q`; the backend reads `search` |
| [B20](#b20) | **Low** | Client API | `notificationApi` calls `PUT` routes that don't exist (backend uses `PATCH`) |
| [B24](#b24) | **Low** | Data model | Six duplicate Mongoose index definitions logged on every boot |
| [B25](#b25) | **Info** | Email | Dead `newLead` template — the only function using it is never called |

---

<a name="b1"></a>
## B1 — `deleteAccount` cascades target wrong field names (High)

**File:** `backend/controllers/userController.js:1244-1294`

Four of the eleven cascade deletes query fields that do not exist on the target schema. Mongo matches nothing and returns `deletedCount: 0` without error.

| Line | Code | Actual schema field | Model |
|---|---|---|---|
| 1252 | `UserSession.deleteMany({ userId })` | `user` | `UserSession.js:407` |
| 1254 | `LoginTracker.deleteMany({ user: userId })` | `userId` | `LoginTracker.js:1969` |
| 1259 | `Report.deleteMany({ reporter: userId })` | `reportedBy` | `Report.js:554` |
| 1274 | `Referral.deleteMany({ …, { referredUser: userId }})` | `referred` | `Referral.js` |

**Effect.** The most serious is `UserSession`: after "permanent" account deletion, every active session document survives. The `User` document is gone, so `authMiddleware` hits the `if (!user)` branch and returns 401 — so this is not an auth bypass — but it is a data-retention failure directly contradicting the API's own response text ("all associated data have been permanently deleted"). Orphaned reports, login trackers, and half the referral graph also persist.

Note `Referral` is partially handled: the `{ referrer: userId }` half of the `$or` is correct, so referrals *made by* the user are deleted; referrals *of* the user are not.

**Fix**
```js
await UserSession.deleteMany({ user: userId });
await LoginTracker.deleteMany({ userId });
await Report.deleteMany({ reportedBy: userId });
await Referral.deleteMany({ $or: [{ referrer: userId }, { referred: userId }] });
```
Also consider a one-off cleanup script for already-orphaned documents.

---

<a name="b2"></a>
## B2 — Deal-verification endpoints are unreachable for every admin (High)

**Files:** `backend/routes/adminRoutes.js:90-92`, `backend/models/Permission.js:1703-1721`

The routes require:
```js
requirePermission("verifications:read")
requirePermission("verifications:approve")
```
But `Permission.resource` is a closed enum:
```
dashboard, users, admins, properties, leads, reports,
categories, settings, audit_logs, analytics, messages, notifications
```
`verifications` is absent. A `Permission` document with `resource: "verifications"` fails schema validation, so it cannot exist, so `admin.getPermissions()` can never return those codes, so `requirePermission` denies **every** admin — including super admins (`requirePermission` checks codes, not level).

**Effect.** `GET /api/admin/verifications`, `POST /api/admin/verifications/:id/approve`, and `.../reject` all return 403 `PERMISSION_DENIED`. The entire deal-closure → reward pipeline (see [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) §6) is blocked at step 2, so no user can ever claim a deal reward. The Admin `DealVerifications` page renders but cannot load data.

> If this feature currently works in production, then those admins are hitting the `catch` branch of `getPermissions()`, which returns `["dashboard:view"]` — that would not match either. Verify against the live database before assuming it works.

**Fix (pick one)**
1. Add `"verifications"` to the `Permission.resource` enum and seed the two Permission docs into the appropriate roles. *(preferred — preserves intent)*
2. Change the routes to an existing code, e.g. `requirePermission("properties:approve")`.
3. Replace with `requireRoleLevel(50)`.

---

<a name="b3"></a>
## B3 — Unescaped message text in the conversation preview (Medium)

**File:** `backend/controllers/chatController.js:952-974`

```js
const sanitizedText = escapeHtml(text?.substring(0, 5000));   // line 952
...
const message = new Message({ text: sanitizedText, ... });     // correct
...
conversation.lastMessage = {
  text,            // ← RAW, unescaped, unbounded
  sender: senderId,
  createdAt: new Date(),
};
```

**Effect.** `Message.text` is safe. `Conversation.lastMessage.text` stores the attacker's original string. It is returned by `GET /api/chat/conversations` and rendered in the inbox list. Also unbounded — the 5 000-char cap is applied only to the sanitized copy.

**Fix:** `text: sanitizedText`.

---

<a name="b4"></a>
## B4 — Property visibility filters test fields that don't exist (Medium)

**Files:** `backend/models/Property.js` (schema), `backend/controllers/propertyController.js:671-679, 743-747`

Public reads filter on:
```js
$or: [{ isActive: { $ne: false } }, { isActive: { $exists: false } }],
isBanned: { $ne: true },
```
Neither `isActive` nor `isBanned` is declared on `propertySchema`. Under Mongoose's default `strict: true`, writes to them are **silently discarded**, so no document ever has them. Both clauses match everything.

Additionally `approvedAt`, `approvedBy`, `disapprovedAt`, `disapprovedBy` (written by `approveProperty`/`disapproveProperty`) and `location` (GeoJSON, written by `updateMyProperty`) are also undeclared and silently dropped.

**Effect.** There is no working ban or soft-delete mechanism for properties — only `isApproved` and `status`. Admin approve/disapprove audit stamps are lost. Geo queries are impossible.

**Fix.** Decide which of these are real features, then add them to the schema. Adding `isActive`/`isBanned` changes the meaning of existing filters, so backfill existing documents (`isActive: true`, `isBanned: false`) in the same migration.

---

<a name="b5"></a>
## B5 — The 5-photo bonus never awards (Medium)

**Files:** `backend/controllers/propertyController.js:459`, `backend/services/rewardService.js:111-118`

```js
await awardPoints(req.user._id, "upload_5_photos", { propertyId: prop._id });
```
`ACTION_CATEGORY_MAP` contains: `list_property`, `mark_sold_rented`, `complete_deal`, `send_enquiry`, `referral_signup`, `report_property`. `upload_5_photos` is absent, so `awardPoints` hits:
```js
if (category === undefined) {
  console.warn(`[RewardService] Unknown action: ${action}`);
  return { success: false, error: `Unknown action: ${action}` };
}
```
The result is discarded by the caller.

**Effect.** Users listing ≥5 photos silently receive nothing. Only a console warning marks it.

**Fix:** add `upload_5_photos: null` to `ACTION_CATEGORY_MAP`, a value to `FIXED_POINTS`, and a label to `ACTION_DESCRIPTIONS` — or delete the call.

---

<a name="b6"></a>
## B6 — Owner-path Cloudinary cleanup computes the wrong `public_id` (Medium)

**File:** `backend/controllers/propertyController.js` (`deleteMyProperty`)

```js
const urlParts = imageUrl.split('/');
const publicIdWithExtension = urlParts.slice(-2).join('/');   // last TWO segments
const publicId = publicIdWithExtension.replace(/\.[^/.]+$/, '');
```
Images are uploaded to `dealdirect/properties/`, so a URL looks like:
`https://res.cloudinary.com/<cloud>/image/upload/v1234/dealdirect/properties/abc123.jpg`

The correct `public_id` is `dealdirect/properties/abc123`. `slice(-2)` yields `properties/abc123`.

The admin path (`deleteProperty`) does it correctly, slicing everything after `upload/v{version}/`.

**Effect.** `cloudinary.uploader.destroy()` silently no-ops for owner-initiated deletions. Orphaned assets accumulate and continue to be billed and publicly reachable by URL.

**Fix:** reuse the admin path's logic in both places (extract a shared `extractPublicId(url)` helper).

---

<a name="b7"></a>
## B7 — Socket JWT accepted as a REST bearer token (Medium)

**Files:** `backend/routes/chatRoutes.js:421-445`, `backend/middleware/authUser.js:554-699`

`GET /api/chat/socket-token` mints `jwt.sign({ id, purpose: 'socket_auth', iat }, JWT_SECRET, { expiresIn: '5m' })`.

`handleJWTAuth` never inspects `purpose`. Because the token has no `sessionId`, it takes the "LEGACY FALLBACK" branch, loads the user by `decoded.id`, checks blocked/inactive/password-changed, and authenticates the request.

**Effect.** A token minted for a third-party real-time layer is a valid REST credential for 5 minutes. Limited blast radius (the requester is already authenticated), but the token crosses a trust boundary it was not scoped for.

**Fix:** in `handleJWTAuth`, before anything else:
```js
if (decoded.purpose && decoded.purpose !== 'api') {
  return res.status(401).json({ success:false, message:'Invalid token', code:'INVALID_TOKEN' });
}
```

---

<a name="b8"></a>
## B8 — `PasswordResetToken` is dead code (Low)

**Files:** `backend/models/PasswordResetToken.js` (188 lines), `backend/routes/userRoutes.js:1132`

The model implements a hashed, single-use, 15-minute token with a 3-per-hour rate limit and a 5-attempt cap. `GET /api/users/reset-password/validate/:token` calls `PasswordResetToken.validateToken()`.

**Nothing ever creates one.** `forgotPassword` writes a hashed OTP to `user.resetPasswordOtp` instead — fields the `User` schema itself labels "Deprecated… kept for migration compatibility."

**Effect.** The validate endpoint always returns `{valid: false}`. 188 lines of better-designed code sit unused while the live path uses the deprecated fields.

**Fix:** either migrate `forgotPassword`/`resetPassword` onto the token model (a real improvement — it has proper rate limiting), or delete the model, the route, and the controller function.

---

<a name="b9"></a>
## B9 — Frontend calls two non-existent user endpoints (Low)

**File:** `client-next/src/context/AuthContext.jsx`

```js
await api.post('/users/verify-mfa', {...});                 // verifyMfa()
await api.post('/users/change-password-required', {...});   // changePasswordOnLogin()
```
Neither route exists in `backend/routes/userRoutes.js` (verified by grep across `routes/` and `controllers/`). **End users have no MFA at all** — MFA is admin-only.

**Effect.** Both would 404. Unreachable in practice: `requiresMfa` / `requiresPasswordChange` are only set when a login response contains `requiresMfa` or `passwordChangeRequired`, and `loginUser` never returns either. This is admin-flow logic copy-pasted into the user context.

**Fix:** delete `verifyMfa`, `changePasswordOnLogin`, `cancelPendingAuth`, `requiresMfa`, `requiresPasswordChange`, and `pendingAuthData` from `AuthContext`, plus the corresponding branches in `login()` and `register()`. Roughly 150 lines.

---

<a name="b10"></a>
## B10 — `ProtectedRoute` redirects to routes that don't exist (Low)

**File:** `client-next/src/context/AuthContext.jsx` (`ProtectedRoute`)

Redirect targets `/verify-mfa`, `/change-password-required`, and `/verify-email` have no directory under `src/app/`. Each would render the 404 page.

Unreachable for the same reason as B9 (`requiresMfa`/`requiresPasswordChange` never become true), except `/verify-email`, which fires whenever `requireVerified` is passed and the user is unverified. **No current caller passes `requireVerified`**, so it is dormant rather than broken — but it will break the moment someone uses that prop.

**Fix:** remove with B9; for `requireVerified`, redirect somewhere real or build the page.

---

<a name="b11"></a>
## B11 — Referral milestones 2 and 3 are unreachable (Low)

**File:** `backend/services/rewardService.js:472-520`

`handleReferralMilestone` supports `signup`, `first_action`, `deal_closure`. Only `createReferralFromCode` calls it, always with `'signup'`.

Even if wired, the other two would fail: they map to actions `referral_first_action` and `referral_deal_closure`, neither of which is in `ACTION_CATEGORY_MAP` — so `awardPoints` would return `{success: false}` and the milestone flag would never be set (the flag is only written when `result.success`).

Supporting dead structures: `Referral.firstActionPointsAwarded`, `dealClosurePointsAwarded` (+ date fields), `User.hasCompletedFirstAction`, and the `firstActions`/`dealClosures` counters in `getReferralStats` (always 0).

**Fix:** either implement — add both actions to the maps and call `handleReferralMilestone(userId, 'first_action')` from `markInterested`/`addProperty` and `'deal_closure'` from `claimDealReward` — or remove the dead branches.

---

<a name="b12"></a>
## B12 — `LoginTracker` is never written (Low)

**Files:** `backend/models/LoginTracker.js`, `backend/services/rewardService.js:612-630`

The model exists for the documented "log in 15+ days in a month → 100 pts" rule, with a unique `{userId, month}` index and a `rewardAwarded` flag. `trackDailyLogin` instead writes to `Reward.monthlyLoginDays` (a `Map`) and `Reward.lastLoginDate`, and its own doc comment concedes it "does not award points in current model."

**Effect.** The collection is always empty. The monthly-login reward is not implemented anywhere. `deleteAccount` tries to clean this collection (with the wrong field name — see B1), compounding the confusion.

**Fix:** implement the streak against `Reward.monthlyLoginDays` (the data is already there) and delete `LoginTracker`, or implement it properly against `LoginTracker` and stop dual-writing.

---

<a name="b13"></a>
## B13 — `validatePropertyCreate` is commented out (Low)

**File:** `backend/routes/propertyRoutes.js:73`

```js
// validatePropertyCreate, // TODO: Re-enable after fixing field whitelist
```
Still imported at line 34.

**Effect.** `POST /api/properties/add` has no express-validator layer — no length caps on title/description, no numeric coercion of `price`, no `listingType` enum check. The controller's own `sanitizePropertyData` whitelist still runs, so mass assignment is blocked; what is lost is **value** validation.

Note the two whitelists genuinely disagree — `validators/index.js` `PROPERTY_CREATE_FIELDS` and `propertyController` `PROPERTY_ALLOWED_FIELDS` list different names — which is presumably the "field whitelist" the TODO refers to. Re-enabling without reconciling them will drop fields the form sends.

**Fix:** reconcile the two lists into one exported constant, then re-enable.

---

<a name="b14"></a>
## B14 — Unescaped `RegExp` in admin lead search (Low)

**File:** `backend/controllers/leadController.js:552`

```js
const searchRegex = new RegExp(search, 'i');
```
Every other search path in the codebase escapes first (`escapeRegExp` in `propertyController`, manual escaping in `getAuditLogs`). This one does not.

**Effect.** ReDoS via `GET /api/admin/leads?search=...`. Admin-authenticated only.

**Fix:** apply the same escaping. Consider extracting `escapeRegExp` into `utils/` so all four call sites share one implementation.

---

<a name="b15"></a>
## B15 — `fetchCsrfToken()` reads a deliberately removed field (Low)

**Files:** `client-next/src/utils/api.js:91-100`, `backend/middleware/csrfProtection.js:97-114`

The client does `return response.data.csrfToken;`. The server's handler has an explicit `SECURITY FIX` comment removing that field from the body — the token is only delivered via the cookie.

**Effect.** `fetchCsrfToken()` always resolves `undefined`. Harmless in practice: the request interceptor reads the cookie directly and never uses this return value. Misleading to a future reader.

**Fix:** change it to return a boolean, or delete it.

---

<a name="b16"></a>
## B16 — Socket fallback emits a removed handler (Info)

**File:** `client-next/src/context/ChatContext.jsx`

```js
} catch (error) {
  // Fallback: Try with user ID for backward compatibility
  if (user._id) newSocket.emit("user_online", user._id);
}
```
`server.js:526` states the `user_online` handler was **removed** as a security fix (it trusted a client-supplied user id).

**Effect.** If `GET /api/chat/socket-token` fails, the fallback silently does nothing and the socket stays unauthenticated — no error surfaces to the user, chat just doesn't work.

**Fix:** replace the fallback with a user-visible error state.

---

<a name="b17"></a>
## B17 — The chat feature is fully built but unreachable in the web UI (High)

**Files:** `client-next/src/components/Chat/ChatWidget.jsx` (581), `ChatButton.jsx` (39), `src/context/ChatContext.jsx` (369)

Verified by grep across all of `client-next/src`:
- `ChatProvider` is **never mounted**. `ClientLayout.jsx` wraps the app in `AuthProvider` only.
- `ChatWidget` and `ChatButton` are **never imported** by any page or layout.
- `useChat()` is called only from those two orphaned components — so if either were rendered today it would immediately throw `"useChat must be used within a ChatProvider"`.
- There is no `/chat` route under `src/app/`.

**Effect.** A complete, working feature is dead on the public site:

| Layer | State |
|---|---|
| `Conversation` + `Message` models | built |
| `chatController.js` (296 L) + `chatRoutes.js` | built, mounted at `/api/chat` |
| Socket.IO server, JWT auth, room authorization (`server.js`) | built |
| `ChatContext` (369 L) | built |
| `ChatWidget` + `ChatButton` (620 L) | built |
| **Mounted in the UI** | **no** |

Downstream consequences: buyers and owners have no in-app messaging; the site-visit flow (`VisitModal` → `visit_request` message) is unreachable because `VisitModal` is only imported by `ChatWidget`; message reporting is unreachable, so the Admin "Reported Messages" page can only ever show data created before this regression (or none at all).

**Fix.** Two lines in `ClientLayout.jsx`:
```jsx
import { ChatProvider } from '../context/ChatContext';
import ChatButton from '../components/Chat/ChatButton';
import ChatWidget from '../components/Chat/ChatWidget';

<AuthProvider>
  <ChatProvider>
    {/* …existing tree… */}
    <ChatButton />
    <ChatWidget />
  </ChatProvider>
</AuthProvider>
```
Before doing this, confirm with the product owner that chat was not **deliberately** disabled — a 950-line feature does not usually get unmounted by accident, and there is no comment explaining it. Check git history for the commit that removed the mount.

---

<a name="b18"></a>
## B18 — Seven orphaned components (~2 900 lines) (Low)

Verified by grep for imports across `client-next/src`:

| Component | ~L | Note |
|---|---|---|
| `components/SampleAgreement/AgreementGenerator.jsx` | 1282 | **Duplicate.** `app/agreements/AgreementsContent.jsx` defines its own `AgreementGenerator` inline. Two divergent copies of the agreement UI |
| `components/Chat/ChatWidget.jsx` | 581 | See B17 |
| `components/LogoLoop/LogoLoop.jsx` + `.css` | 321 + 183 | **Duplicate.** `TopLocalities.jsx` defines its own internal `LogoLoop` |
| `components/AuthModal/AuthModal.jsx` | 487 | Superseded by the `/login` and `/register` routes |
| `components/Navbar/MegaMenu.jsx` | 216 | `Navbar.jsx` does not import it |
| `components/Navbar/CityDropdown.jsx` | 171 | Same |
| `components/HeroSection/HeroSection_omnibox.jsx` | 358 | Alternate hero; `HomeContent` imports `HeroSection.jsx` |
| `components/Chat/ChatButton.jsx` | 39 | See B17 |
| `components/MiddelSection.jsx` + `MiddelComp.jsx` | 41 + 32 | Unused |
| `components/Property/PropertyFilter.jsx` | 65 | Unused |
| `components/SampleAgreement/SampleAgreement.jsx` | 198 | Unused |

**Effect.** Dead code inflates the repository and, worse, creates ambiguity: a future editor may fix a bug in `components/SampleAgreement/AgreementGenerator.jsx` and see no change, because the live copy is inside `AgreementsContent.jsx`. Tree-shaking keeps them out of the bundle, so there is no runtime cost.

**Fix.** Delete after resolving B17 (which un-orphans two of them). The two duplicate pairs — `AgreementGenerator` and `LogoLoop` — should be reconciled into one implementation each rather than simply deleted, since the orphaned copy may be the better one.

---

<a name="b19"></a>
## B19 — `propertyApi.search()` sends the wrong query parameter (Low)

**Files:** `client-next/src/utils/api.js:343-347`, `backend/controllers/propertyController.js` (`searchProperties`)

```js
search: async (query) => {
  const response = await api.get('/properties/search', { params: { q: query } });
  return response.data;
},
```
`searchProperties` destructures `const { search, category, ... } = req.query`. It never reads `q`. `getSuggestions` is the endpoint that reads `q`.

**Effect.** The helper performs an **unfiltered** search — the backend receives no search term and returns the first page of everything. Silent: the caller gets a 200 with plausible-looking results.

Not currently user-visible, because the property list screens build their query strings directly rather than going through this helper. It is a trap for the next person who uses it.

*Independently identified in `MOBILE_APP_ARCHITECTURE_PLAN.md` §0, which instructs the mobile app to send `search` and explicitly warns against "fixing" the backend to accept `q`.*

**Fix:** `params: { search: query }`.

---

<a name="b20"></a>
## B20 — `notificationApi` calls non-existent routes (Low)

**Files:** `client-next/src/utils/api.js:417-433`, `backend/routes/notificationRoutes.js`

| Client call | Backend route |
|---|---|
| `PUT /notifications/:id/read` | `PATCH /notifications/:id/read` |
| `PUT /notifications/read-all` | `PATCH /notifications/mark-all/read` |

Both differ in **method**, and the second also differs in **path**.

**Effect.** Both would 404 → `notFoundHandler` → `AppError('Resource not found', 404)`. Not user-visible today because `NotificationsContent.jsx` calls the endpoints directly rather than through these helpers.

**Fix:** change to `api.patch('/notifications/${id}/read')` and `api.patch('/notifications/mark-all/read')`.

> B19 and B20 share a root cause: `utils/api.js` is a 758-line helper layer that has drifted out of sync with the routes, while the screens bypass it. Either bring the helpers back in line and route all calls through them, or delete the stale ones. Leaving both in place guarantees the next drift.

---

<a name="b26"></a>
## B26 — Cloudinary assets orphaned by past deletions (Medium)

[B6](#b6) is fixed going forward, but every property deleted **before** 2026-08-01 left its images on Cloudinary. Those URLs remain publicly reachable and continue to consume storage quota.

Two sources:
- **Owner deletions** (`deleteMyProperty`) — the `slice(-2)` bug meant `destroy()` never matched. Verified: 4 of 5 sampled URLs resolved only with the corrected derivation.
- **Admin deletions** (`deleteProperty`) — only walked `property.images`, never the `categorizedImages` buckets, so categorised images were always orphaned.
- **Account deletions** — `Property.deleteMany()` removed the records with no asset cleanup at all.

**Fix:** a reconciliation script — list assets under `dealdirect/properties` via the Cloudinary Admin API, collect every URL still referenced by a `Property` document, and destroy the difference.

⚠️ **Must be dry-run first.** A bug in the "still referenced" query would delete live images. Also account for assets referenced from `Project.media`, `UnitType.photos`, `Builder.logoUrl`, and `Blog.coverImage`, which live in different folders but must not be caught by a broad sweep.

---

<a name="b27"></a>
## B27 — Six collections are retained on account deletion (Medium — **needs product decision**)

`deleteAccount` now correctly removes properties (with assets), sessions, tokens, login trackers, inquiries, saved searches, reports, notifications, messages, rewards, and referrals.

It deliberately does **not** touch these, because each also belongs to a counterparty or forms a financial/legal record:

| Collection | Why it is retained |
|---|---|
| `Lead` | Appears in the property **owner's** lead list |
| `Agreement` | Signed legal document binding two parties |
| `TransactionVerification` | Deal proof + its Cloudinary documents (see [B23](#b23)) |
| `RedemptionRequest` | Payout record, may be mid-processing |
| `CampaignMember` | Group-buy commitment; deleting skews campaign counters |
| `ProjectBooking` | Booking + payment record held by the admin |

Each carries a `userSnapshot` with name, email, and phone, so **personal data survives account deletion** in all six.

**Options per collection:** delete · anonymise (strip `userSnapshot`, null the ref) · retain for a defined period. Anonymising is usually right for the counterparty-facing ones — the owner keeps a usable lead history without retaining a deleted user's contact details.

Explicitly flagged in a comment block in `userController.deleteAccount`.

---

<a name="b23"></a>
## B23 — Deal-closure documents are never deleted (Medium — **accepted risk**)

**Files:** `backend/models/TransactionVerification.js`, `backend/middleware/documentUpload.js`, `backend/controllers/propertyController.js` (`closeDeal`, `deleteMyProperty`), `backend/controllers/userController.js` (`deleteAccount`)

When an owner closes a deal they upload proof documents — in practice sale deeds, rental agreements, and identity documents. These are uploaded to Cloudinary under `dealdirect/deal-documents` with `resource_type: "raw"` for PDFs, producing **public, permanent URLs** stored in `TransactionVerification.documentUrls[]`.

**Nothing ever deletes them.** Not deal rejection, not property deletion, not account deletion, not admin action. There is no cleanup path anywhere in the codebase.

**Effect.** Personal legal documents remain publicly retrievable by URL indefinitely, including after the user deletes the property and their account. Combined with [B1](#b1) and [B6](#b6), a user who deletes everything still leaves photos, proof documents, sessions, and reports behind. Relevant to India's DPDP Act data-retention expectations.

**Status: accepted risk, 2026-08-01.** The owner is discussing handling with the client before any change. Mitigating factor: Cloudinary URLs contain random public IDs and are not enumerable.

**When revisited, the options are:**
1. Delete documents on deal rejection and on property/account deletion.
2. Move to Cloudinary **signed/private** delivery so retrieval requires a backend-generated, time-limited URL. Requires changing how the Admin panel displays them.
3. Both — appropriate for documents containing personal data.

---

<a name="b24"></a>
## B24 — Six duplicate Mongoose index definitions (Low)

Every boot logs:
```
[MONGOOSE] Warning: Duplicate schema index on {"email":1} found …
[MONGOOSE] Warning: Duplicate schema index on {"referralCode":1} found …
[MONGOOSE] Warning: Duplicate schema index on {"expiresAt":1} found …
[MONGOOSE] Warning: Duplicate schema index on {"name":1} found …
[MONGOOSE] Warning: Duplicate schema index on {"email":1} found …
[MONGOOSE] Warning: Duplicate schema index on {"expiresAt":1} found …
```

Cause: the same field declares an index **twice** — once inline (`unique: true` or `index: true` on the field) and again via an explicit `schema.index()` call. Affected: `userModel` (`email`, `referralCode`), `UserSession` (`expiresAt`), `AdminSession` (`expiresAt`), `Admin` (`email`), and `Role` (`name`).

**Effect.** Harmless at runtime — Mongo creates one index. But six warnings on every boot train you to ignore startup output, which is where real problems also appear.

**Fix:** remove the redundant declaration in each pair, keeping whichever expresses the intent better (usually the explicit `schema.index()` when options like `sparse`/`unique` are involved).

---

<a name="b25"></a>
## B25 — Dead `newLead` email template (Info)

`utils/emailService.js` defines a purpose-built `newLead` template with a property card and lead details. The only function that uses it, `leadController.createLead`, is **never called** — `createLead` appears solely inside a comment at `leadController.js:650`. `propertyController.markInterested` creates the `Lead` inline instead.

**Effect.** Owners *are* notified of new leads, but through the generic `generalNotification` template (via the `Notification` post-save hook) rather than the designed one. The better-looking template is dead code.

**Fix:** either call `createLead` from `markInterested`, or delete `createLead` + `sendNewLeadNotification` + the `newLead` template.

---

<a name="b28"></a>
## B28 — `Property` taxonomy refs are null or wrong in production (High)

**Files:** `backend/models/Property.js` (`category`, `subcategory`, `propertyType`), `backend/controllers/propertyController.js:1811` (`searchProperties`)

Found 2026-08-03 while building the mobile search filters. This one is **data, not code** — the filters are written correctly and the schema is sound. Verified against `https://backend.dealdirect.in`, 36 approved listings:

| Check | Result |
|---|---|
| Listings where `category` / `subcategory` / `propertyType` come back `null` | **15 of 36**, despite the controller populating all three |
| The other 21 | all carry the **same** `propertyType` id — the one named **"Plot"** — while their own `propertyTypeName` reads "Apartment / Flat", "Penthouse", "Villa" |
| `?propertyType=<Residential>` | **0** results |
| `?propertyType=<Commercial>` | **0** results |
| `?propertyType=<Plot>` | **21** results, none of which are plots |
| All 19 categories probed individually | only 2 match anything: "Residential Plot" → 17, "Commercial Land" → 4, both wrong |

**Effect.** Every ObjectId-based property filter is broken for every client. A user filtering by "Apartment" gets an empty list, which reads as "no apartments listed" rather than "this filter does not work". The denormalised `categoryName` and `propertyTypeName` columns are **correct on all 36 rows**, so the display is fine — only filtering is affected.

**Fix.** Backfill `category` / `subcategory` / `propertyType` from the denormalised name columns, then find and fix whatever write path sets them wrong (the add-property flow is the place to start, since the corruption is consistent rather than random). No client change is needed once the data is right.

**Until then.** The mobile app ships no category or property-type filter, deliberately. Do not add one to any client.

---

<a name="b29"></a>
## B29 — `priceUnit` holds its schema default on rupee-priced listings (Medium)

**Files:** `backend/models/Property.js:23`, `client-next/src/app/properties/PropertyListContent.jsx:254`, `client-next/src/app/HomeContent.jsx:79`

`priceUnit` defaults to `"Lac"` and nothing overwrites it on most listings, so it records the default rather than the unit. On the live corpus, 15 of 36 listings carry `priceUnit: "Lac"` alongside a plainly rupee-scale `price` (65000, 17800000, 36000, 225000). `price` is rupees.

The website's `normalizePrice(price, unit)` multiplies by 1e5 whenever the unit contains "lac" or "lakh". It is used in exactly two places, both on the website: the client-side **price-range filter** and the **price sort**.

**Effect.** On the live site, "Under ₹50 Lakh" evaluates a ₹36,000 rental as ₹36 crore and excludes it. Price sorting orders those rows as if they were 100,000× more expensive. **Display is unaffected** — display calls `formatPrice(property.price)`, which correctly treats the value as rupees and never consults `priceUnit`.

**Fix.** Either stop writing a default for `priceUnit` and backfill it to something truthful, or delete `normalizePrice` from the website and filter on the raw rupee value the way `formatPrice` already displays it. The second is a two-line change and fixes the visible symptom immediately.

**Mobile:** treats `price` as rupees everywhere. See `dealdirect-mobile/src/ui/PriceLabel.tsx`.

---

<a name="b30"></a>
## B30 — `buildingType` and `size` filter on fields that do not exist (Low)

**File:** `backend/controllers/propertyController.js:1840-1841`

`searchProperties` reads `buildingType` and `size` from the query and writes both straight into the Mongo filter. Neither field is on `propertySchema`. Mongoose 8 defaults `strictQuery` to `false`, so both unknown paths reach MongoDB and match zero documents.

**Effect.** Any client sending either param gets an empty result set with no error. Nothing sends them today, so this is latent rather than live.

**Fix.** Delete both from the destructure and the filter, or add the fields to the schema if they were intended. Deleting is the honest option — nothing writes them.

---

## Cross-Cutting Notes

**Inconsistent success envelopes.** `GET /api/properties/list` returns a **bare array**; almost everything else returns `{success, data}`. Frontend code compensates with `res.data?.data || res.data || []` in several places. Not a bug, but a recurring source of them.

**Two `requireOwnership` implementations** exist (`authUser.js` and `roleGuard.js`) with different signatures. Neither is used by any route — controllers check ownership inline. Pick one, use it, delete the other.

**`server.js` line 733 / `adminController.js`:** several `catch` blocks contain `message: 'An unexpected error occurred' || "Failed to …"` — the `||` is dead since the left operand is always truthy. Cosmetic.

**No test suite.** `backend/package.json` → `"test": "echo \"Error: no test specified\" && exit 1"`. There are no test files in any of the four applications. Every fix above must be verified manually.
