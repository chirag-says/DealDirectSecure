# API_REFERENCE.md — Complete Endpoint Reference

Base URL: `https://backend.dealdirect.in` (prod) · `http://localhost:9000` (dev)
All routes are mounted under `/api/*` except `/`, `/ping`, `/health`, `/api/health`.

**Auth legend**
| Symbol | Meaning |
|---|---|
| 🌐 | Public — no auth |
| 🔒 | `authMiddleware` — valid `user_session` cookie (or Bearer fallback) |
| 👑 | `protectAdmin` — valid `admin_session` **and** `mfaVerified` |
| 👁 | `attachAdminIfPresent` — public, but an admin sees more |
| 🔑 | Shared-secret header (`X-Hubble-Secret`) or HMAC signature |

Related: [AUTH_SYSTEM.md](AUTH_SYSTEM.md) · [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) · [DATABASE.md](DATABASE.md)

---

## Conventions

**Success shape** is inconsistent across the codebase. Three forms exist:
```jsonc
{ "success": true, "data": [...] }          // most endpoints
{ "success": true, "properties": [...] }    // some named-key endpoints
[ ... ]                                     // GET /api/properties/list returns a BARE ARRAY
```
Always check the specific endpoint below. `GET /api/properties/list` returning a bare array is the most common source of frontend bugs.

## CSRF protection (Phase 1, since 2026-08-01)

15 routes require **both** a whitelisted `Origin` header **and** a matching `X-CSRF-Token` header / `csrf_token` cookie pair. Both browser clients send this automatically via their axios interceptors.

`/api/rewards/redeem` · `/api/rewards/admin/adjust-points` · `PUT /api/rewards/admin/redemptions/:id` · `/api/properties/add` · `PUT /api/properties/my-properties/:id` · `/api/properties/admin/add` · `PUT /api/properties/edit/:id` · `/api/properties/interested/:id` · `/api/properties/:id/report` · `/api/campaigns/:id/join` · `/api/campaigns/:id/exit` · `/api/contact` · `/api/chat/message/send` · `/api/chat/conversation/start`

Failure codes: `CSRF_ORIGIN_REJECTED`, `CSRF_MISSING_COOKIE`, `CSRF_MISSING_HEADER`, `CSRF_TOKEN_MISMATCH` — all 403.

Requests **without** an `Origin` header (mobile app, Next.js SSR, webhooks) bypass the check by design — CSRF is browser-only. Set `CSRF_ENFORCE=false` to disable entirely. The protected list lives in `server.js`, not in route files.

> **`/api/agreements/*` is unmounted** (client decision, 2026-08-01) — every agreement endpoint returns 404. The section below is retained for restoration.

**Error shape** (from `globalErrorHandler`):
```jsonc
{ "success": false, "message": "<generic>", "code": "<CODE>", "requestId": "<id>" }
```
Messages are aggressively genericised in **all** environments. `requestId` matches the `X-Request-ID` response header and the server log line.

---

## Health & Meta

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/ping` | 🌐 | `{pong:true, time}`. Registered before all middleware |
| GET | `/health` · `/api/health` | 🌐 | Skipped by the global rate limiter |
| GET | `/` | 🌐 | API name/version/dbStatus |
| GET | `/debug-startup` | 🌐 | **Non-production only.** Env presence flags, cwd, node version |
| GET | `/api/csrf-token` | 🌐 | Sets `csrf_token` cookie. Deliberately does **not** return the token in the body |

---

## Users — `/api/users`
Controller `userController.js` · Routes `userRoutes.js`

### Public (all rate-limited: `authRateLimit` 10/15min + `authLimiter` 5/15min)

| Method | Path | Body | Returns / Notes |
|---|---|---|---|
| POST | `/register` | `{name, email, password, phone, role?, referralCode?}` | 200 `{email}`. **Sends OTP by SMS; 500 if SMS unconfigured.** No session issued. 20 kB body cap |
| POST | `/register-direct` | `{name, email, password, phone?}` | 201 `{user}` + session cookie. Role forced to `user`. Deletes any existing unverified user with that email |
| POST | `/verify-otp` | `{email, otp, referralCode?}` | 201 `{user}` + session. Sets `isVerified`, creates wallet, applies referral, fires WhatsApp + welcome email |
| POST | `/resend-otp` | `{email}` | 200. Requires `user.phone` and configured SMS |
| POST | `/login` | `{email, password}` | 200 `{user}` + session. 10 kB cap. 423 locked · 403 blocked · 400 unverified · 401 generic |
| POST | `/forgot-password` | `{phone}` or `{email}` | 200. **404 if no account — leaks existence.** 60 s cooldown. Sends OTP by SMS |
| POST | `/reset-password` | `{phone\|email, otp, newPassword}` | 200. Revokes **all** sessions. Also sets `isVerified = true` |
| GET | `/reset-password/validate/:token` | — | **Dead endpoint** — no code ever creates a `PasswordResetToken` |

### Authenticated

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/logout` | 🔒 | Revokes current session, clears both cookies |
| POST | `/logout-all` | 🔒 | Revokes every session for the user |
| GET | `/sessions` | 🔒 | Active sessions with `isCurrent` flag |
| DELETE | `/sessions/:sessionId` | 🔒 | Ownership verified before revoke |
| GET | `/profile` · `/me` | 🔒 | Identical handlers. `/me` is what the frontend polls |
| PUT | `/profile` | 🔒 | multipart. `validateProfileUpdate` whitelists 8 fields; `profileImage` goes through magic-byte validation → Cloudinary |
| PUT | `/change-password` | 🔒 | Revokes **other** sessions, keeps current |
| DELETE | `/me` | 🔒 | Cascade delete — **four of the cascades target wrong field names**, see [KNOWN_BUGS.md](KNOWN_BUGS.md) |
| POST | `/send-upgrade-otp` | 🔒 + verified | Buyer → owner. 400 if already owner |
| POST | `/verify-upgrade-otp` | 🔒 + verified | Sets `role = 'owner'` |
| POST | `/add-property` | 🔒 + verified + role owner | **Legacy.** Uses local disk storage (`uploads/`), not Cloudinary. Prefer `/api/properties/add` |

### Admin

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/list?role=` | 👑 | `role=Buyer` maps to `role: "user"` |
| PUT | `/block/:id` | 👑 | Toggle. Blocking revokes all that user's sessions |
| GET | `/owners-projects` | 👑 | Owners joined with their properties |
| GET | `/export-csv` · `/export-pdf` | 👑 | Buyers (`role: "user"`) |
| GET | `/export-owners-csv` · `/export-owners-pdf` | 👑 | Owners |

---

## Properties — `/api/properties`
Controller `propertyController.js` (2 396 lines) · Routes `propertyRoutes.js`

> **Route order matters.** `/search`, `/suggestions`, `/filter`, `/my-properties`, `/saved`, `/admin/*` are all declared **before** `/:id`. Adding a new literal path after `/:id` will be shadowed.

### Public

| Method | Path | Query | Returns |
|---|---|---|---|
| GET | `/list` | `isBuilderProperty`, `limit` | **BARE ARRAY.** Filters: `isApproved:true`, not banned/inactive, status not in rejected/suspended/draft/pending, and builder-null unless `isBuilderProperty=true` |
| GET | `/property-list` | — | `{success, data[]}`. Approved + owner-only (builder excluded) |
| GET | `/search` | `search, category, subcategory, propertyType, buildingType, size, city, priceFrom, priceTo, page=1, limit=12, sort=newest\|priceAsc\|priceDesc` | `{data, total, page, pages}`. Rate limited 20/min. Regex is escaped against ReDoS |
| GET | `/suggestions` | `q` (min 2 chars) | `{suggestions[≤8]}` — `$facet` over titles / localities / cities. Rate limited 20/min |
| GET | `/filter` | `search, sort` | `{success, data}`. **No pagination — loads the full result set, then filters populated fields in JS** |
| GET | `/:id` | — | Single property. 404 (not 403) if unapproved/banned/inactive — existence is not revealed. **Increments `views` on every call** |

### Authenticated

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/my-properties` | 🔒 | Populates `interestedUsers.user` |
| POST | `/add` | 🔒 + `ownerOnlyListingAccess` | multipart: `images` ≤15, `categorizedImages` ≤50. Runs inside a **MongoDB transaction** enforcing one-listing-per-owner. Auto-approved. Fans out saved-search notifications + rewards + WhatsApp. `validatePropertyCreate` is **commented out** in the route |
| PUT | `/my-properties/:id` | 🔒 + owner | Rebuilds the flat `images[]` from `categorizedImages`. Ownership checked by `findOne({_id, owner})` |
| DELETE | `/:id` | 🔒 | `deleteMyProperty` — owner-scoped; also destroys Cloudinary assets |
| GET | `/saved` | 🔒 | Properties where the user is in `interestedUsers` |
| DELETE | `/saved/:id` | 🔒 | `$pull` + `$inc likes: -1` |
| POST | `/interested/:id` | 🔒 | **Max 5 per buyer.** Creates Lead + Notification + WhatsApp + reward. See [ARCHITECTURE.md](ARCHITECTURE.md) §9 |
| GET | `/interested/:id/check` | 🔒 | `{isInterested}` |
| DELETE | `/interested/:id` | 🔒 | Removes interest |
| POST | `/:id/report` | 🔒 | `{reason}` 10–1000 chars. Blocks duplicate active reports. Awards 100 pts |
| POST | `/:id/close-deal` | 🔒 owner | multipart `documents` ≤5 (PDF/images → Cloudinary `raw` for PDFs). `{buyerId, closingType: sold\|rented}`. Buyer must be in `interestedUsers`. Sets property `pending_verification` |
| POST | `/claim-deal-reward/:verificationId` | 🔒 | Only after admin approval. **Rolls the random reward at claim time.** Idempotent via `ownerClaimed`/`buyerClaimed` |

### Admin

| Method | Path | Notes |
|---|---|---|
| GET | `/admin/all` | 👑 `search, status(listed\|rejected), startDate, endDate, hasBuilder, builderId` |
| POST | `/admin/add` | 👑 `addPropertyForBuilder` — requires `builderId`; sets `owner: null` |
| PUT | `/edit/:id` | 👑 Whitelist-sanitized update |
| DELETE | `/delete/:id` | 👑 Also destroys Cloudinary images |
| PUT | `/approve/:id` | 👑 Clears `rejectionReason` |
| PUT | `/disapprove/:id` | 👑 **Requires** `rejectionReason` or `reason` |

---

## Leads — `/api/leads`
All routes 🔒. Owner-scoped; every mutation re-checks `lead.propertyOwner` against `req.user._id` (IDOR guard).

| Method | Path | Notes |
|---|---|---|
| GET | `/` | `status, property, page, limit, sort, startDate, endDate`. Returns `data`, `stats` (per status + `today`), `pagination`. Status is whitelist-validated against NoSQL operator injection |
| GET | `/analytics` | `days=30`. Status breakdown, daily series, top-10 properties, conversion rate, unread count |
| GET | `/export` | XLSX of the **last 3 months**, via ExcelJS. 404 if empty |
| GET | `/property/:propertyId` | 403 unless the caller owns the property |
| PUT | `/:id/status` | `{status, notes}` — status must be in the 6-value enum, notes capped at 2000 |
| PUT | `/:id/viewed` | Sets `isViewed` + `viewedAt` |
| POST | `/:id/contact` | `{action, note}` → pushes `contactHistory` **and forces `status: 'contacted'`** |

Admin equivalents live at `GET /api/admin/leads` and `PUT /api/admin/leads/:id`.

---

## Chat — `/api/chat`
All routes 🔒 (`router.use(authMiddleware)`).

| Method | Path | Notes |
|---|---|---|
| GET | `/socket-token` | JWT `{id, purpose:'socket_auth'}`, **5-minute** expiry. Required before any socket action |
| POST | `/conversation/start` | `{propertyId}` only. **`ownerId` is never accepted from the client** — derived from the property. 400 on self-chat |
| GET | `/conversations` | Adds `otherParticipant`, `myUnreadCount`, `isOwner` |
| GET | `/messages/:conversationId` | `page, limit=50`. Participant check → marks read → resets that user's unread counter |
| POST | `/message/send` | `{conversationId, text, messageType}`. Text HTML-escaped and capped at 5000. ⚠️ `conversation.lastMessage.text` stores the **unescaped** original |
| GET | `/unread-count` | Sum across conversations |
| DELETE | `/conversation/:conversationId` | Soft archive (`isActive = false`) |

**Socket.IO events** (same HTTP server, not under `/api`): `authenticate` → `authenticated`/`auth_error`; `join_conversation` (verifies participation) → `error`; `send_message` (relay only, no persistence); `typing`/`stop_typing`; `users_online` broadcast; `disconnect`.

---

## Agreements — `/api/agreements`
Body limit 50 kB. `/generate` additionally rate-limited to **20/hour**.

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/templates` | 🌐 | Static template metadata |
| GET | `/states` | 🌐 | Indian states list |
| POST | `/webhook/payment` | 🔑 | HMAC `sha256(agreementId\|transactionId\|amount)` in `signature`, verified with `timingSafeEqual`. **Verification is skipped entirely when `PAYMENT_WEBHOOK_SECRET` is unset.** Idempotent by `transactionId`. Amount must match rent or deposit within ₹0.01 or the payment is recorded as `fraud_suspected` and a critical AuditLog entry is written. Rate limited 30/min |
| GET | `/admin/all` | 👑 | All agreements |
| POST | `/generate` | 🔒 owner\|user | See below |
| GET | `/my-agreements` | 🔒 | Only where caller is owner or buyer |
| GET | `/:id` | 🔒 | IDOR-guarded by `isPartyToAgreement` |
| POST | `/:id/sign` | 🔒 | Verifies `contentHash` before accepting a signature; refuses a modified document. Records IP + User-Agent. Advances status |

### `POST /generate`
```jsonc
{
  "propertyId": "…",          // required
  "buyerId": "…",             // required when the caller is the owner
  "landlordName": "…", "landlordAge": 40, "landlordAddress": "…",
  "landlordPhone": "…", "landlordAadhaar": "…",   // only last 4 digits stored
  "tenantName": "…", "tenantAge": 30, "tenantAddress": "…",
  "tenantPhone": "…", "tenantAadhaar": "…",
  "startDate": "2026-08-01",
  "durationMonths": 11, "noticePeriod": 1, "rentDueDay": 5,
  "additionalTerms": "…"      // sanitized against prompt injection
}
```
Server behaviour:
- **All money comes from the Property document**, never the request: `rentAmount = property.price`, `securityDeposit = property.securityDeposit || property.deposit || rent × 2`.
- Ownership is enforced: an owner may only generate for their own property; a buyer is always the buyer.
- `additionalTerms` runs through ~25 prompt-injection regexes plus a dangerous-character strip. A match returns 400 `INVALID_TERMS`.
- Generation uses **Gemini `gemini-2.0-flash`** with an immutable `systemInstruction` and user terms wrapped in `<user_additional_terms>` XML tags marked as data-only. **Any AI failure silently falls back to `buildLocalAgreement()`**, a hand-written template — so the endpoint works with no `GEMINI_API_KEY`.
- Maharashtra → `LEAVE_AND_LICENSE` (Licensor/Licensee); all other states → `RENTAL_AGREEMENT` (Lessor/Lessee).
- Idempotency: `sha256(property-owner-buyer)`. A non-terminal existing agreement returns 200 `{isDuplicate: true}`.

---

## Rewards — `/api/rewards`

| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/store` | 🌐 | The 8 hardcoded `REWARDS_STORE` items |
| GET | `/catalogue/categories` | 🌐 | Proxy → RewardPort |
| GET | `/catalogue/subcategories/:categoryId` | 🌐 | Proxy |
| GET | `/catalogue/products` | 🌐 | Proxy |
| POST | `/catalogue/products/filter` | 🌐 | Proxy `{categoryId, subCategoryId, sortBy}` |
| POST | `/catalogue/products/details` | 🌐 | Proxy `{productId}` |
| GET | `/wallet` | 🔒 | Balance, tier, multiplier, next-tier progress, last 10 transactions |
| GET | `/transactions` | 🔒 | `page, limit`. **Paginated in JS over the whole embedded array** |
| GET | `/referral-code` | 🔒 | Generates one if missing |
| GET | `/referrals` | 🔒 | Referral list + milestone flags |
| POST | `/redeem` | 🔒 | `{rewardSlug, bankDetails?}`. Creates a `RedemptionRequest` and debits points |
| GET | `/admin/overview` | 👑 | `page, limit, sort, order, search` |
| POST | `/admin/adjust-points` | 👑 | Manual `adjustment` transaction |
| GET | `/admin/redemptions` | 👑 | `status, page, limit` |
| PUT | `/admin/redemptions/:id` | 👑 | `{status, adminNotes, voucherCode}`. **`status: "failed"` auto-refunds the points** |
| GET | `/admin/user/:userId/wallet` | 👑 | Any user's wallet |

### Hubble gift cards — `/api/rewards/hubble`
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/config` | 🔒 | SDK config for the frontend |
| GET | `/token` | 🔒 | 32-byte single-use SSO token, **5 min, stored in an in-process Map** |
| POST | `/sso` | 🔑 | Called by Hubble's backend. `X-Hubble-Secret` must match `HUBBLE_WEBHOOK_SECRET`. Consumes the token |
| GET | `/balance?userId=` | 🔑 | `{totalCoins: availablePoints}` |
| POST | `/debit` | 🔑 | `{userId, coins, referenceId, note}`. Idempotent by `referenceId` |
| POST | `/reverse` | 🔑 | `{userId, referenceId, note}`. Idempotent |

---

## Builder Projects

### Builders — `/api/builders` (👑 **all routes**, `router.use(protectAdmin)`)
| Method | Path | Notes |
|---|---|---|
| GET | `/` · `/:id` | List / detail |
| POST | `/` | multipart `logo`. **`phone` is the unique de-dupe key** |
| PUT | `/:id` | multipart `logo` |
| DELETE | `/:id` | |

### Projects — `/api/projects`
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/builder/:builderId` | 👁 | Declared **before** `/:id` |
| GET | `/` | 👁 | `search, city, category, status, isActive, page, limit`. Anonymous callers are forced to `isActive: true`; an admin viewer may pass `isActive=false` |
| GET | `/:id` | 👁 | 404 for anonymous when `isActive === false` |
| POST | `/` | 👑 | multipart `.any()` — file fields validated against a 12-name allowlist by `organizeProjectFiles`; anything else → 400. 15 MB/file |
| PUT | `/:id` | 👑 | Same upload pipeline |
| POST | `/:id/construction-update` | 👑 | multipart `images` ≤10 |
| DELETE | `/:id` | 👑 | |

### Unit types — `/api/unit-types`
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/project/:projectId` | 👁 | Before `/:id` |
| GET | `/:id` | 👁 | |
| POST | `/` · PUT `/:id` | 👑 | multipart `twoDFloorPlan`(1), `threeDFloorPlan`(1), `unitPhotos`(≤20). Pre-save derives `pricePerSqft` and `effectivePrice`; then recalculates the parent project's `priceRange` |
| DELETE | `/:id` | 👑 | Also recalculates `priceRange` |

### Group-buy campaigns — `/api/campaigns`
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/unit-type/:unitTypeId` · `/project/:projectId` | 🌐 | Declared before `/:id` |
| GET | `/:id` | 🌐 | |
| POST | `/:id/join` | 🔒 | **Atomic**: `findOneAndUpdate` filtered on `status:'active'`, unexpired, and `$expr: memberCount < maxBuyers`, incrementing `memberCount`. If `CampaignMember.create` then fails (duplicate → 409) the counter is rolled back. Rate limited 10/15min |
| POST | `/:id/exit` | 🔒 | Rate limited 10/15min |
| POST | `/:id/payment-proof` | 🔒 | multipart `paymentProof` |
| POST | `/` · PUT `/:id` | 👑 | Create/update campaign |
| GET | `/:id/members` · `/:id/pending-payments` | 👑 | |
| PUT | `/members/:memberId/verify` | 👑 | Sets `tokenStatus: 'paid'`; the post-save hook recounts campaign counters |

### Bookings — `/api/bookings`
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/` | 🔒 | Creates a `ProjectBooking` in `enquiry` status |
| POST | `/:id/payment` | 🔒 owner of booking | multipart `screenshot` + UTR → `payment_submitted` |
| GET | `/my` | 🔒 | |
| GET | `/payment-config` | 🔒 | Returns `{qrUrl, upiId}` from env. **Auth-gated so the QR never ships in client code.** 503 if `DEALDIRECT_PAYMENT_QR_URL` is unset |
| GET | `/` | 👑 | List all |
| PUT | `/:id/verify` | 👑 | `{action: approve\|reject, adminNotes}`. Approve → `confirmed`, then an **atomic** `findOneAndUpdate` with `availableUnits: {$gte: 1}` decrements inventory; if that fails the booking is auto-cancelled with a 409 and the client is emailed. Also `syncBookingToCampaign` auto-enrols the buyer as a **paid** campaign member |
| PUT | `/:id/status` | 👑 | Manual status change |

---

## Content & Support

### Blogs — `/api/blogs`
| Method | Path | Auth | Notes |
|---|---|---|---|
| GET | `/meta/categories` · `/meta/tags` | 🌐 | Declared before `/:slug` |
| GET | `/` | 🌐 | Published only |
| GET | `/:slug` | 🌐 | Increments `views` |
| GET | `/admin/all` · `/admin/:id` | 👑 | Includes drafts |
| POST | `/admin` · PUT `/admin/:id` · DELETE `/admin/:id` | 👑 | |
| PATCH | `/admin/:id/publish` · `/admin/:id/unpublish` | 👑 | |
| POST | `/admin/upload-cover` | 👑 | multipart `coverImage` → magic-byte validation → Cloudinary → `{url}` |

### Contact — `/api/contact` (20 kB body cap)
| Method | Path | Auth |
|---|---|---|
| POST | `/` | 🔒 — creates inquiry, notifies admin via WhatsApp |
| GET | `/my-inquiries` | 🔒 |
| GET | `/admin/all` · `/admin/:id` · PUT `/admin/:id` · DELETE `/admin/:id` | 👑 |
| PATCH | `/admin/:id/read` · `/admin/mark-all-read` | 👑 |

### Notifications — `/api/notifications` (all 🔒)
`GET /` · `PATCH /:id/read` · `PATCH /mark-all/read`

### Saved searches — `/api/saved-searches` (all 🔒)
`POST /` (validated whitelist) · `GET /mine` · `PATCH /:id/toggle` · `PUT /:id` · `DELETE /:id`

### Taxonomy
| Resource | Public read | Admin write |
|---|---|---|
| `/api/propertyTypes` | `GET /list-propertytype` | `POST /add-property-type` · `PUT /edit/:id` · `DELETE /delete/:id` |
| `/api/categories` | `GET /list-category` | `POST /add-category` · `PUT /edit/:id` · `DELETE /delete/:id` |
| `/api/subcategories` | `GET /list` · `GET /byCategory/:categoryId` | `POST /add` · `PUT /edit/:id` · `DELETE /delete/:id` |

> These three use inconsistent verb-in-path naming (`add-category`, `list-category`, `edit/:id`). It is legacy; match the existing style when extending them rather than mixing conventions within a resource.

---

## Admin — `/api/admin`
Controller `adminController.js`

| Method | Path | Auth | Permission | Notes |
|---|---|---|---|---|
| POST | `/login` | 🌐 | — | 10 kB cap. Returns one of three shapes: `{requiresMfa}`, `{requiresMfaSetup}`, or `{admin}` |
| POST | `/mfa/verify` | 🌐 | — | Uses the `admin_mfa_pending` cookie. `{code, isBackupCode?}` |
| POST | `/logout` · `/logout-all` | 👑 | — | |
| GET | `/sessions` · DELETE `/sessions/:sessionId` | 👑 | — | |
| GET | `/profile` | 👑 | — | The admin app's auth probe |
| POST | `/change-password` | 👑 | — | ≥12 chars. Revokes all other sessions |
| POST | `/mfa/setup` | 👑 | — | Returns QR data-URL + **10 backup codes, shown once** |
| POST | `/mfa/confirm` | 👑 | — | Enables MFA and upgrades the current session |
| POST | `/mfa/disable` | 👑 | — | Own account needs password; another admin needs role level ≥100 |
| GET | `/dashboard/stats` | 👑 | `dashboard:read` | Counts, lead funnel, 6-month series, recent properties, top owners |
| GET | `/leads` | 👑 | `leads:read` | |
| PUT | `/leads/:id` | 👑 | `leads:update` | |
| GET | `/reports` | 👑 | `reports:read` | Defaults to `contextType: 'message'` when `type` is absent |
| PUT | `/reports/:id` | 👑 | `reports:update` | |
| GET | `/verifications` | 👑 | `verifications:read` | ⚠️ `verifications` is not in the Permission `resource` enum |
| POST | `/verifications/:id/approve` | 👑 | `verifications:approve` | Sets property `sold`/`rented`, sends both parties a "claim your reward" notification. **Does not award points** |
| POST | `/verifications/:id/reject` | 👑 | `verifications:approve` | Requires `adminNotes`. Reverts property to `active` |
| GET | `/audit-logs` | 👑 | **super admin (level ≥100)** | `category, action, adminId, startDate, endDate, severity, securityOnly`. `action` regex is escaped |

**`registerAdmin` exists in the controller but is not routed.** Admins are created by DB seeding only.

---

## Rate Limits Summary

| Scope | Window | Max | Applies to |
|---|---|---|---|
| Global | 15 min | 500 | Everything except `/health` |
| Auth | 15 min | 5 | user login/register/forgot-password, admin login. `skipSuccessfulRequests` |
| In-memory auth (per module) | 15 min | 10 | `authRateLimit` on user + admin routes — a second, independent counter |
| Transactional | 1 hour | 20 | `/api/agreements/generate` |
| Webhook | 1 min | 30 | `/api/agreements/webhook` |
| Search | 1 min | 20 | `/api/properties/search`, `/suggestions`, `/filter` |
| Group buy | 15 min | 10 | campaign join/exit |
| Upload concurrency | — | 10 in flight | `uploadConcurrencyGuard`, process-wide |

All counters are **in-process** — they multiply by the number of instances.
