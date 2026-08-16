# DATABASE.md — MongoDB Schema Reference

> Source of truth: `backend/models/*.js` (26 files). Mongoose 8, MongoDB Atlas.
> Connection: `backend/config/db.js` — single `mongoose.connect(MONGO_URI)`, 10s server-selection timeout.
> **In production a failed DB connection does NOT exit the process** — the server stays up and `/health` reports `database: disconnected`. In dev it calls `process.exit(1)`.

Related: [MASTER_MEMORY.md](MASTER_MEMORY.md) · [AUTH_SYSTEM.md](AUTH_SYSTEM.md) · [BUSINESS_LOGIC.md](BUSINESS_LOGIC.md) · [API_REFERENCE.md](API_REFERENCE.md)

---

## 1. Collection Map (26 models)

| Model file | Collection | Domain | Owns lifecycle of |
|---|---|---|---|
| `userModel.js` | `users` | Identity | End users (buyer/owner) |
| `UserSession.js` | `usersessions` | Identity | Server-side user sessions |
| `PasswordResetToken.js` | `passwordresettokens` | Identity | Reset tokens (**largely unused — see §9**) |
| `Admin.js` | `admins` | Identity | Admin accounts + MFA |
| `AdminSession.js` | `adminsessions` | Identity | Admin sessions |
| `Role.js` | `roles` | RBAC | Admin roles + level |
| `Permission.js` | `permissions` | RBAC | `resource:action` codes |
| `AuditLog.js` | `auditlogs` | Compliance | Admin action trail |
| `Property.js` | `properties` | Marketplace | Listings (owner **and** builder) |
| `PropertyType.js` | `propertytypes` | Taxonomy | "Apartment / Flat", "Office Space"… |
| `Category.js` | `categories` | Taxonomy | Residential / Commercial |
| `SubCategory.js` | `subcategories` | Taxonomy | Third taxonomy level |
| `Lead.js` | `leads` | Marketplace | Buyer→owner interest records |
| `Conversation.js` | `conversations` | Chat | 1:1 threads scoped to a property |
| `Message.js` | `messages` | Chat | Individual messages |
| `Report.js` | `reports` | Moderation | Reported messages/properties |
| `Notification.js` | `notifications` | Engagement | In-app + email fan-out |
| `SavedSearch.js` | `savedsearches` | Engagement | Stored filter sets + alerts |
| `ContactInquiry.js` | `contactinquiries` | Support | Contact-us tickets |
| `Agreement.js` | `agreements` | Legal | AI-generated rental/sale agreements |
| `TransactionVerification.js` | `transactionverifications` | Rewards | Deal-closure proof + admin approval |
| `Reward.js` | `rewards` | Rewards | Points wallet + embedded transactions |
| `Referral.js` | `referrals` | Rewards | Referrer→referred milestones |
| ~~`RedemptionRequest.js`~~ | ~~`redemptionrequests`~~ | Rewards | **DELETED 2026-08-01** — pre-Hubble store, verified unreachable, 0 documents |
| `LoginTracker.js` | `logintrackers` | Rewards | Monthly login-day streak (**dual-written, see §9**) |
| `Blog.js` | `blogs` | Content | SEO blog posts |
| `Builder.js` | `builders` | Projects | Developer profiles (no login) |
| `Project.js` | `projects` | Projects | A builder's development |
| `UnitType.js` | `unittypes` | Projects | Purchasable config within a project |
| `GroupBuyCampaign.js` | `groupbuycampaigns` | Projects | Group-buy discount campaign |
| `CampaignMember.js` | `campaignmembers` | Projects | User participation in a campaign |
| `ProjectBooking.js` | `projectbookings` | Projects | Unit booking + QR/UTR payment |

> Count note: CLAUDE.md says "26 schemas"; the directory actually holds 32 model files. Treat the table above as authoritative.

---

## 2. Relationship Graph

```
                        ┌──────────┐
                        │  Admin   │──ref──> Role ──refs──> Permission[]
                        └────┬─────┘         (level 0-100)
                             │ createdBy / addedBy / reviewedBy
     ┌───────────────────────┼────────────────────────────────┐
     v                       v                                v
┌─────────┐            ┌──────────┐                     ┌───────────┐
│ Builder │──1:N──────>│ Project  │──1:N──────────────> │ UnitType  │
└─────────┘            └────┬─────┘                     └─────┬─────┘
     │                      │                                 │ 1:N
     │ (denormalized on     │ 1:N (denormalized builder)       v
     │  UnitType/Campaign)  │                        ┌──────────────────┐
     │                      └──────────────────────> │ GroupBuyCampaign │
     │                                               └────────┬─────────┘
     v                                                        │ 1:N
┌──────────┐                                          ┌───────────────┐
│ Property │<────── builder (nullable)                │ CampaignMember│──> User
└────┬─────┘                                          └───────────────┘
     │ owner (nullable) ──> User
     │
     ├─1:N──> Lead ──> User (buyer) + User (propertyOwner)
     ├─1:N──> Conversation ──1:N──> Message
     ├─1:N──> Agreement (owner + buyer + property)
     ├─1:N──> TransactionVerification (owner + buyer)
     └─embedded──> interestedUsers[{ user, interestedAt }]

┌──────┐  1:1  ┌────────┐  embedded  ┌──────────────┐
│ User │──────>│ Reward │───────────>│ transactions │
└──┬───┘       └────────┘            └──────────────┘
   ├─1:N──> UserSession (TTL)
   ├─1:N──> SavedSearch
   ├─1:N──> Notification
   ├─1:N──> RedemptionRequest
   ├─1:1──> Referral (as `referred`, unique)
   └─1:N──> Referral (as `referrer`)

ProjectBooking ──> Project + UnitType + Builder + User(nullable)
```

**Critical invariant:** `Property.owner` and `Property.builder` are mutually exclusive in practice.
- `owner != null, builder == null` → individual seller listing. Appears in `/properties` feed.
- `owner == null, builder != null` → admin-posted builder listing. Appears **only** in the builder feed (`?isBuilderProperty=true`).
Every public query in `propertyController.js` filters on this. **Breaking that filter leaks builder stock into the consumer feed.**

---

## 3. Identity Collections

### `users` (`userModel.js`)

| Field | Type | Notes |
|---|---|---|
| `name` | String, req, ≤100 | |
| `email` | String, req, **unique**, lowercased | regex `/^\S+@\S+\.\S+$/` |
| `password` | String, req, ≥8, `select:false` | bcrypt cost **12** (hashed in controller, **not** a pre-save hook) |
| `role` | enum `user` \| `buyer` \| `owner`, default `buyer` | `user` and `buyer` are **both** buyer roles (legacy drift) |
| `phone` | String, **unique+sparse** | `/^[6-9]\d{9}$/` — Indian mobile |
| `alternatePhone`, `address{line1,line2,city,state,pincode}`, `profileImage`, `dateOfBirth`, `gender`, `bio` | | profile |
| `isActive` | Bool, default true | soft deactivate |
| `isBlocked` | Bool, default false | admin ban |
| `blockReason` / `blockedAt` / `blockedBy` | `select:false` | admin-only |
| `preferences.emailNotifications` | Bool, default true | gates the Notification post-save email |
| `preferences.smsNotifications` | Bool, default false | |
| `isVerified` | Bool, default false | phone-OTP verified |
| `otp`, `otpExpires` | `select:false` | **SHA-256 hashed** (`otp + OTP_SECRET`) |
| `security.failedLoginAttempts` | Number, `select:false` | lock at 5 |
| `security.lockoutUntil` | Date, `select:false` | 15 min lockout |
| `security.passwordChangedAt` | Date | drives `changedPasswordAfter()` |
| `security.lastLoginAt` / `lastLoginIp` | | |
| `security.sessionVersion` | Number | `invalidateSessions()` bumps it — **currently never read by auth middleware** |
| `referredBy` | ref User | |
| `referralCode` | String, unique+sparse, uppercase | auto-generated `DD` + 4 chars in pre-save, 5 collision retries |
| `hasCompletedFirstAction` | Bool | referral milestone flag |
| `resetPasswordOtp` / `resetPasswordOtpExpires` | `select:false` | marked "deprecated" in code but **this is the live reset path** |

**Indexes:** `email`(u), `role`, `isVerified`, `isBlocked`, `createdAt:-1`, `referralCode`(sparse), `referredBy`.

**`toJSON` transform** strips password, all OTP fields, block metadata, `__v`, and the three private `security.*` fields. Statics: `getSafeFields()` (projection string), `getPublicFields()` (`name profileImage role bio`).

### `usersessions` (`UserSession.js`)
Server-side sessions — the primary auth store. See [AUTH_SYSTEM.md](AUTH_SYSTEM.md) §3.

| Field | Notes |
|---|---|
| `user` | ref User, indexed |
| `sessionToken` | **stores the SHA-256 hash, not the raw token** (same value as `tokenHash`) |
| `tokenHash` | SHA-256 of the raw 48-byte base64url token |
| `fingerprint` | sha256(UA + truncated-IP), first 32 chars |
| `fingerprintData{userAgent,os,browser,ipPrefix,device}` | parsed components for *lenient* validation |
| `deviceInfo{userAgent,platform,browser,isMobile}` | display only |
| `ipAddress`, `lastActivity`, `isActive`, `revokedAt`, `revokedReason` | |
| `expiresAt` | **TTL index `expireAfterSeconds: 0`** — Mongo auto-deletes |

**Indexes:** `user+isActive`, `tokenHash`, `expiresAt`, `sessionToken`(u).

### `admins` (`Admin.js`)

| Field | Notes |
|---|---|
| `password` | min **12** chars, hashed in a **pre-save hook** at cost 12, enforced by regex (upper+lower+digit+special) |
| `role` | **`Schema.Types.Mixed`** — accepts a legacy String (`"admin"`) *or* an ObjectId ref to Role. This duality drives `getPermissions()` |
| `additionalPermissions[]` | refs Permission, merged on top of role permissions |
| `mfa.enabled` / `.required`(default **true**) / `.secret`(select:false) / `.backupCodes[]`(select:false, bcrypt-hashed) / `.lastVerified` | TOTP via Speakeasy |
| `security.*` | failedLoginAttempts (lock at 5 for **30 min**), lockoutUntil, lastLogin, lastLoginIp, passwordChangedAt, `mustChangePassword` |
| `isActive`, `deletedAt` (soft delete), `createdBy` | |

**Query middleware:** `pre(/^find/)` auto-filters `deletedAt: null` unless `.setOptions({ includeDeleted: true })`.

**`getPermissions()` security semantics (important):**
- String role → returns only `["dashboard:read","dashboard:view","properties:read"]` + logs a migration warning.
- Missing role → `[]` (deny all).
- Role doc not found → `[]`.
- Role resolves but yields **0** permission codes → `[]` (deliberately does *not* fall through to a default).
- Thrown exception → `["dashboard:view"]` minimal fallback.

### `adminsessions` (`AdminSession.js`)
Same shape as UserSession plus:
- `mfaVerified` — **`protectAdmin` refuses every request while false**.
- `mfaSetupPending` — when true, only `/mfa/setup`, `/mfa/verify-setup`, `/mfa/generate-secret`, `/mfa/confirm` are reachable.
- `sessionToken` here is the **raw** 64-byte hex token (unlike UserSession, which hashes).
- TTL index on `expiresAt`.
- Three validators exist: `verifyFingerprint` (exact hash), `validateFingerprintLenient` (**the one actually used**), `validateFingerprintStrict` (defined, never called).

### `roles` / `permissions`
- `Role.name` enum: `super_admin` | `admin` | `manager` | `viewer`; `level` 0–100 (`requireSuperAdmin` = level ≥ 100); `permissions[]` refs; `canManageAdmins`; `isSystem`.
- `Permission.code` must match `/^[a-z_]+:[a-z_]+$/`, auto-derived from `resource:action` in a `pre("validate")` hook. Compound unique index on `{resource, action}`.
- `Permission.resource` enum is **fixed**: dashboard, users, admins, properties, leads, reports, categories, settings, audit_logs, analytics, messages, notifications.
  ⚠️ Routes reference `verifications:read` and `verifications:approve` — `verifications` is **not** in this enum, so those Permission docs cannot be created through the schema. See [KNOWN_BUGS.md](KNOWN_BUGS.md).

### `auditlogs`
Append-only admin trail. `category` enum (11 values), `action` free string, sanitized `request.body` (password/otp/mfaCode stripped by the `log()` static), `client.ipAddress` (required, indexed), `result` enum success/failure/partial/denied, `severity` low→critical, `isSecurityEvent` bool. Stack traces stored **only** when `NODE_ENV === "development"`. Logging failures are swallowed — audit never breaks a request. No TTL: **this collection grows unbounded.**

---

## 4. Marketplace Collections

### `properties` (`Property.js`) — the hottest collection

Structure highlights:
- **Dual ownership**: `owner` (ref User) *or* `builder` (ref Builder).
- **Triple taxonomy**, each stored both as ObjectId ref *and* denormalized name: `propertyType`/`propertyTypeName`, `category`/`categoryName`, `subcategory`. Controllers overwhelmingly read the **name** fields; the refs are frequently absent on user-created listings because the Add Property form posts names as strings.
- `categoryName` is normalized to exactly `"Residential"` or `"Commercial"` in `addProperty` (regex-infers from property type when ambiguous).
- **Address duplication**: `address{line,area,city,state,pincode,landmark,nearby[],latitude,longitude}` plus top-level `city` and `locality` convenience copies. Queries hit both — always write both.
- `area{totalSqft,carpetSqft,builtUpSqft,superBuiltUpSqft,plotSqft,pricePerSqft}`.
- `images[]` flat array (backward compat) **and** `categorizedImages.residential.{14 keys}` / `.commercial.{17 keys}`. On update, the flat array is **rebuilt** from the categorized map.
- `parking.covered` / `.open` are `Mixed` (string or number). `maintenance` and `deposit` are `Mixed` too.
- ~25 flattened commercial config fields (workstations, cabins, frontage, powerLoad…).
- `status` enum: `active`, `pending`, `sold`, `rented`, `inactive`, `pending_verification`. Default `active`.
- `isApproved` default **true** — listings are auto-published; admin disapproval is the moderation action, not approval.
- Counters: `views`, `likes`, `inquiries`. `interestedUsers[{user, interestedAt}]` embedded.

**Indexes:** `owner`, `builder`, `{status,isApproved}`, `{city,status}`, `{listingType,status,createdAt:-1}`, `{address.city,address.state}`, `{categoryName,propertyTypeName}`, `price`, `createdAt:-1`.
⚠️ No text index — all search uses escaped `RegExp`, which cannot use these indexes for leading-wildcard matches.

**Fields written by controllers but absent from the schema** (Mongoose silently drops them under default `strict`): `isBanned`, `isActive`, `approvedAt`, `approvedBy`, `disapprovedAt`, `disapprovedBy`, `location` (GeoJSON), `buildingName`, `buildingType`. Public read filters test `isBanned: {$ne:true}` / `isActive: {$ne:false}` — these pass vacuously since the fields never persist. See [KNOWN_BUGS.md](KNOWN_BUGS.md).

### `leads`
Created automatically when a buyer marks interest. Carries `userSnapshot` and `propertySnapshot` so the lead survives later profile/listing edits.
- `status` enum: `new` → `contacted` → `interested` → `negotiating` → `converted` | `lost`.
- `contactHistory[{action,note,date}]`, `isViewed`/`viewedAt`, `source` enum website|mobile_app|direct.
- **Unique compound index `{user, property}`** — hard-prevents duplicate leads at the DB level.
- Other indexes: `{propertyOwner, createdAt:-1}`, `property`, `status`.

### `conversations` / `messages`
- `Conversation.participants[]` (refs User), `property` (**required** — every thread is property-scoped), `lastMessage{text,sender,createdAt}` denormalized for the inbox list, `unreadCount` as a **`Map<userId, Number>`**, `isActive`.
- Socket.io authorization queries exactly `{_id, participants: userId, isActive: true}` (see `server.js:552`).
- `Message.messageType` enum includes `visit_request` / `visit_confirmation` — site-visit scheduling rides on the chat rail.
- `readBy[{user, readAt}]`, `isDeleted` soft flag.

### `notifications`
Small schema, big side effect: **`post('save')` and `post('insertMany')` hooks send an email** via `utils/emailService.js#sendGeneralNotification` when `user.preferences.emailNotifications !== false`. The hook appends `?intendedFor=<email>` to `data.actionUrl`.
⚠️ Creating notifications in a loop therefore triggers one User lookup + one SMTP send **per document**. Bulk-inserting saved-search matches fans out real email.

### `savedsearches`
`filters{search,city,propertyType,priceRange,availableFor}`, `notifyEmail`, `notifyInApp`, `isActive`. Matched on every property creation (`addProperty` loads **all** active saved searches into memory — O(n) per listing).
Price bands are hardcoded in the matcher: `low` < ₹50L, `mid` ₹50L–₹1.5Cr, `high` > ₹1.5Cr.

---

## 5. Agreements

`agreements` is the most security-hardened collection.

| Field | Purpose |
|---|---|
| `idempotencyKey` | **unique**. `sha256(propertyId-ownerId-buyerId).slice(0,32)` — deliberately **no timestamp** (a prior version included `Date.now()`, defeating idempotency) |
| `signature` | HMAC-SHA256 over `{idempotencyKey, contentHash, owner, buyer, property, amount, createdAt}` using `AGREEMENT_SECRET_KEY` (falls back to `JWT_SECRET`). `select:false` + stripped in `toJSON` |
| `contentHash` | sha256 of `content` — `verifyIntegrity()` re-derives and compares |
| `owner`/`ownerSnapshot`, `buyer`/`buyerSnapshot` | snapshots hold **`aadhaarLastFour` only**, never the full number |
| `financials` | `amount` + `amountSource` enum (`property_price`\|`property_deposit`) + `amountVerifiedAt` — amounts are read from the Property doc server-side, never trusted from the client |
| `agreementType` | `LEAVE_AND_LICENSE` \| `RENTAL_AGREEMENT` \| `SALE_AGREEMENT` |
| `duration` | startDate, endDate, months, noticePeriodMonths(1), lockInPeriodMonths(3) |
| `status` | draft → pending_owner_signature → pending_buyer_signature → signed → active → expired\|cancelled\|terminated |
| `signatures.owner/.buyer` | `{signed, signedAt, ipAddress, userAgent}` |
| `payments[]` | transaction id, gateway, status incl. `fraud_suspected`, `webhookValidated` |
| `auditLog[]` | append-only per-action trail |

**Idempotency is status-scoped:** `createSecureAgreement` only treats an existing doc as a duplicate when its status is **not** in `['cancelled','terminated','expired']` — so a cancelled agreement can be recreated for the same trio.

`pre('save')` hard-rejects any role other than `owner`/`user` in the snapshots — the retired **Agent** role can never appear in a legal document.

---

## 6. Rewards Collections

### `rewards` (wallet, 1:1 with User)
- `totalPoints` (lifetime, drives tier), `availablePoints` (spendable), `tier` enum bronze|silver|gold|diamond.
- `transactions[]` **embedded** sub-docs — `{type: earn|redeem|forfeit|adjustment, action, points, basePoints, multiplier, description, metadata}`, `createdAt` only.
- `monthlyLoginDays` as `Map<"YYYY-MM", Number>`, `lastLoginDate` `"YYYY-MM-DD"` for same-day dedupe.
- **`optimisticConcurrency: true`** — `save()` checks `__v` and throws `VersionError` on a concurrent write. `rewardService.awardPoints` / `redeemPoints` catch this and **retry exactly once**.

**Tier thresholds / multipliers** (defined in the model, mirrored nowhere else):

| Tier | totalPoints | Multiplier |
|---|---|---|
| bronze | 0–999 | 1.0× |
| silver | 1 000–4 999 | 1.1× |
| gold | 5 000–14 999 | 1.25× |
| diamond | ≥ 15 000 | 1.5× |

⚠️ **Unbounded array growth:** every earn/redeem pushes into `transactions[]`. A heavy user's wallet document grows toward the 16 MB BSON cap. `getTransactionHistory` also loads the **entire** array and paginates in JS.

### `referrals`
`{referrer, referred}` with three milestone flag/date pairs (signup, firstAction, dealClosure).
Two unique indexes: `{referrer, referred}` and **`{referred}` alone** — a user can only ever be referred once.

### `redemptionrequests`
`rewardType` enum (voucher, listing_boost, premium_listing, cash_transfer, valuation_report, priority_support, rewardport_product), `pointsSpent`, `status` pending→processing→fulfilled|failed|cancelled, `voucherCode`, RewardPort order ids, `bankDetails{accountName,accountNumber,ifscCode,upiId}`.
⚠️ `bankDetails` is stored **in plaintext** with no `select:false`. See [SECURITY.md](SECURITY.md).

### `transactionverifications`
Deal-closure proof. `documentUrls[]` with a validator requiring ≥1 entry. `status` pending|approved|rejected. Separate `ownerReward`/`buyerReward` `{points, cashValue}` and `ownerClaimed`/`buyerClaimed` booleans — the reward is rolled **at claim time**, not at approval time, so the "door game" reveal is genuinely random per claimer.

### `logintrackers`
`{userId, month:"YYYY-MM", loginDays:[Number], rewardAwarded}` with unique `{userId, month}`.
⚠️ Dead in practice: `rewardService.trackDailyLogin` writes to `Reward.monthlyLoginDays` instead and never touches this collection.

---

## 7. Projects / Group-Buy Collections

Hierarchy is strict: **Builder → Project → UnitType → GroupBuyCampaign → CampaignMember**. Child docs denormalize every ancestor id so listing queries never need `populate`.

### `builders`
No login. Admin-managed. Profile fields feed the "About the Developer" block: `description`, `yearEstablished`, `totalProjectsDelivered`, `totalSqFtDelivered`, `operatingCities[]`, `awards[{name,year}]`, `websiteUrl`, `logoUrl`.
**Unique index on `phone`** — this is the de-dupe key. Text index on `{name, company}`.

### `projects`
Large nested document, grouped: `basics` (name, description, category enum Residential|Commercial|Mixed Use, subType enum of 8, status enum New Launch→Completed, ownershipType, highlights[], reraNumber), `location` (+ `coordinates{lat,lng}` and `connectivity` distances), `nearbyPlaces[]`, `overview`, `amenities[{category,name,icon}]`, `media` (7 image arrays + brochure + walkthrough), `documents` (5 legal URLs), `legal`, `paymentPlans[]`, `financials`, `bankApprovals[]`, `constructionUpdates[]`, `salesContact`.

**Deliberate design decision, stated in the schema comments:** *no data field is required*. Only `builder` and `createdBy` are enforced, and both are set server-side. These are admin-authored records — partial saves are intended. **Do not add `required: true` to `basics.name` or anything else.**

Denormalized counters maintained by other controllers: `priceRange{min,max}` (recomputed on UnitType create/update/delete), `activeCampaignCount`, `unitTypeCount`.

Text index `project_search_text` on `basics.name`, `location.city`, `location.locality`.

### `unittypes`
`config{name,bedrooms,bathrooms,balconies,hasUtilityArea}`, `area` (incl. plot dims for villas/plots), `facing[]` enum of 8, `furnishing` enum, `parking{covered,open,ev}`, deep `specifications` tree (structure/flooring/kitchen/bathroom/doors/windows/electrical), `floorPlans{twoDUrl,threeDUrl,videoUrl}`, `photos[{url,room,caption}]`, `pricing`, `paymentTerms`, `inventory{totalUnits,availableUnits,bookedUnits,blockedUnits,towerAllocation[]}`, `highlights[]`.

**`pre('save')` derives pricing:**
```
pricePerSqft  = round(basePrice / area.carpetSqft)          // carpet, not built-up
effectivePrice = basePrice + plc + parking + clubhouse
               + legal + maintenance + viewPremium
```
`paymentTerms` (bookingAmount, GST, stamp duty, registration) is **deliberately excluded** from `effectivePrice` — those are taxes/fees, not list price. Note `floorRisePerSqft` is stored but also not included.

### `groupbuycampaigns`
DealDirect's USP. `discountPerBuyer` is a **flat ₹ amount, not a percentage** — pre-agreed with the builder, no negotiation state machine. `buyerTargets{minBuyers ≥2, maxBuyers|null}`, `duration{startDate,endDate}`, `perks[]`, `status` active|paused|completed|expired|cancelled, counters `memberCount`/`paidMemberCount`, internal `adminNotes`.

### `campaignmembers`
Unique `{campaign, user}`. `tokenStatus` pending|paid|refunded, `paymentReference` (UPI txn), `paymentProofUrl` (screenshot), `paymentRecordedBy` (Admin).
**`post('save')` hook recounts** `memberCount` and `paidMemberCount` from the DB (`countDocuments`) rather than incrementing — chosen to avoid drift under races. Hook errors are logged, never thrown.

### `projectbookings`
QR/UTR payment flow, no gateway: `enquiry` → `payment_submitted` → `confirmed` → `completed`|`cancelled`, mirrored by `payment.status` pending|submitted|verified|rejected. Holds `payment.utrNumber` + `payment.screenshotUrl` + `verifiedBy`. `statusHistory[]` audit.

---

## 8. Content & Support

### `blogs`
`slug` unique+indexed. `category` enum of 7 (Buyer Guide, Seller Guide, Market Trends, Legal, Finance, Vastu & Design, News). `status` draft|published; `publishedAt` auto-set on first publish. `readTime` auto-computed in `pre('save')` at **200 wpm** after stripping HTML. SEO overrides `seoTitle` (≤70) / `seoDescription` (≤160).
Indexes: `{status,publishedAt:-1}`, `{status,category,publishedAt:-1}`, and a **text index** on title/excerpt/content/tags/category.

### `contactinquiries`
`userSnapshot`, `category` enum of 7, `status` pending|in-progress|resolved|closed, `priority` low→urgent, `adminNotes`/`adminResponse`, `handledBy`, `isRead`.

### `reports`
`contextType` message|property; carries `message`+`conversation` **or** `property`. `status` pending|reviewed|resolved|dismissed. Duplicate active reports by the same user on the same property are blocked in the controller (not the DB).

---

## 9. Data Integrity Warnings

Read this before touching any deletion or migration path.

1. **`deleteAccount` field-name mismatches** (`userController.js` ~line 1244) — four of the cascade deletes target fields that do not exist, so the data is orphaned rather than removed:
   | Call | Actual schema field |
   |---|---|
   | `UserSession.deleteMany({ userId })` | `user` |
   | `LoginTracker.deleteMany({ user: userId })` | `userId` |
   | `Report.deleteMany({ reporter: userId })` | `reportedBy` |
   | `Referral.deleteMany({ referredUser: userId })` | `referred` |
   Sessions in particular survive account deletion. Details in [KNOWN_BUGS.md](KNOWN_BUGS.md).

2. **`PasswordResetToken` is orphaned.** The model implements a proper hashed, single-use, rate-limited token, and `GET /api/users/reset-password/validate/:token` reads it — but `forgotPassword` writes an OTP to `user.resetPasswordOtp` instead and never creates a token doc. The validate endpoint can therefore never succeed.

3. **`Property` writes fields the schema does not define** (§4). Adding them to the schema retroactively would change the meaning of existing public-read filters — audit those filters first.

4. **No migrations framework.** `backend/scripts/` holds one-off scripts (`migrateLegacyUsers.js`, `normalizeCategoryName.js`, `sync-bookings-to-campaigns.js`, `seedBlogs.js`) run manually. There is no version table and no rollback. Schema changes are effectively additive-only in production.

5. **Embedded arrays without bounds:** `Reward.transactions`, `Agreement.auditLog`, `Property.interestedUsers`, `Lead.contactHistory`. Only `interestedUsers` has an application-level cap (5 per buyer, enforced in `markInterested`).

6. **Transactions require a replica set.** `addProperty` opens a real `mongoose.startSession()` transaction for the one-listing-per-owner check. This works on Atlas but **fails against a standalone `mongod`** — relevant for local dev.
