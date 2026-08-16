# BUSINESS_LOGIC.md — Workflows and the Rules Behind Them

Every workflow below is described as: **what it does → why it exists → the invariants you must not break.**

Related: [API_REFERENCE.md](API_REFERENCE.md) · [DATABASE.md](DATABASE.md) · [AUTH_SYSTEM.md](AUTH_SYSTEM.md) · [KNOWN_BUGS.md](KNOWN_BUGS.md)

---

## 1. The Three Actor Model

| Actor | Logs in? | Creates listings? | Notes |
|---|---|---|---|
| **Buyer** (`role: "user"` or `"buyer"`) | yes | no | Two spellings of one role. Every check must accept both |
| **Owner** (`role: "owner"`) | yes | **exactly one** | Reached only by OTP upgrade from buyer |
| **Builder** | **no** | via admin | A contact record; admin posts everything on their behalf |
| **Admin** | yes (MFA) | yes, for builders | Separate auth system entirely |

The **Agent** role is permanently retired. `blockRetiredRoles` runs globally in `server.js`, `sanitizeUser` throws on unknown roles, `Agreement.pre('save')` rejects agent snapshots, and `agreementController` has an explicit agent check. If you see "agent" anywhere, it is a guard, not a feature.

---

## 2. Property Listing

### Posting — `POST /api/properties/add`

**Why the constraints exist**
- **One listing per owner account.** A product decision to keep the platform owner-direct rather than broker-fronted. Enforced inside a real MongoDB transaction (`session.startTransaction()`) — `findOne({owner})` then `create([data], {session})` — because a plain count-then-create raced.
- **Auto-approved.** `isApproved` is set `true` at creation ("client requirement"). Moderation is reactive: admins *disapprove*, they never approve.
- **Strict field whitelist.** `sanitizePropertyData` copies only the ~60 names in `PROPERTY_ALLOWED_FIELDS`; everything else is dropped. `ADMIN_ONLY_FIELDS` (`isApproved`, `owner`, `views`, `likes`, `interestedUsers`, `status`, …) are then deleted again as a second pass. Admin fields can only be set through `setAdminOnlyFields()`, which itself filters to that same list.

**Data shaping, in order**
1. JSON-parse the stringified multipart fields: `area, parking, address, flooring, features, legal, extras, imageCategoryMap`.
2. Coerce `negotiable` from `"true"` to boolean.
3. Flatten `features` to top level, extracting `parking` and `extras` first.
4. Whitelist-sanitize.
5. Map Cloudinary URLs: `images[]` from the `images` field; `categorizedImages` built by walking `imageCategoryMap` and consuming `categorizedImages` URLs in order.
6. `setAdminOnlyFields({isApproved: true, owner: req.user._id})`.
7. Normalize coordinates into `address.latitude/longitude` (accepts a legacy `address.coordinates` object).
8. **Normalize `categoryName` to exactly `"Residential"` or `"Commercial"`** — matching on `/residen/`, `/commercial/`, else inferring from the property type via `/office|shop|showroom|restaurant|cafe|warehouse|industrial|co-?working|commercial/`, else defaulting to Residential.

**Post-create fan-out**
- Saved-search matching (see §7) → `Notification.insertMany` → an email per notification.
- `awardPoints("list_property")` → weighted-random reward.
- `awardPoints("upload_5_photos")` when ≥5 images — ⚠️ **this action is not in `ACTION_CATEGORY_MAP`, so it always fails silently.** See [KNOWN_BUGS.md](KNOWN_BUGS.md).
- `sendNewPropertyWhatsApp` to the admin number.

### Editing — `PUT /api/properties/my-properties/:id`
Ownership via `findOne({_id, owner: userId})`. Then a large form-field → schema-field remap (`expectedPrice → price`, `builtUpArea → area.builtUpSqft`, `bhkType → bhk`, `reraId → legal.reraId`, `servantRoom/poojaRoom/… → extras.*`, `parkingCovered/Open → parking.*`, `priceNegotiable → negotiable`).

**Image rule:** `existingCategorizedImages` (kept) plus newly uploaded ones are merged into `categorizedImages`, then the flat `images[]` array is **rebuilt from scratch** from that map. Anything not present in `existingCategorizedImages` is dropped. A client that forgets to send it will wipe the gallery.

`delete data.owner` guarantees ownership cannot be transferred.

### Deletion
Owner (`DELETE /api/properties/:id`) and admin (`DELETE /api/properties/delete/:id`) both destroy Cloudinary assets by parsing the `public_id` out of the URL. **The two paths parse it differently** — the owner path takes the last two segments, the admin path takes everything after `upload/v{version}/`. For nested folders (`dealdirect/properties/x`) only the admin version is correct.

### Public visibility
Every public read applies:
```js
isApproved: true,
$or: [{isActive: {$ne: false}}, {isActive: {$exists: false}}],
isBanned: {$ne: true},
status: {$nin: ['rejected','suspended','draft','pending']},
// plus: builder null (consumer feed) OR builder set (builder feed)
```
`isActive` and `isBanned` are **not in the schema**, so those two clauses currently pass vacuously. `getPropertyById` returns **404**, not 403, for a hidden property — existence is not disclosed.

---

## 3. Search, Filter, Suggestions

Three separate endpoints with three different implementations:

| Endpoint | Mechanism | Paginated? | Cost |
|---|---|---|---|
| `/search` | escaped `RegExp` across title, description, address.city/area/locality + structured filters | yes (`page`, `limit=12`) | Two queries (`countDocuments` + find) |
| `/suggestions` | single `$facet` aggregation → titles / grouped localities / grouped cities, capped at 8 | n/a | One aggregation |
| `/filter` | DB regex on title+city, **then JS filtering over populated `category`/`subcategory`/`propertyType` names, then JS sorting** | **no** | Loads the entire matching set into memory |

`/filter` is the expensive one and is why `searchLimiter` (20/min) covers it. All three escape regex metacharacters via `escapeRegExp` to prevent ReDoS.

> `getAllLeads` in `leadController.js` builds `new RegExp(search, 'i')` **without** escaping — the one place the protection is missing.

---

## 4. Interest → Lead Pipeline

The commercial heart of the product.

```
Buyer clicks "I'm Interested"
  → caps: ≤5 active interests per buyer, cannot be your own listing, no duplicates
  → Property.$push interestedUsers, $inc likes
  → Lead created with userSnapshot + propertySnapshot
  → Notification to owner  → email via post-save hook
  → WhatsApp to owner + admin copy
  → awardPoints("send_enquiry")  (≤5/day earn cap)
```

**Why snapshots.** `Lead.userSnapshot` and `propertySnapshot` freeze the buyer's contact details and the listing's headline facts at the moment of interest. If the buyer later edits their phone or the owner changes the price, the lead record still reflects what was true at contact time. Lead exports and the admin lead view read the snapshot first, the populated ref second.

**Why the unique index.** `{user, property}` unique on `Lead` is the real duplicate guard; the `findOne` check in the controller is only there to avoid a noisy error.

**Lead lifecycle:** `new → contacted → interested → negotiating → converted | lost`.
`POST /api/leads/:id/contact` **forces status to `contacted`** as a side effect of logging a contact-history entry.

Reaching `converted` **no longer awards anything** — that moved to the deal-verification flow (§6). The code comment records the change explicitly.

Every lead mutation re-reads the lead and compares `lead.propertyOwner` to `req.user._id` before writing (IDOR guard), and logs `⚠️ IDOR attempt` on mismatch.

---

## 5. Rewards Economy

`services/rewardService.js` + `models/Reward.js`. **Conversion: 1 point = ₹0.05.**

### Earning
Five earning actions, three of which roll a weighted random tier:

| Action | Category | Tiers | Range |
|---|---|---|---|
| `list_property` | `property_posting` | 22 | 40 pts (₹2) … 100 000 pts (₹5 000) |
| `mark_sold_rented` (owner) | `property_sale` | 17 | 1 000 … 500 000 pts (₹25 000) |
| `complete_deal` (buyer) | `property_sale` | 17 | same |
| `send_enquiry` | `property_enquiry` | 19 | 20 … 2 000 pts |
| `referral_signup` | fixed | — | 100 pts |
| `report_property` | fixed | — | 100 pts |

`getRandomReward` walks the tier list subtracting weights from `Math.random() * totalWeight`. The weights are steeply skewed — for `property_posting` the lowest tier carries weight 150 000 of ~235 000 total (~64 %), while the top tier carries 2 (~0.0009 %). This is a lottery, not a schedule.

Final award = `round(basePoints × tierMultiplier)`, where the multiplier comes from the wallet's current tier (bronze 1.0 / silver 1.1 / gold 1.25 / diamond 1.5).

**Caps:** `send_enquiry` is limited to 5 awards per calendar day, computed by filtering the wallet's embedded `transactions` array for today's entries.

**Concurrency:** `Reward` has `optimisticConcurrency: true`. `awardPoints` and `redeemPoints` catch `VersionError` and retry **exactly once** (`_retryCount < 1`).

### Tiers
Driven by `totalPoints` (lifetime), never by `availablePoints`. Redeeming therefore cannot demote a user.

### Redeeming
`REWARDS_STORE` is a hardcoded array of 8 items across three categories:
- **on_platform** — featured listing ₹500 (10 000 pts), 30-day premium placement (20 000), free valuation report (10 000), 3-month priority support (20 000)
- **lifestyle** — Amazon ₹250 (5 000), Swiggy/Zomato ₹300 (6 000), Starbucks ₹200 (4 000)
- **cash** — ₹1 000 bank transfer (20 000)

Redemption creates a `RedemptionRequest` (status `pending`) and debits immediately. An admin marking it `failed` **auto-refunds** the points as an `adjustment` transaction.

Note the internal exchange rates are not consistent with ₹0.05/pt: the Amazon ₹250 voucher costs 5 000 pts (₹0.05/pt, on-rate) while the ₹1 000 bank transfer costs 20 000 pts (also ₹0.05/pt) but the ₹500 featured listing costs 10 000 pts (₹0.05/pt). These are all on-rate — the on-platform items are the ones priced at face value rather than discounted.

### Referrals
`referralCode` is auto-generated in a `User` pre-save hook: `"DD"` + 4 random alphanumerics, retried up to 5 times against collisions.

Three milestones exist on the `Referral` document (signup / first_action / deal_closure) but **only `signup` is ever fired** (from `createReferralFromCode` during registration). `first_action` and `deal_closure` have flags, dates, and handler branches, but nothing calls `handleReferralMilestone` with them. Additionally `referral_first_action` and `referral_deal_closure` are **not** in `ACTION_CATEGORY_MAP`, so those calls would fail even if wired.

Guards: no self-referral, one referrer per user (unique index on `referred`).

### Reward reveal UX
`RewardRevealRouter` picks the animation from `reward.rewardCategory`:
- `property_sale` → `PropertyHuntGame` (3-door "Shagun" reveal)
- `property_posting` / `property_enquiry` → `SpinWheelOverlay`
- anything else → the door game

---

## 6. Deal Closure & Verification

Introduced to stop reward farming via self-declared "converted" leads.

```
1. Owner: POST /api/properties/:id/close-deal
     { buyerId (must be in interestedUsers), closingType: sold|rented, documents[1..5] }
   → TransactionVerification { status: 'pending' }
   → Property.status = 'pending_verification'
   → notification to owner ("submitted")

2. Admin: POST /api/admin/verifications/:id/approve  { adminNotes? }
   → Property.status = closingType ('sold' | 'rented')
   → verification.status = 'approved'
   → "Claim Your Reward" notification to BOTH owner and buyer
   → NO points awarded here

   or /reject { adminNotes required }
   → Property.status back to 'active'
   → rejection notification to owner

3. Each party: POST /api/properties/claim-deal-reward/:verificationId
   → must be a party; verification must be 'approved'
   → already claimed → returns the stored reward (idempotent)
   → awardPoints(owner ? 'mark_sold_rented' : 'complete_deal')
   → stores points + cashValue on ownerReward / buyerReward, sets *Claimed
```

**Why the reward is rolled at claim time, not approval time:** each party gets an independent random draw and a genuine reveal animation. Rolling at approval would make the "spin" a replay of a known result.

Guards: duplicate pending verification per property is rejected; the property cannot already be `sold`/`rented`/`pending_verification`; at least one proof document is required (also enforced by a schema validator).

---

## 7. Saved Searches & Notifications

On **every** property creation the controller loads **all** `SavedSearch` documents with `isActive: true` and matches in JS:

| Filter | Rule |
|---|---|
| `city` | case-insensitive equality against `prop.address.city` |
| `propertyType` | string equality against the property's `propertyType` **ObjectId** |
| `availableFor` | case-insensitive equality against `listingType` |
| `priceRange` | `low` < ₹50 L · `mid` ₹50 L–₹1.5 Cr · `high` > ₹1.5 Cr |

Matches become `Notification` documents via `insertMany`, whose `post('insertMany')` hook **sends one email per notification** (subject to `user.preferences.emailNotifications`). The hook appends `?intendedFor=<email>` to `data.actionUrl`.

Two consequences worth knowing before changing anything here:
- The match is O(all active saved searches) per listing, in the request path.
- The `propertyType` comparison compares an ObjectId to whatever the user stored — user-created listings frequently have no `propertyType` ref at all (only `propertyTypeName`), so that filter usually excludes rather than includes.

---

## 8. Chat & Site Visits

- A conversation is always scoped to a **property** and has exactly two participants.
- `startConversation` accepts **only `propertyId`**. The owner is derived from the property — a fix for an IDOR/spam vector where the client could name any `ownerId`.
- Unread counts are a `Map<userId, Number>` on the conversation, incremented on send and zeroed when the recipient fetches messages.
- Message text is HTML-escaped and capped at 5 000 chars. ⚠️ `conversation.lastMessage.text` stores the **raw** text — the inbox preview renders unescaped content.
- **Site visits ride on chat.** `Message.messageType` includes `visit_request` and `visit_confirmation`; `VisitModal` sends one and `ChatWidget` renders an accept affordance. There is no separate Visit collection — the admin "Site Visit Management" page reads these messages.
- Reporting a message creates a `Report` with `contextType: 'message'`, surfaced in the admin Reported Messages page.

---

## 9. Agreements

See [API_REFERENCE.md](API_REFERENCE.md) for the request shape. The business rules:

1. **The platform never trusts client-supplied money.** Rent, deposit, and maintenance are read from the `Property` document at generation time and stamped with `amountSource` + `amountVerifiedAt`.
2. **Aadhaar is truncated to 4 digits** before storage, everywhere.
3. **Jurisdiction switches the document type.** Maharashtra → Leave & License (Licensor/Licensee, citing the Maharashtra Rent Control Act 1999). Everything else → Residential Rental Agreement (Lessor/Lessee).
4. **AI is optional.** Gemini `gemini-2.0-flash` generates the prose, but any failure — missing key, API error, timeout — falls back to `buildLocalAgreement()`. The endpoint has no hard AI dependency.
5. **Prompt injection is defended structurally**, not just by filtering: an immutable `systemInstruction` declares core legal clauses non-negotiable, and user terms are wrapped in `<user_additional_terms>` tags with an explicit instruction to treat them as literal data. ~25 regexes reject obvious attempts up front.
6. **Tamper detection.** `contentHash` is verified before a signature is accepted; a modified agreement cannot be signed.
7. **Idempotency is status-scoped** — a cancelled/terminated/expired agreement can be regenerated for the same owner+buyer+property.
8. `lockInPeriodMonths = min(3, durationMonths)`.

---

## 10. Builder Projects & Group Buy

### Hierarchy
`Builder → Project → UnitType → GroupBuyCampaign → CampaignMember`, with every level denormalizing its ancestors' ids so listing queries avoid `populate`.

### Why nothing is required on Project/UnitType
The schemas state it explicitly: these are **admin-authored** records. Only the server-set references (`builder`, `createdBy`, `project`) are enforced. Admins save partial drafts and fill in details over time. **Do not add `required: true` to data fields.**

### Denormalized counters and who maintains them
| Field | Maintained by |
|---|---|
| `Project.priceRange {min,max}` | `unitTypeController` — recomputed by aggregation on unit-type create/update/delete |
| `Project.unitTypeCount`, `Project.activeCampaignCount` | project/campaign controllers |
| `UnitType.activeCampaignCount` | campaign controller |
| `GroupBuyCampaign.memberCount`, `paidMemberCount` | `CampaignMember` **post-save hook**, which recounts via `countDocuments` rather than incrementing |

### Group buy mechanics
Deliberately simple: no negotiation, no milestones, no gateway.
- Admin pre-agrees terms with the builder and creates the campaign with a **flat ₹ `discountPerBuyer`** (not a percentage), `minBuyers ≥ 2`, an optional `maxBuyers`, a date window, and free-text `perks[]`.
- Users join; joining is **atomic**: `findOneAndUpdate` with `status:'active'`, `duration.endDate > now`, and `$expr: {$lt: ["$memberCount", "$buyerTargets.maxBuyers"]}`, incrementing `memberCount`. If the subsequent `CampaignMember.create` fails (duplicate → 409), the increment is rolled back.
- Users pay DealDirect's UPI and upload a screenshot; an admin verifies and sets `tokenStatus: 'paid'`.

### Booking flow (QR/UTR, no payment gateway)
```
enquiry → payment_submitted → confirmed → completed
                            ↘ cancelled
```
- `GET /api/bookings/payment-config` is **auth-gated** so the UPI QR URL never ships in client bundles; 503 if `DEALDIRECT_PAYMENT_QR_URL` is unset.
- Admin approval decrements inventory **atomically**: `findOneAndUpdate({_id, "inventory.availableUnits": {$gte: 1}}, {$inc: {availableUnits: -1, bookedUnits: +1}})`. If that returns null (last unit taken concurrently), the booking is auto-cancelled, the client is emailed, and the API returns 409.
- `syncBookingToCampaign` then auto-enrols the buyer as a **paid** `CampaignMember` in any active campaign for that project+unitType, keeping the group-buy counter honest against real bookings.

---

## 11. Moderation

| Surface | Trigger | Admin action |
|---|---|---|
| Property listing | `POST /api/properties/:id/report` (reason ≥10 chars, **awards 100 pts**) | Property Reports page → `PUT /api/admin/reports/:id` |
| Chat message | report from ChatWidget | Reported Messages page |
| Listing quality | admin judgement | `PUT /api/properties/disapprove/:id` — **rejection reason mandatory** |
| User conduct | admin judgement | `PUT /api/users/block/:id` — revokes all that user's sessions |

Duplicate active property reports from the same user are rejected. `Report.status`: `pending → reviewed → resolved | dismissed`; reaching any non-pending state stamps `reviewedBy` + `reviewedAt`.

Note: paying 100 points for a report is an incentive that a hostile user could farm; the only guard is the one-active-report-per-user-per-property rule.

---

## 12. Analytics

**Owner** (`GET /api/leads/analytics`): status breakdown, daily lead series over N days, top-10 properties by lead count, conversion rate, leads this week, unread count — all Mongo aggregations scoped to `propertyOwner`.

**Admin** (`GET /api/admin/dashboard/stats`): user/property/lead totals, approved vs pending, rent vs sale split (regex on `listingType`), lead funnel, three 6-month `$dateToString` series, 5 most recent properties, top 5 owners by property count via `$lookup`.

Both run **live aggregations on every request** — no caching, no materialized views.

---

## 13. Business Invariants — Do Not Break

1. One property per owner account (transaction-enforced).
2. Maximum 5 active interests per buyer.
3. A buyer cannot express interest in their own listing.
4. `Lead` is unique per `{user, property}`.
5. Builder properties never appear in the consumer feed, and vice versa.
6. Agreement money always comes from the Property document.
7. Aadhaar is stored as last-4 only.
8. Deal rewards are rolled at **claim** time, once per party.
9. Group-buy discount is a flat ₹ amount per buyer, not a percentage.
10. Inventory decrement must stay atomic with a `$gte: 1` guard.
11. Campaign counters are **recounted**, never incremented, by the post-save hook.
12. The Agent role stays retired.
13. `send_enquiry` earns at most 5 times per day.
14. Redemption failure refunds points.
