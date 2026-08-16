# CHANGELOG_AI.md — Architectural Change Log for AI Assistants

**This file is written by AI assistants, for AI assistants.** It is not a user-facing release log and not a substitute for git history.

## Why this file exists

Git tells you *what* changed. This file tells you *what a future session needs to know* about a change — the reasoning, the assumptions, the invariants introduced or broken, and which documents in `AI/` are now stale.

## When to append an entry

Append when you make a change that would surprise a session reading only the code:

- Schema change (field added/removed/renamed, index added, enum extended)
- New endpoint, or a change to an existing endpoint's contract
- Auth or authorization change
- A new invariant, or the removal of one
- Behaviour that contradicts something documented in `AI/`
- Fixing anything listed in [KNOWN_BUGS.md](KNOWN_BUGS.md)
- Adding, removing, or upgrading a dependency in a way that changes behaviour
- Any change to the middleware order in `server.js`

**Do not append** for: typo fixes, styling tweaks, copy changes, or refactors with no behavioural effect.

## Format

```markdown
## YYYY-MM-DD — <short title>

**Files changed**
- `path/to/file.js` — what changed there

**Reason**
Why. The problem, not the diff.

**Architectural impact**
What a future session must now assume. New invariants, removed invariants,
behaviour that changed. Write "None" if genuinely none.

**Migration notes**
Data migration, env vars, deploy ordering, backfill. "None" if none.

**Docs updated**
Which files in AI/ were edited to stay accurate. If you changed behaviour and
did NOT update the docs, say so explicitly — that is a debt marker.
```

## Rules

1. **Newest entries at the top**, directly under this line.
2. Never rewrite or delete an existing entry. Correct it with a new one that references the old.
3. If a change makes an `AI/` document wrong, **fix that document in the same change** and say so under *Docs updated*.
4. Be specific about invariants. "Made property search faster" is useless; "search now uses a `$text` index, so leading-wildcard matching no longer works" is what the next session needs.

---

## 2026-08-13 — Mobile plan of record rewritten: four product decisions, 18-defect register (docs only)

**Files changed**
- `dealdirect-mobile/docs/HANDOFF.md` — new §9 (decisions D1–D4, defect register F1–F18, wave plan W1–W5); §1, §4, §8 corrected to match
- `MOBILE_APP_ARCHITECTURE_PLAN.md` — marked historical with a banner; no longer a source of scope
- `dealdirect-mobile/docs/API_CONTRACT.md` — wallet shape corrected (no `balance` key), `utrNumber`/payment-status shape added to bookings, store/redeem marked dead, chat/agreements banners
- No application code was modified

**Reason**
Chirag reviewed the mobile app, found the home search bar fake and the plan not reflecting reality, and asked for a bulletproof handover plan following `client-next` business logic. A four-way sweep (website surface, mobile wiring, plan doc, business-logic parity) produced the defect register; Chirag then decided four open product questions.

**Decisions recorded (2026-08-13, Chirag)**
- **D1** Agreements withdrawal stands; mobile deletes its three placeholder stubs.
- **D2** Chat/messages: unmount all mobile entry points (incl. `SocketProvider`/`PushBridge`), keep code on disk — the website's own pattern (B17's unmounted `ChatProvider` is deliberate product state, not just a bug).
- **D3** Rewards redemption is a **separate workstream** (real money); this roadmap ships display-only rewards changes.
- **D4** Group buy is **on hold** until the website's own group-buy work settles; booking wire-correctness fixes proceed anyway.

**Most consequential new findings** (full list: HANDOFF §9.3)
- Mobile rewards screen shows 0 points for every user (`wallet.balance` read; service returns `availablePoints`).
- Booking payment sends `utr`; controller reads `utrNumber` — the reference number is silently discarded.
- Mobile types `payment.verified`/`payment.utr` which don't exist on `ProjectBooking`; the booking screen can never show verified/rejected.
- Website bug found in passing: `ProfileContent.jsx:1155` still links to the 404'd `/agreements` page (recorded in HANDOFF §9.7 with six others).

**Migration notes**
None. Documentation only. Note for deploy planning: the next `git push` is a deploy (Hostinger imports `origin/main`) and flips three API surfaces under the app — `listingType` starts working, agreements and store/redeem 404. HANDOFF §9.6 sequences W2/W3 around that.

**Docs updated**
`dealdirect-mobile/docs/HANDOFF.md`, `dealdirect-mobile/docs/API_CONTRACT.md`, `MOBILE_APP_ARCHITECTURE_PLAN.md`, this file.

---

## 2026-08-14 — Auth screen shell + Alert/toast split (frontend only)

**Files changed**
- Added: `src/auth/components/AuthShell.tsx`, `src/auth/components/AuthResult.tsx`
- Modified: all five `app/(auth)/*` screens, `src/ui/EmptyState.tsx` (new `actionVariant` prop), plus the seven screens whose alerts changed

**Reason**
Closes the two items the previous entry left outstanding. Full detail in **`dealdirect-mobile/docs/HANDOFF.md` §9.10**.

**Auth**
Five screens shared no layout: four centred their content, register did not, all padded at 24 against the app's 16, and each had a different back affordance. Now one `AuthShell`, with centring as an explicit prop — `center={false}` for the two tall forms, because centring a scroll view taller than the viewport clips the top and puts the title out of reach. Their four hand-built terminal states became `AuthResult`, which adds the icon all four lacked.

**The Alert/toast rule, now applied consistently**
A modal is for a **question**; a toast is for an **answer**. Thirteen alerts became eight. The eight that remain are all destructive confirmations or genuine questions, and each now fires a toast on completion. Converted: close-deal submission, OTP resend, photo-permission explanation, invalid-video error.

One documented exception: "Cannot place calls" stays a modal because it carries a phone number the user must transcribe, and a 2.6-second toast cannot serve that.

**Migration notes**
None — presentation only. `tsc --noEmit` clean, `expo lint` 0 errors (1 unused-var warning, pre-existing in `ThemeProvider.tsx`), `expo export --platform android` succeeds. **Not run on a device.**

**Docs updated**
`dealdirect-mobile/docs/HANDOFF.md` (§9.10), this file.

---

## 2026-08-14 — Mobile UI system pass (frontend only; backend untouched)

**Files changed**
- `dealdirect-mobile/` only.
- Added: `src/ui/ScreenHeader.tsx`, `src/ui/ListGroup.tsx`, `src/ui/Metrics.tsx`, `src/ui/Toast.tsx`, `scripts/adopt-screen-header.mjs`
- Modified: `global.css`, `src/theme/{colors,fonts,layout,index}.ts`, `src/ui/{Card,Button,TabBar,index}.tsx`, `app/_layout.tsx`, and ~25 route files

**Reason**
Chirag: every screen except Home looked unfinished. Full write-up, including the rules that follow for new screens, is in **`dealdirect-mobile/docs/HANDOFF.md` §9.10** — read that, not this entry.

**Four systemic faults, all fixed**
1. **Two typefaces.** `FontOverrideProvider` was mounted at Home's root only; it now sits at the app root, so the whole app is DM Sans.
2. **`global.css` and `colors.ts` were out of sync** — both `--color-background` and `--color-surface` were bound to pure white, defeating the depth ladder `colors.ts` documented. `Screen` reads the CSS, so every screen was a white card on a white page. Both now bind `palette.canvas`; `Card`'s `bordered` default flipped to `false`.
3. **20 screens duplicated the same header.** Now one `ScreenHeader`; the codemod that converted them is kept in `scripts/`.
4. **Headers padded at 20, content at 16** — titles misaligned with content app-wide, and skeletons shifted 4pt when data landed. `screenPadding` is now a token.

**Two rendering bugs fixed in passing**
- `Button`'s disabled state never rendered: its animated `style` returned `opacity: 1` unconditionally and merges after NativeWind's classes, overriding `opacity-50`. Every disabled button looked enabled.
- `Card`'s press feedback dimmed (the language of *disabled*); it springs now.

**New invariants**
- Press feedback is scale, never opacity.
- Tab screens use `edges={['top']}` — `TabBar` already pays the bottom inset.
- `Alert.alert` is for questions and errors; confirmations use the new `useToast()`.

**Migration notes**
None — presentation only, no API or data change. Verified with `tsc --noEmit` (clean), `expo lint` (0 errors; 17 warnings, all in generated/config files or pre-existing rule classes) and `expo export --platform android` (succeeds). **Not run on a device.**

**Docs updated**
`dealdirect-mobile/docs/HANDOFF.md` (§9.10), this file.

---

## 2026-08-13 — Mobile W1–W5 implemented (frontend only; backend untouched)

**Files changed**
- `dealdirect-mobile/` only. No file under `backend/`, `client-next/` or `Admin/` was modified.
- Deleted: `app/agreements/` (3 placeholder routes), `src/features/home/components/SearchSheet.tsx`
- Added: `src/features/home/components/HeroSearchField.tsx`, `src/features/rewards/components/RewardReveal.tsx`, `src/features/content/` (blog, faq, pages), `app/blog/index.tsx`, `app/blog/[slug].tsx`, `app/support.tsx`

**Reason**
Executes the wave plan in `dealdirect-mobile/docs/HANDOFF.md` §9.4. Full per-wave implementation notes, including every place the code diverged from the scope and why, are in **§9.9 of that file** — read it rather than reconstructing from this entry.

**Invariants introduced or changed**
- **Chat is unmounted, not deleted.** No app path reaches messaging. The `chat` tab route stays registered with `href: null` — deleting that declaration puts Messages back in the tab bar. `SocketProvider` and `PushBridge` are no longer mounted, so the app holds no socket connection and requests no notification permission.
- **Agreements: mobile has no client and no routes.** `src/api/endpoints/agreements.ts` remains, unregistered, with a header explaining the withdrawal.
- **Rewards: no redemption path on mobile.** `useRewardsStore` and `useRedeemReward` are removed; the screen links to the website. Re-adding them needs the D3 decision.
- **One search implementation.** Home's hero field is real and commits to the Search tab; there is no second search surface.
- **`area.pricePerSqft` is derived on submit**, never asked for and never read back on edit, so it cannot go stale against a changed price.
- **Close-deal outcome is derived from `listingType`**, not chosen, so a sale listing can no longer be closed as "rented".

**Contract corrections that were live bugs**
- Wallet: `availablePoints`, not `balance` (every user previously saw 0 points).
- Booking payment: `utrNumber`, not `utr`; `payment.status` enum, not a `verified` boolean.
- `POST /properties/add` and `POST /properties/interested/:id` both carry a `reward` object; both were being discarded.

**Migration notes**
None — client-side only, no schema or data change. Verified with `npx tsc --noEmit` (clean), `npx expo lint` (0 errors, pre-existing warnings 13 → 11) and `npx expo export --platform android` (succeeds). **Not run on a device.** The deploy caveat from the previous entry still stands.

**Docs updated**
`dealdirect-mobile/docs/HANDOFF.md` (§9.4 status banner, new §9.9), this file.

---

## 2026-08-03 — `listingType` added to `/properties/search` (approved backend change)

**Files changed**
- `backend/controllers/propertyController.js` — `searchProperties` reads an optional `listingType`
- `dealdirect-mobile/` — Home screen rebuilt as a discovery surface; `listingType` threaded through the mobile contract, filter model and browse screen

**Reason**
Rent versus sale is the primary axis of any property search and could not be
filtered server-side. The website works around it by loading every property and
filtering client-side, which the mobile app is forbidden to do. Approved by the
owner as an additive change.

**What it does**

| Send | Matches |
|---|---|
| `rent` | `Rent`, `rent` |
| `sale` / `sell` | `Sell`, `Sale`, `sell`, `sale` |
| anything else | ignored; filter not applied |

The `$in` expansion is required rather than defensive. The schema enum holds six
spellings of three meanings, so `filter.listingType = value` would return only
the listings that happen to share the caller's casing — roughly half the correct
set, silently.

**Verified against the running backend**

| Query | Total |
|---|---|
| baseline | 36 |
| `listingType=rent` | 24 |
| `listingType=sale` | 12 |
| `listingType=nonsense` | 36 |

24 + 12 = 36, so the partition is exact and no listing is stranded. An
unrecognised value returning the full list rather than an empty one is
deliberate: a typo should degrade to "no filter", never to "no results".

**Architectural impact**
Backward-compatible by construction. Omitting the param leaves the query
identical to before and the response shape is untouched, so `client-next` and
`Admin` are unaffected — neither sends it. This is now the correct way for any
client to split rent from sale; do not filter `listingType` client-side, and do
not use the `search=for Rent` title-text trick, which depends on a title naming
convention rather than on data.

**Migration notes**
None. No schema change, no index change, no backfill. `listingType` is already
indexed via `{ listingType: 1, status: 1, createdAt: -1 }`.

**Deploy ordering** — the change is live on the local backend only. Until it
ships to `backend.dealdirect.in`, a mobile build pointed at production sends
`listingType` and production ignores it, so the Home rent/sale cards land on an
unfiltered list. Wrong, but not broken, and it corrects itself on deploy.

**Docs updated**
- `dealdirect-mobile/docs/API_CONTRACT.md` — §4.1 table row and the replaced
  "no listingType param" note

---

## 2026-08-03 — Mobile M3 (property discovery), and three backend data findings

**Files changed** — all under `dealdirect-mobile/`, plus this log. **No backend,
website or Admin file was touched.**
- `src/features/properties/*` — new: adapter, search data access, infinite feed
  hook, card, skeleton, list
- `src/features/search/*` — new: filter model, recent searches, autocomplete
  hooks, search bar, suggestion panel, filter sheet
- `src/api/queryKeys.ts`, `src/lib/useDebouncedValue.ts` — new
- `app/(tabs)/index.tsx`, `app/(tabs)/search.tsx` — replaced M1 stubs
- `src/ui/PriceLabel.tsx` — **corrected**, see finding 2
- `src/types/backend/property.ts` — **corrected** suggestions type, see finding 3
- `dealdirect-mobile/docs/API_CONTRACT.md` — new §4.1, §4.2, discrepancy #5

**Reason**
M3 of the approved mobile plan. Everything was verified against the live
production API before being built, which is where the three findings came from.
None of them is visible from reading the backend source alone; all three need
the data.

**Finding 1 — taxonomy refs are corrupt in production.**
On the 36 approved listings, `Property.category`, `.subcategory` and
`.propertyType` are `null` on 15, and on the other 21 the `propertyType` ref
points at the **same** document (the one named "Plot") regardless of what the
listing is — apartments and penthouses included. Probing all 19 categories
through `/properties/search`, only two match anything ("Residential Plot" → 17,
"Commercial Land" → 4) and both match the wrong listings. The denormalised
`categoryName` / `propertyTypeName` strings are correct on every row.

Consequence: the `category`, `subcategory` and `propertyType` params on
`/properties/search` are unusable, and the website's category filtering is
presumably affected the same way. The mobile app therefore ships **no category
or property-type filter**. A backfill of the refs from the denormalised names
would fix all of it with no client change. **Not attempted here** — writing to
production property documents is well outside this milestone.

**Finding 2 — `priceUnit` is not a unit.**
It defaults to `"Lac"` (`models/Property.js:23`) and carries that default on 15
of 36 listings whose `price` is plainly in rupees (65000, 17800000, 36000).
`price` is rupees. The website's display path (`utils/formatPrice.js`) already
treats it that way and never reads `priceUnit`; its separate `normalizePrice`
helper *does* multiply by 1e5 on `"Lac"`, and is used for the website's own
client-side price-range filter and price sort — both of which are consequently
wrong on those rows. M1 had ported `normalizePrice` into the mobile `PriceLabel`
believing it was the display path; that has been removed. Left as-is, it would
have rendered a ₹65,000 rental as "₹650 Crore".

**Finding 3 — `/properties/suggestions` returns objects, not strings.**
`{type, value, subtitle, image?}` where `type ∈ project | locality | city`. M0
had typed it `string[]`. Corrected in the mobile types and the contract doc.

**Architectural impact**
Backend behaviour is unchanged — nothing here is a code change to the server.
What changes is what a future session may assume:
- Do **not** filter properties by `category` / `subcategory` / `propertyType`
  ObjectId in any client until the refs are backfilled. Use the denormalised
  name columns for display.
- Treat `Property.price` as rupees. Do not multiply by `priceUnit`.
- `buildingType` and `size` are accepted by `searchProperties` but exist on no
  schema; Mongoose 8 defaults `strictQuery: false`, so sending either passes an
  unknown path to Mongo and empties the result set.
- `/properties/search` has no `listingType` param, so rent-versus-sale cannot be
  filtered server-side by any client.

**Migration notes**
None applied. Two candidate backend changes are *proposed and unapproved*:
(a) backfill the taxonomy refs from `categoryName` / `propertyTypeName`;
(b) add `listingType` as an optional `/properties/search` param, which is
additive and changes no existing response. Both need approval under section 7 of
`MOBILE_APP_ARCHITECTURE_PLAN.md`.

**Docs updated**
- `dealdirect-mobile/docs/API_CONTRACT.md` — §4.1 (which search params actually
  work, with measurements), §4.2 (suggestions shape), §8 discrepancy #5
- `dealdirect-mobile/README.md` — M3 status, the two open decisions
- `AI/KNOWN_BUGS.md` — findings 1 and 2 added as backend data bugs
- **Not updated, deliberately:** `AI/DATABASE.md` and `AI/API_REFERENCE.md` still
  describe the taxonomy refs and `priceUnit` as if they were sound. They are
  accurate about the *schema*; the findings above are about the *data*. Flagged
  here so a future session does not read them as contradicted.

---

## 2026-08-01 — Pre-Hubble redemption layer removed

**Files changed**
- `backend/services/rewardService.js` — removed `REWARDS_STORE`, `redeemPoints()`, `getRedemptionRequests()`, `updateRedemptionStatus()`
- `backend/controllers/rewardsController.js` — removed `redeemReward`, `getRewardsStore`, `adminGetRedemptions`, `adminUpdateRedemption`
- `backend/routes/rewardsRoutes.js` — removed 4 routes
- `backend/models/RedemptionRequest.js` — **deleted**
- `backend/server.js` — removed 2 now-dead CSRF guard entries
- `client-next/src/utils/api.js` — removed `rewardsApi.getStore()` / `.redeem()`
- `client-next/.../RewardsDashboardContent.jsx` — removed `handleRedeem` + `redeemLoading`
- `Admin/src/pages/RewardsManagement.jsx` — removed the Redemption Requests tab, its modal, and dead state
- `Admin/src/api/adminApi.js` — removed `getRedemptions` / `updateRedemption`

**Reason**
Redemption moved to the **Hubble Gift Card SDK**. The in-house store it replaced was left in place and had rotted into a trap: an audit pass (mine) read the schema and reported a live "user burns 20,000 points and can't be paid" bug. The owner challenged it and required proof of reachability.

**Reachability proof, gathered before deleting anything:**
| Check | Result |
|---|---|
| `rewardsApi.getStore()` call sites in `client-next` | **0** |
| `handleRedeem()` invocations (any `onClick`) | **0** — defined, never called |
| What the Redeem tab renders | `<HubbleStorefront/>` **only** |
| `RedemptionRequest` documents in production | **0** |

All four removed endpoints confirmed 404 after the change; every surviving rewards endpoint still responds.

**Architectural impact**
- **`Reward` (the wallet), the earning engine, tiers, and multipliers are untouched and remain load-bearing.** Hubble reads and writes them through `GET /hubble/balance`, `POST /hubble/debit`, `POST /hubble/reverse`. Do not confuse the wallet with the removed redemption layer.
- `POST /api/rewards/redeem`, `GET /api/rewards/store`, `GET|PUT /api/rewards/admin/redemptions*` no longer exist.
- The RewardPort catalogue endpoints (`/catalogue/*`) were **left in place** — separate integration, still routed.
- Admin Rewards Management now has 3 tabs (Overview, User Wallet Lookup, Adjust Points).

**Verified**
Backend boots clean with zero load errors; `client-next` `next build` compiles; `Admin` `vite build` succeeds.

**Migration notes**
- The `redemptionrequests` collection is now unreferenced. It held 0 documents, so it can be dropped whenever convenient.
- `updateRedemptionStatus()` contained the only points-refund-on-failure logic. It was unreachable, but if a redemption flow is ever rebuilt, that refund behaviour must be reimplemented.

**Process note**
This is the second finding in one session that dissolved under a reachability check (the first: chat being unmounted was an intentional client decision). **Presence of code in this repository does not imply users can reach it.** Going forward, prove a path from UI → API → database before reporting a defect.

**Docs updated**
`CHANGELOG_AI.md`, `KNOWN_BUGS.md`, `SECURITY.md`, `API_REFERENCE.md`, `DATABASE.md`, `BUSINESS_LOGIC.md`.

---

## 2026-08-01 — Agreements hidden; CSRF Phase 1 enabled; CORS rejection returns 403

**Files changed**
- `backend/server.js` — `/api/agreements` mount commented out; `requireCsrf` applied to 15 named routes
- `backend/middleware/csrfProtection.js` — added `requireCsrf(allowedOrigins)` factory
- `backend/middleware/errorHandler.js` — CORS rejections now map to 403 `CORS_REJECTED`
- `client-next/src/app/agreements/page.js` — returns `notFound()`
- `client-next/src/components/Navbar/Navbar.jsx` — 3 "Agreements" links commented out

### Agreements hidden (client decision)
Withdrawn for now, to return later. **Nothing deleted** — controller, model, `AgreementsContent.jsx`, and all existing records are intact. Hidden in exactly three places, all marked `AGREEMENTS — HIDDEN`; reverse them together.

Side effect worth keeping in mind: unmounting also closes `POST /api/agreements/webhook/payment`, which skips HMAC verification whenever `PAYMENT_WEBHOOK_SECRET` is unset ([SECURITY.md](SECURITY.md) H2). **Set that variable, or make the check fail closed, before re-enabling.**

Verified: all 4 agreement endpoints return 404; unrelated routes unaffected.

### CSRF Phase 1
`validateCsrfToken` was disabled at two independent points (commented-out `app.use`, plus an early-return for every `/api/*` path) while cookies are `SameSite=None` — so CORS was the only thing standing between an attacker's `<form>` and a state-changing endpoint.

`requireCsrf` is a **new** validator, applied per-route rather than globally. The old one is untouched so nothing depending on it changes.

**Two independent checks:** Origin must be on the CORS whitelist (browsers always send `Origin` on cross-origin POST, including form submissions, and page JS cannot forge it); and the non-HttpOnly `csrf_token` cookie must equal the `X-CSRF-Token` header, compared with `timingSafeEqual`.

**Requests with no `Origin` header pass through deliberately.** CSRF depends on a browser attaching cookies to an unintended request; a client with no `Origin` (Expo app, Next.js SSR, curl, webhooks) is not that. Requiring a token there would break the mobile app — whose `api/client.ts` deliberately omits CSRF plumbing — while defending against nothing.

**15 routes protected:** rewards redeem / admin adjust-points / admin redemptions; property add, my-properties update, admin add, admin edit; mark-interested; report; campaign join/exit; contact; chat send + conversation start.

**`CSRF_ENFORCE=false` disables it instantly without a redeploy.**

Verified: 4 attack shapes → 403; trusted origin + valid token → 401 (reached auth); no-Origin → 401; public GET → 200.

### CORS rejection: 500 → 403
`cors()` signals a disallowed origin by passing an `Error`, which fell through to the generic 500 branch. Wrong semantically, and — now that Sentry reports 5xx — **every scanner sending a foreign Origin would have raised a Sentry issue and buried real errors.** Now a 403 `CORS_REJECTED` marked `isOperational`.

**Architectural impact**
- `requireCsrf` is applied in `server.js` **before** the routers, as middleware-only layers that call `next()`. New protected routes go in that block, not in route files — it is the single documented list.
- Phase 2 (extend to all authenticated mutations) is blocked on frontend regression testing and automated tests, per the owner's plan.
- Any new frontend fetch that bypasses `utils/api.js` / `adminApi.js` must send `X-CSRF-Token` manually. Both clients' axios interceptors already do this for POST/PUT/PATCH/DELETE.

**Migration notes**
- No schema or data change.
- `CSRF_ENFORCE` is a new optional variable. Absent = enforcement on.
- If a production flow breaks, set `CSRF_ENFORCE=false`, confirm the cause, then re-enable.

**Docs updated**
`CHANGELOG_AI.md`, `KNOWN_BUGS.md`, `SECURITY.md`, `API_REFERENCE.md`.

---

## 2026-08-01 — Cloudinary asset deletion + account-deletion cascade fixed

**Files changed**
- `backend/controllers/propertyController.js` — added exported `extractCloudinaryPublicId()` and `deletePropertyAssets()`; both `deleteProperty` (admin) and `deleteMyProperty` (owner) now use them
- `backend/controllers/userController.js` — corrected 4 cascade field names in `deleteAccount`; property assets are now destroyed before the records; documented the six deliberately-retained collections

**Reason**
1. **B6** — `deleteMyProperty` derived the Cloudinary `public_id` with `slice(-2)`, producing `properties/abc123` instead of `dealdirect/properties/abc123`. `destroy()` returns `{result:"not found"}` rather than throwing, so it failed **silently** and every owner-deleted image stayed publicly reachable forever. `deleteProperty` (admin) used `slice(uploadIndex + 2)`, which assumes a version segment always exists, and only walked `property.images` — never the `categorizedImages` buckets.
2. **B1** — four cascade deletes queried non-existent fields (`UserSession.userId`, `LoginTracker.user`, `Report.reporter`, `Referral.referredUser`), matching nothing while reporting success. Sessions surviving "permanent" deletion was the most serious.
3. `Property.deleteMany()` in `deleteAccount` orphaned every image with no cleanup at all.

**Architectural impact**
- **`extractCloudinaryPublicId()` is now the single correct derivation.** It handles URLs with *and* without a version segment, and preserves nested folder paths. Do not hand-roll public_id extraction again — import this.
- **`deletePropertyAssets()` is the only supported way to remove a property's assets.** It covers the flat `images` array *and* both categorised buckets, de-duplicates (the same URL often appears in both), and never throws — a storage failure must not block deleting the database record.
- `userController` now imports from `propertyController`. Verified non-circular (`propertyController` does not import `userController`) and confirmed by a clean boot.
- `Notification.deleteMany` dropped its `recipient` clause — that field does not exist on the schema.

**Verified**
Against 5 real production URLs, checked with `cloudinary.api.resource()` (read-only): **old derivation resolved 1/5, new derivation resolved 5/5.** The single old success was a legacy 2-segment path that `slice(-2)` matched by coincidence.

**Migration notes**
- **Assets orphaned before this fix still exist** — see [KNOWN_BUGS.md](KNOWN_BUGS.md) B26. A reconciliation script is needed, and must be dry-run first.
- Six collections referencing a deleted user are still retained by design — see B27. Requires a product decision, not a code fix.
- No schema change, no data migration.

**Docs updated**
`CHANGELOG_AI.md`, `KNOWN_BUGS.md`.

---

## 2026-08-01 — Backend error tracking wired up (Sentry)

**Files changed**
- `backend/instrument.js` — **new.** Loads env, then calls `Sentry.init()`
- `backend/server.js` — `import Sentry from "./instrument.js"` as the first import; `Sentry.setupExpressErrorHandler(app)` between `notFoundHandler` and `globalErrorHandler`
- `backend/middleware/errorHandler.js` — `uncaughtException` and `unhandledRejection` now report to Sentry
- `backend/package.json` — `start`/`dev` scripts now use `node --import ./instrument.js`

**Reason**
`@sentry/node` was installed and `SENTRY_DSN` was configured, but `Sentry.init()` was never called anywhere. **The backend had no error reporting at all** — only the frontend did. This is why the deal-verification regression (B2) sat broken across two commits with nobody noticing.

**Architectural impact**
- `instrument.js` **must remain the first import in `server.js`** and must keep its own env loading. ESM links the entire module graph before evaluating any module, so `Sentry.init()` running later cannot patch `express`/`http`. Verified: without the `--import` flag Sentry logs *"express is not instrumented"*; with it, the warning disappears.
- `server.js` still calls `dotenv.config()` itself. That is now redundant but deliberate — dotenv does not overwrite already-set vars, so it is a no-op, and `server.js` stays readable standalone.
- **Client-facing behaviour is unchanged.** `setupExpressErrorHandler` reports and re-throws; `globalErrorHandler` still produces the sanitised response.
- Only **5xx** are reported (`shouldHandleError`). 401s from expired sessions and 404s from scanners are normal traffic and would bury real errors.
- `sendDefaultPii: false` plus a `beforeSend` hook that strips cookies, request bodies, and the `authorization` / `cookie` / `x-csrf-token` / `x-hubble-secret` headers. This codebase handles OTPs, session tokens, and Aadhaar fragments — none may leave the server.
- Running `node server.js` without `--import` still works and still reports errors; only auto-instrumentation/tracing degrades. Fails soft.

**Migration notes**
- **`SENTRY_DSN` is absent from `backend/.env.production`.** It must be added on the production server or production still has no reporting. Backend uses its own Sentry project (`…2712784`), separate from the frontend (`…6814544`).
- Deploys must use `npm start` / `npm run dev`. A raw `node server.js` in a process manager loses instrumentation.
- Verified end-to-end: a test event was delivered (`Sentry.flush()` returned true).

**Docs updated**
`CHANGELOG_AI.md`, `KNOWN_BUGS.md`, `DEPENDENCIES.md`, `ENVIRONMENT.md`.

---

## 2026-08-01 — Deal verification 403 fixed; email links repaired; admin accounts reduced

**Files changed**
- `backend/routes/adminRoutes.js` — removed `requirePermission()` from the 3 `/verifications` routes
- `backend/utils/emailService.js` — added `toAbsoluteUrl()`; `generalNotification` now absolutises and escapes its action link
- `backend/test-smtp.js` — added as a standalone SMTP credential tester, then **deleted before the first push** (diagnostic tooling, not application code). Same for `test-sentry.js`. Ask for them to be regenerated if a mail or Sentry problem needs diagnosing.
- Production database — two admin accounts soft-deleted

**Reason**
1. **B2 (deal verification 403).** Commit `79ae3ab` added `requirePermission("verifications:read" / ":approve")`. Those codes can never resolve — `Permission.resource` is a closed enum without `"verifications"` — so every admin got 403, including super admins. Git history shows commit `e437dc6` had these routes working with `protectAdmin` alone, which is how 6 verifications were previously approved. **The fix is a revert of a recent regression, not a workaround.** Confirmed by the user in production and re-verified after the fix.
2. **Email action links were broken.** `approveDealVerification` stored a *relative* `actionUrl: "/notifications"`. Emails have no base URL, so it rendered as `http:///notifications` — empty host. Fixed at the email layer rather than the call site, because `Notification.data.actionUrl` is also intended for in-app routing where a relative path is correct.
3. **Three active super_admin accounts existed**, not one. Reduced to one at the owner's instruction.

**Architectural impact**
- Verification routes are protected by `protectAdmin` alone, matching ~35 other admin routes. To reinstate permission guards: add `"verifications"` to the `Permission.resource` enum, seed the records, attach to roles, and verify against the database **first**.
- `toAbsoluteUrl()` is now the single choke point for email links. Relative paths resolve against `CLIENT_URL` (fallback `https://dealdirect.in`); non-http schemes (`javascript:`, `mailto:`) return `null` and render no link.
- Admin removal used **soft delete** (`deletedAt` + `isActive:false` + session revocation), not hard delete, because `AuditLog` references admins by `_id` — hard deletion would orphan 123 security audit entries. Reversible; undo commands are in the session log.

**Migration notes**
- 25 stale `AdminSession` rows were revoked as part of the admin removal.
- No schema or data migration. Production DB writes were limited to 2 admin documents, 25 session documents, and 2 new audit entries.
- One `TransactionVerification` was stuck `pending`; it belonged to the owner's own test and was approved after the fix. No real customers were affected.

**Docs updated**
`CHANGELOG_AI.md`, `KNOWN_BUGS.md`.

---

## 2026-08-01 — AI knowledge base created

**Files changed**
- `AI/` — new directory, 16 documents (this file included)
- No application code was modified

**Reason**
No durable architectural documentation existed. `CLAUDE.md` was thin and partly inaccurate (claimed 26 schemas against 32 model files, 14 controllers against 19, and referenced a `client/` directory that no longer exists). Every session was re-deriving the same architecture from scratch.

This pass read the backend in full (server, config, all middleware, all 32 models, all 19 controllers, all 20 route files, all 5 services, the email utility), the `client-next` infrastructure and component surface, the `Admin` shell and routing, and the `dealdirect-mobile` scaffolding, then recorded the results.

**Architectural impact**
None to runtime behaviour. Twenty defects were identified and verified by reading source — see [KNOWN_BUGS.md](KNOWN_BUGS.md). **None were fixed.** The four most consequential:

- **B17** — the entire chat feature (backend controller, Socket.IO layer, `ChatContext`, `ChatWidget`, `ChatButton` — ~1 900 lines across the stack) is built but `ChatProvider` is never mounted and neither component is ever imported. Chat is unreachable in the web UI.
- **B2** — `adminRoutes.js` requires `verifications:read`/`verifications:approve`, but `verifications` is not in the `Permission.resource` enum, so those permission documents cannot exist and the deal-verification endpoints deny every admin. This blocks the whole deal-closure → reward pipeline.
- **B1** — `deleteAccount` cascades use four wrong field names (`UserSession.userId`, `LoginTracker.user`, `Report.reporter`, `Referral.referredUser`). Sessions in particular survive "permanent" account deletion.
- **B4** — `Property` public-visibility filters test `isBanned` and `isActive`, neither of which exists on the schema. Both clauses match everything, so there is no working ban or soft-delete for listings.

Also recorded: 7 unused backend dependencies and 1 unused frontend dependency, all verified by grep; and a significant `.env` / `.env.production` variable drift ([ENVIRONMENT.md](ENVIRONMENT.md) §4) that would disable SMS, WhatsApp, RewardPort, Hubble, booking QR, and Sentry if `.env.production` were deployed verbatim.

**Migration notes**
None. Documentation only.

**Docs updated**
All 16 files in `AI/` created:
`MASTER_MEMORY.md` · `ARCHITECTURE.md` · `FILE_MAP.md` · `DATABASE.md` · `AUTH_SYSTEM.md` · `API_REFERENCE.md` · `COMPONENT_INDEX.md` · `BUSINESS_LOGIC.md` · `STYLING_GUIDE.md` · `DEPENDENCIES.md` · `SECURITY.md` · `PERFORMANCE.md` · `ENVIRONMENT.md` · `KNOWN_BUGS.md` · `FUTURE_PLANS.md` · `CHANGELOG_AI.md`

`CLAUDE.md` was **not** modified and still contains the stale counts noted above. Consider updating it to point at `AI/MASTER_MEMORY.md`.
