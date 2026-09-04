# DealDirect Upgrade: Master Plan

Date: 2026-09-04. Author: Sakha, for Chirag.
Inputs: `dealdirectupgradeplan.docx` (the 16-week client proposal, August 2026), `AI/GROWTH_RESEARCH_PHASE2.md` (the research it was distilled from), `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md` + `DEALDIRECT-APP-FUNCTIONAL-REVIEW.md` + `dealdirect-mobile/docs/HANDOFF.md` (mobile state of record), `backend/` as read today.

Hard rule from Chirag: **the mobile Home screen is not touched.** Everything below adds routes, extends other screens, or lands behind Home's existing entry points (the Activity tiles, the Updates preview, the notification resolver). Home's file, hero, header and rails stay as they are.

---

## 0. The frame

The docx sells the client 16 platform features. Thirteen of them are server-side state that does not exist yet (alerts, deal page, visits, reviews, locality data, price history). The mobile app can be the best surface for all of them, but it cannot *be* them. So this is one plan with two lanes per feature:

- **Backend lane:** additive only. New models, new routes, new jobs. No existing contract changes, no existing route removed, nothing the website or Admin calls today behaves differently. This is the condition under which "backend is production, do not modify" and "implement the docx" can both be true.
- **Mobile lane:** the primary, designed surface. Full screens, push delivery, native texture.
- **Web thin slice (optional, per feature):** the client's users are on the website today and the app is not in a store yet. Where the feature is a message (alerts, digests, reminders) the web gets it free through the same dispatcher. Where it is a screen, the plan names the smallest web render and leaves it to Chirag whether it ships in the same week.

Three facts that override the docx's week order:

1. **The app has never run on a device.** Roughly 20 mobile commits, two Home rebuilds and the whole native layer (map, camera, location, biometrics, date picker) are verified by `tsc`, lint and `expo export` only, and the native batch cannot load without `expo prebuild` + a fresh build. Nothing gets built on top of that until a build runs and the Phase 2 QA script passes.
2. **Server push does not exist.** No device-token model, no registration route, no sender. Every "alert" feature in the docx (weeks 3, 4, 5, 7, 16) is, on mobile, a push notification. The token pipeline is therefore the first backend addition, not the last.
3. **There is no scheduler.** The backend has no cron, no job runner, one `setInterval` inside the Hubble service. Price-drop scans, weekly digests, visit reminders, nightly locality aggregation and the rental clock all need one. Built once, table-driven, reused by every later week.

---

## 1. The engines (build once, use everywhere)

Every feature below is a thin layer over one of five engines. This is the "one engine, many uses" test applied to the whole docx.

### E1. Dispatcher: `notify(userId, event)`

Extends `backend/services/notificationService.js`, which already owns persistence and email. It gains:

- A **channel policy table** keyed by event kind: `{ inApp: always, push: if token, whatsapp: journeyCritical, email: digestOrDocument }`. Journey-critical = owner replied, visit confirmed/reminder, price drop on a shortlisted home, agreement step, close verified. Everything else is in-app + push only.
- **Per-user weekly cap** (default 3 outbound WhatsApp/email per week, journey-critical exempt), enforced in the dispatcher, stored as a rolling counter on the user.
- **A deep-link payload standard**: every notification's `data` carries `{ kind, id }` from one enum. Mobile's `resolveNotificationTarget` already exists and validates before navigating; it grows one case per new kind. No screen can be raised into a confirmation or payment sheet from a notification, same invariant as today.
- **Push sender**: Expo Push Service (free, batches of 100, receipts). Tokens live in a new `PushToken` model (`user`, `token`, `platform`, `lastSeenAt`), registered by `POST /users/push-token`, removed on logout and on `DeviceNotRegistered` receipts.
- **Email transport** swapped from Gmail SMTP to Brevo SMTP (config change in `utils/emailService.js`, free 300/day, ₹ pricing beyond, no AWS onboarding). Nodemailer stays.
- **WhatsApp**: `whatsappService.js` gains a second provider behind the same three exported functions, Meta Cloud API, selected by env. WAHA remains for admin-internal sends only. Meta business verification is Chirag's action item and runs in parallel from week 1.

### E2. Scheduler: `backend/jobs/`

One in-process runner (the backend is single-instance by design, so no distributed lock is needed). A `jobs/registry.js` table: `{ name, cron, handler }`. A `JobRun` collection records `{ name, startedAt, finishedAt, cursor, ok }` so a restart mid-job does not double-send: every handler is idempotent on its cursor (last processed timestamp or id). Jobs: `price-drop-scan` (every 15 min), `visit-reminders` (hourly), `owner-weekly-digest` (Mon 08:00 IST), `locality-aggregate` (nightly), `rental-clock` (daily), `points-expiry-nudge` (daily), `notification-ttl` (native Mongo TTL index, not a job). Adds `node-cron`; nothing else.

### E3. The deal spine: `Lead`

The docx's deal page, site visits, messaging, agreement placement, reviews and close verification all attach to one existing document: `Lead` (unique per buyer+property, owner denormalised, status enum already present). No new "Deal" model. `Lead` gains, all optional:

- `stage`: `contacted → visit_scheduled → visited → agreement → closed` (derived, never set by the client; each transition has one server-side cause).
- `visits[]`: `{ scheduledAt, status: proposed|confirmed|done|cancelled|no_show, proposedBy, confirmedBy, feedback: interested|not_interested|thinking, remindersSent[] }`.
- `conversation`: ref to the existing `Conversation` (chat is fully built server-side, mounted behind `CHAT_ENABLED`).
- `agreement`: ref to `Agreement` (routes exist, mount commented out at `server.js:958`).
- `firstOwnerResponseAt`: set once, the input to the response-time display.
- `verification`: ref to `TransactionVerification` (the close; already exists).

Both parties read the same lead through one new route, `GET /leads/:id/deal`, which returns the lead with only the fields each side may see (buyer never sees owner notes; owner never sees the buyer's other leads).

### E4. Price data: `PriceChange` + `LocalityStat`

- `PriceChange` `{ property, from, to, at, listingType, city, locality, bhk }`, written from the one place price is edited (`propertyController` edit path, additive hook). Read by: price history on the listing, days-on-platform, price-drop alerts, and the nightly aggregate.
- `LocalityStat` `{ city, locality, listingType, bhk, period: YYYY-Qn, medianAsking, count, sampleFloor }`, produced nightly by E2 from live listings + `PriceChange`. Never published where `count < 5` (the honesty floor; the research is explicit that an AVM is not buildable on Indian data and we do not pretend). Read by: locality pages, "asks 8% below locality median" on listings, price guidance in the listing form, the monthly index email.

### E5. Server shortlist: `Shortlist`

Mobile already has a device-local shortlist that provably never creates a lead (the module imports no API client). The docx wants it private, unlimited, cross-device and alertable, which needs the server. `Shortlist` `{ user, property, addedAt, note }`, routes `GET/POST/DELETE /shortlist`, plus `POST /shortlist/share` producing a read-only token for a spouse/parent (research item 9). Mobile merges MMKV → server on first authenticated launch, then the local store becomes the offline cache of the server list. Invariant unchanged: **shortlisting notifies nobody and creates no Lead.** Contact remains an explicit act through the existing `POST /properties/interested/:id`.

---

## 2. Feature register

Each row maps one docx week to its engines and its mobile surface. Effort is Chirag-plus-Sakha at full sessions, both lanes included. S ≤ 2 d, M 3–5 d, L 1–2 wk.

| # | Docx wk | Feature | Backend (additive) | Mobile surface | Web thin slice | Effort |
|---|---|---|---|---|---|---|
| F1 | 1 | Reward payout fixes | B5 `upload_5_photos` map entry; B11 referral milestones wired (`first_action` on interest/listing, `deal_closure` on claim); B12 streaks: **delete** `LoginTracker` + `monthlyLoginDays` write (research reversed this one) | Rewards screen copy already honest; transactions show the new lines | none | S |
| F2 | 1 | Notification cleanup | TTL index on `Notification` (`isRead:true` + 90 d) | none | none | S |
| F3 | 1 | Usage tracking | `Event` collection `{ user?, anon, name, props, at }`, `POST /events` (batched, rate-limited, 30 names whitelisted), TTL 90 d raw + monthly rollup job | `track()` helper, 12 events: session start, search, view, shortlist, save search, contact, visit booked, visit done, agreement, claim, alert opened, push opened | same helper on web | M |
| F4 | 1 | Email provider | Brevo SMTP env swap | none | none | S |
| F5 | 1 | Official WhatsApp | Meta Cloud API provider in `whatsappService` behind env; templates registered | none | none | M (+ Meta verification wait) |
| F6 | 0 | **Push pipeline** (not in docx; prerequisite for weeks 3–16 on mobile) | E1: `PushToken`, `POST /users/push-token`, Expo sender, receipts | Register on login, remove on logout; permission asked at the first moment it earns it (first shortlist or saved search), never on launch; Updates tab reads badge from the same store | none | M |
| F7 | 2 | Shortlist | E5 | Activity › Shortlist becomes server-backed; heart on cards/detail; share sheet; "Continue where you left off" already exists (`ResumeSearchCard`) | `/shortlist` page, list only | M |
| F8 | 3 | Saved searches + new-match alerts | Honour `notifyEmail`/`notifyInApp` (today ignored), add `notifyPush`; `notifySavedSearchMatches` routes through E1 | First-session prompt after the second search ("Get told when a 2BHK in Wakad under ₹30L is listed"), Activity › Searches shows last-match time; deep link opens results pre-filtered | flags honoured automatically | M |
| F9 | 4 | Price-drop alerts | E4 `PriceChange` + E2 scan job over shortlist + saved-search matches | Detail shows "Price dropped ₹2L on 3 Sep"; push deep-links to the listing | badge on listing | M |
| F10 | 5 | Owner weekly report | E2 job: views, new leads, awaiting reply, response time; email + push; opens analytics | Owner › Analytics gains a "This week" card and a "waiting on you" list, in that order | email only | M |
| F11 | 6 | Deal page | E3 `GET /leads/:id/deal`, stage derivation, `PUT /leads/:id/stage` refused (server-derived) | New route `app/deal/[leadId]`; progress tracker pre-stamped ("Contact made: 4 Sep") with the reason shown; Activity › Enquiries becomes **Deals** and lists by stage; owner reaches the same page from the lead card | `/deals/:id` page | L |
| F12 | 7 | Site visits | `visits[]` on Lead: propose (either side), confirm (other side), done/no-show (either, both asked), feedback (buyer, 3 taps); E2 reminders T-1d, T-2h through E1 | Native date/time picker on the deal page; calendar add via `expo-calendar` (one new native module, evaluated); post-visit feedback sheet arrives as a push that opens straight to the three buttons | propose/confirm on the deal page | L |
| F13 | 8 | Messaging in the deal | `CHAT_ENABLED=true`; **preconditions before flipping**: B3 stored XSS in `lastMessage.text`, B7 socket JWT accepted as REST bearer, `POST /chat/message/report` route, and a lure detector (regex table: token/advance/UPI/QR patterns) that injects a warning system message | Chat thread mounted **only** inside `app/deal/[leadId]`; the dark `(tabs)/chat` stays dark; socket connects only while a deal page is open; push for new message when app is backgrounded (E1) | thread inside the web deal page | L |
| F14 | 9 | Agreement in the deal + response speed | Mount `agreementRoutes` (re-opens D1, Chirag decides); agreement generation offered at stage ≥ `visited`; `firstOwnerResponseAt` median exposed as `responseHours` on public listing payload | "Generate agreement" appears on the deal page at the right stage, PDF in a viewer, sign flow; listing cards and detail show "usually replies within ~4 h" only when ≥ 3 leads exist for the owner | same | L |
| F15 | 10 | Rewards adjustment | New action rows in `rewardService` (visit confirmed by both, agreement completed: **non-cashable points**), fixed close payout with shagun draw as bonus, `payoutHoldUntil` on `TransactionVerification`, anti-fraud fields on User (`deviceHash`, `payoutVpa`, `accountAgeAtClose`) and a linkage query in the admin approve path | Rewards screen explains the milestones honestly; claim screen shows the hold with its reason | same explainer | M, **after Chirag shows the client the numbers** |
| F16 | 11 | Verified-deal reviews | `Review` `{ verification, author, subject, ratings{accuracy, responsiveness, seriousness}, text, submittedAt, publishedAt }`; both submit, publish when both are in or after 14 d; only parties of an approved `TransactionVerification` may write | Prompt arrives with the reward claim; owner block on the detail shows published reviews | owner block | M |
| F17 | 12 | Badges + buyer seriousness | `User.verification { identity, documents }` set by the existing admin verify path; lead payload gains `buyerContext { activeWeeks, shortlistsInLocality, budgetFit }` computed on read, aggregate only | Badge on owner block and cards; lead card shows the three signals | badge | M |
| F18 | 13 | Locality price pages | E4 `LocalityStat` + `GET /localities/:city/:slug` | New route `app/locality/[slug]`; reached from the detail's locality line and from search results header; charts via the existing chart primitives | **SSR page on web; this is where the SEO value is, the mobile screen alone earns none of it** | M |
| F19 | 14 | Price intelligence on listings | Reads E4: history, days listed, delta vs median; `priceGuidance` on `POST /properties/add` response | Detail "Price" section grows three lines; listing form step shows "Similar 2BHKs in Wakad ask ₹28–34L" while the owner types | detail lines | S |
| F20 | 15 | EMI + compare | none | **Already built** (`tools/emi`, `tools/affordability`, compare mode in search). Polish pass only: compare from shortlist, EMI prefilled from the listing price | web has EMI; compare optional | S |
| F21 | 16 | Rental clock + referrals + expiry | E2 daily job: verified rentals at month 10 → owner and tenant; referral offer at `claim-deal-reward` response; `Reward.pointsExpireAt` (does not exist today, additive) + nudge at 14 d | Updates carries all three; claim screen shows the referral card at the high point; rewards screen shows expiry | email for the clock | M |

Deliberately not in the register (research verdicts, unchanged): AVM or "fair price" estimates, login streaks, contact masking, group buy (D4 still held), society management software, a floating site-wide chat widget.

---

## 3. Phases and order

Dependencies, not the docx's calendar, set the order. Each phase ends with a device pass and a local commit; nothing is pushed or deployed until Chirag says so, and production ships in the order **backend → mobile build → web**.

### Phase 0. Stand on ground (weeks 1–2)

Goal: an app that provably runs, reports crashes, and can be told things.

1. `expo prebuild --clean`, EAS development build, run `DEALDIRECT-MOBILE-PHASE2-QA-SCRIPT.md` on a physical Android. Fix what breaks. This is the gate above every other line.
2. Sentry for mobile (W9): `sendDefaultPii: false`, user `{id, role}` only, release + `X-App-Version` correlation. Needs a mobile DSN.
3. E1 dispatcher + F6 push pipeline + F4 email swap + F2 TTL.
4. E2 scheduler skeleton with one job (`notification-ttl` is Mongo-native, so the first real job is F10's digest, dry-run mode).
5. F1 reward fixes, F3 event tracking.
6. F5 WhatsApp provider scaffold; Chirag starts Meta verification (documents from the client).

Exit: a push arrives on a locked phone from a backend event; a forced crash shows in Sentry; the QA script passes; the dashboard query for "first-session activation" returns a number.

### Phase 1. The return spine (weeks 3–5)

F7 shortlist → F8 saved-search alerts → F9 price-drop alerts. In that order because F9 scans F7's and F8's data, and F8's first-session prompt is the top-of-funnel for both.

Exit: a price edit on a shortlisted home produces a push within 15 minutes that opens the listing; a new listing matching a saved search does the same; the Activity tab is fully server-backed and works offline from cache.

### Phase 2. The deal room (weeks 6–10)

F11 deal page → F12 visits → F13 messaging → F14 agreement + response time → F10 owner digest (now that there is something to report on).

Two product decisions gate this phase (see §5): re-opening D2 for chat inside the deal page only, and re-opening D1 for the agreement mount. If either stays closed, the deal page ships without that wall and nothing else moves.

Exit: buyer and owner see the same deal, propose and confirm a visit, get reminded, leave feedback, message each other with the scam warning visible, and generate an agreement at the right stage. Owner median first-response time is measurable.

### Phase 3. Trust (weeks 11–13)

F15 rewards adjustment (Chirag presents numbers to the client first; engineering waits for the yes) → F16 reviews → F17 badges + buyer context.

Exit: first review published from a verified close; zero payout reaches a linked pair in a seeded fraud test; badges render.

### Phase 4. Data products (weeks 14–15)

E4 nightly aggregation → F18 locality pages (web SSR + mobile screen) → F19 price intelligence → F20 polish.

Exit: `/localities/pune/wakad` renders on web with a live median and is indexable; the listing form shows guidance; the detail shows history and delta.

### Phase 5. LTV + store (weeks 16–17)

F21 rental clock, referral, expiry → store submission (`DEALDIRECT-MOBILE-PUBLISH-CHECKLIST.md`: icon and splash done, Sentry from Phase 0, strip dev gallery, Play account, data-safety form; iOS is its own track after Android).

---

## 4. Designing the app, not just filling it

Rules that hold across every phase, so the app reads as one product rather than sixteen features:

- **Home is untouched.** New surfaces plug into it only through what it already renders: the Activity tiles (labels may change, e.g. "Enquiries" → "Deals"), the Updates preview, and the notification resolver. No new section on Home.
- **Activity is the buyer's desk.** Segments become Shortlist · Deals · Searches · Visits. Bookings (builder projects) stay as a fifth segment. Every segment has loading, empty and error states with one action each.
- **The deal page is the app's centre of gravity.** One screen, both roles, a vertical progress tracker at the top, then the walls: visit, messages, documents/agreement, close. Anything the docx puts "in the deal" lives here and nowhere else; no floating chat, no separate visits list outside Activity.
- **Notifications earn their tap.** Every push deep-links to the exact object, opens with the relevant part in view, and is never a confirmation or payment. Permission is asked at the first shortlist or saved search, with the reason in the sheet, and never again if declined.
- **Honest numbers only.** Response time shows only at ≥ 3 leads; locality medians only at ≥ 5 listings; "below locality average" only when the median exists. The research's whole point is that the data anchor is DealDirect's edge and a dishonest number destroys it.
- **Texture is already there.** `src/ui` has the component set, `src/theme` has motion and typography, haptics and reduced-motion are wired. New screens use them. A single design pass per phase (interaction-design and ios-design skills) reviews the new screens against the existing ones; no redesign.
- **Owner side is a dashboard, not a form.** Analytics gets the weekly card; leads get the buyer context; the listing form gets price guidance inline. The owner never leaves their flow to learn something the app already knows.
- **Every native module is justified once.** Phase 0 adds Sentry; F12 may add `expo-calendar`. Nothing else in this plan needs a native module, so after Phase 0's rebuild, everything else can go out over EAS Update.

---

## 5. Decisions Chirag makes before the corresponding phase

1. **Additive backend work is in scope.** The docx is a backend proposal, so I have planned as if the answer is yes, but the standing rule is to ask. Confirm, and Phase 0 begins.
2. **Chat inside the deal page (re-opens D2).** Recommend yes, deal-page-only, after the four preconditions in F13. Without it the deal page is a tracker with no channel.
3. **Agreement mount (re-opens D1).** Recommend yes, deal-page-only; the code is complete on both ends and the docx promises it in week 9.
4. **Rewards numbers.** F15 waits until the client has seen the table. I will draft it from `rewardService.js` when Phase 3 approaches.
5. **Web thin slices.** Ship per feature in the same week, or batch after the mobile lane? Recommend per feature for the message-type features (free) and batch the screen-type ones.
6. **Providers.** Expo Push Service (recommended over raw FCM/APNs: one sender, receipts, no Firebase project) and Brevo (recommended over SES: no AWS onboarding, ₹ billing). Both reversible behind the same interfaces.
7. **Store accounts and the Meta business documents** are Chirag's, both needed from week 1 to avoid waiting later.

---

## 6. What could make this plan wrong

- The device pass in Phase 0 could reveal that the Home rebuild or the native layer needs more than a week of repair. The phase absorbs it; the rest of the plan slides, it does not change shape.
- `CHAT_ENABLED` has never been true in production. Socket.IO presence is in-process; fine for one instance, and the backend is one instance, but the first real load is unknown. F13 ships with a kill switch that leaves the deal page intact.
- The 20 req/min shared search limiter (`/properties/search`) is a real constraint for saved-search matching at scale and for the first-session prompt. Matching runs server-side on create, so it does not consume it, but the results deep link does. Watch in F3's events.
- Meta verification can take weeks. F5 is built early and waits; nothing depends on it except the WhatsApp channel of E1, which degrades to push + email.

~Sakha
