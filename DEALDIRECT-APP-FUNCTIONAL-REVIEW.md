# DealDirect Mobile — Functional Review: App or Web Port?

Date: 2026-08-23. Code state: working tree on `main` (last commit `b722dc3`).
Question under review: not "does mobile match the website" (that is `DEALDIRECT-MOBILE-PARITY-AUDIT.md`), but "is this shaped like an app at all". The complaint being tested: *"it's a website converted into an app, not a functional app."*

Method: four parallel investigations, then synthesis.
1. Screen-by-screen inventory of all 42 mobile routes with functional-vs-marketing classification and a native-capability matrix (source-verified, file:line).
2. Full backend capability inventory (every route file verified, client usage grepped in both clients).
3. Competitor research: NoBroker, 99acres, MagicBricks, Housing.com, Zillow, Redfin (app stores, help docs, vendor case studies, teardowns).
4. App-first design literature: Apple HIG, Material 3, NN/g, Airbnb case studies, push/retention research.

---

## 1. Verdict

The complaint is right, but the diagnosis in it is wrong, and the difference matters because it changes what to fix.

**At the code level this is not a web port.** The inventory found 33 of 42 routes fully functional, marketing copy under 5% of screen code, geometry-matched skeletons on 20+ screens, offline-first cold start from a persisted cache, optimistic mutations with rollback in 7 places, gesture-composed photo zoom, draft autosave on the listing wizard, and an auth lifecycle (proven-not-assumed sessions, SecureStore cookie mirror) that is more careful than the website's. The engineering is app-grade and in several places ahead of client-next.

**At the product level the complaint is exactly correct.** The app has the website's *shape*: its information architecture, its retention model, and its silences are all a website's. Three sentences capture it:

1. **The app never speaks first.** There is zero push infrastructure on either end (no token storage, no send path, verified by grep across the whole backend). The only "new activity" signal is a bell dot that appears after the user has already opened the app. That is a browser tab's retention model. Every competitor's re-engagement engine (Zillow's daily saved-search alerts, Housing's instant lead alerts, NoBroker's chat-driven nudges) starts from push.
2. **It is organized around the website's sitemap, not the user's activity.** Home opens with the website's hero headline and closes with a marketing CTA slab. The Profile tab renders a link directory its own comment describes as "every destination in the app" (that is a footer). FAQ copy is ported verbatim from `FAQContent.jsx`. The blog ships as two routes that regex-strip CMS HTML. Competitors organize around "my ongoing hunt": shortlisted + contacted + saved searches + visits in one surface (MagicBricks dashboard, NoBroker Activities tab, 99acres resume-last-search).
3. **The three capabilities that define a property app on a phone are absent: map, camera, location.** The map screen is an 11-line placeholder rendering "M4 · not built". `launchCameraAsync` is never called anywhere (photos must already be in the gallery). There is no `expo-location` and no server-side geo at all (no GeoJSON, no 2dsphere index, no near-me).

Scored against a 20-point app-vs-web-port checklist from the design research (§3): **11/20. Threshold for "you shipped an app" is 14.**

The good news: because the engineering foundation is genuinely native, this is mostly *product reshaping plus a small number of missing capabilities*, not a rebuild.

---

## 2. Why it feels like a website — the five root causes

### RC1 — No push, no badge, no reason to return
- Backend: no `pushTokens` field, no register endpoint, no send path (grep-verified zero hits for fcm/expo push across models, controllers, services). No unread-count endpoint either: a badge would have to fetch 100 notification rows and count client-side.
- Mobile: `expo-notifications` is installed but only wired for *local* notifications bridged from the chat socket, and both `SocketProvider` and `PushBridge` were unmounted from the root layout on 2026-08-13. `shouldSetBadge: false`. Nothing ever fires.
- Consequence: an owner gets a lead (the single most valuable event in the marketplace) and finds out whenever they happen to open the app. The industry response norm is 24 hours; leads that wait longer are lost (99acres' own guidance to owners). The rewards economy, the saved-search alert system, and the deal-verification flow all generate notification rows that die in a list nobody is told to open.

### RC2 — Home is a landing page, Profile is a footer
- `Hero.tsx:150-169`: "Buy, Rent & Sell Properties / Directly from Owners. No middleman. No commission fees." That is the pitch to a stranger. The person seeing it has already installed the app.
- `CtaBanner.tsx:31-70` closes Home with "Ready to find your home? → Browse Properties". Its own docstring admits it violates the rule that marketing blocks belong on the website.
- `(tabs)/profile.tsx:230-274` (`PublicSections`): link groups titled "Explore", "Plan your purchase", "Help", ~14 rows, on the account tab. The code comment states the design goal was *coverage* of every destination. That is a sitemap.
- No competitor's home screen carries marketing. Zillow opens on the map. Redfin opened on "Find Homes". 99acres opens on resume-your-last-search.

### RC3 — Map, camera, location absent
- `app/property/[id]/map.tsx` is the last placeholder in the app, on the screen type (location) that users of a property app expect most.
- The backend's `categorizedImages` schema has a full per-room photo taxonomy (14 residential buckets, 8 commercial). Camera-per-room capture maps 1:1 onto it and would be a genuinely app-native listing flow. Instead the wizard only opens the photo library.
- No location permission is ever requested; no near-me, no auto-detected city, no distance on cards. (Server-side geo search does not exist either; see §5 for what is client-doable now vs backend-gated.)

### RC4 — There is no shortlist, and "saved" is a trap
- Server-side, "saved properties" *is* the interest list: capped at 5 active, and every save creates a Lead, notifies the owner by email and WhatsApp, and awards points. There is no way to casually shortlist 20 properties while browsing, which is the single most common behavior in this category (Redfin: ~70% of app users favorite at least one home, ~40% accumulate 30+; favorites lists are shareable because house-hunting is usually a two-person decision).
- The buyer also has no view of what happened to their enquiry: no "my enquiries with status" surface exists server-side. Contacted-property history is a first-class list in every competitor (NoBroker Activities, MagicBricks dashboard, 99acres responses).

### RC5 — The retention core (chat) is built and dark
- A complete chat stack exists on both ends: ~1,900 backend lines (REST + Socket.IO + models), a 286-line typed socket manager and full thread UI on mobile. All of it is behind `CHAT_ENABLED`, which no environment sets. Site-visit scheduling rides on chat (`visit_request` message types), so it is dark too.
- For direct owner-buyer marketplaces, in-app chat is what the platform can see, moderate, and re-engage from. NoBroker's chat integration is credited with a 25% transaction lift in the CometChat case study. This stays a product decision (D2), but the review must state its weight: it is the largest already-built retention feature in the codebase.

---

## 3. The 20-point scorecard, applied

Binary criteria from the design research (Apple HIG, Material 3, NN/g, marketplace patterns). Score < 14 = web port.

| # | Criterion | Verdict | Evidence |
|---|---|---|---|
| 1 | First screen is the core tool, not marketing | **Fail** | Hero headline + closing CTA slab on Home |
| 2 | Zero screens exist only to describe the product | **Fail** | `/support` (ported FAQ), `/blog`, `/blog/[slug]` |
| 3 | Bottom tab bar, 3-5 destinations, no hamburger | Pass | Home / Properties / Saved / Profile + Post dock |
| 4 | No tab named "Home"; tabs name tasks | **Fail** | First tab is Home |
| 5 | Each tab keeps its own stack and state | Pass | expo-router tab stacks |
| 6 | Pull-to-refresh on every list, top-triggered | **Fail** (narrow) | Missing on Profile, Settings, Owner Analytics; the gesture silently no-ops (`Refreshable` mounted without `onRefresh`) |
| 7 | Scroll position survives navigate-away | Pass | Stack-preserved; unverified on device |
| 8 | Skeletons matched to final layout, no spinners | Pass | Exemplary; 20+ sites, geometry-matched |
| 9 | Offline cold start shows cached content | Pass | MMKV-persisted query cache, 24h |
| 10 | Optimistic writes with rollback | Pass | 7 mutation sites |
| 11 | Login persists indefinitely | Pass | SecureStore mirror + proven restore |
| 12 | Biometric unlock / confirm offered | **Fail** | No `expo-local-authentication` |
| 13 | Browse without account; signup only at need | Pass | Guests land on tabs; actions prompt |
| 14 | Push permission via contextual soft-ask | **Fail** | No push at all |
| 15 | Every important event pushes + deep-links | **Fail** | No push; deep links scheme-only, no universal links, no `getInitialURL` handling |
| 16 | Filters/sort/actions in sheets, not screens | Pass | Filter sheet, sort, enquiry sheet, compare sheet |
| 17 | Push transitions, swipe-back everywhere | Pass | Native stack + parallax detail |
| 18 | Empty states name a reason and an action | Pass | Shared `EmptyState` primitive, wired everywhere |
| 19 | Forms are stepped with native pickers/keyboards | **Fail** | Settings is one 11-field web form; DOB is regex-validated free text ("no date-picker module installed"); checkbox glyphs instead of `Switch`; hardcoded hex colours |
| 20 | Tab badges reflect server state without refresh | **Fail** | No unread-count endpoint; bell dot appears only after open |

**Score: 11/20.** The failures cluster exactly where the "feels like a website" instinct points: voice (14, 15, 20), shape (1, 2, 4), and native texture (6, 12, 19).

---

## 4. What the app should be — target shape

### Tab bar (buyer default)

| Tab | Contents | Replaces |
|---|---|---|
| **Search** | Search-first surface: search bar + resume-last-search card (filters intact, 99acres pattern), then results. List/map toggle when the map lands. | Home-as-landing-page + Properties (merged) |
| **Activity** | The hunt in one place: Shortlist (new, unlimited) · Contacted/enquiries with status · Saved searches with new-match counts · Bookings. | Saved (widened to match NoBroker Activities / MagicBricks dashboard) |
| **Post** (dock action) | Unchanged: raised centre action. | — |
| **Updates** | Notification inbox with unread badge; becomes Inbox (chat + notifications) if chat ships. | Bell-in-hero |
| **Profile** | Account, wallet summary, owner hub entry, devices, settings, help. Sitemap deleted. | Profile-as-footer |

Personal-dashboard content (recently viewed, recommendations, project rail) lives at the top of Search, above results, and collapses on scroll or query focus. Tools (EMI, affordability) stay reachable from listing context and Profile, not as home-screen tiles.

### Owner experience
Keep single-app navigation now (owner base is small), but make the owner hub a dashboard with numbers, not a menu: response-time stat, unread leads, views trend, listing completion score with nudges (photos, price, refresh). Adopt the Airbnb mode-switch pattern (per-role tab bars, switch in Profile) only when owner tooling deepens; do not mix owner tabs into the buyer tab bar.

### Voice
Every event a user would complain about missing must push, and every push must deep-link to its exact screen. Taxonomy with guardrails in §6, item group B.

---

## 5. Every change

Grouped by dependency. **[M]** = mobile-only, no backend change. **[B]** = requires backend work (backend is production; each [B] item needs explicit approval before any code). **[D]** = product decision for Chirag first. Existing plan IDs (W1-W25) referenced where the item already exists there.

### Group A — Make the app speak (the identity change)

| # | Change | Tag | Detail |
|---|---|---|---|
| A1 | Push token registration + send path | **[B]** | `pushTokens[]` on User, register/unregister endpoints, Expo push send call inside `notifyUser`/`notifyUsers`. Every existing notification trigger (new lead, saved-search match, deal approved/rejected/claim, booking status) becomes a push for free because they all already flow through `notificationService`. Highest-leverage single change in this review. |
| A2 | Unread-count endpoint | **[B]** | `GET /notifications/unread-count`. A few lines; today a badge requires fetching 100 rows. |
| A3 | Mobile push wiring | [M] | `expo-notifications` registration, deep-link routing from push payload to the exact screen (reuse the hardened `resolveNotificationTarget`), app icon badge (`setBadgeCountAsync`), tab badge on Updates. |
| A4 | Permission soft-ask priming | [M] | Never at launch. Buyers: after first enquiry ("Get notified when the owner responds"). Owners: after first listing ("Get alerted the moment someone is interested"). Native prompt only after the soft-ask is accepted. |
| A5 | Notification preferences | [M] + **[B]** | Per-category toggles (transactional always on, match alerts, marketing) backed server-side; guardrails: max 2-3 marketing/week, quiet hours 22:00-07:00, batch saved-search matches into one daily digest push. |
| A6 | Universal links (W24) | [M] | `associatedDomains`/`intentFilters`/AASA + `getInitialURL` handling. A share of dealdirect.in links should open the app. |

### Group B — Reshape (sitemap → activity)

| # | Change | Tag | Detail |
|---|---|---|---|
| B1 | Delete Home's marketing bookends | [M] | Remove the hero pitch headline and `CtaBanner`. Hero becomes a search box. |
| B2 | Merge Home into a search-first tab | [M] | Resume-last-search card (query + filters, one tap), recently viewed, rails demoted below the tool. Tab renamed Search. |
| B3 | Widen Saved into Activity | [M] | Segments: Shortlist (after D-group lands) · Enquiries · Saved searches · Bookings. Bookings currently hides under Profile links. |
| B4 | Promote notifications to a tab (Updates) | [M] | With A2/A3 badge. The bell-dot-inside-hero pattern dies. |
| B5 | Strip Profile to an account screen | [M] | Delete `PublicSections`. Keep account card, wallet teaser, owner hub, devices, settings, support. |
| B6 | Return-to-intent after login | [M] | Guest taps Enquire → login → **resume the enquiry on that property**. Today they are dropped on Home and must find the listing again (`login.tsx:43` hard-replaces to tabs; zero pendingIntent hits in the codebase). Web already has this; mobile lost it. Applies to enquire, shortlist, book, claim-reward. |
| B7 | Drop the blog from the app, or render it properly (W12) | **[D]** | Recommendation: drop. It is website SEO content; every competitor keeps articles on the web. If kept: real HTML renderer, not the regex stripper. |
| B8 | Shrink Support | [M] | The verbatim-ported FAQ accordion goes; keep contact actions, version, legal links. Answer questions contextually (e.g. rewards questions on the rewards screen). |

### Group C — The definitional capabilities

| # | Change | Tag | Detail |
|---|---|---|---|
| C1 | Property location map (W11) | [M] | Leaflet WebView per `docs/MAP_IMPLEMENTATION.md` (WebView stays strictly non-API). Kills the last placeholder. |
| C2 | Map view of search results | [M] | Pins from the already-fetched result page (client-side lat/lng), list/map toggle. No backend needed for v1. |
| C3 | True geo search | **[B]** | GeoJSON `location` on Property (currently silently dropped, B4 in KNOWN_BUGS), 2dsphere index, `$near`/bounds params on `/search`. Gate for "near me", radius, draw-on-map. Backfill needed for existing listings from stored lat/lng. |
| C4 | Camera capture in the listing wizard | [M] | `launchCameraAsync` alongside the library picker; room-by-room capture prompts mapped to the `categorizedImages` buckets the backend already defines. Also on payment-screenshot upload. |
| C5 | Location permission + near-me | [M] then **[B]** | v1: auto-detect city, sort current page by distance client-side. Real radius search waits on C3. |

### Group D — Missing marketplace primitives

| # | Change | Tag | Detail |
|---|---|---|---|
| D1 | True shortlist (favorites) | **[B]** + [M] | New model + endpoints: unlimited, zero side effects (no lead, no owner email, no points). Heart on every card, optimistic. Keep "interested" as the explicit contact action with its 5-cap and consequence copy. This separates *considering* from *contacting*, which the platform currently conflates. |
| D2 | Buyer enquiry status | **[B]** + [M] | Buyer-facing view of their leads: at minimum "sent / owner viewed / owner responded" derived from `Lead.isViewed` + `contactHistory`. Feeds the Activity tab and a Tier-1 push ("The owner viewed your enquiry"). |
| D3 | Price-drop alerts on shortlist | **[B]** | Trigger on price change for favorited listings. Zillow/Redfin's second-strongest alert after new-match. Depends on D1. |
| D4 | Lead channel attribution | **[B]** (one line) | `Lead.source` enum already includes `"mobile_app"`; nothing sets it. Set it at the interest write path so the business can see what the app produces. |

### Group E — Owner side: form → dashboard

| # | Change | Tag | Detail |
|---|---|---|---|
| E1 | Lead push with quick actions (needs A1) | [M] | New-lead push deep-links to the lead with Call / WhatsApp / Mark-contacted one tap away. This is the whole owner value proposition on mobile. |
| E2 | Owner dashboard numbers | [M] | Response-time stat, unread leads, 14-day views/enquiries trend on the hub card (data already served by `/leads/analytics`). |
| E3 | Listing completion score | [M] | Client-computed score + nudges (photos per room, price sanity, description length), MagicBricks pattern. |
| E4 | Per-property lead drill-down | [M] | `GET /leads/property/:propertyId` is live, ownership-checked, and used by no client. Wire it from the listing card. |
| E5 | Leads export via share sheet + date filter (W14) | [M] | `GET /leads/export` with `sessionHeaders()` → share sheet. |
| E6 | Analytics pull-to-refresh (W17) | [M] | Currently silently no-ops. |

### Group F — Native texture (the "feel" list)

| # | Change | Tag | Detail |
|---|---|---|---|
| F1 | Haptics | [M] | `expo-haptics` on: shortlist tap, enquiry success, reward reveal, Post dock press, pull-to-refresh trigger. Zero today. |
| F2 | Real form controls in Settings | [M] | Date picker module for DOB (free-text regex today), `Switch` instead of checkbox glyphs, theme tokens instead of hardcoded `#2563EB`/`#9CA3AF`, split the 11-field card into sections. |
| F3 | Biometric gate | [M] | Optional app-lock (`expo-local-authentication`); biometric confirm before session revoke and delete-account entry (password still required by the server, as it should be). |
| F4 | Swipeable rows | [M] | Swipe-to-remove on shortlist and notifications; long-press menus on listing cards (Share / Shortlist / Hide). |
| F5 | Clipboard | [M] | Copy referral code (share-only today). |
| F6 | Pull-to-refresh on Profile and Settings (W17) | [M] | Both mount `Refreshable` with no handler. |
| F7 | Reward reveal theatre (W21) | [M] | Port the spin-wheel/door split by `rewardCategory`; add haptics. The server design (roll at claim time) makes the animation honest. |
| F8 | Transactions pagination (W20) | [M] | Load-more; one page of 50 today. |
| F9 | OTA updates wiring | [M] | `expo-updates` configured, never checked; add `checkForUpdateAsync` on foreground. |
| F10 | Sentry (W9) | [M] | Zero telemetry today. Mirror web's PII posture (`id` + `role` only). Precondition for any store release. |
| F11 | Dead-code hygiene | [M] | `/properties/filter` string still present (410 endpoint), chat routes reachable by scheme deep link, dev gallery bundled. Verify against W7's "done" claim, which nothing has device-tested. |

### Group G — Product decisions (Chirag decides, each unlocks built capability)

| # | Decision | What it unlocks |
|---|---|---|
| G1 | **Enable chat, mobile-first?** (re-opens D2) | ~1,900 backend lines + full mobile client, live behind `CHAT_ENABLED=true`. Also unlocks site visits (visit_request messages). Preconditions before flipping: B3 (stored XSS in `lastMessage.text`), B7 (socket JWT accepted as REST bearer), missing `POST /chat/message/report` route, and push (A1), because chat without push is half-alive. Competitor evidence says this is the retention core; NoBroker credits chat with a 25% transaction lift. |
| G2 | **Login streak?** | `Reward.monthlyLoginDays` is already written on every login; nothing reads or awards it (B12). One read endpoint + one award call = a native retention hook with the hard part done. |
| G3 | **Rewards catalogue in-app?** | `GET /rewards/catalogue/*` is public, proxied, and used by zero mobile code. A native browse of what points buy makes the wallet mean something. Redemption itself stays in the Hubble WebView (it is their SDK; that is fine). |
| G4 | **Click & Earn supply mechanic?** | NoBroker's camera-first crowdsourcing (photograph a TO-LET board, earn on verification, ~35k listings/month) is the most app-native growth mechanic in this market and slots into the existing rewards economy + admin verification queue. New backend surface; a product bet, not a port. |
| G5 | **Group buy (D4)** and **contact form (W25)** | Unchanged from the parity plan; group-buy actions stay gated until the completion engine exists. |

### Scaling landmine (not a feature, must be scheduled)
Several search facets (category, city, furnishing, construction status) filter client-side over one 100-row page because the backend's ObjectId taxonomy params are broken (B28). This silently returns wrong results the moment live inventory passes ~100. The real fix is the taxonomy backfill (already deferred to phase 5 cutover); the app should carry a guard until then.

---

## 6. Sequencing

Impact × confidence ÷ effort, respecting dependencies:

1. **Phase A — Voice** (A1-A5 + E1): push infra, badge, priming, lead push. The single change that moves the app from "website in a frame" to "thing in my pocket that tells me when something happens". Everything in A1/A2 is small, additive backend work, but it is backend work: needs approval first.
2. **Phase B — Shape** (B1-B6, B8, F6): tab restructure, marketing deletion, return-to-intent. Pure mobile, no permissions needed, large perceived change.
3. **Phase C — Definitional capabilities** (C1, C2, C4, C5-v1, F1-F5): map, camera, location, texture.
4. **Phase D — Primitives** (D1-D4, E2-E5): shortlist model, buyer status, owner dashboard. Mixed [B]+[M].
5. **Phase E — Decisions** (G1-G4), each its own workstream once decided.

F10 (Sentry) and F11 (hygiene) ride along with whichever phase ships first; no store release without F10.

Nothing in this review invalidates the parity plan (W1-W25); it sits above it. The parity plan makes mobile a *correct* client. This review is about making it an *app*. Both are needed; parity P0s (already coded, still device-unverified) come first regardless.

---

## 7. Scorecard, revisited

| Checkpoint | Today | After Phases A-B | After A-D |
|---|---|---|---|
| 20-point app scorecard | 11/20 | 16/20 | 19/20 |
| Remaining fails at 19/20 | — | — | #2 only if blog stays |

The one thing this review asks nobody to do: rebuild. The foundation (data layer, offline, skeletons, optimistic writes, auth lifecycle) is the hard part of a native app, and it is already better than most shipped apps in this category. What is missing is the product decision to stop mirroring the website and start behaving like a tool.
