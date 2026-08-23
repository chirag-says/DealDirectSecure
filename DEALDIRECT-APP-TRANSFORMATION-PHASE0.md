# DealDirect Mobile — Transformation Phase 0: Baseline

Date: 2026-08-24. Branch `main`, working tree dirty.
Purpose: establish a verified baseline before any product-shape change. **No product behavior was modified in Phase 0.**
Parent documents: `DEALDIRECT-APP-FUNCTIONAL-REVIEW.md` (why), `DEALDIRECT-MOBILE-PARITY-AUDIT.md` + `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md` (correctness work underneath).

---

## 1. Current architecture understanding

**Stack.** Expo 54 / RN 0.81 / expo-router 6 (filesystem routes, `typedRoutes: true`), TanStack Query 5 persisted to MMKV, NativeWind 4 + a token-based theme, FlashList 2, Reanimated 4, react-hook-form + zod, axios with a cookie-mirroring client. 45 route files (42 addressable), 10.4k LOC in `app/`, 29.3k LOC in `src/`.

**Baseline verification, run today:**

| Check | Result |
|---|---|
| `npx tsc --noEmit` | **Clean, exit 0** |
| `npx expo lint` | **0 errors, 12 warnings** (3 axios named-export cautions, 1 unused import, 8 `Array<T>` style) |
| Native project | `android/` present (prebuilt, dev-client workflow). **No `ios/`.** |
| Existing build artifact | `android/app/build/outputs/apk/debug/app-debug.apk` present |
| Emulator | AVD `Medium_Phone_API_36.1` available; `adb devices` currently empty |
| Tests | **None.** No framework, no config, no test script |

**Consequence that shapes the whole plan:** the debug dev-client APK plus the existing AVD means **Phase 1 is device-verifiable without a native rebuild**, because Phase 1 adds no native modules. Phase 3 (map, camera, location, haptics, biometrics) adds native modules and *will* require a rebuild and a fresh dev client.

**`typedRoutes: true` is the safety net for this entire transformation.** Renaming a route file makes `tsc --noEmit` fail at every stale `href`/`pathname`. Route restructuring is therefore compiler-checked, not grep-checked.

**Working tree state — the single biggest risk.** 43 uncommitted mobile files: 37 modified, 2 deleted, 6 untracked, +2193/−540 lines. This is the parity plan's Phase 1/2 (W1-W4, W7, W8) plus a Hubble redemption WebView, sitting on `main`, **typecheck-clean but never run on a device or against a live API** (the plan's own §2b says so explicitly). Two marketing components (`AboutDealDirect.tsx`, `TrustStrip.tsx`) were already deleted here — someone had already started the de-marketing pass.

Notable items inside that uncommitted work:
- `src/ui/TabBar.tsx` — 460 lines changed. The tab bar is already mid-rework.
- `src/ui/BottomNavBar.tsx` — **new, 369 lines, imported by nothing.** An orphan.
- `src/config/features.ts` — `GROUP_BUY_ENABLED = false`, applied at the data layer.
- `src/auth/components/RequireAuth.tsx` — new guest guard.

---

## 2. Current mobile product structure

Route → what it does today → what it must become.

### Tab shell (`app/(tabs)/_layout.tsx`)
Four tabs plus a raised Post action, with `chat` registered at `href: null`.

| Current tab | File | Current purpose | Target |
|---|---|---|---|
| Home | `(tabs)/index.tsx` | Discovery landing page: hero pitch → recently viewed → popular rail → projects rail → budget tools → 3 collection rails → city grid → **marketing CTA slab**. Owns no results; every affordance routes to Properties. | **Merged into SEARCH.** Becomes the search tool: field, intent, filters, resume-search, then results. |
| Properties | `(tabs)/properties.tsx` | The real search engine: two explicit modes (editing/results), debounced suggestions, recent searches, quick-filter rail, filter sheet, sort, density toggle, compare mode, save-search, related fallback, infinite feed. 458 lines, the best screen in the app. | **Becomes SEARCH's body.** Extracted to a component, mounted by the Search tab. |
| Saved | `(tabs)/saved.tsx` | Two segments: Interested listings (with the enquiry cap meter) + Saved searches. Its own doc comment is emphatic that this is *not* favourites. | **ACTIVITY.** Widened: Shortlist, Enquiries, Saved searches, Bookings, Visits (when chat ships). |
| Profile | `(tabs)/profile.tsx` | Account card + wallet + owner/upgrade card, then `PublicSections`: "Explore" / "Plan your purchase" / "Help" nav groups. Comment states the design goal was **coverage of every destination**. | **PROFILE.** Account only. Sitemap deleted. |
| (hidden) chat | `(tabs)/chat.tsx` | Full conversation list, unreachable (D2). | Unchanged, stays dark. |
| — | — | Notifications live at `app/notifications.tsx`, a stack route reached from a bell inside the Home hero. | **UPDATES.** Promoted to a tab with a badge. |

### Stack routes (unchanged in Phase 1 unless noted)
Property detail + gallery + **map (11-line placeholder)** · owner properties/leads/analytics/new/edit · projects list/detail/unit/booking/bookings/campaign · rewards + redeem (WebView) + claim-reward · settings + sessions/change-password/delete-account · auth (login/register/verify-otp/forgot/reset) · blog + blog detail · support · tools (emi/affordability) · dev gallery.

---

## 3. Transformation map

```
CURRENT                          TARGET
──────────────────────────────────────────────────────────────────
(tabs)/index      Home       ┐
                             ├──►  (tabs)/index      SEARCH
(tabs)/properties Properties ┘        discovery header when idle,
                                      results when querying

(tabs)/saved      Saved      ────►  (tabs)/activity  ACTIVITY
                                      Shortlist | Enquiries |
                                      Searches | Bookings

notifications     stack      ────►  (tabs)/updates   UPDATES
                                      + badge, + deep-link targets

(tabs)/profile    Profile    ────►  (tabs)/profile   PROFILE
                                      account only

Post dock         unchanged  ────►  Post dock (unchanged in Phase 1)
```

**Route-name changes and their call sites** (all compiler-checked by `typedRoutes`):

| Change | Call sites to update |
|---|---|
| `/properties` → folded into `/(tabs)` | 8: `(tabs)/index.tsx:105`, `(tabs)/chat.tsx:85`, `(tabs)/profile.tsx:239`, `(tabs)/saved.tsx:80,397,443`, `property/[id]/index.tsx:284`, `tools/affordability.tsx:246` |
| `/(tabs)/saved` → `/(tabs)/activity` | 2: `(tabs)/profile.tsx:165`, `notifications.tsx:56` |
| `/notifications` → `/(tabs)/updates` | 2: `(tabs)/index.tsx:158`, `(tabs)/profile.tsx:170` (the endpoint string in `api/endpoints/notifications.ts` is unrelated and stays) |

Old paths are preserved as redirect routes so `dealdirect://` deep links and any notification `actionUrl` already in flight keep working.

---

## 4. Backend dependencies

Nothing in Phase 1 requires a backend change. Everything below is deferred to its own approval gate.

| ID | Capability | Endpoints/models | Production behavior changes? | Migration | Rollback |
|---|---|---|---|---|---|
| **[B1]** | True shortlist | New `Shortlist` model (or `User.shortlist[]`), `GET/POST/DELETE /shortlist` | No — purely additive, nothing existing reads it | None (new collection) | Drop the routes; app degrades to no shortlist |
| **[B2]** | Push delivery | `User.pushTokens[]`, `POST/DELETE /users/push-token`, send call inside `services/notificationService.js` | **Yes** — `notifyUser` gains a side effect. Must be fire-and-forget with a `.catch`, matching the existing external-call convention, so a push failure cannot break a lead write | Additive field | Remove the send call; notifications keep working as today |
| **[B3]** | Unread count | `GET /notifications/unread-count` | No — new read-only route | None | Delete route; badge falls back to counting the 100-row list |
| **[B4]** | Buyer enquiry status | New buyer-scoped read over `Lead` (`isViewed`, `contactHistory`) | No, if a new route. **Yes** if `GET /leads` is widened — do not widen it | None | Delete route |
| **[B5]** | Geo search | `Property.location` GeoJSON + 2dsphere index + `$near`/bounds on `/properties/search` | **Yes** — touches the busiest endpoint in the product, and needs a backfill of ~all listings from `address.latitude/longitude` | **Yes, real backfill** | Ignore the new params; index drop |
| **[B6]** | Price-drop alerts | Trigger on price change for shortlisted listings | Yes — new notification fan-out | Depends on B1 | Remove trigger |
| **[B7]** | Lead channel attribution | Set `Lead.source = 'mobile_app'` at the interest write path | **Yes**, one line, but it writes a field nothing currently populates | None | Revert the line |

**[D] Product decisions, not engineering:** enable chat (`CHAT_ENABLED`, with its three preconditions), delete blog from the app, device-local vs backend shortlist for the interim, login streak, rewards catalogue in-app, Click & Earn.

---

## 5. Safe mobile-only changes (no production backend touched)

All of Phase 1, plus most of Phase 3:

- Tab restructure and every route rename.
- Search-first surface: hero de-marketing, resume-last-search (MMKV, same pattern as `recentlyViewed`), discovery header ordering.
- Activity workspace assembled from hooks that already exist (`useSavedProperties`, `useSavedSearches`, `useMyBookings`).
- Updates tab: existing `useNotifications` and the hardened `resolveNotificationTarget`.
- Profile de-sitemapping.
- Return-to-intent after auth.
- Support trimming; blog demoted out of navigation.
- Phase 3 natives: property map (Leaflet in the existing `react-native-webview`, non-API), map view over already-fetched coordinates, camera capture, location permission for city detection and client-side distance, haptics, swipe actions, real `Switch` and date picker, share sheet, clipboard, biometric app-lock.
- Pull-to-refresh gaps, transactions pagination, dead-code removal, Sentry.

---

## 6. Reusable existing components — preserve, do not rewrite

Verified strong and load-bearing. Nothing on this list gets replaced for stylistic reasons.

**Infrastructure:** `src/api/client.ts` (cookie mirror, session-fatal observer), `src/api/endpoints/*` (the most accurate client contract in the repo), `src/api/errors.ts` taxonomy, `src/api/queryClient.ts` (retry policy tuned to the rate limiter), `src/api/persistence.ts` (MMKV, 24h, chat excluded), `src/auth/AuthProvider.tsx` (proven-not-assumed sessions), `src/storage/secure.ts`, `src/config/optionalNative.ts` (lazy native imports so one missing module cannot kill the route tree).

**UI primitives (31 files in `src/ui/`):** `Screen`, `ScreenHeader`, `Sheet`, `Segmented`, `ListGroup`, `EmptyState`, `ErrorState`, `Skeleton`, `Toast`, `Refreshable`, `Rail`, `PressableScale`, `RangeSlider`, `Image`, `PriceLabel`, `OfflineBanner`.

**Feature modules:** the whole of `src/features/search/` (11 components + a 424-line `filters.ts` documenting which backend params were probed and rejected), `src/features/properties/` (cards, `ZoomableImage`, `recentlyViewed`), `src/features/saved/` (`saveToggle` + `EnquirySheet` consequence copy), `src/features/savedSearches/`, `src/features/leads/`, `src/features/listings/ListingForm`, `src/features/notifications/targets.ts`.

**Patterns to keep applying:** deferred mounting (`Reveal`) as rate-limit defence, geometry-matched skeletons, optimistic mutations with rollback (7 sites), `Alert` for irreversible confirms vs `Toast` for results, reduced-motion honoured in every entrance.

---

## 7. Risk areas

| # | Risk | Severity | Mitigation |
|---|---|---|---|
| R1 | **43 uncommitted, device-unverified files.** A Phase 1 regression will be indistinguishable from a latent bug in the parity work. | **High** | Commit the working tree as a local checkpoint before any Phase 1 edit (local only; no push). Device-smoke the parity P0 flows first so the baseline is known-good, not just known-compiling. |
| R2 | **Merging Home + Properties** touches the app's most complex screen (458 lines, two modes, 8 pieces of state, compare, filters, related). | **High** | Extract verbatim into a component first, mount it, verify identical behavior, and only then add the discovery header. Two commits, not one. |
| R3 | **Rate limiter.** `/properties/search` allows 20 req/min per IP, shared behind carrier NAT. A Search tab that renders discovery *and* results could double the cold-start request count. | **High** | Preserve `Reveal`. Discovery rails must not mount while results are mounted; the idle discovery header and the results feed are mutually exclusive states, not stacked sections. |
| R4 | **Shortlist must not create leads.** `useSaveToggle` currently raises the enquiry confirmation sheet; a heart wired to it would silently email owners. | **High** | The shortlist control is a new, separate affordance. The existing heart keeps its consequence sheet and is relabelled as the enquiry action. No shortlist ships against `/properties/interested/*`. |
| R5 | Deep links and notification `actionUrl`s point at old paths. | Medium | Keep `properties`/`saved`/`notifications` as redirect routes; do not delete the files. |
| R6 | `TabBar.tsx` has 460 uncommitted lines of in-flight change; `BottomNavBar.tsx` is a 369-line orphan. Editing the wrong one wastes a cycle. | Medium | Confirm `TabBar` is the mounted bar (it is, via `(tabs)/_layout.tsx:48`), delete the orphan, then edit. |
| R7 | Client-side facet filtering runs over one 100-row page because the backend taxonomy refs are broken (B28). Breaks past ~100 live listings. | Medium | Out of scope to fix (needs the taxonomy cutover). Do not build new UI that assumes those facets are server-truthful. |
| R8 | Removing the Profile sitemap can orphan routes reachable from nowhere else (blog, tools, projects, support). | Medium | Audit reachability per route before deleting a row; relocate rather than strand. |
| R9 | No tests anywhere. Every verification is manual. | Medium | Device smoke per phase; consider the contract suite from the parity plan's Phase 5 once shape work settles. |
| R10 | Store/deep-link identifiers are frozen (`in.dealdirect.mobile`), and app version must stay out of the User-Agent or every session is revoked. | Low but fatal if breached | Do not touch `app.config.js` identity fields or `client.ts` UA constants. |

---

## 8. Phase 1 implementation plan

Six ordered work items. Every one is `[M]`. After each, `tsc --noEmit` + `expo lint`; device pass at the end of the phase.

### 1.0 — Checkpoint (no code change)
Local commit of the 43 in-flight files as a labelled baseline. Rollback point for everything after.

### 1.1 — Tab shell
- `app/(tabs)/_layout.tsx`: four tabs — Search (`index`), Activity, Updates, Profile — plus the Post dock; `chat` stays `href: null`; `properties`, `saved`, `notifications` registered `href: null` as redirect-only routes.
- `src/ui/TabBar.tsx`: labels and icons for the new set.
- Delete `src/ui/BottomNavBar.tsx` (orphan).

### 1.2 — Search tab (two commits)
- **(a) Extract, no behavior change.** Move the body of `app/(tabs)/properties.tsx` into `src/features/search/components/SearchScreen.tsx`. `app/(tabs)/index.tsx` renders it. `app/(tabs)/properties.tsx` becomes a param-forwarding redirect. Verify results, filters, compare, save-search, suggestions all behave exactly as before.
- **(b) Discovery header.** When the screen is idle (no query, no filters, results untouched): search field with intent (Buy/Rent), quick filters, **Continue your search** card (query + filters + result count, one-tap resume, new `src/features/search/resume.ts` on MMKV following the `recentlyViewed` precedent), recently viewed, then a trimmed discovery set. `Hero.tsx` loses the marketing headline and keeps the field. `CtaBanner.tsx` deleted. Collection rails, city grid and project rail are re-evaluated against R3 — kept only where they earn their request budget.

### 1.3 — Activity tab
- `app/(tabs)/activity.tsx` from `saved.tsx`. Segments: **Shortlist** (see decision below), **Enquiries** (today's Interested list, relabelled honestly, keeping the cap meter), **Searches** (unchanged), **Bookings** (existing `useMyBookings`, moved out of the Profile links).
- `app/(tabs)/saved.tsx` → redirect.

### 1.4 — Updates tab
- Extract `app/notifications.tsx` into `src/features/notifications/components/NotificationsScreen.tsx`; mount at `app/(tabs)/updates.tsx`; old route becomes a redirect. Unread count from the existing hook (a real badge waits on **[B3]**). Bell leaves the hero.

### 1.5 — Profile
- Delete `PublicSections`' three nav groups; keep `AppearanceGroup`. Retain account, wallet, owner hub, settings, logout. Relocate anything orphaned by the deletion (R8).

### 1.6 — Return-to-intent
- New `src/auth/pendingIntent.ts` (in-memory + MMKV fallback, single-use, expiring).
- Producers: property detail enquiry, shortlist, unit booking/enquiry, claim-reward.
- Consumers: `login.tsx` (replacing the hard `router.replace('/(tabs)')` at line 43), `register.tsx`, `verify-otp.tsx`.

### 1.7 — Content demotion
- Blog out of navigation; routes stay on disk pending decision **[D]**.
- `app/support.tsx`: keep contact actions, version, legal links; drop the ported FAQ accordion.

### Exit criteria
`tsc --noEmit` clean · `expo lint` no new warnings · every route reachable · redirects verified · **device pass on `Medium_Phone_API_36.1`**: cold start, search → filter → detail → enquiry, guest enquiry → login → resumed, activity segments, updates deep-link, offline cold start, both themes. Anything unverified is reported as `DEVICE VERIFICATION PENDING`.

### Open decision blocking 1.3
**Shortlist in the interim.** Three options: (a) ship the Shortlist segment as a visible, explained, backend-blocked empty state; (b) device-local MMKV shortlist now (precedent exists: `recentlyViewed`, and the website's localStorage project bookmarks), migrating to the server when **[B1]** lands; (c) omit the segment entirely until **[B1]**. Recommendation: **(b)**, because it creates no leads, matches an existing pattern, and makes the shortlist-vs-enquiry distinction legible immediately. It does not sync across devices, which must be said in the UI.

---

## 9. What will NOT be touched

**Never, in any phase, without a separate explicit approval:**
- `backend/` — production. No route, controller, model, service, or env change. Every `[B]` item stops at a written proposal.
- `client-next/` and `Admin/` — the website and admin remain exactly as they are. The website keeps the blog, FAQ, marketing pages and SEO content; that is its job.
- Deployment configuration of any app (per-app Hostinger git imports).
- Anything on `AI/MASTER_MEMORY.md` §5 "never change without instruction".

**Preserved inside the mobile app:**
- Auth lifecycle, cookie handling, SecureStore, the constant per-platform User-Agent, the no-`Origin` constraint, `X-App-Version`.
- `src/api/*`: client, endpoint registry, error taxonomy, query client, MMKV persistence.
- The design system: tokens, theme provider, all 31 `src/ui` primitives, the skeleton system, reduced-motion behavior.
- Offline caching, optimistic mutations, FlashList usage, `Reveal` deferred mounting.
- The listing wizard's draft autosave and image compression.
- `GROUP_BUY_ENABLED = false` and the `href: null` chat gating (D2/D4 hold).
- Bundle identifiers and store identity in `app.config.js`.

**No framework migration, no rewrite, no WebView conversion, no state-management replacement.** The engine stays; the product shape changes.
