# DealDirect Mobile — Phase 2 Device QA Script

Status: **NOT RUN.** Device validation was requested and then withdrawn; the emulator was stopped without a pass being executed. This document is the pass, written so it can be run by anyone (or by a later session with device access) without rederiving it.

Target: the Phase 1 tree, commits `068577c`..`2ffa2eb` on `main`.
Static verification already passing: `tsc --noEmit` clean, `expo lint` 0 errors / 12 pre-existing warnings, `expo export --platform android` bundles.

---

## 0. Before you start — read this

**The app points at PRODUCTION.** `dealdirect-mobile/.env` sets `EXPO_PUBLIC_API_URL=https://backend.dealdirect.in/api`. The file's own header warns about it. Consequences for this pass:

| Action | Production side effect |
|---|---|
| Confirming an enquiry | Creates a real `Lead`; emails **and** WhatsApps a real owner with the tester's name, email and phone; awards points; consumes 1 of the buyer's 5 slots. **The owner keeps the lead even if you withdraw.** |
| Registering | Creates a real user + sends a real SMS OTP |
| Posting a listing | Writes a real listing and uploads to production Cloudinary |
| Booking a unit | Creates a real `ProjectBooking` against a real project |
| Claiming a reward | Irreversibly rolls and banks a real reward |

**Rule for this pass: stop at every write boundary.** Raising the enquiry confirmation sheet is a read; pressing Confirm is not. Every check below is marked READ or **WRITE**. Do not run a WRITE check unless Chirag has explicitly said to.

**The safe alternative** is to point `.env` at a local backend (`http://10.0.2.2:9000/api` from the emulator) and run `cd backend && npm run dev`. Note `POST /properties/add` needs a Mongo replica set, and `/register` needs Equence SMS credentials — use `/register-direct` instead. This unlocks every WRITE check without touching real users.

### Setup

```bash
emulator -avd Medium_Phone_API_36.1 -no-snapshot-load
```
```bash
adb wait-for-device && adb install -r dealdirect-mobile/android/app/build/outputs/apk/debug/app-debug.apk
```
```bash
cd dealdirect-mobile && npx expo start --dev-client
```

Phase 1 added **no native modules**, so the existing debug APK loads this JS. No rebuild is needed. (Phase 3 will need one.)

Useful during the pass:

```bash
adb logcat -s ReactNativeJS:V ReactNative:V AndroidRuntime:E
```
```bash
adb exec-out screencap -p > shot.png
```

---

## 1. The bottom navigation — run this first and hardest

This has regressed before. It is the single most likely place to find a Phase 1 defect, because `TabBar.tsx` had 460 uncommitted lines of in-flight change at the Phase 0 baseline and the destination map was rewritten on top of that.

What the dock is supposed to do: float as a pill, show four icon-only tabs plus a raised red Post action, and expand **only the active tab** to reveal its label. Selected tab takes `accent` (blue); the Post action is the only `brand` (red) element. Motion is split on purpose — shape springs, ink/colour tweens — and all of it is driven by one `focused` boolean per item, deliberately not by three independent mechanisms (that was the old flicker bug; see the rewrite note in `src/ui/TabBar.tsx`).

| # | Check | Expected |
|---|---|---|
| N1 | Cold start | Dock springs in from 90% scale, once. No pop from zero, no second entrance. |
| N2 | Tap through all four tabs in order | Exactly one label visible at a time; the pill width animates rather than jumping. |
| N3 | **Rapid switching** — tap 4 tabs as fast as possible, 10× | No window where two labels show, no window where none show, no half-faded text sliding. Interrupting mid-flight must retarget, not queue. |
| N4 | Return to a previously visited tab | Correct active state immediately; no flash of the wrong tab. |
| N5 | Scroll a long list, then switch tabs mid-scroll | Dock does not jump or re-enter; no layout shift. |
| N6 | Open the keyboard (tap search field), then close | Dock must not ride up with the keyboard, duplicate, or re-run its entrance animation. |
| N7 | Detail → back | Dock does not remount. Watch for a second bar appearing behind the first. |
| N8 | Light ↔ dark (system setting) | Colours swap; no white flash; the selected pill does not travel through grey (it animates opacity on a correctly-coloured layer, not `backgroundColor` from `transparent`). |
| N9 | Android gesture navigation (3-button **and** gesture mode) | Dock clears the home indicator; `paddingBottom` follows the inset. |
| N10 | Tab content remount check | Watch `adb logcat` for repeated query fires on tab switch. Tabs must keep their own stack and not refetch on every visit. |

**Specifically look for:** flicker · jumping · layout shift · label animating character-by-character (the `measure` width fix) · icon outline/filled swapping instead of crossfading · duplicate bars · wrong active tab · unnecessary remounts · safe-area movement.

---

## 2. Search — the new idle/results split

The contract: **idle discovery and active results are mutually exclusive**, and the idle state issues **zero** requests. It is implemented as the list header of the results list, not a separate screen, so results are always mounted underneath — which is intended, and is why there is only ever one search query in flight.

| # | Check | Type | Expected |
|---|---|---|---|
| S1 | Cold start lands on Search | READ | First screen is the search field + quick filters + results. No hero headline, no "Ready to find your home?" banner anywhere. |
| S2 | Idle content | READ | Recently viewed (empty on a fresh install), "Browse by type" tiles, "Popular searches" chips. Resume card absent until a search has been run. |
| S3 | **Request count on cold start** | READ | Exactly **one** `/properties/search`. The old Home fired three identical `limit=100` calls; if you see more than one, that is a regression. |
| S4 | Type a query (≥2 chars) | READ | Suggestion panel takes over. At most one debounced `/properties/suggestions` call. |
| S5 | Focus the empty field on a fresh install | READ | Results stay visible behind it — must **not** go blank. This was a real bug fixed 2026-08-15; the idle header must not have reintroduced it. |
| S6 | Commit a search | READ | Idle block disappears entirely. Verify it is unmounted, not merely scrolled past. |
| S7 | Buy / Rent segmented control | READ | Result count changes. (Production partition measured previously: 21 rent + 10 sale = 31 total.) |
| S8 | Quick filter pills | READ | Facet applies; several are client-side over one 100-row page by design (B28). |
| S9 | Filter sheet → apply | READ | Sheet dismisses, results update, idle block stays gone. |
| S10 | Sort (newest / price asc / desc) | READ | Order changes; no full-screen spinner, skeletons only. |
| S11 | Compare mode | READ | Toggling on switches density to cards; selection circle replaces the heart; max 3, same type. Leaving clears selection. |
| S12 | Clear the search | READ | Returns to the whole corpus **and** the idle block comes back. |
| S13 | **Resume card** | READ | Run a filtered search → go to another tab → return. Card shows the query, the filter chips, and "about N matches last time". Tapping Resume restores the **whole filter set**, not just the term. |
| S14 | Resume dismiss | READ | X removes the card; it does not come back until a new criteria-bearing search runs. |
| S15 | Layout jump | READ | When results land, nothing under the header shifts. Skeletons are geometry-matched. |

---

## 3. Shortlist — the critical correctness check

**A shortlist tap must produce ZERO network requests.** Source-level proof already exists (`features/shortlist` imports no API client — grep for `@/api`, `axios`, `fetch(`, `endpoints` returns comment matches only). This section is the runtime proof.

### How to capture network traffic

The reliable method, since the backend is HTTPS and okhttp will not log paths by default: **run the emulator behind a logging proxy.**

```bash
emulator -avd Medium_Phone_API_36.1 -no-snapshot-load -http-proxy 127.0.0.1:8888
```

Any small logging proxy on 8888 will do. Over HTTPS you will see `CONNECT backend.dealdirect.in:443` per connection rather than paths — which is sufficient here, because the assertion is *zero requests to the API host*, not *which path*.

For path-level detail, point `.env` at a local backend instead and read its request log.

| # | Check | Type | Expected |
|---|---|---|---|
| L1 | Open a property detail | READ | Action bar shows **Save** (bookmark outline) beside "I'm interested". Two controls, distinct shapes. |
| L2 | Tap Save | READ | Fills instantly (optimistic, no spinner). Toast: "Shortlisted. Kept on this device, and the owner is not told." **Proxy log must show no new request.** |
| L3 | Tap Save again | READ | Un-fills instantly. No toast (removal is silent by design). No request. |
| L4 | Shortlist 5 listings, kill the app, cold start | READ | All 5 still present. Still no requests to draw them — the list replays MMKV snapshots, it must not refetch (refetching would inflate `views`). |
| L5 | **Verify no Lead was created** | READ | Sign in as the test buyer → Activity → Enquiries. Shortlisted items must **not** appear. The enquiry counter must be unchanged. |
| L6 | Verify no owner contact | READ | No email/WhatsApp to the owner. (Confirm with a listing you control, or check the owner's leads via Admin.) |
| L7 | Remove from the Activity list | READ | X on the row removes immediately, no confirmation, no request. |
| L8 | Shortlist cap | READ | Advertised as unlimited; a 200-entry ceiling trims oldest silently. Not worth testing by hand. |

---

## 4. Enquiry and return-to-intent

| # | Check | Type | Expected |
|---|---|---|---|
| E1 | Signed-in: tap "I'm interested" | READ | Consequence sheet rises stating what will happen. **STOP HERE** unless writes are authorised. |
| E2 | Confirm the enquiry | **WRITE** | Creates a real lead. Only with explicit approval. |
| E3 | Enquiry cap copy | READ | With 5 used, button disabled and the supporting line explains why. |
| E4 | **Guest → Enquire → Login → resume** | **WRITE** (needs an account) | Signed out, tap "I'm interested" → login screen. Sign in → returns to **the same property** with the confirmation sheet **already raised**. Not the Search tab, not the property with no sheet. |
| E5 | Intent survives an app kill | **WRITE** | At the login screen, kill the app, relaunch, sign in. Intent must still resume (it persists to MMKV for exactly this — the owner-registration OTP flow leaves the app). |
| E6 | Intent expires | READ | Trigger an intent, wait >15 min, sign in. Must land on the tabs, **not** resume. |
| E7 | Guest → unit Book → login | **WRITE** | Returns to the same unit with the **booking** sheet open. |
| E8 | Guest → unit Enquire → login | **WRITE** | Returns to the same unit with the **enquiry** sheet open — the two must not be confused. |
| E9 | Reward claim via notification while signed out | **WRITE** | Prompt says it will bring you back; signing in returns and claims. |
| E10 | Deep-link safety | READ | Open `dealdirect://property/<id>?resume=bogus` — must open the listing and raise **nothing**. Likewise `resume=booking` on a unit via a hand-written link should be treated as a normal open by a signed-out user. |

> E4–E9 need a disposable test account. On production that means a real registration. Strongly prefer a local backend for this section.

---

## 5. Activity

| # | Check | Type | Expected |
|---|---|---|---|
| A1 | Four segments | READ | Shortlist · Enquiries · Searches · Bookings. Opens on Shortlist. |
| A2 | Shortlist empty state | READ | "Nothing shortlisted yet", explains the owner is not told and there is no limit, falls back to a recently-viewed rail when history exists. |
| A3 | Shortlist footer | READ | "Your shortlist is kept on this device. Owners are not notified." |
| A4 | Enquiries | READ | The interested list with the cap meter. Label reads Enquiries, never Favourites. |
| A5 | Searches | READ | Saved searches with alert toggles and delete. Running one applies its filters to Search. |
| A6 | Bookings | READ | Booking/enquiry rows; "Enquiry · no payment needed" vs a token amount. |
| A7 | Guest on each segment | READ | Shortlist works signed out (device-local). The other three show a sign-in prompt, **not** a 401 error state. |
| A8 | Segment deep link | READ | `dealdirect://(tabs)/activity?segment=searches` opens on Searches. A bogus value falls back to Shortlist. |

---

## 6. Updates, Profile, redirects

| # | Check | Type | Expected |
|---|---|---|---|
| U1 | Updates tab | READ | Titled "Updates", no back arrow, pull-to-refresh works, last row clears the dock. |
| U2 | Unread subtitle | READ | "N unread" derived from loaded rows. **There must be no dock badge** — that is deliberate until a server unread-count endpoint exists. |
| U3 | Notification → property | READ | Opens the listing. |
| U4 | Notification → saved-search match | READ | Opens Activity **on the Searches segment**. |
| U5 | Notification never follows `actionUrl` | READ | Target resolution is validated; a hostile `actionUrl` must not navigate. |
| P1 | Profile | READ | Account card, rewards summary, owner/upgrade card, Explore (Builder projects), Plan your purchase (2 calculators), Help, Appearance, Account (Rewards, Settings), Log out. |
| P2 | No duplicated tabs | READ | No rows reading "Browse properties", "Notifications", "Interested listings" or "My bookings". |
| P3 | Guest profile | READ | Sign-in prompt **plus** the public sections, not a wall. |
| P4 | Settings | READ | Profile fields, change password, sessions, delete account all reachable. |
| P5 | Theme control | READ | System / Light / Dark all apply. |
| R1 | `dealdirect://properties?priceBand=1cr-5cr&listingType=sale` | READ | Redirects to Search **with the filters applied** — params must survive. |
| R2 | `dealdirect://saved` | READ | Redirects to Activity. |
| R3 | `dealdirect://notifications` | READ | Redirects to Updates. |
| R4 | Back from a redirect target | READ | Must not pass back through the dead route. |

---

## 7. Resilience, theming, performance

| # | Check | Expected |
|---|---|---|
| X1 | Offline cold start | Airplane mode, kill, relaunch. Last-cached listings render from MMKV; offline banner shows; no blank screen, no error screen. |
| X2 | Offline → online | Banner clears, refresh recovers. |
| X3 | Rate-limit copy | Rapid repeated searches → friendly copy with retry-after, not a raw error. |
| X4 | Loading states | Skeletons everywhere, no full-screen spinners on content screens. |
| X5 | Empty states | Every empty list names a reason and offers one action. |
| X6 | Error states | Kill the network mid-request → `ErrorState` with a working Retry. |
| X7 | Light and dark | Every Phase 1 surface in both. Watch the resume card, shortlist row, and the new action bar — all use theme tokens, but they are new. |
| X8 | Scroll performance | Long results list; FlashList should hold ~60fps. Watch for jank when the idle header unmounts. |
| X9 | Tab state preservation | Scroll Search, switch to Activity, return — scroll position and query intact. |
| X10 | Android back | From a detail screen, back returns to the correct tab. From a root tab, back exits. No dead-end. |
| X11 | Keyboard | Search field, listing form, login — no content hidden behind the keyboard, dock behaves (N6). |
| X12 | Safe areas | Notch and gesture bar respected on every new/moved screen. |

---

## 8. Report template

Fill this in as you go; it maps to what Phase 2 must answer.

- **PASS** — flows that worked.
- **FAIL** — actual defects, with the exact reproduction, a screenshot, and any `logcat` output.
- **VISUAL** — works but looks or feels wrong.
- **PERFORMANCE** — jank, duplicate requests, unnecessary loading flashes.
- **NAVIGATION** — back behaviour, redirects, state preservation.
- **PRODUCT** — anything still reading as website-shaped.
- **SCREENSHOTS** — at minimum: cold-start Search idle, results with the idle block gone, property detail action bar (both controls), Activity on each segment, Updates, Profile, dark mode, offline cold start.

### The seven questions Phase 2 must answer

1. Does the app feel meaningfully different from the website?
2. Does Search feel like the primary job?
3. Does Activity feel like an ongoing property journey?
4. Does Profile feel like an account rather than a sitemap?
5. Does it feel more functional than explanatory?
6. What still makes it feel like a website?
7. What is the single highest-impact next change?

---

## 9. Known limitations going in

These are already understood and should not be logged as new failures:

- `property/[id]/map` is still a placeholder rendering "M4 · not built" (Phase 3, W11).
- `blog/[slug]` strips HTML to plain paragraphs (W12). Blog is deep-link-only by design now.
- Settings is one long form; date of birth is free text, toggles are checkbox glyphs (Phase 3, F2).
- No push, no dock badge, no haptics, no biometrics, no camera capture, no location (Phases 3–4).
- Rewards redemption is a Hubble WebView (D3).
- Chat and group buy are deliberately dark (D2, D4).
- Several search facets filter client-side over one 100-row page (B28) and will be wrong past ~100 live listings.
