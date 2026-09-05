# DealDirect Mobile — Store Publishability Checklist

Date: 2026-08-24. Target: Google Play **and** Apple App Store.
Grounded in the actual state of `dealdirect-mobile/` on this date, not a generic list.

Legend — **Severity**: 🔴 blocker (cannot ship without) · 🟡 important (ship risk / rejection risk) · 🟢 polish.
**Owner**: `mobile` (code) · `backend` (server) · `you` (decision/account/asset) · `infra` (build/store ops).
**Status**: ✅ done · ◻️ not done · ⚠️ partial / needs verify.

---

## 0. The one gate above all others

◻️ 🔴 `mobile`/`you` — **Run it on a device.** Roughly 18 commits since Phase 1 — two Home rebuilds, the dock, the header, query search, and the entire Phase 3 native layer — have never run on real hardware, and the Phase 3 modules cannot even load without a rebuild. Both stores reject apps that crash on launch or on a core flow. Nothing below this line is trustworthy until a build runs and the Phase 2 QA script (`DEALDIRECT-MOBILE-PHASE2-QA-SCRIPT.md`) passes. **This is the single highest-priority item.**

---

## 1. Accounts & build infrastructure

| | Sev | Owner | Item |
|---|---|---|---|
| ◻️ | 🔴 | you | **Google Play Developer account** ($25 one-time). |
| ◻️ | 🔴 | you | **Apple Developer Program** ($99/year). Required even to build for TestFlight. |
| ✅ | — | infra | EAS project configured (`eas.json`, project id, `appVersionSource: remote`, `autoIncrement`). Production profile points at the prod backend — the `.env` file is local-Metro only, so there is no accidental-staging risk in store builds. |
| ◻️ | 🔴 | infra | **First iOS build has never been produced.** No `ios/` native project has been generated. Needs a Mac or an EAS cloud build (`eas build -p ios`). This is a whole track, not a checkbox — see §7. |
| ◻️ | 🟡 | infra | App signing: enrol in **Google Play App Signing** (upload key + Google-managed signing key); iOS distribution certificate + provisioning profile via EAS credentials. |
| ⚠️ | 🟡 | infra | The committed `android/` folder is a prebuild. Confirm a clean `expo prebuild --clean` reproduces it after the Phase 3 native modules, or delete it and let EAS prebuild. A stale native folder that predates the new modules will not include them. |

---

## 2. App identity & assets

| | Sev | Owner | Item |
|---|---|---|---|
| ◻️ | 🔴 | you/`mobile` | **App icon is not configured.** `app.config.js` has no `icon` / `android.adaptiveIcon` / `ios.icon` field and there is no source icon in `assets/`. A store icon must be a 1024×1024 PNG (no alpha for iOS) plus an Android adaptive icon (foreground + background). `assets/home/brand/logo.png` exists as a starting point but must be exported at the right sizes and wired in. |
| ◻️ | 🔴 | you/`mobile` | **Splash screen** is not configured (`expo-splash-screen` is a dependency but no `splash`/plugin config). Set a branded splash so cold start does not show a blank/white frame. |
| ⚠️ | 🟡 | infra | `version: '0.1.0'` — decide the launch version (likely `1.0.0`). Build numbers auto-increment via EAS. |
| ✅ | — | infra | Bundle identifier `in.dealdirect.mobile` frozen for both platforms. **Do not change** — after a store build it is permanent. |
| ◻️ | 🟢 | you | Confirm the app **name** as it appears on the home screen and store ("DealDirect") and that it is not trademarked by another Play/App Store entry. |

---

## 3. Engineering quality gates

| | Sev | Owner | Item |
|---|---|---|---|
| ◻️ | 🔴 | mobile | **Device pass** (see §0). Cold start, search, detail, enquiry, map, camera, the dock, offline start, both themes, on a real mid-range Android and — for the App Store — a real iPhone. |
| ⚠️ | 🔴 | you | **Crash reporting — code done 2026-09-04, needs a DSN.** `@sentry/react-native` is installed and wired (`src/observability/sentry.ts`): `sendDefaultPii: false`, `{id, role}` only, cookies and auth headers scrubbed from every event and breadcrumb. Without `EXPO_PUBLIC_SENTRY_DSN` it is a no-op, so **the app currently ships blind**. Create the project, set the DSN, and set `SENTRY_ORG`/`SENTRY_PROJECT`/`SENTRY_AUTH_TOKEN` for source maps. |
| ◻️ | 🟡 | mobile | **Strip the dev gallery route** (`app/(dev)/gallery.tsx`) from production, or guard the whole `(dev)` group behind `__DEV__`. It is deep-linkable by filesystem today. |
| ✅ | — | mobile | No stray `console.log` in `src`/`app` (0 found). |
| ✅ | — | mobile | Typecheck clean, lint 0 errors, Android bundle builds, mobile unit tests pass (285 as of 2026-09-04, and growing with each phase). |
| ⚠️ | 🔴 | mobile | **A rebuild is mandatory before any device test.** `@sentry/react-native` joined the five native modules from Phase 3, so the existing debug APK cannot load the current JS. `expo prebuild --platform android` ran clean on 2026-09-04; the EAS build has not been produced. |
| ◻️ | 🔴 | you | **FCM credentials.** Android push registers nothing without `google-services.json` and FCM V1 credentials in EAS; iOS needs an APNs key. The failure is silent by design (logged as `[push]`), so this is easy to miss until nobody receives a notification. |
| ◻️ | 🟡 | mobile | **Performance on a low-end device.** The app is FlashList + Reanimated + MMKV (good), but the two WebViews (map, Hubble rewards) are memory-heavy — verify on a 3–4 GB device that opening the map and returning does not get the app killed. |
| ◻️ | 🟢 | mobile | Accessibility pass: the app already sets `accessibilityLabel`/`accessibilityRole` widely; spot-check with TalkBack/VoiceOver that the dock, sheets, and the map fallback announce correctly. |

---

## 4. Store-policy compliance (both stores)

| | Sev | Owner | Item |
|---|---|---|---|
| ✅ | — | mobile | **In-app account deletion.** Both stores now require it; `settings/delete-account` exists and works (password + typed phrase + biometric confirm). Apple requires it be reachable in-app; Google requires an in-app path AND a web path — confirm the website also offers deletion, or provide a deletion-request URL. |
| ◻️ | 🔴 | you | **Privacy policy URL**, publicly reachable, linked in both store listings AND in-app. The website has `/privacy`, and **it now predates four data flows** (push token, installation id, device hash, usage events) plus the retention split at deletion. It must be rewritten before submission — see [`DEALDIRECT-STORE-DATA-DISCLOSURE.md`](DEALDIRECT-STORE-DATA-DISCLOSURE.md) §1, §2 and §3. |
| ◻️ | 🔴 | you | **Google Play Data Safety form.** Fill it from [`DEALDIRECT-STORE-DATA-DISCLOSURE.md`](DEALDIRECT-STORE-DATA-DISCLOSURE.md) §1 and §2, which were derived by reading the code on 2026-09-05. **Four data flows are newer than this checklist**: the push token, the installation id, the device hash used by the fraud check, and usage events. Declaring the old list would now be inaccurate. |
| ◻️ | 🔴 | you | **Apple App Privacy "nutrition label"** — the same disclosure in Apple's format, set in App Store Connect. |
| ◻️ | 🔴 | you | **Content / age rating** questionnaires (Google IARC + Apple age rating). A property marketplace is low-risk; answer honestly (user-generated content = listings + any chat). |
| ⚠️ | 🟡 | mobile/you | **Location permission justification.** Foreground-only, on-demand (good — background location is a heavy review item and the app declares none). Google requires a **prominent in-app disclosure** before the first location prompt and a Permissions Declaration in the console; the soft-ask copy is in `CityPickerSheet`. Verify the disclosure wording satisfies Google's form. |
| ⚠️ | 🟡 | mobile | **Permission strings** are all set (camera, location Face ID) — verify each reads as a clear user benefit, since Apple rejects vague purpose strings. |
| ◻️ | 🟢 | you | Support URL / support email and a marketing URL for the listings. |

---

## 5. Apple-specific review landmines

Apple review is stricter than Google's; these are the ones that could actually get DealDirect rejected.

| | Sev | Owner | Item |
|---|---|---|---|
| ◻️ | 🔴 | you/mobile | **Guideline 3.1.1 — In-App Purchase.** This is the real risk. The rewards economy lets users earn points and **redeem them via the Hubble WebView**. If those points redeem for *digital* goods/credit, Apple may demand IAP and reject external redemption. Real-estate services and physical vouchers are usually fine, but the Hubble redemption flow needs review against 3.1.1 **before** submission. Options: keep redemption web-only and not linked from the iOS app, or get clarity that the rewards are for physical/partner goods. **Needs your decision + possibly a product change for iOS.** |
| ⚠️ | 🟡 | mobile | **Guideline 4.2 — Minimum functionality / "not a web wrapper."** The app is genuinely native, so this is low risk — but two WebViews (map, Hubble) draw scrutiny. The map is clearly a component within a native app (fine). The Hubble rewards screen is a full-screen WebView; make sure the app around it is unmistakably native so it doesn't read as a wrapper. |
| ✅ | — | mobile | **Sign in with Apple (4.8):** required *only* if the app offers third-party/social login (Google/Facebook). DealDirect uses email + phone-OTP, no social login, so this does **not** apply. Do not add social login without also adding Sign in with Apple. |
| ⚠️ | 🟡 | mobile | **App Tracking Transparency (ATT):** required only if the app tracks users across other apps/sites for ads. DealDirect does not — but if Sentry or any analytics with an ad SDK is added, re-check. Currently: no ATT prompt needed. |
| ◻️ | 🟡 | you | **Payments:** the UPI/booking flow uses external UPI for a *physical service* (property booking), which Apple permits — but be ready to explain it in review notes. |
| ◻️ | 🟢 | infra | **Demo account** for Apple reviewers (a working login), plus review notes explaining the OTP flow so the reviewer can get past sign-in. |

---

## 6. Google-specific items

| | Sev | Owner | Item |
|---|---|---|---|
| ✅ | — | infra | **Target API level** — Expo SDK 54 targets a current Android API, satisfying Play's minimum. Confirm at build time. |
| ◻️ | 🟡 | infra | **App Bundle (.aab)**, not APK, for the Play production track. `eas build -p android --profile production` produces it. |
| ◻️ | 🟡 | you | **Data deletion web path** (Google's account-deletion policy wants an off-app route too). |
| ◻️ | 🟢 | infra | **Closed/internal testing track** first (Play Console) before production, to catch install/signing issues on real devices. |

---

## 7. The iOS track (a whole workstream, not a checkbox)

The App Store half is materially more work than Play, because **iOS has never been built**:

- ◻️ 🔴 `infra` — Generate the iOS native project (`expo prebuild -p ios`) and build via **EAS cloud** (no Mac needed) or a Mac.
- ◻️ 🔴 `infra` — Apple distribution certificate + provisioning profile (EAS can manage).
- ◻️ 🟡 `mobile` — iOS-specific verification: the two WebViews, the native date picker (iOS renders it differently), haptics, Face ID, the safe-area/notch layout of the new pinned Home header, and the map's `message` bridge (iOS delivers to `window`, Android to `document` — the map handles both, but verify).
- ◻️ 🟡 `infra` — **TestFlight** build and a real-device pass before App Store submission.
- ◻️ 🟢 `mobile` — Universal links (`associatedDomains` + the `apple-app-site-association` file on the domain) — deferred as M12/W24; not a launch blocker but needed for shared-link deep linking to open the app on iOS.

**If time-boxed:** ship **Android first** (one store, cheaper account, no 3.1.1 IAP question, existing build), then iOS as a fast follow once the 3.1.1 rewards question is resolved.

---

## 8. Store listing content (marketing, both stores)

| | Sev | Owner | Item |
|---|---|---|---|
| ◻️ | 🔴 | you | **Screenshots** — several per device class (phone required; Apple also wants 6.7" and 6.5", and iPad if `supportsTablet` stays true). Capture the real app: Home, Search, a listing, the map, Activity. |
| ◻️ | 🔴 | you | **App title, subtitle, short + full description, keywords.** |
| ◻️ | 🟢 | you | **Feature graphic** (Play) and optional preview video. |
| ◻️ | 🟢 | you | Reconsider `supportsTablet: true` — if the layout is not tablet-tuned, Apple will test it on iPad and may reject on layout bugs. Either tune it or set tablet support off for v1. |

---

## 9. Product-quality items that raise the bar (not strict blockers)

These are the difference between "passes review" and "users keep it." From the functional review, still open:

- ◻️ 🟡 `backend` — **Push notifications (Phase 4).** The app still never speaks first. Not a store requirement, but for a marketplace it is the retention core. Needs the backend device-token pipeline.
- ◻️ 🟡 `backend` — **Server-synced shortlist + buyer enquiry status (Phase 5).** The shortlist is device-local today, which is honest but loses on reinstall.
- ◻️ 🟢 `mobile` — Pull-to-refresh gaps (Profile/Settings/Analytics), transactions pagination, blog HTML renderer, swipe row actions, full biometric app-lock.
- ◻️ 🟢 `mobile` — Reward-reveal theatre, universal links.

---

## 10. Recommended sequence to first submission

1. **Rebuild + device pass** (§0) — mandatory, unblocks trust in everything.
2. **Icon + splash** (§2) — cannot submit without them.
3. **Sentry** (§3) — do not ship blind.
4. **Strip the dev gallery** (§3).
5. **Resolve the Apple 3.1.1 rewards question** (§5) — this can change scope, so decide early.
6. **Dev accounts + store listings + privacy/data-safety forms** (§1, §4, §8) — can proceed in parallel.
7. **Android internal-testing build → production.**
8. **iOS track** (§7) — EAS build → TestFlight → App Store, once 3.1.1 is settled.

**Fastest honest path to "publishable":** Android-only, after items 1–4 and 6. The App Store adds the iOS build track and the rewards-redemption review question on top.
