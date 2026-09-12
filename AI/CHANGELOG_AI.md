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

## 2026-09-12 — Mobile: the website's help and legal pages rendered natively (mobile only)

**Files changed** (`dealdirect-mobile/`)
- `src/features/content/pages/model.ts` — **new.** The content model: `ContentPage` → sections (or tabbed parts) → blocks (paragraph, heading, bullets, callout, cards, stats, quote, tags, faq, contact, actions). `RichText` is a string with `**bold**` runs; `parseRichText` is the only thing that reads the markers.
- `src/features/content/pages/{privacy,terms,rewardsTerms,faq,about,whyUs,contact}.ts` — **new.** One file per website route, copy verbatim (contact excepted, see its module doc). `pages/index.ts` is the registry the Support screen lists from.
- `src/features/content/components/ContentPageView.tsx` — **new.** The one renderer. Prose blocks share a card; structural blocks sit on the page; inside an accordion everything is flat.
- `src/features/content/components/ContactForm.tsx` — **new.** `POST /contact` (session required); guests see `SignInPrompt` in its place.
- `src/features/content/pages/pages.test.ts` — **new.** Structural guards, plus a parity check that reads each page's website source (when `../client-next` is beside the mobile checkout) and fails if a sentence in the app is no longer on the website.
- `app/legal/[id].tsx` — WebView removed; renders from the registry. `app/legal/contact.tsx` — **new** static route (wins over `[id]`).
- `app/support.tsx` — rows come from the registry, grouped Help / About / Legal; "Send us a message" added under Talk to us.
- `src/features/content/index.ts`, `support.ts` — registry exports; `pages.ts` (the `LEGAL_LINKS` web-link builder) **deleted**.

**Reason**
Store review reads the privacy policy and terms inside the app. A WebView of the website needs a network, renders the website's chrome, and is what reviewers flag as a wrapped site. The owner asked for every page Play Store checks to be in the APK, themed like the app. The website's pages are bespoke JSX with no shared data source, so the copy was ported as data rather than fetched.

**Architectural impact**
- The legal text now has TWO copies. The rule: a change to a website page under `client-next/src/app/{privacy,terms,faq,about,why-us,rewards/terms}` lands in the matching `pages/*.ts` in the same commit. `pages.test.ts` enforces this whenever both checkouts are present.
- `/legal/<id>` ids are the registry's: `faq`, `about`, `why-us`, `privacy`, `terms`, `rewards-terms`, plus the static `contact`. `welcome.tsx` already pushes `/legal/terms` and `/legal/privacy`.
- `react-native-webview` is still a dependency (property map, video, redeem use it); nothing here removed native code, so the fingerprint is unchanged and this ships as an OTA update.
- Content dates are carried as text from the source, never computed. The rewards terms page shows no date because the website computes one.

**Known content issues, not fixed here**
- The privacy policy and terms describe a B2B goods marketplace (orders, shipments, warehousing, GST), not a property app, and do not mention location, photos or Google sign-in. Play's Data Safety review compares the policy against what the app collects. Rewrite before submission is the owner's call.
- The website's contact page shows placeholder-looking numbers (`+91 98765 43210`, `+91 22 1234 5678`) and support@/business@ addresses that appear nowhere else; the app uses the footer's contact@ and +91 92-8963 8963 instead.

**Migration notes**
None.

**Docs updated**
This entry. `AI/` has no mobile content-page section to correct; the mobile parity audit deliverables at the repo root still describe the WebView and are stale on this point.

## 2026-09-05 — Mobile: the hero redrawn to measurements of the reference (mobile only)

**Files changed**
- `src/features/home/heroTheme.ts` — `useMockScale()` (device points per reference pixel, reference width 738), the header geometry constants, colours sampled from the mockup.
- `src/features/home/components/{HomeHeader,HomeHero,HomeSearchField}.tsx` — every dimension is now a reference pixel through `mockPx`; the header controls are pale glass with dark ink; the search pill is 86 tall with the 84 submit circle overlapping its right end. `HOME_HEADER_ROW` is gone; the hero pads by `HEADER_TOP_PX + HEADER_ROW_PX` and the headline top by `HERO_HEADLINE_TOP_PX`.

**Reason**
Chirag: the first pass was not an accurate replica. The mockup was measured element by element (bounding boxes by colour mask, colours by pixel sample) and the layout rebuilt as a proportional replica rather than in theme tokens.

**Architectural impact**
The top of Home is the one place in the app that does not use the spacing tokens, by design: the reference is the spec. The search field's behaviour and the pin handover are unchanged. The logo is the website's `dealdirect_logo.png`, byte-identical to `assets/home/brand/logo.png`.

**Verification**
tsc clean, lint 0 errors, 350 tests. No web renderer in the project, so not compared visually here; verified by measurement only. Not run on a device.

**Docs updated**
None.

## 2026-09-05 — Mobile: launch motion, first-launch welcome, the hero rebuilt to the reference (mobile only)

**Files changed**
- NEW `src/features/onboarding/{entryRoute,welcomeState,index}.ts`, `components/AnimatedSplash.tsx`, `welcomeState.test.ts`; NEW `app/welcome.tsx`.
- `app/index.tsx` — the entry route now comes from `resolveEntryRoute(status, hasSeenWelcome())`.
- `app/_layout.tsx` — mounts `AnimatedSplash` over everything until its choreography ends; registers `welcome` with a fade.
- `src/storage/mmkv.ts` — `PREF_KEYS.welcomeSeen`.
- NEW `assets/home/brand/hero-dusk.webp` (1536×1024, 37 KB, from the supplied artwork); NEW `src/features/home/heroTheme.ts`.
- `src/features/home/components/HomeHero.tsx`, `HomeHeader.tsx` rewritten to the reference mockup; `HomeSearchField.tsx` restyled (one white pill, blue submit inside it); `app/(tabs)/index.tsx` two prop lines (city picker moved to the header, "List property" pill removed from it).

**Reason**
Chirag's request of 2026-09-05: an animated launch with the mark, a distinct first-launch welcome with a Skip, and the hero replicated from a supplied mockup and background image, with the search field's behaviour untouched.

**Architectural impact**
- Cold start: signed in → the app; signed out and never introduced on this install → `/welcome`; signed out and introduced → the app. "Introduced" is a device fact (`welcomeSeen`), set by any of the welcome's three exits and never cleared on logout. `entryRoute.ts` is the only decision point.
- `AnimatedSplash` continues the native splash: same mark, same size, same white, so the handover is invisible. `MARK_WIDTH` and `SHEET` mirror `app.config.js`; change one, change the other.
- The hero is photo-led and dark in both colour schemes (`heroTheme.ts`); the header is transparent at rest and fades to the hero's near-black as the page scrolls. The search pin handover arithmetic is unchanged; `HOME_HEADER_ROW` is 80 (was 52) and the hero pads by it.
- The city chip moved from the hero into the header. The "List property" pill left the header; the listing card further down Home remains the owner's entry point.
- `PressableScale` takes a single `ViewStyle`; four call sites use object spread, per HANDOFF §10.10.

**Migration notes**
None. No native module, no env var.

**Verification**
`tsc --noEmit` clean, `expo lint` 0 errors, 350 tests, `expo export` bundles. **Nothing ran on a device**; the launch motion, the welcome and the hero framing are all unverified on hardware.

**Docs updated**
None. `HANDOFF.md` §2.8 (Home) is now stale on the header contents — debt marker.

## 2026-09-05 — Mobile Phases 1, 4 and 5: shortlist on the server, price intelligence, locality pages (mobile only)

Plan of record: `DEALDIRECT-UPGRADE-MASTER-PLAN.md`. Consumes the Phase 1/4/5 backend as-is. **No backend file was touched.** `app/(tabs)/index.tsx` and `src/features/home/**` were not touched (Home is frozen). The web lane (entry below, same date) covers the same three features in `client-next/`; the two were built independently against the same contract.

**Files changed** — `dealdirect-mobile/` only.

Contract layer:
- NEW `src/types/backend/shortlist.ts`, `src/types/backend/locality.ts`. NEW `src/api/endpoints/shortlist.ts` (`list, ids, add, merge, remove, setNote, share, revokeShare, shared`), `src/api/endpoints/localities.ts` (`list, detail, guidance`).
- `src/types/backend/property.ts` — `PriceChange`, `PriceMarketComparison`, `PriceIntelligence`; `Property.priceIntelligence`; `ClaimDealRewardResponse.referral`.
- `src/types/backend/savedSearch.ts` — `notifyPush`, read-only `lastMatchAt` / `matchCount`; `CreateSavedSearchRequest.notifyPush`.
- `src/types/backend/common.ts` — `NOT_SHORTLISTED`, `EMPTY_SHORTLIST`, `LOCALITY_NOT_FOUND`, `LOCATION_REQUIRED`.
- `src/api/queryKeys.ts` — `shortlist`, `shortlistList`, `shortlistIds`, `shortlistShared(token)`, `localities(params)`, `locality(slug, listingType)`, `priceGuidance(params)`.
- `src/storage/mmkv.ts` — `PREF_KEYS.shortlistMergedFor`.

Shortlist, server-backed (F7):
- `src/features/shortlist/store.ts` — rewritten in role, not in mechanism. Still MMKV, still synchronous, still imports no API client. It is now the guest list AND the offline cache; new exports `setLocalShortlist`, `clearLocalShortlist`, `restoreLocalShortlist`, `findLocalShortlistEntry`, `setLocalShortlistNote`, `localShortlistIds`, `useLocalShortlist`, `localEntryToItem`. `toggleShortlist` / `removeFromShortlist` / `isShortlisted` / `useShortlist` were renamed to their `…Local…` variants; `useShortlist` now lives in `hooks.ts`.
- NEW `src/features/shortlist/{types,adapters,api,hooks,merge}.ts` + `merge.test.ts` (14 cases). NEW `components/{ShareShortlistSheet,ShortlistNoteSheet}.tsx`; `components/{ShortlistButton,ShortlistRow}.tsx` rewritten.
- NEW `app/shortlist/shared/[token].tsx` — public, read-only, "This is <label>'s shortlist".
- `app/(tabs)/activity.tsx` — the Shortlist segment renders `useShortlistList()`, with a toolbar (Compare / Share), per-row notes, a sold/rented marker, and compare mode reusing `CompareBar` + `CompareSheet`.
- `src/features/search/compare.ts` + `CompareBar` + `CompareSheet` — row set and props widened from `PropertySummary` to a new `ComparableProperty` (`negotiable`, `views`, `imageCount`, `coordinates` optional). The Negotiable row prints an em dash for unknown rather than "No".

Saved searches (F8):
- `src/features/savedSearches/{types,adapters,hooks,index}.ts` — `notifyPush`, `matchCount`, `lastMatchAt`, derived `isMuted`, new `matchLine()`. `useUpdateSavedSearchAlerts` writes all three channels and recomputes `isMuted` optimistically.
- `components/SavedSearchRow.tsx` — three channel chips replacing the single in-app switch, the match line, and an explicit muted line. `components/SaveSearchSheet.tsx` — the same three channels at creation; the OS notification prompt is skipped when the user turned push off.

Price intelligence (F19) and locality (F18):
- NEW `src/features/properties/priceIntelligence.ts` + `priceIntelligence.test.ts` (26 cases) — the pure payload-to-lines function: a 3-point dead band around the median, "below" / "above" / "in line", honest scope wording, null handling for every field, history sorted newest first. NEW `components/PriceStory.tsx`.
- `app/property/[id]/index.tsx` — a "Price" section under the facts; the locality line becomes a control only when a slug exists; "Open the full calculator" passes the price to `/tools/emi`.
- NEW `src/features/locality/{format,hooks,index}.ts` + `format.test.ts` (21 cases), `components/{TrendBars,PriceGuidanceLine}.tsx`. NEW `app/locality/[slug].tsx`.
- `src/features/listings/components/ListingForm.tsx` — one muted guidance line under the price field, debounced on (city, locality, listingType, bhk).

Phase 5 and analytics:
- `app/claim-reward/[verificationId].tsx` — `ReferralShareCard` at the reward moment, native Share of the server's message plus `${WEB_URL}/register?ref=CODE`. `app/rewards/index.tsx` already carried a referral card and was not touched.
- `src/analytics/events.ts` — `shortlist_share { count }`, `locality_view { slug }`, `price_guidance_shown { city }`, emitted from the share sheet, the locality screen and the guidance line. `src/analytics/track.test.ts` — the whitelist count assertion moved 16 to 19.
- NEW `src/lib/shortDate.ts` (`formatShortDay`), exported from `@/lib`.

**Reason**
Master plan Phases 1, 4 and 5, mobile lane. The shortlist stops being a device-local compromise and becomes the thing every portal has, without ever becoming the enquiry. A price stops being a number with no context. A locality gets a page that says what its listings ask, and says plainly that asking is not selling.

**Architectural impact**
- **The shortlist has two owners and one direction.** TanStack Query owns the truth for a signed-in user; the MMKV store owns the paint and is written by successful fetches and by optimistic mutations. Nothing reads the store to decide what to send the server except the one-time merge. The store still imports no API client.
- **`useShortlist()` never issues a request.** Home reads it (`shortlist.length`) and HANDOFF §5.2 forbids an eager query there, so it observes `qk.shortlistList()` with `enabled: false` and falls back to the local store. `useShortlistList()` is the same key with `enabled` on and is called only by the Activity segment. `useShortlist()` must keep returning an array.
- **The local-to-server handover is once per account per install**, decided by the pure `decideMerge` and guarded by `PREF_KEYS.shortlistMergedFor` (survives logout, like `deviceLinkedFor`). On success the local list is cleared and the list query is invalidated so the store repopulates from the server. Known gap, documented in `merge.ts`: a guest-era list created AFTER the first handover on the same install is not auto-merged. Re-arming the guard would resurrect rows the user deleted on another device, which is the worse failure.
- **`useShortlistSync()` is mounted by `ShortlistButton` and the Activity Shortlist segment, never at the root.** A user who never touches the feature issues no shortlist request, and the launch path gains none.
- **`ShortlistButton` now issues requests.** Its old doc comment promised it could not; that promise is superseded by F7 and the file says so. The invariant that survives: a shortlist entry still creates no Lead, notifies no owner, awards no points, and counts against no cap. Do not merge the shortlist and the interested list.
- **`priceIntelligence.market.deltaPct` is interpreted in exactly one place.** Negative means the listing asks BELOW the median. Anything inside ±3 points reads as "in line". A market line without a `slug` renders nothing, because the locality page it would open does not exist.
- **A locality below the sample floor is an empty state, not an error.** `GET /localities/:slug` 404s and `useLocality` reports `isMissing` separately from `error`, with retry disabled for that case. `GET /localities/guidance` answers 200 with a null body and the listing form renders nothing at all.
- **The locality page is reached only from a server-issued slug** (`priceIntelligence.market.slug`). Composing a slug from city and locality strings would link to pages that 404 for every locality below the floor.
- **Both pure modules format dates from a hand-written month table, not `Intl`.** Node under `en-IN` writes "Sept"; Hermes without full ICU writes something else. `src/lib/shortDate.ts` is the shared copy for app code; `priceIntelligence.ts` keeps its own because it must stay importable by `node --test` with no runtime imports.
- **Compare now accepts `ComparableProperty`.** Every `PropertySummary` still satisfies it, so no existing call site moved, but a row must handle an absent `negotiable` rather than printing "No".
- **The shared-shortlist route is public and read-only by construction** — `ShortlistRow` renders controls only for the props it is given, and that screen passes none. It raises no sheet and no confirmation, so it is safe as a cold-start deep link.

**Migration notes**
No schema change, no backend change, no new dependency, no new native module. Every new field is optional and every new surface is gated on its presence, so the app renders correctly against a backend older than Phase 1: the shortlist endpoints 404, `useShortlistList` falls back to the local store, and `PriceStory` and the locality entry points unmount. The device-local shortlists that already exist on installed devices are handed to the server on the first authenticated launch.

`.expo/types/router.d.ts` is git-ignored and must be regenerated for the two new routes (`/locality/[slug]`, `/shortlist/shared/[token]`); `expo start` does it, or
`EXPO_ROUTER_APP_ROOT="$PWD/app" node -e "require('expo-router/build/typed-routes').regenerateDeclarations('.expo/types')"`.

**Docs updated**
None. Debt markers: `dealdirect-mobile/docs/HANDOFF.md` §2.6 still describes saved searches as exposing two notification channels and §3.2 still says there is no private save — both are now stale. `AI/FILE_MAP.md` does not list `src/features/{shortlist,locality}`, `src/features/properties/priceIntelligence.ts` or `src/lib/shortDate.ts`; `AI/API_REFERENCE.md` still lacks `/shortlist` and `/localities`.

**Verification**
`npx tsc --noEmit` clean. `npx expo lint` 0 errors / 17 warnings (all pre-existing). `npm test` 346/346 across 49 suites (new: `src/features/shortlist/merge.test.ts` 14, `src/features/properties/priceIntelligence.test.ts` 26, `src/features/locality/format.test.ts` 21). `npx expo export --platform android` bundles (8.23 MB hbc). **Nothing was run on a device or emulator.** The shortlist handover, the share-link round trip, the note sheet, compare from the shortlist, the three-channel saved-search toggles, the price section, the locality screen and its trend bars, the listing-form guidance line and the claim-screen referral share are all unverified on hardware.

## 2026-09-05 — Web Phases 1 and 4: locality price pages, price intelligence, shortlist (client-next only)

Plan of record: `DEALDIRECT-UPGRADE-MASTER-PLAN.md`, features F7, F18 and F19. Web lane only — `client-next/` plus this file. The backend was not touched; every endpoint used here was already implemented and tested in the backend entry below. The mobile app was not touched.

**Files changed**

New, pure logic (no React, and no arithmetic left in any component):
- `client-next/src/utils/priceIntelligence.js` — money formatting, date phrasing, the market-position dead band, price-history rows, owner response and review wording
- `client-next/src/utils/localityFormat.js` — quarter labels, page title and meta description, quarter-on-quarter wording, trend-bar geometry, the disclaimer text, `localityHref`
- `client-next/src/utils/shortlistStore.js` — one shared client cache of saved property ids, read through `useSyncExternalStore`

New routes (each is the required two files: server `page.js` plus a `'use client'` `*Content.jsx`):
- `client-next/src/app/localities/page.js` + `LocalitiesContent.jsx` — index of published localities, filterable by city and by sale/rent
- `client-next/src/app/localities/[slug]/page.js` + `LocalityContent.jsx` + `not-found.jsx` — the detail page
- `client-next/src/app/shortlist/page.js` + `ShortlistContent.jsx` — the signed-in user's saved homes
- `client-next/src/app/shortlist/shared/[token]/page.js` + `SharedShortlistContent.jsx` + `not-found.jsx` — read-only shared list

New components:
- `client-next/src/components/PriceIntelligence/PriceIntelligence.jsx` — the "Price" block on a listing
- `client-next/src/components/PriceIntelligence/OwnerSignals.jsx` — verification badges, response time, review summary
- `client-next/src/components/PriceGuidance/PriceGuidance.jsx` — the muted comparable-range line on the listing form's price step
- `client-next/src/components/Shortlist/SaveButton.jsx` — the bookmark control; also exports `SAVE_PRIVACY_NOTE`
- `client-next/src/components/Shortlist/ShortlistCard.jsx` — one saved home, shared by the private and the shared view

Modified:
- `client-next/src/components/JsonLd.jsx` — added `LocalityStatsJsonLd`
- `client-next/src/app/sitemap.js` — `/localities` plus every published locality, sale and rent
- `client-next/src/app/robots.js` — `Disallow: /shortlist`; the prefix rule also covers the share links
- `client-next/src/middleware.js` — comment only, recording why `/shortlist` must NOT join `PROTECTED_ROUTES`
- `client-next/src/app/properties/[id]/PropertyDetailsContent.jsx` — price block, owner signals, save button
- `client-next/src/app/properties/PropertyListContent.jsx` — save button on both card variants
- `client-next/src/app/add-property/AddPropertyContent.jsx` and `client-next/src/app/edit-property/[id]/EditPropertyContent.jsx` — price guidance on step 3
- `client-next/src/components/Navbar/Navbar.jsx` — Shortlist link in the desktop dropdown and the mobile menu, with an inline bookmark glyph following that file's no-icon-package convention
- `client-next/src/components/Footer/Footer.jsx` — site-wide "Locality Prices" link

**Reason**

The locality pages are the only part of the upgrade that earns organic search traffic, and the plan says so outright. Everything else in this lane exists to make those numbers useful at the point of decision: on the listing (where does this price sit), in the listing form (what are neighbours asking), and in the shortlist (the homes a buyer is actually weighing).

**Architectural impact**

Indexability, which is the part most likely to be got wrong by a later change:

- **Indexable:** `/localities` and `/localities/[slug]`. Both are `dynamic = 'force-dynamic'` server components, so the medians are in the HTML before any JavaScript runs. The detail page exports `generateMetadata` carrying the locality, the city and the median in the title, and emits schema.org `Dataset` JSON-LD.
- **Not indexable:** `/shortlist` and `/shortlist/shared/[token]`. Both set `robots: { index: false }` in metadata, both fall under `Disallow: /shortlist`, and neither is in the sitemap. A share link is a private URL handed to one person, not content.
- **The sitemap now enumerates localities.** `sitemap.js` calls `GET /localities` once per listing type and emits one URL per published locality. Sale is the bare URL, rent carries `?listingType=rent`, matching the `alternates.canonical` each page emits. Both fetches are individually guarded: if the API is down the arrays stay empty and the sitemap still builds with its static, property, project and blog entries.

New invariants:

- A 404 from `GET /localities/:slug` is a NORMAL answer meaning "below the sample floor, nothing published". It becomes a real HTTP 404 through `notFound()` so a page with no numbers on it is never indexed as thin content. An unreachable backend is NOT a 404: it renders a calm unavailable state, because answering 404 during an outage would de-index every locality at once. Same three-way split the property detail page already uses.
- The shortlist and the "I'm Interested" flow are separate controls everywhere. Saving is a slate bookmark, interest is the red heart. Saving touches only `/shortlist/*` and never `/properties/interested/*`, and the privacy note ("the owner is not told") is rendered beside the button and reused verbatim on `/shortlist`.
- `/shortlist` is guarded inside its content component, NOT in `middleware.js`. The middleware match is `pathname === route || pathname.startsWith(route + '/')`, so listing `/shortlist` there would also block the public `/shortlist/shared/<token>`, which is meant for someone with no DealDirect account.
- Price guidance never blocks submission, never prefills the price field, and is never phrased as a recommendation. It has no callback into form validation.
- No component performs arithmetic on a price or a percentage. All of it, and every sentence built from a number, lives in the two utils modules. The listing-versus-median dead band is `MARKET_DEAD_BAND_PCT = 2`, so a 0.4% difference reads "in line with" rather than "below"; the quarter-on-quarter flat band is `QOQ_FLAT_BAND_PCT = 0.5`.
- Nothing on these pages may be worded as a valuation. `disclaimerLines()` states, visibly on every locality page, that the figures are asking prices from live DealDirect listings, that publication requires at least `sampleFloor` listings, and that this is not a valuation.
- `LocalityStatsJsonLd` emits `Dataset`, deliberately not `Product` or `Offer`. Marking a median asking price as an Offer would tell Google that DealDirect is selling a home at that price.

Assumption a future session should check: `market.deltaPct` and `qoqPct` are read as signed values where negative means lower. The backend contract states this for `qoqPct` and it is inferred for `deltaPct`. If that sign is ever inverted, `classifyMarketPosition` in `priceIntelligence.js` is the single place to change.

Also worth knowing: `/shortlist` and the older `/saved-properties` (backed by `GET /properties/saved`) now coexist and look similar to a user. They were left separate because merging them would change the behaviour of an existing feature, which is outside this lane.

**Migration notes**

None. No env vars, no schema, no build step. Deploy ordering is the obvious one: the backend carrying `/localities/*`, `/shortlist/*` and the `priceIntelligence` and `ownerStats` fields on `GET /properties/:id` must be live before this frontend is. Until it is, every new surface degrades to rendering nothing rather than erroring — the locality index shows its empty state, the price block and owner signals disappear, guidance stays silent, and `/shortlist` shows its "did not load" state.

**Docs updated**

None. `AI/API_REFERENCE.md` and `AI/FILE_MAP.md` still do not list the `/localities` and `/shortlist` routes or any of the new `client-next` files. That debt was opened by the backend entry below; this entry adds the frontend half of it. Flagging it rather than leaving it silent.

---

## 2026-09-05 — Backend Phases 1, 4 and 5 of the upgrade master plan (additive)

Plan of record: `DEALDIRECT-UPGRADE-MASTER-PLAN.md`. Additive as before: no existing route changed its contract, and every behaviour that costs money or sends a message is either off by default or narrower than what it replaces.

**Files changed**

Phase 1 — the return spine (F7, F8, F9)
- NEW `models/Shortlist.js` (plus `ShortlistShare`), `controllers/shortlistController.js`, `routes/shortlistRoutes.js` at `/api/shortlist`: uncapped private saves, notes, bulk merge for the mobile local→server migration, `GET /shortlist/ids`, and a rotating read-only share link with a public `GET /shortlist/shared/:token`.
- NEW `models/PriceChange.js`, `services/priceLogService.js`. Every price write path now logs: owner create, builder create, owner edit, admin edit. A no-op edit records nothing.
- NEW `utils/savedSearchMatch.js` — the matching rules extracted from two drifted copies inside `propertyController` into one module used by both the create-time fan-out and the price-drop scan. Semantics preserved exactly, including the deliberately un-trimmed city comparison.
- NEW `jobs/priceDropScan.js` (every 15 min): drops of 2% or more reach everyone who shortlisted the listing plus everyone whose saved-search budget the listing has just fallen into. Never the owner, never for a hidden/sold listing, never at a price that has since moved, and never twice.
- `models/SavedSearch.js` — `notifyPush` (default true), `lastMatchAt`, `matchCount`, two indexes. `services/notificationService.js` — `narrow()` applies a per-recipient channel override that can only take channels away; `notifySavedSearchMatches` now honours all three flags, which were stored, editable in two clients and read by nothing.
- `models/Notification.js` — `hidden`, so `notifyInApp: false` with `notifyEmail: true` is honest: the row carries the email and stays out of the notification centre. `notificationController` filters on it.
- `middleware/validators/index.js` — `notifyPush` whitelisted and validated. A field missing from the whitelist is stripped before the controller sees it, which is exactly how a flag ends up silently ignored.

Phase 4 — data products (E4, F18, F19)
- NEW `models/LocalityStat.js` with `SAMPLE_FLOOR = 5`, `utils/locality.js` (slug, bhk bucket, listing-type normalisation, IST quarters, median, percentile, percent change), `services/localityService.js`, `jobs/localityAggregate.js` (nightly, full recompute of the current quarter only), `controllers/localityController.js`, `routes/localityRoutes.js` at `/api/localities`.
- The sample floor is the honesty control: every bucket is stored, only buckets at or above five listings are `published`, and only published rows leave the building. A locality below the floor 404s exactly like one that does not exist.
- `GET /properties/:id` gains `priceIntelligence` — price history, days listed, last drop, and the delta against the locality median for the same configuration.
- `GET /localities/guidance` gives an owner mid-listing the interquartile range of comparable asking prices. A range, never a recommendation.

Phase 5 — LTV (F21)
- NEW `jobs/rentalClock.js`: at month ten of a verified rental, both sides hear, each told what to do next. Marked before sending, so a crash costs a nudge rather than duplicating one on a billed channel.
- NEW `jobs/pointsExpiry.js`: activity-based lapse with a warning fourteen days ahead and a `forfeit` transaction that explains itself. `POINTS_INACTIVITY_DAYS` defaults to 0, which disables the whole job.
- NEW `utils/referralCode.js` — generation extracted from `rewardsController` now that the reward-claim path mints codes too. `claim-deal-reward` returns a `referral` block so the invitation lands at the reward moment.
- `TransactionVerification.renewalNudgedAt`, `Reward.expiryNudgedAt`.
- `utils/aggregateDelete.js` — the cascade now covers `Shortlist` and `ShortlistShare` (16 collections).

**Reason**
The three phases the plan calls the return spine, the data products and the lifetime-value loop: a reason to come back tomorrow, a research surface that earns search traffic, and the only recurring loop the product has.

**Architectural impact**
- Saved-search flags now do what they say. A per-entry `channels` override narrows the type's policy and can never widen it; `notifyUsers` lifts it off the entry before insert, because Mongoose would drop it silently.
- `Shortlist` and the enquiry (`interestedUsers` + `Lead`) are different concepts and must stay so. The shortlist controller imports neither `Lead` nor the notification service, and a test asserts that.
- Locality statistics are asking prices from our own listings, never a valuation. There is no public sold-price registry in India to build one from, and every label says "asking".
- Nine scheduled jobs now. All handlers remain pure functions of `({ now, cursor })`.

**Migration notes**
- New env key: `POINTS_INACTIVITY_DAYS` (0 = off). No other configuration changes.
- Indexes build lazily: `Shortlist` unique `{user, property}`, `ShortlistShare` TTL, `PriceChange`, `LocalityStat` unique bucket, two on `SavedSearch`.
- No backfill. The price log starts empty, so "days listed" is null for every existing listing until its next edit; the locality pages publish after the first nightly run.
- `npm install` not required (no new dependency).

**Verification**
752 unit and 1044 integration tests pass. New suites: `tests/{locality-math,saved-search-match}.test.js` and `tests/integration/{shortlist,alerts,locality,ltv}.test.js`. Nothing was run against production.

**Docs updated**
`AI/API_REFERENCE.md` and `AI/DATABASE.md` gain the new collections and routes. `AI/KNOWN_BUGS.md` unchanged. `AI/FILE_MAP.md` still does not list `jobs/`, `services/priceLogService.js` or `services/localityService.js` — debt marker.

## 2026-09-05 — Mobile Phases 2 and 3: the deal room, reviews, trust surfaces (mobile only)

Plan of record: `DEALDIRECT-UPGRADE-MASTER-PLAN.md`. Consumes the backend entry below dated 2026-09-04 as-is. **No backend file was touched.** `app/(tabs)/index.tsx` and `src/features/home/**` were not touched (Home is frozen). Built across two sessions; the second finished D, E, F, H, I and K below after the first was cut off.

**Files changed** — `dealdirect-mobile/` only.

The deal (Phase 2):
- NEW `src/api/endpoints/deals.ts` — `dealsEndpoints.{list, detail, proposeVisit, updateVisit, visitFeedback, openConversation, attest}` against `/api/deals`. NEW `src/types/backend/deal.ts` — `DealStage`, `Visit`, `DealListRow`, `DealDetail`, `BuyerContext`, every request/response.
- NEW `src/features/deals/`: `hooks.ts` (`useMyDeals` infinite, `useDeal`, `useProposeVisit`, `useUpdateVisit`, `useVisitFeedback`, `useOpenConversation`, `useAttestClose`; every write invalidates `qk.deals` AND `qk.leads`), `stage.ts` (labels, tones, order), `visitState.ts` (which controls each party sees per visit status, pure), `visitTime.ts` (validation, 60-day cap), `components/{DealProgress, VisitCard, VisitSheet, DealRow, CounterpartCard, DealMessages, ReportMessageSheet, AgreementCard, CloseCard, BuyerContextCard}.tsx`, tests `stage.test.ts`, `visitState.test.ts`, `visitTime.test.ts`.
- `app/deal/[leadId].tsx` — REPLACES the Phase 0 placeholder. Listing strip, progress, counterpart (phone on the buyer side only after `contactRevealed`), visits, messages, agreement (only when `agreementsEnabled`), close (verification, attestation, claim, review), buyer context (owner side). Behind `RequireAuth` with a `deal` intent. Emits `deal_open`, `visit_proposed`, `visit_confirmed`, `visit_done`, `message_sent`.
- `src/socket/SocketProvider.tsx` — disconnects in its effect cleanup. **It is mounted ONLY by the deal page, around the message wall, and only when the deal has a conversation.** Not at the root; D2 (HANDOFF §9.1) stands.
- `src/features/chat/{api,hooks,index}.ts`, `components/ChatComposer.tsx` — `sendMessage` returns `{ message, warning, wire }` so a lure warning the server appends lands in the thread and is re-emitted on the socket; `onFocus` on the composer. `src/api/endpoints/chat.ts` — `reportMessage` (`POST /chat/message/report`). `src/types/backend/chat.ts` — `warning`, `flagged`, the report request/response.
- `src/auth/pendingIntent.ts` — `deal` and `review` intents (return-to only; nothing re-fires).
- `src/api/errors.ts`, `src/types/backend/common.ts` — the Phase 2/3 error codes (`NOT_A_PARTY`, `VISIT_ALREADY_OPEN`, `CHAT_DISABLED`, `PAYOUT_ON_HOLD`, ...) and `details.holdUntil` / `details.visitId`.
- `src/types/backend/lead.ts` — `stage`, `firstOwnerResponseAt`, `buyerContext` on `Lead`, all optional. NEW `src/features/leads/buyerContext.ts` — `buyerContextLine`, `buyerContextFacts`, `budgetFitLabel` (one wording for the row and the card).
- `src/api/queryKeys.ts` — `deals`, `dealList`, `dealDetail`, `reviews`, `reviewEligibility`, `reviewsForUser`, `rewardsPolicy`.

Reviews and trust (Phase 3):
- NEW `src/api/endpoints/reviews.ts` — `reviewsEndpoints.{eligibility, submit, forUser, mine}`. NEW `src/types/backend/review.ts`.
- NEW `src/features/reviews/`: `hooks.ts` (`useReviewEligibility`, `useSubmitReview`, `useUserReviews` infinite by 10), `components/{StarRating, ReviewCard, OwnerReviewsSheet}.tsx`.
- `app/review/[verificationId].tsx` — REPLACES the Phase 0 placeholder. Keyed by the verification; renders the eligibility state the server reports; emits `review_submitted`.
- `src/types/backend/property.ts` — `OwnerStats`, `Property.ownerStats`. `src/features/properties/{types,adapters}.ts` — `PropertyDetail.ownerStats` (null when absent). `src/features/properties/components/DetailOwner.tsx` — verification badge, "Usually replies within ~Nh", "★ overall · N verified reviews"; the reviews line is a control only when the page passes `onShowReviews`. `app/property/[id]/index.tsx` — threads `ownerStats`, owns `OwnerReviewsSheet` (list fetched only once opened). **Still never renders the owner's phone or email.**
- `src/api/endpoints/rewards.ts`, `src/types/backend/rewards.ts` — `policy` (`GET /rewards/policy`), `RewardsWallet.lockedPoints`. `src/features/rewards/hooks.ts` — `useWallet().lockedPoints`, NEW `useRewardsPolicy` (1h stale). `app/rewards/index.tsx` — locked points line under the balance when > 0; "How rewards work" card (milestones only when non-empty, close payout line, hold days, point value). Numbers only.
- `app/claim-reward/[verificationId].tsx` — 409 `PAYOUT_ON_HOLD` renders a calm "Reserved for you" state with `holdUntil`, not an error; both it and the success state offer "Review this deal" → `/review/:verificationId`.
- `src/api/endpoints/users.ts`, `src/types/backend/user.ts` — `registerDevice` (`POST /users/device`). NEW `src/auth/deviceLink.ts` — `linkDeviceOnce(userId)`: posts the analytics installation id once per (install, account), guarded by `PREF_KEYS.deviceLinkedFor` (`src/storage/mmkv.ts`), fire-and-forget, errors swallowed and the guard left unset. `src/auth/AuthProvider.tsx` — calls it from the identity effect alongside push registration.

Owner surfaces and Activity:
- `app/(tabs)/activity.tsx` — the `enquiries` segment is labelled **"Deals"** (value unchanged: Home's tile and `hrefForTarget` send it) and renders `useMyDeals()` with `DealRow`, both roles, sorted by `updatedAt`, tap → `/deal/:id`, paginated. `EnquiryMeter` stays as the list header (from `useSavedProperties`), and a buyer-side row whose listing is still on the saved list gets an overflow that withdraws the enquiry via `useRemoveInterest`. Withdrawing frees the slot and leaves the deal row: the lead does not un-exist. `SavedPropertyCard`, `useSaveToggle` and `EnquirySheet` are no longer used on this screen.
- `src/features/leads/components/LeadCard.tsx` — one muted `buyerContextLine` when `lead.buyerContext` is present. `app/owner/leads/[id].tsx` — primary "Open deal" button → `/deal/:leadId`. NEW `src/features/leads/thisWeek.ts` (+ test) — `summariseWeek`, `isWaitingOnOwner`. `app/owner/analytics.tsx` — "This week" block at the top from `useLeads()`: new leads in 7 days, leads waiting on the owner (no `firstOwnerResponseAt` when the field is present, else `isViewed === false`; older than 24h; not converted/lost), "N+" when more pages exist, plus "Your weekly report arrives every Monday."
- `src/features/deals/components/{CounterpartCard,VisitSheet}.tsx` — two `&apos;` lint fixes only.

**Reason**
Master plan Phases 2 and 3, mobile lane: the lead becomes a deal the user can follow (visits, thread, agreement, close) from either side; trust content (reviews, verification, reply time) only verified parties can write; rewards that cannot be farmed before a verified close. The Activity tab is where a buyer already went to see enquiries, so that is where deals live.

**Architectural impact**
- **`SocketProvider` is mounted only inside `app/deal/[leadId].tsx`.** Nothing else in the app opens a socket. A screen that needs one mounts it itself and accepts the connect/disconnect cost.
- **Chat and agreements are server-gated, not client-gated.** The deal page reads `chatEnabled` / `agreementsEnabled` from `GET /deals/:leadId` and renders a quiet "not available" line otherwise. `useOpenConversation` treats 503 `CHAT_DISABLED` as state, not fault.
- **`Lead.stage` is never sent by the client.** Every deal write returns it; the hooks invalidate `qk.deals` and `qk.leads` together because one document backs both.
- **The buyer never sees the owner's phone before `contactRevealed`**, and the public property detail still shows neither phone nor email. `ownerStats` is aggregate only.
- **Withdrawing an enquiry does not remove the deal.** The Activity row stays; only the slot and the overflow go. Copy says so.
- **`PAYOUT_ON_HOLD` is a state.** The claim screen must not render it as an error; the hold date comes from `error.details.holdUntil`.
- **Device linkage is once per (install, account)** and its guard survives logout by design (`prefsStorage`, not user-scoped storage). A second account on the same phone re-sends, which is the case the fraud check exists for.
- The "This week" figures are client-derived from the first lead page(s); they are lower bounds when `hasMore` and the screen says so with a "+". Exact counts would need a server field that does not exist.
- The Activity "Deals" segment issues two authenticated requests (`GET /deals`, `GET /properties/saved`); a guest issues neither.

**Migration notes**
No schema change, no backend change, no new dependency, no new native module. Everything renders correctly against a backend older than Phase 2/3: every new field is optional and every new section is gated on its presence.

**Docs updated**
`dealdirect-mobile/docs/HANDOFF.md` §14 (written by the first session) already points at this entry. Debt markers: `AI/FILE_MAP.md` does not list `src/features/{deals,reviews}`, `src/auth/deviceLink.ts`, `src/features/leads/{buyerContext,thisWeek}.ts`; `AI/API_REFERENCE.md` still lacks `/deals`, `/reviews`, `/rewards/policy`, `/users/device`; `AI/MASTER_MEMORY.md`'s "scaffolding only" description of the mobile app is long stale.

**Verification**
`npx tsc --noEmit` clean. `npx expo lint` 0 errors / 17 warnings (12 pre-existing plus five `Array<T>` / unused-helper warnings from the first session's files, left as they are). `npm test` 285/285 across 34 suites (new: `src/features/leads/thisWeek.test.ts`, 9 cases). `npx expo export --platform android` bundles (8.15 MB hbc). **Nothing was run on a device or emulator.** The deal room flows (propose, confirm, done by both, feedback, message with a lure, report, attest, review), the Activity Deals list, the owner reviews sheet, the reserved-payout state and device linkage are all unverified on hardware; the installed dev client cannot load this JS without the rebuild the Phase 0 entry describes.

## 2026-09-04 — Mobile Phase 0: push tokens, tap routing, usage events, Sentry (mobile only)

**Files changed** — `dealdirect-mobile/` only. **No backend file was touched.** The backend side of this (push-token routes, `/events`, `data.kind` on notifications) was already deployed by the backend lane and is consumed here as-is.
- NEW `src/notifications/pushToken.ts` — token lifecycle: `registerPushTokenIfPermitted`, `unregisterPushToken`, `setPushTokenUser`, `peekCachedPushToken`, `clearPushTokenCache`. Never prompts.
- NEW `src/notifications/PushRouter.tsx` — push tap → route, warm and cold start, one-shot per response id. Mounted in `app/_layout.tsx` inside `AuthProvider`.
- NEW `src/analytics/{events,queue,track,installationId,index}.ts` — usage-event vocabulary (typed map), pure persisted queue, RN glue (AppState, timer, `POST /events`), per-install `anon` id.
- NEW `src/observability/{sentry,index}.ts` — `initSentry`, `setSentryUser`, `wrapRoot`; `@sentry/react-native` loaded through `optionalNativeModule`.
- NEW `app/deal/[leadId].tsx`, `app/review/[verificationId].tsx` — PLACEHOLDERS ("Coming soon") so typed routes accept `/deal/:id` and `/review/:id`. The deal and review lanes replace these files wholesale.
- NEW tests `src/features/notifications/targets.test.ts`, `src/analytics/track.test.ts`; `package.json` `test` glob is now `src/**/*.test.ts`.
- `src/features/notifications/targets.ts` — `NOTIFICATION_KINDS`, `readNotificationKind`, `resolveTargetFromData` (kind-first), `hrefForTarget` (the ONE target→route function); new target kinds `deal`, `message`, `review`, `digest`. `resolveNotificationTarget` tries `data.kind` before its older `type`/`propertyId`/`actionUrl` heuristics.
- `src/api/endpoints/users.ts` — `registerPushToken`, `removePushToken` (DELETE with body), `logout` now typed `LogoutRequest` (`{ pushToken? }`). `src/api/endpoints/misc.ts` — `eventsEndpoints.ingest`. `_contract.ts` — `'events'` rate tier. `src/types/backend/{user,misc}.ts` — the request/response types.
- `src/auth/AuthProvider.tsx` — on any user change: `setSentryUser({ id, role } | null)`, `setPushTokenUser`, and (when authenticated) fire-and-forget `registerPushTokenIfPermitted`; `logout` sends `{ pushToken }` when cached; `endSession` clears the token cache.
- `src/storage/mmkv.ts` — three `PREF_KEYS`: `pushToken`, `installationId`, `analyticsQueue`.
- `app/_layout.tsx` — `initSentry()` at module scope, `useEffect(startAnalytics, [])`, `<PushRouter />`, default export is now `wrapRoot(RootLayout)`.
- `app/(tabs)/updates.tsx` — row tap goes through `hrefForTarget`, emits `notification_opened { kind }`.
- `app/(tabs)/index.tsx` (Home, FROZEN) — ONE callback changed, `openNotification`, 3 lines: `router.push(target ? hrefForTarget(target) : '/(tabs)/updates')`. Unavoidable: the old `else` branch sent every unrecognised kind (now `deal`, `message`, `review`, `digest`) to the saved-searches segment. Nothing else in the file or under `src/features/home/` was touched.
- Call sites, one or two lines each: `ShortlistButton.tsx` (`shortlist_add` + permission prompt + token registration on ADD), `SaveSearchSheet.tsx` (`saved_search_create` + the same prompt/registration on success), `saved/saveToggle.ts` (`contact_owner` on interest success), `properties/hooks.ts` `useRecordPropertyView` (`property_view`, already deduped per id, called by the detail screen), `search/components/SearchScreen.tsx` (`search { city, listingType, results }` once per distinct filter set after results settle).
- `app.config.js` — `@sentry/react-native/expo` plugin (org/project from `SENTRY_ORG`/`SENTRY_PROJECT`, defaults `dealdirect`/`dealdirect-mobile`). `.env.example` — `EXPO_PUBLIC_SENTRY_DSN` (optional). `src/notifications/handler.ts` — doc comment only: the "no backend push" note is now history.
- Installed: `@sentry/react-native@~7.2.0` via `npx expo install`; `package-lock.json` regenerated with `node scripts/relock.mjs` (npm 10.9.3, EAS-compatible).

**Reason**
Master plan Phase 0, mobile lane: the app must be able to receive a push and open the right screen, report crashes, and say what users do. Until now `resolveNotificationTarget` guessed from `type` and `propertyId`; every push and in-app notification now carries `data.kind`, and the client reads that first.

**Architectural impact**
- **The OS notification prompt is asked at exactly two moments and never at launch:** the first shortlist add and the first saved-search create. `requestNotificationPermissionOnce` still asks once ever. `registerPushTokenIfPermitted` NEVER prompts; it only posts a token the OS has already allowed. Do not add a launch-time prompt.
- **`hrefForTarget` is the only place a `NotificationTarget` becomes a route.** Home, Updates and PushRouter all call it. A new kind is added in `targets.ts` (vocabulary + resolver + href) and nowhere else. `data.actionUrl` is still consulted for one shape only (`/propert(y|ies)/<24-hex>`), and never by the kind-first resolver.
- **`data.kind` is closed and ids are validated as ObjectIds.** `visit` resolves to the deal (`/deal/:leadId`). `message` opens `/deal/:leadId` when a leadId is present, else `/chat/:conversationId`. **`review` requires `verificationId`; a payload carrying only `reviewId` resolves to nothing** (the review route is keyed by verification, and routing a review id into it would 404). If the review lane keys its screen differently, change `targets.ts`, not the callers.
- **Push token cache is keyed on (token, userId) with a 24h re-post window,** cleared on every session end. Re-posting re-points the token at the current account; the logout body carries it so the server drops it.
- **Usage events are whitelisted at the type level** (`UsageEvents` map): an unknown name or prop is a compile error. Queue: MMKV-mirrored, cap 200 (oldest dropped), batches of 50, flush at 20 / every 30s while foregrounded / on background. A 4xx drops the batch; network, 5xx **and 429** keep it (429 deviates from "drop on 4xx" deliberately: it is "not now", not "not ever"). The 30s timer is a no-op on an empty queue, so the Search tab's idle state still issues no request.
- **Sentry sends `{ id, role }` only.** `sendDefaultPii: false`; `beforeSend`/`beforeSendTransaction` delete `request.cookies`, `request.headers` and any breadcrumb data key named `cookie`/`authorization`/`set-cookie`. Without `EXPO_PUBLIC_SENTRY_DSN` the SDK never initialises and `wrapRoot` is the identity.
- The `features/shortlist` store still imports no API client. `ShortlistButton` (the component) now imports `@/analytics` and `@/notifications`; the only requests it can cause are the usage event and the token registration, never a property endpoint. Its doc comment says so.
- `AuthProvider` imports `@/notifications/pushToken` by file, not the barrel, because the barrel exports `PushBridge` which imports `@/auth`.
- Two native additions since the last rebuild: `@sentry/react-native` (new) and the push half of `expo-notifications` (module already present, now actually used for tokens). **REQUIRES `expo prebuild` and a fresh dev-client / production build** (`runtimeVersion.policy: 'fingerprint'`).

**Migration notes**
- Env: `EXPO_PUBLIC_SENTRY_DSN` (runtime, optional), `SENTRY_ORG`, `SENTRY_PROJECT`, `SENTRY_AUTH_TOKEN` (build time, for source-map upload; skipped without). None are set anywhere yet. A mobile Sentry project and DSN are still needed.
- **Android push needs FCM credentials that do not exist in this repo:** `getExpoPushTokenAsync` on Android requires a `google-services.json` referenced from `app.config.js` (`android.googleServicesFile`) and FCM V1 credentials uploaded to EAS. Without them the call throws, `registerPushTokenIfPermitted` swallows it with a `[push]` warning, and no token is ever registered. iOS needs an APNs key in EAS. Neither is a code change here.
- No schema change, no backend change, no data migration.

**Docs updated**
None. Debt markers: `dealdirect-mobile/docs/HANDOFF.md` §2.14 and §5.1 still say server push is blocked and list four native modules; both are now stale. `AI/FILE_MAP.md` does not list `src/analytics/`, `src/observability/`, `src/notifications/{pushToken,PushRouter}`.

**Verification**
`npm test` 223/223 (two new suites), `npx tsc --noEmit` clean, `npx expo lint` 0 errors / 12 pre-existing warnings, `npx expo export --platform android` bundles (8.04 MB hbc). Typed routes for `/deal` and `/review` were regenerated by calling `expo-router`'s `regenerateDeclarations` directly, since `expo export` does not touch `.expo/types/router.d.ts` (only `expo start` does); that file is git-ignored. **Nothing was run on a device or emulator. The permission prompt, token registration, cold-start push routing, event flushing and Sentry initialisation are all unverified on hardware, and the current dev client cannot load this JS without a rebuild.**

## 2026-09-04 — Backend Phases 0, 2 and 3 of the upgrade master plan (additive)

Plan of record: `DEALDIRECT-UPGRADE-MASTER-PLAN.md` (repo root). Everything below is additive: no existing route changed its contract, no existing field changed meaning, and every new behaviour that costs money or changes what users receive is behind configuration whose default reproduces the pre-change behaviour.

**Files changed**

Phase 0 (engines E1, E2; F1–F6)
- NEW `models/PushToken.js`, `models/OutboundLog.js`, `models/JobRun.js`, `models/Event.js` (Event + EventRollup).
- NEW `services/pushService.js` — Expo Push Service sender, batches of 100, `DeviceNotRegistered` disables the token, receipts polled by a job. `EXPO_PUSH_URL` is overridable (the test harness points it at a loopback fake).
- `services/notificationService.js` — `NOTIFICATION_POLICY` (per-type channels: push / email always|capped|never / whatsapp / critical), `WEEKLY_CAP=3` on email+WhatsApp for non-critical types via `OutboundLog`, `data.kind` stamped on every notification, `pushOnly()` for chat. Every pre-existing type keeps `email: "always"`.
- `services/whatsappService.js` — Meta Cloud API provider behind `WHATSAPP_PROVIDER` / `META_WA_*`; same exported functions. WAHA remains the fallback.
- NEW `jobs/runner.js` (node-cron, `JobRun` rows, overlap + stale protection, cursor idempotency), `jobs/registry.js` (the job table), `jobs/pushTokenPrune.js`, `jobs/eventsRollup.js`, and later `jobs/visitReminders.js`, `jobs/ownerWeeklyDigest.js`, `jobs/reviewPublish.js`. Started from `server.js` only outside `NODE_ENV=test`; `JOBS_ENABLED=false` disables.
- NEW `controllers/pushTokenController.js` + `routes/userRoutes.js`: `POST/DELETE /users/push-token`. `POST /users/logout` accepts `{pushToken}`; logout-all deletes all tokens.
- NEW `controllers/eventController.js` + `routes/eventRoutes.js`: `POST /events` (closed name whitelist, per-name prop whitelist, 50/batch, 30 batches/min/IP, optionalAuth), `GET /admin/metrics` (admin).
- `models/Notification.js` — partial TTL index `ttl_read_notifications` (read rows expire 90 days after last update; unread never).
- `services/rewardService.js` — B5 `upload_5_photos` mapped (50 pts, once per property); B11 `referral_first_action` (50) and `referral_deal_closure` (500) mapped and wired from `markInterested`, `addProperty`, `claimDealReward`; B12 `trackDailyLogin` and `LoginTracker` DELETED, `Reward.monthlyLoginDays/lastLoginDate` removed from the schema (research reversed the streak mechanic).
- `controllers/chatController.js` — B3 fixed: `conversation.lastMessage.text` now stores the escaped text.
- `utils/aggregateDelete.js` — cascade now deletes `PushToken`, `OutboundLog`, `Event` (14 collections, was 12).
- `.env.example` — new keys documented.

Phase 2 (engine E3; F10–F14)
- `models/Lead.js` — the deal spine: `stage` (derived, cached), `visits[]` (proposed/confirmed/done/no_show/cancelled, `doneConfirmedBy[]`, `remindersSent[]`, feedback), `conversation`, `agreement`/`agreementAt`, `verification`, `closedAt`, `firstOwnerResponseAt`. Three new indexes.
- NEW `utils/dealStage.js` (`deriveStage`, `progressFor`), `utils/scamHeuristics.js` (`detectLure`, warning copy).
- NEW `controllers/dealController.js` + `routes/dealRoutes.js` at `/api/deals`: `GET /deals`, `GET /deals/:leadId`, `POST /deals/:leadId/visits`, `PUT /deals/:leadId/visits/:visitId` (confirm|cancel|done|no_show), `POST .../feedback`, `POST /deals/:leadId/conversation` (503 `CHAT_DISABLED` unless `CHAT_ENABLED=true`), `POST /deals/:leadId/attest`.
- `controllers/chatController.js` — lure detection on send (message flagged + a `system` warning message), `owner_replied` notification on the owner's first message per lead, push-only nudges otherwise (throttled per conversation), NEW `POST /chat/message/report` (Report with `contextType: message`).
- `controllers/leadController.js` — owner status updates and contact logs set `firstOwnerResponseAt`; `GET /leads` rows gain `buyerContext`.
- `controllers/propertyController.js` — public `GET /properties/:id` gains `ownerStats { responseHours, answered, verified, documentsVerified, reviews }` (response time null under 3 answered leads); `closeDeal` links the verification to the lead; claim refuses `PAYOUT_ON_HOLD`.
- `controllers/adminController.js` — approval closes the lead through the spine, runs the linkage check, sets the hold, sends `review_request`; NEW `PUT /admin/users/:id/verification`; verification list rows gain `fraudFlagDetails`.
- `controllers/agreementController.js` — generation attaches the agreement to the lead and notifies both; full signature awards the agreement milestone. `server.js` mounts `/api/agreements` only when `AGREEMENTS_ENABLED=true` (D1 re-opened, off by default).
- `models/Property.js` — `digestBaseline {views, at}` for the weekly digest delta.

Phase 3 (F15–F17)
- NEW `config/rewardPolicy.js` — env-driven: `MILESTONE_REWARDS_ENABLED`, `MILESTONE_VISIT_POINTS`, `MILESTONE_AGREEMENT_POINTS`, `CLOSE_PAYOUT_FIXED_POINTS`, `PAYOUT_HOLD_DAYS`, `PAYOUT_HOLD_DAYS_FLAGGED`. Defaults = pre-Phase-3 behaviour. `GET /rewards/policy` is the public explainer.
- `models/Reward.js` — `lockedPoints`; `addTransaction` routes `metadata.cashable === false` earns into it (tier progress, never redeemable). `services/rewardService.js` — `awardMilestone()`, fixed close base on top of the draw when configured.
- `models/TransactionVerification.js` — `payoutHoldUntil`, `fraudFlags[]`, `attestations.{owner,buyer}`. NEW `utils/fraudLinkage.js` (same_device, same_phone, same_ip, young_account, first_action_close, owner_velocity, attestation_missing/dispute/mismatch).
- `models/userModel.js` — `verification {identity, documents, verifiedAt, verifiedBy}`, `deviceHashes[]` (select false), `payoutVpa` (select false). NEW `POST /users/device`.
- NEW `models/Review.js`, `controllers/reviewController.js`, `routes/reviewRoutes.js` at `/api/reviews`: `POST /reviews`, `GET /reviews/user/:userId` (public, published only), `GET /reviews/mine`, `GET /reviews/eligibility/:verificationId`. Simultaneous reveal: publishes when both sides are in or 14 days after the first (`jobs/reviewPublish.js`).
- NEW `utils/buyerContext.js` — `{activeWeeks, enquiries, visitsDone, budgetFit}` per buyer, aggregate only.

**Reason**
The client proposal (`dealdirectupgradeplan.docx`) and the growth research behind it: return triggers, the deal as the system of record, trust content only verified parties can write, and rewards that cannot be farmed before a verified close.

**Architectural impact**
- The backend now has a scheduler. Handlers are pure functions of `({ now, cursor })` and are tested by direct call; only `jobs/runner.js` touches the clock. Add a job = one row in `jobs/registry.js`.
- Every notification carries `data.kind` from a closed vocabulary (`property, leads, dealReward, savedSearches, deal, visit, message, review, digest`). Clients route on it; `actionUrl` remains informational.
- `Lead.stage` is derived. No client may set it; `syncStage` refreshes it whenever a fact changes.
- The buyer sees the owner's phone in the deal room only after `firstOwnerResponseAt` is set. The owner sees buyer contact at once (unchanged).
- Milestone points are non-cashable by construction (`lockedPoints`), not by policy text.
- Chat messages never write Notification rows; they push only. The Updates tab is unaffected by chat volume.
- `CHAT_ENABLED` and `AGREEMENTS_ENABLED` are the two product switches; both default off.

**Migration notes**
- New env keys (see `.env.example`): `EXPO_ACCESS_TOKEN` (optional), `WHATSAPP_PROVIDER`, `META_WA_*`, `JOBS_ENABLED`, `AGREEMENTS_ENABLED`, the six reward-policy keys. Email: switch SMTP to Brevo when the account exists (config only).
- Indexes build lazily on first boot (Notification TTL, Lead deal indexes, Review unique). No backfill: every new field is optional with a default.
- `npm install` on the server (`node-cron` added).
- Deploy order unchanged: backend first, then the mobile build that advertises these features.

**Verification**
`npm test` (unit) and `npm run test:integration` both green after the change, including new suites: `tests/{deal-stage,scam-heuristics,notification-policy,jobs-pure,reward-policy}.test.js` and `tests/integration/{push-and-policy,events,deal-room,deal-room-chat-off,trust}.test.js`. Nothing was run against production.

**Docs updated**
None of `AI/API_REFERENCE.md`, `AI/DATABASE.md`, `AI/FILE_MAP.md`, `AI/KNOWN_BUGS.md` were updated in this change — debt marker. KNOWN_BUGS B3, B5, B11, B12 are fixed by this entry; DATABASE.md still lists `logintrackers`.

## 2026-08-24 — Mobile Phase 3: native capability layer (mobile only, REBUILD REQUIRED)

**Files changed**
- NEW `dealdirect-mobile/src/native/{haptics,location,biometrics,clipboard,index}.ts` — capability wrappers, each behind `optionalNativeModule`.
- NEW `src/features/properties/components/map/{leafletHtml.ts, LeafletMap.tsx}` — Leaflet-in-WebView, typed bridge.
- `app/property/[id]/map.tsx` — was the last `Placeholder`; now a real map, degrades to locality text.
- `src/features/search/components/{SearchScreen,ResultsToolbar}.tsx` — list ↔ map toggle over results.
- `src/features/listings/imagePicker.ts` + `ListingForm.tsx` — `captureListingImage` (camera).
- `src/features/home/components/CityPickerSheet.tsx` — "Use my location" (OS reverse-geocode + `matchCity`).
- NEW `src/ui/DateField.tsx` — native date picker, degrades to text; wired into Settings DOB and listing `availableFrom`.
- `app/settings/index.tsx` — RN `Switch` replaces checkbox glyphs.
- `app/settings/delete-account.tsx` — biometric confirm before deletion.
- `app.config.js` — expo-location (foreground), expo-local-authentication, datetimepicker plugins.
- Deleted `src/dev/Placeholder.tsx`.
- Installed: expo-haptics, expo-location, expo-local-authentication, expo-clipboard, @react-native-community/datetimepicker.

**Reason**
Group C/F of `DEALDIRECT-APP-FUNCTIONAL-REVIEW.md`: the definitional mobile capabilities the app lacked (map, camera, location) and the native texture (haptics, real controls, biometric confirm).

**Architectural impact**
- **The WebView map is a session-security invariant, not a style choice.** It receives markers over `postMessage` and emits only taps; it must NEVER originate an API request, because the cookie session is bound to a constant User-Agent and the absence of an Origin header, and a WebView request would carry an Origin and 403 on the 16 CSRF-guarded routes. See `leafletHtml.ts`.
- Every native module loads through `optionalNativeModule`; absence degrades, never crashes.
- Biometrics are CONFIRMATION, never authentication: server still mints/revokes the session and still requires the password to delete.
- Location is foreground + on-demand only; no watcher, no background permission.

**Migration notes**
- **REQUIRES `expo prebuild` + a fresh dev-client / production build.** Five new native modules change the fingerprint (`runtimeVersion.policy: 'fingerprint'`), so the current debug APK cannot load this JS. This is the point at which the deferred device build becomes mandatory.
- No backend change, no schema change. Leaflet loads from unpkg (pilot); vendoring is a flagged follow-up.

**Not done (deferred, stated so it is not assumed complete)**
- Sentry crash reporting (W9/F10): needs a mobile Sentry DSN + project decision — not installed.
- Full biometric app-lock: only the sensitive-action confirm is wired.
- Swipe row actions, pull-to-refresh gaps (W17), transactions pagination (W20): pure-JS, not in this native batch.
- Server push (Phase 4): needs a device-token pipeline the backend does not have.

**Docs updated**
None. `AI/FILE_MAP.md` and `AI/COMPONENT_INDEX.md` do not yet list `src/native/` or the map components — debt marker.

**Verification**
`tsc --noEmit` clean, `expo lint` 0 errors / 12 baseline warnings, `expo export` (Android) bundles. **Nothing run on a device — DEVICE VERIFICATION PENDING, and this batch cannot even load without a rebuild.**

## 2026-08-24 — Mobile Phase 1: the app stops being shaped like the website (mobile only)

**Files changed**
- `app/(tabs)/_layout.tsx`, `src/ui/TabBar.tsx` — tab set is now Search / Activity / Updates / Profile. `properties`, `saved` and `chat` are registered `href: null`.
- `app/(tabs)/index.tsx` — was Home (marketing landing page); now mounts the search engine.
- `src/features/search/components/SearchScreen.tsx` — NEW. The former `app/(tabs)/properties.tsx`, moved verbatim (diff of the old route body against it is four hunks, all doc comments). Gained an idle-state list header.
- `src/features/search/resume.ts`, `components/ResumeSearchCard.tsx` — NEW. "Continue your search": last filter set + result count, MMKV, 14-day expiry.
- `app/(tabs)/activity.tsx` — was `saved.tsx`. Four segments: Shortlist, Enquiries, Searches, Bookings. Accepts a validated `segment` param.
- `app/(tabs)/updates.tsx` — was `app/notifications.tsx`, promoted to a tab.
- `src/features/shortlist/**` — NEW feature module (store + row + button).
- `src/auth/pendingIntent.ts` — NEW. Return-to-intent across login/register/OTP.
- `app/(tabs)/profile.tsx` — link directory removed.
- `app/support.tsx`, `src/features/content/faq.ts` (deleted) — ported FAQ removed.
- `app/(tabs)/properties.tsx`, `app/(tabs)/saved.tsx`, `app/notifications.tsx` — now redirects.
- Deleted: `src/features/home/components/{Hero,HeroSearchField,CtaBanner}.tsx`, `src/ui/BottomNavBar.tsx` (orphan, 369 lines).
- `src/features/projects/components/BookingRow.tsx` — NEW, extracted from `app/projects/bookings.tsx` and shared with Activity.
- `src/storage/mmkv.ts` — three new `PREF_KEYS`: `resumeSearch`, `shortlist`, `pendingIntent`.

**Reason**
The functional review (`DEALDIRECT-APP-FUNCTIONAL-REVIEW.md`) found the codebase genuinely native but the PRODUCT shaped like the website: a marketing home screen, a Profile tab that was the app's sitemap, ported FAQ and blog, and navigation organised around the company's destinations rather than the user's activity. Phase 1 changes the shape only.

**Architectural impact**
- **A future session must not assume `/(tabs)/properties` is a screen.** It is a param-forwarding redirect; the search screen is `/(tabs)` and its implementation is `features/search/components/SearchScreen`.
- **There are now TWO save concepts and they must never be merged.** `features/shortlist` is device-local, creates no Lead, notifies nobody, and imports no API client — that last part is the enforcement, not a convention. `features/saved` (`useSaveToggle` → `POST /properties/interested/:id`) remains the capped, owner-notifying enquiry. Wiring a shortlist control to the interest endpoint would silently email owners.
- New invariant: every `resume` route param is validated against the values its screen expects, so a deep link can open a screen but can never raise a confirmation or payment sheet.
- `PendingIntent` is single-use and expires in 15 minutes; it persists to MMKV because the owner-registration OTP flow can be killed by the OS while the user reads an SMS.
- The Search tab's idle state issues **no** network requests. Anything added there must keep that property — `/properties/search` is limited to 20/min per IP shared behind carrier NAT.
- Updates deliberately has **no** dock badge and derives "unread" from the 100 rows it already holds, because `GET /notifications/unread-count` does not exist.

**Migration notes**
None. No backend change, no schema change, no env var. Deploys independently as a mobile-only release.

**Docs updated**
None yet — this is a debt marker. `AI/FILE_MAP.md` and `AI/COMPONENT_INDEX.md` still describe the Home tab, `app/(tabs)/saved.tsx` and `app/notifications.tsx` at their old paths. `DEALDIRECT-MOBILE-PARITY-AUDIT.md` §4 and §9 are now stale on routes and navigation. `DEALDIRECT-APP-TRANSFORMATION-PHASE0.md` holds the plan this executed.

**Verification**
`tsc --noEmit` clean, `expo lint` 0 errors / 12 pre-existing warnings, `expo export` (Android) bundles. **No flow has been run on a device or emulator — DEVICE VERIFICATION PENDING.**

## 2026-08-22 — Mobile: Hubble redemption in-app, unit-page depth, and a third dead-field defect

**Files changed** — `dealdirect-mobile/` only; **no backend file was touched** and no endpoint, schema or env var was added.
- Added: `app/rewards/redeem.tsx`, `src/features/rewards/hubble.ts`, `plugins/withUpiQueries.js`, `src/ui/BottomNavBar.tsx`
- Modified: `src/api/endpoints/rewards.ts`, `src/types/backend/rewards.ts`, `src/types/backend/project.ts`, `src/features/rewards/index.ts`, `app/rewards/index.tsx`, `app/projects/unit/[unitTypeId].tsx`, `app.config.js`, `src/ui/{TabBar,PressableScale}.tsx`, `app/(tabs)/index.tsx`, `src/features/home/{cities.ts,index.ts}`
- Deleted: `src/features/home/components/{TrustStrip,AboutDealDirect}.tsx`
- Dependencies added: `react-native-webview`, `lucide-react-native`, `react-native-svg` — **all three are native; an OTA update cannot deliver any of this.**

**Rewards redemption (reverses half of D3).** D3 recorded redemption as a separate workstream because it moves real money; Chirag asked for it in-app on 2026-08-22. Implemented as the Hubble SDK hosted in a WebView, consuming the two client-facing routes that already existed (`GET /api/rewards/hubble/config`, `GET /api/rewards/hubble/token`). The other four Hubble routes are server-to-server behind `X-Hubble-Secret` and are Hubble's to call.

Three constraints drove the design:
1. **The WebView must never call the DealDirect API.** `api/client.ts` documents why: `requireCsrf` waves through requests with no `Origin`, which is the native client's exemption, and a WebView *does* send `Origin` — twelve write routes would answer `CSRF_ORIGIN_REJECTED`. Compliant by construction here: the WebView loads `sdk.myhubble.money`, and the session is fetched natively and passed in via the URL.
2. **The session is deliberately outside TanStack.** The SSO token is single-use with a five-minute server-side life, so a cached one is always spent or expired; and the config carries `appSecret`, which the MMKV persister would write to disk. Both live in component state. Config is fetched **before** the token so a 503 does not burn a perishable credential.
3. **Internal-URL matching is on HOST, not the SDK base URL.** Matching the base URL alone sends Razorpay to the system browser: the user pays outside the WebView and the SDK never sees the result.

UPI handoff needs native declarations on both platforms or `Linking.openURL` fails silently. `/android` and `/ios` are gitignored prebuild output here, so this is a config plugin (`plugins/withUpiQueries.js`), verified through `expo config --type introspect`. **The scheme/package list is the common Indian set and has NOT been confirmed with Hubble** — their guide asks for exactly that review.

**Unit-page depth (W6).** Added area/configuration, price breakdown, all-inclusive cost sheet, specifications, availability with tower allocation, interiors grouped by room, and the video-tour link. GST, stamp duty and registration are computed for display only and stay **out** of `effectivePrice`, matching the server's pre-save hook and the website — folding taxes into a list price would misstate every cross-project comparison. The cost sheet hides itself when none of the three is configured, because a "total" equal to the price above it implies there is nothing more to pay.

**Third dead-field defect, same class as the previous two.** `UnitType.floorPlans` is `{twoDUrl, threeDUrl, videoUrl}`; the mobile type declared `twoDFloorPlan`/`threeDFloorPlan`. Both reads were permanently `undefined`, so **the floor plan at the top of the unit screen never rendered once**. With `inventory.available` (2026-08-22, earlier) and the `wallet.balance`/`payment.utr` pair (F1/F5, 2026-08-13), that is three separate cases of a mobile type inventing field names. The registry is accurate about ROUTES and has been repeatedly wrong about nested FIELD paths; a contract test asserting adapters against recorded fixtures would have caught all three.

**Also in this pass:** the dock was made genuinely floating (absolutely positioned, so the navigator reserves no strip), its selection animation rebuilt onto one coordinated set of shared values, and two motion bugs fixed — `interpolateColor` from `'transparent'` (which is *black* at zero alpha, so the pill flashed grey mid-transition; now an opacity-animated solid layer) and a label that re-ellipsised every frame inside the shrinking clip (now pinned to its measured width). Home lost the trust strip and the "Why DealDirect" pitch, gained Ranchi in Explore by City (the only live city with inventory and no tile), and moved the budget tools under Builder Projects.

**Migration notes**
None — client-side only. `tsc --noEmit` clean, `expo lint` 0 errors (12 pre-existing warnings), `expo export --platform android` succeeds, config plugin verified by introspection. **Nothing in this entry has been run on a device.** For redemption that gap matters more than usual: the UPI handoff can only be proven on real hardware with real UPI apps installed, and the backend needs `HUBBLE_*` env vars set or `/config` returns 503 (which the screen renders as "unavailable", not an error).

**Docs updated**
This file. `DEALDIRECT-MOBILE-PARITY-AUDIT.md` and the implementation plan still list W6 as outstanding and rewards as display-only; both are now stale on those two points.

---

## 2026-08-22 — Mobile Phase 2 (part): guest guards + `listingType` deploy question settled (mobile only)

**Files changed**
- `dealdirect-mobile/` only. Added `src/auth/components/RequireAuth.tsx`; modified `src/auth/index.ts`, `app/settings/{sessions,change-password,delete-account}.tsx`, `app/claim-reward/[verificationId].tsx`, and `app/projects/booking/[bookingId].tsx`.

**W8 — guest guards.** Four routes rendered for a signed-out user and failed at the request, turning "not signed in" into "something is broken": the three settings sub-screens and the reward-claim screen, which is reached from a notification tap — precisely when a session may have lapsed. New `RequireAuth` is `OwnerOnly` with the role assertion removed, and follows its convention of rendering children while `status === 'restoring'` so a cold start never flashes a refusal at a signed-in user. Consequence for anything placed behind it: the screen must tolerate a moment with no user, which is what the query layer's `enabled` guards are for. `claim-reward` additionally gates its auto-claim effect on a DECIDED session — firing during the probe would spend the `attempted` ref on a request guaranteed to 401.

**W10 — `listingType` is deployed; the constraint is withdrawn.** The plan carried a deploy-ordering risk: mobile sends `listingType` on every Buy/Rent search, and if production lacked the 2026-08-03 backend change the toggle would silently no-op. Measured directly against production with read-only GETs on `/api/properties/search`: baseline **31**, `rent` **21**, `sale` **10**, `nonsense` **31**. The partition is exact (21 + 10 = 31) and an unrecognised value degrades to "no filter" rather than "no results". **The param is live.** No store build needs to wait on a backend deploy for this.

**Two Phase 1 defects found by self-review and fixed in the same pass** (`app/projects/booking/[bookingId].tsx`)
1. **"Booking not found" immediately after a successful booking.** The screen finds its booking in the cached `GET /bookings/my` list. Arriving straight from the booking sheet, that list is one item out of date and a background refetch is in flight — `isPending` is false when cached data exists, so the loading branch did not catch it and the empty state won. Now `!booking && isRefreshing` reads as loading.
2. **An enquiry quoted a token amount.** The server resolves and persists `payment.tokenAmount` for an enquiry too, so an enquiry on a unit that has a booking amount displayed "Token amount: ₹X" to a buyer who had just been told no payment was needed. Suppressed when the booking is enquiry-only.

**Architectural impact**
`RequireAuth` is the standard gate for account-scoped routes with no role requirement; `OwnerOnly` remains correct where a role matters. Neither is security — both routes stay enforced server-side.

**Not done in this phase**
**W9 (crash reporting) is not started.** It adds `@sentry/react-native`, a native module: it needs a full rebuild, which would invalidate the dev build currently installed for manual device testing, and a mobile-specific Sentry DSN that does not exist yet. Deferred deliberately rather than half-applied.

**Migration notes**
None. Client-side only. `tsc --noEmit` clean, `expo lint` 0 errors (12 warnings, all pre-existing), `expo export --platform android` succeeds, and the debug build runs clean on an emulator against production with no redbox. **Individual flows still not exercised end-to-end.**

**Docs updated**
`DEALDIRECT-MOBILE-PARITY-AUDIT.md` (PA-8 marked resolved with the measurement, status banner added), `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md` (new §2b status table), this file.

---

## 2026-08-22 — Mobile Phase 1: four P0 parity defects fixed (mobile only; backend untouched)

**Files changed**
- `dealdirect-mobile/` only. **No file under `backend/`, `client-next/` or `Admin/` was modified**, and no endpoint, schema or env var was added — every fix conforms the client to contracts the production backend already enforces.
- Added: `src/config/features.ts`
- Modified: `src/api/{client,errors,index}.ts`, `src/api/endpoints/{projects,users}.ts`, `src/auth/AuthProvider.tsx`, `src/types/backend/{common,project,user}.ts`, `src/features/projects/{bookings,campaigns,index}.ts`, `src/features/profile/hooks.ts`, `app/projects/{[id],bookings}.tsx`, `app/projects/booking/[bookingId].tsx`, `app/projects/unit/[unitTypeId].tsx`, `app/projects/campaign/[campaignId].tsx`, `app/settings/delete-account.tsx`

**Reason**
Phase 1 of `DEALDIRECT-MOBILE-IMPLEMENTATION-PLAN.md`. Seven backend/web commits between 2026-08-13 and 2026-08-22 changed the projects and bookings contracts; none touched mobile, which had been frozen since `982b85d`. Four defects were user-visible.

**The four fixes**

1. **Account deletion never worked.** `useDeleteAccount` sent no body; `deleteAccount` requires `{password}` and answers 400 `PASSWORD_REQUIRED` without one. Every deletion attempt from the app failed — the one flow App Store review is guaranteed to exercise. The screen now collects the password, maps 401 `INVALID_PASSWORD` to a field error, and reports `retainedListings` when the cascade keeps deal evidence back. The typed word stays `DELETE` rather than the website's `DELETE-<email>`: the password is the authorisation, the phrase is a speed bump, and a 30-character phrase is a desktop-keyboard decision.

2. **Bookings were behind the contract.** Mobile sent no `intent`, so every submission was a booking and was refused with `BOOKING_NOT_CONFIGURED` on the three-of-eight unit types with no `paymentTerms.bookingAmount` — exactly where the website now offers a working enquiry. Added: the `intent: 'enquiry'` path as a second CTA, `POST /bookings/:id/cancel` (absent from the registry entirely), and specific copy plus a next step for `NO_INVENTORY`, `BOOKING_NOT_CONFIGURED` and 409 `DUPLICATE_ENQUIRY`. An enquiry no longer lands on a payment form quoting ₹0.

3. **No global session teardown.** A session revoked mid-run (password change elsewhere, fingerprint revocation, admin block) was noticed only by the four calls `AuthProvider` makes itself; every other screen showed a generic error while the app went on rendering as signed-in. `setSessionFatalObserver` now reports any session-fatal response to the auth layer, which decides. Guarded twice — a guest cannot be logged out, and the provider's own calls are excluded — because the cost of a false positive is discarding a working session.

4. **Group buy is gated off** (`GROUP_BUY_ENABLED = false`). The website deleted its entire group-buy render in `79461c3` because nothing applies `discountPerBuyer`; mobile was left as the only client taking memberships and payment proof for a mechanic with no completion engine, and exit is refused once `tokenStatus` is `paid`. The flag is applied at the data layer, so a surface that never asks for campaigns cannot render one. All wiring stays on disk; flipping the flag is the whole of the change when the mechanic ships.

**Contract corrections found while verifying** (all read fields that do not exist, in the F1/F5/F6 class)
- `UnitType.inventory` is `{ totalUnits, availableUnits, bookedUnits, blockedUnits }`, **not** `{ total, available }`. Both read sites (`app/projects/[id].tsx`, `app/projects/unit/[unitTypeId].tsx`) were permanently `undefined`, so the availability chip never rendered and a sold-out unit never disabled its own button — the buyer filled in the form and met `NO_INVENTORY` at submit.
- `UnitType.paymentTerms` and `Project.financials` are now typed rather than `Record<string, unknown>`, because the token resolution needs `bookingAmount` from both, in that order.
- `ProjectBooking` gained `source`, `contactHistory`, `assignedTo`; `Project` gained `publication` and `views`; `ProjectListParams.limit` documents the server's clamp to 60.
- `BackendErrorCode` gained the eight client-facing codes the backend already emits.

**Architectural impact**
- **A session-fatal response from anywhere now ends the session.** `AUTH_OWNED_PATHS` in `AuthProvider.tsx` is the exclusion list; anything the auth layer calls on its own behalf must be added to it or it will race the handler.
- **401 no longer implies a dead session.** `INVALID_PASSWORD` is a password re-check inside an authenticated request; `SESSION_SAFE_401_CODES` in `api/errors.ts` keeps it out of both `kindForStatus` and `isSessionFatal`. Without that exception the new global handler would log a user out for a typo, clearing storage on the way.
- **`useMyBookings` is now auth-gated and reports `signedIn`.** Screens must check `isLoading` **before** `signedIn`: during the cold-start probe nobody is signed out, they are undecided, and a sign-in prompt shown to a returning user is a claim the app then retracts.
- Project visibility is `publication.status`-driven, not `isActive`. `basics.status` is a construction stage and must never be read as visibility.

**Migration notes**
None. Client-side only; no schema, data, endpoint or env change. Verified with `npx tsc --noEmit` (clean), `npx expo lint` (0 errors; 12 warnings, all pre-existing) and `npx expo export --platform android` (succeeds). **Not run on a device and not exercised against a live API** — the behavioural claims above are traced against `backend/controllers/{booking,user}Controller.js` and `backend/models/{UnitType,Project,ProjectBooking}.js`, not observed.

**Docs updated**
This file. `DEALDIRECT-MOBILE-PARITY-AUDIT.md` findings PA-1 to PA-4 and the inventory correction are now addressed in code; the audit and plan documents still describe them as open and should be re-read against this entry.

---

## 2026-08-17: Phase 3A.1, four defects fixed (notifications routing, property field contract, upload coupling, multipart bodies)

**Files changed**
- `backend/routes/notificationRoutes.js`: `PATCH "/mark-all/read"` now declared before `PATCH "/:id/read"`.
- `backend/middleware/upload.js`: the `cloudinaryConfigured` check moved below the "no files" early return in `validateAndUploadToCloudinary`.
- `backend/controllers/propertyController.js`: `sanitizePropertyData` now uses `Object.prototype.hasOwnProperty.call(data, field)`; nine dead names removed from `PROPERTY_ALLOWED_FIELDS`.
- `backend/tests/integration/`: three new suites (`notifications`, `upload-unavailable`, `upload-validation`), a `setup/fixtures.js` with synthetic image bytes, an email observer in `setup/fakeProviders.js`, and deterministic index building in `setup/app.js`.

**Reason**
The Phase 3A integration suite reported three defects as passing tests asserting broken behaviour. This pass fixed them and replaced those tests with assertions of the correct behaviour. The suite now has zero `todo` entries.

**Architectural impact**
- **Mark-all-as-read now works.** It never had. Express matched `/:id/read` first and cast `"mark-all"` to an ObjectId. Nothing else changed; both handlers were already correct.
- **Property editing now works for multipart requests.** This is the significant one. Multer 2 builds `req.body` with `Object.create(null)`, and `sanitizePropertyData` called `data.hasOwnProperty(...)`, which throws on a prototype-less object. The edit form posts multipart and sends no `features` key, so `data` was never rebuilt by the spread at line ~1499 and reached the sanitizer without a prototype: **every save from the edit screen returned 500.** Creation escaped only because the add form does send `features`. Anything that writes to `req.body` from a multipart route must assume no prototype.
- **An image-service outage no longer blocks text-only edits.** A file-carrying request still fails fast with 503 before magic-byte validation and before any upload; that ordering is deliberate and load-bearing.
- **The property field contract is now documented by path, not by name.** The whitelist contains two different kinds of entry: schema paths, and transient input names that `updateMyProperty` translates (`carpetArea` to `area.carpetSqft`, and eleven more). The create and update paths accept **different shapes**: add-property sends nested objects, edit-property sends flat state, and only the latter is translated. Do not assume a body that works on PUT works on POST.
- Nine names (`floor`, `age`, `availability`, `possessionDate`, `waterSupply`, `ownershipType`, `buildingName`, `buildingType`, `seatCapacity`) were removed from the whitelist. No behaviour change: no form sent them, they matched no schema path, and no property code read them.
- `availableFrom` was never broken. Phase 3A listed it as discarded because the check compared a `Date` to an ISO string.

**Two issues left open (not fixed)**
1. `cloudinary.uploader.upload_stream` returns a Q promise the SDK never settles on failure (`uploader.js:595-607`), so every failed upload leaks an unhandled rejection. Noisy, not fatal: `errorHandler.js:471` logs without exiting and the HTTP response is a correct `500 UPLOAD_FAILED`.
2. Five models cannot build their indexes. `models/Role.js` declares `name` as `unique: true` then adds `roleSchema.index({ name: 1 })` at line 57; `Admin`, `User`, `UserSession` and `AdminSession` share the shape. In production the losing index is simply never created.

**Migration notes**
None. No schema change, no data migration, no production infrastructure touched.

**Docs updated**
[`DEALDIRECT-INTEGRATION-TESTS.md`](../DEALDIRECT-INTEGRATION-TESTS.md) sections 5-9 rewritten: the field matrix, the two new upload suites, the nine-mutation table, and the two open issues. `AI/KNOWN_BUGS.md` still does not carry any of this; that debt marker stands.

## 2026-08-17: Integration-test harness (Phase 3A); three test seams in app code

**Files changed**
- `backend/tests/integration/**` (new, 11 files): the harness. `setup/guard.js` (refuses unsafe NODE_ENV / database targets), `setup/db.js` (in-memory replica set + truncation), `setup/externals.js` (credential neutralisation + network egress blocking), `setup/fakeProviders.js` (loopback SMS provider, synthetic Cloudinary config), `setup/app.js` (Supertest + per-request client IP), `setup/factories.js`, and four suites.
- `backend/server.js`: `connectDB()` and `httpServer.listen()` are now skipped when `NODE_ENV === "test"`, and `app` is exported. No behaviour change outside tests.
- `backend/services/hubbleService.js`: the module-level token-cleanup `setInterval` is now `unref()`d.
- `backend/package.json`: `test` narrowed to `tests/*.test.js`; added `test:integration` and `test:all`.
- `.gitignore`, `backend/.gitignore`: un-ignore `backend/tests/integration/**` so the suite is committable.

**Reason**
The 471-test unit suite asserts against source text and pure functions. It cannot see the failure mode that has cost this codebase the most: a value accepted by the API, reported as saved, and discarded before it reaches the database. Only a round trip through the real middleware chain into a real database shows that.

**Architectural impact**
- `app` is now an export of `server.js`. Nothing in the running application imports it; it exists for the harness.
- `NODE_ENV=test` is now a meaningful mode: the process does not connect to Mongo and does not listen on 9000. Anything added to `server.js` that assumes a live connection at import time will break the harness.
- `hubbleService`'s cleanup timer no longer holds the event loop open. In the server the listening socket does that anyway, so the sweep still fires as before.
- Three defects were found and **not** fixed, each recorded as a passing test that asserts the current broken behaviour, so it turns red when fixed:
  1. `PATCH /api/notifications/mark-all/read` is unreachable. `routes/notificationRoutes.js` declares `PATCH "/:id/read"` one line earlier, so Express matches the wildcard, `markNotificationRead` gets `id = "mark-all"`, the ObjectId cast fails and it returns 500. Mark-all-as-read has never worked. Fix is a one-line reorder.
  2. Twenty-two fields in `PROPERTY_ALLOWED_FIELDS` are accepted by `sanitizePropertyData` but never written by `addProperty` (`carpetArea`, `landmark`, `reraId`, `buildingName`, `possessionDate` and others; full list in the test). Same class as the `priceUnit` bug fixed in Phase 0/1, still open.
  3. `validateAndUploadToCloudinary` returns 503 for any request on a route it guards, whether or not a file is present, so an image-service outage blocks title-only edits.

**Migration notes**
None. No schema change, no migration, no production infrastructure touched. `mongodb-memory-server` and `supertest` added as devDependencies only.

**Docs updated**
[`DEALDIRECT-INTEGRATION-TESTS.md`](../DEALDIRECT-INTEGRATION-TESTS.md) (new, at repo root) documents the harness, the isolation argument, timings, and the three findings. `AI/KNOWN_BUGS.md` was **not** updated with the three defects above: that is a debt marker.

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
