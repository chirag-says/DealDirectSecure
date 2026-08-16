# COMPONENT_INDEX.md — Frontend Components

Covers `client-next/` and `Admin/`. For each component: purpose, props, dependencies, and who renders it.

⚠️ **Eleven components are orphaned** (never imported). They are marked **ORPHAN** and catalogued in [KNOWN_BUGS.md](KNOWN_BUGS.md) B17/B18. Do not assume a component is live because it exists.

Related: [FILE_MAP.md](FILE_MAP.md) · [STYLING_GUIDE.md](STYLING_GUIDE.md) · [ARCHITECTURE.md](ARCHITECTURE.md)

---

## The Route Component Pattern

Every route in `client-next` is two files. This is the most important convention in the frontend:

```
src/app/<route>/
  page.js           Server Component — metadata, ssrFetch, JSON-LD, renders <XContent initial…={} />
  XContent.jsx      'use client' — all state and interactivity, seeded from initial* props
  XWrapper.jsx      (optional) wraps XContent in <ProtectedRoute>
```

`*Content.jsx` components are **not reusable**. They are page bodies that happen to live in their own file so the server component can stay a server component. Do not import one from another.

---

## client-next — Layout & Shell

### `ClientLayout.jsx`
Wraps everything. Renders `AuthProvider` → `ScrollToTop` (Suspense) → `Navbar` (Suspense) → `{children}` → `Footer` → `ToastContainer`.
- **Props:** `{children}`
- **Uses:** AuthContext, Navbar, Footer, ScrollToTop, react-toastify
- **Used by:** `app/layout.js`
- ⚠️ **`ChatProvider` is absent here** — that is B17.
- Body wrapper carries `pt-16 lg:pt-20` to clear the fixed navbar. Changing navbar height means changing this padding.

### `Navbar/Navbar.jsx` — 1170 L, the largest component
The most-touched file in the frontend. Handles desktop nav, mobile drawer, city selector, search with autocomplete, auth-aware menus, notification badge, and rewards entry.
- **Props:** none — reads everything from `useAuth()` and the router
- **Uses:** `next/link`, `next/image`, `next/dynamic`, `useRouter`/`usePathname`/`useSearchParams`, react-icons/ai + /fa, `utils/api`, `useAuth`, toast
- **Used by:** `ClientLayout`
- Must be inside `<Suspense>` because it calls `useSearchParams()`.
- Role-aware: `canAddProperty` (owner + verified + no existing listing) gates the "Register Property" CTA.
- ⚠️ Does **not** import `MegaMenu` or `CityDropdown` — both are orphans; the equivalent UI is inlined here.

### `Footer/Footer.jsx` (210 L)
Static links, socials, legal. Defines a local `FaXTwitter` SVG because react-icons lacked it.

### `ScrollToTop/ScrollToTop.jsx` (21 L)
Resets scroll on pathname change. Uses `useSearchParams` → must be Suspense-wrapped.

---

## client-next — Home Page

### `HeroSection/HeroSection.jsx` (883 L)
Tabbed search hero (Buy / Rental / Projects / PG / Plot / Commercial / Agents) driven by `filterConfig.js`.
- **Props:** `{ filters, setFilters }` — controlled by `HomeContent`
- **Uses:** the filter sub-components below, `filterConfig.js`
- **Used by:** `HomeContent`

### Filter sub-components (`components/HeroSection/`)
All share the shape `({ value, onChange, isOpen, onToggle, ... })` — a dropdown with a trigger button and a panel.

| Component | ~L | Options source |
|---|---|---|
| `BudgetFilter` | 78 | `budgetOptions` — 33 values, ₹5 L → ₹75 Cr |
| `PropertyTypeFilter` | 78 | `propertyTypes` (Residential / Commercial) |
| `ProjectPropertyTypeFilter` | 78 | `projectPropertyTypes` |
| `CommercialPropertyTypeFilter` | 53 | `commercialPropertyTypes` |
| `PossessionFilter` | 53 | Ready To Move / Under Construction |
| `FurnishingFilter` | 53 | Furnished / Semi / Unfurnished / Gated |
| `TransactionTypeFilter` | 52 | — |
| `AvailableForFilter` | 52 | — |
| `PostedByFilter` | 52 | — |
| `AgentForFilter` | 52 | — |

`filterConfig.js` (66 L) is the **single source** for all option lists and per-tab configuration. Add options there, not in the components.

### `TopLocalities/TopLocalities.jsx` (185 L)
Marquee of city cards. **Defines its own internal `LogoLoop`** — the standalone `components/LogoLoop/` is an orphan duplicate.

### `PressMarquee/PressMarquee.jsx` (100 L)
Scrolling press logos from `data/pressReleases.json`. Contains a local `MediaChip` sub-component.

---

## client-next — Rewards

### `Rewards/RewardRevealRouter.jsx` (38 L) — read this first
Dispatches to the correct reveal animation by `reward.rewardCategory`:
```
property_posting | property_enquiry → <SpinWheelOverlay/>
property_sale    | anything else    → <PropertyHuntGame/>
```
- **Props:** `{ reward, onClose }` where `reward = { pointsAwarded, cashValue, rewardTier, rewardCategory, description }`
- **Used by:** `AddPropertyContent`, `MyPropertiesContent`, `NotificationsContent`, `PropertyDetailsContent`
- **Always render this**, never the two children directly — that is how category routing stays in one place.

### `PropertyHuntGame.jsx` (196 L)
Three-door "Shagun" reveal for sale/deal rewards. framer-motion.

### `Rewards/SpinWheelOverlay.jsx` (215 L)
Spin-wheel reveal for posting/enquiry rewards.
- **Props:** `{ reward, onClose, category }`

---

## client-next — Property

### `Properties/CloseDealModal.jsx` (370 L)
Owner submits deal closure: pick a buyer from `interestedUsers`, choose sold/rented, upload ≤5 proof documents.
- **Props:** `{ isOpen, onClose, property, onSuccess }`
- **Calls:** `POST /api/properties/:id/close-deal` (multipart)
- **Used by:** `MyPropertiesContent`

### `EmailVerificationModal/EmailVerificationModal.jsx` (298 L)
Blocks unverified users from listing.
- **Props:** `{ isOpen, onClose, user, onVerified }`
- **Used by:** `AddPropertyContent`

### `VisitModal/VisitModal.jsx` (133 L)
Site-visit request form.
- **Props:** `{ isOpen, onClose, propertyTitle, onConfirm }`
- **Used by:** `ChatWidget` only — therefore currently unreachable (B17)

---

## client-next — Blog & SEO

### `Blog/BlogCard.jsx` (105 L)
- **Props:** `{ post, featured = false }`
- **Used by:** `BlogListContent`, `BlogPostContent` (related posts)

### `Blog/TableOfContents.jsx` (67 L)
Parses headings out of markdown and renders anchor links.
- **Props:** `{ content }`

### `Blog/BlogJsonLd.jsx` (39 L)
- **Props:** `{ blog }` → BlogPosting structured data

### `JsonLd.jsx` (227 L) — five named exports
| Export | Props | Emits |
|---|---|---|
| `OrganizationJsonLd` | — | Organization |
| `WebsiteJsonLd` | — | WebSite + SearchAction |
| `BreadcrumbJsonLd` | `{ items }` | BreadcrumbList |
| `PropertyJsonLd` | `{ property }` | RealEstateListing |
| `FAQJsonLd` | `{ faqs }` | FAQPage |

**Rendered from `page.js` server components**, never from client components — that keeps structured data in the initial HTML where crawlers see it. Used by 7 route files.

---

## client-next — Chat (built, not mounted — B17)

### `Chat/ChatWidget.jsx` (581 L) **ORPHAN**
Full messenger: conversation list, thread, composer, typing indicators, message reporting, visit-request rendering. Contains `ChatMessage` and `ConversationItem` sub-components.
- **Uses:** `useChat()`, `VisitModal`

### `Chat/ChatButton.jsx` (39 L) **ORPHAN**
Floating launcher with unread badge. **Uses `useChat()`** — throws if rendered without `ChatProvider`.

---

## client-next — Orphaned Components

| Component | ~L | Why it is dead |
|---|---|---|
| `SampleAgreement/AgreementGenerator.jsx` | 1282 | Duplicate — the live copy is inlined in `app/agreements/AgreementsContent.jsx` |
| `AuthModal/AuthModal.jsx` | 487 | Superseded by `/login` + `/register` routes |
| `HeroSection/HeroSection_omnibox.jsx` | 358 | Alternate hero design |
| `LogoLoop/LogoLoop.jsx` + `.css` | 321+183 | Duplicate — `TopLocalities` has its own |
| `Navbar/MegaMenu.jsx` | 216 | Nav menu inlined into `Navbar.jsx` |
| `SampleAgreement/SampleAgreement.jsx` | 198 | — |
| `Navbar/CityDropdown.jsx` | 171 | City selector inlined into `Navbar.jsx` |
| `Property/PropertyFilter.jsx` | 65 | — |
| `MiddelSection.jsx` / `MiddelComp.jsx` | 41 / 32 | — |

`Property/PropertyList.jsx` (42 L) is imported by `app/properties/page.js` via `ClientPropertyList.jsx` and **is** live.

---

## Admin — Shell

### `AdminProtectedRoute.jsx` (48 L)
Reads `useAdmin()`; renders a spinner while `isLoading`, redirects to `/admin/login` when unauthenticated. Wraps every route except the four auth routes.

### `Sidebar.jsx` (183 L) / `Header.jsx` (141 L)
Navigation shell. Collapsible: `w-64` open, `lg:w-20` mini on desktop, off-canvas with overlay on mobile. Sidebar state lives in `App.jsx` and responds to a `resize` listener.

### `NotificationBanner.jsx` (10 L)
Thin banner.

---

## Admin — Dashboard Widgets

| Component | ~L | Props | Library |
|---|---|---|---|
| `MetricCard.jsx` | 19 | `{ title, value, icon, … }` | — |
| `ChartCard.jsx` | 51 | `{ title, children }` | wrapper |
| `GrowthChart.jsx` | 71 | monthly series | recharts |
| `FunnelChart.jsx` | 28 | lead funnel | recharts |

Consumed by `Dashboard.jsx` from `GET /api/admin/dashboard/stats`.

---

## Admin — The Wizard Kit (`components/wizard/`)

The reusable multi-step form system behind `CreateProject`, `CreateUnitType`, and `CreateCampaign`. **This is the one genuinely reusable component set in the repo — use it for any new admin creation flow.**

| Component | ~L | Purpose |
|---|---|---|
| `Wizard.jsx` | 173 | Step orchestration, navigation, submit |
| `FileDropzone.jsx` | 171 | Drag-and-drop uploads with previews |
| `ConfirmModal.jsx` | 87 | Confirmation dialog |
| `FormField.jsx` | 61 | Labelled input + error display |
| `Stepper.jsx` | 54 | Step progress indicator |
| `useFormDraft.js` | 72 | **Hook** — persists in-progress form state to localStorage so a refresh doesn't lose a half-filled project |

Validated by zod schemas in `src/schemas/`:
- `projectSchema.js` (111) · `unitTypeSchema.js` (148) · `campaignSchema.js` (97)

These schemas are the **only structured validation in any frontend**. Mirror the backend model when editing them — nothing enforces agreement.

---

## Admin — Map Components

### `LocationPicker.jsx` (540 L)
Leaflet map with a draggable marker returning `{lat, lng}`. Used in project and property creation.

### `LocationAutocomplete.jsx` (157 L)
Location search backed by `data/real-estate-locations.json` and `india-states.json`.

Both depend on `leaflet` + `react-leaflet` and must be client-only.

---

## Custom Hooks

There are **almost none**. The codebase deliberately keeps logic in components and contexts.

| Hook | File | Purpose |
|---|---|---|
| `useAuth()` | `client-next/src/context/AuthContext.jsx` | Throws outside `AuthProvider`. Returns user, loading, error, `isAuthenticated`, `isOwner`, `isBuyer`, `isVerified`, `ownerHasProperty`, `hasRole()`, `canAddProperty`, `canAccessOwnerFeatures`, and the auth actions |
| `useChat()` | `client-next/src/context/ChatContext.jsx` | Throws outside `ChatProvider` — **which is never mounted** (B17) |
| `useAdmin()` | `Admin/src/context/AdminContext.jsx` | `authStatus`, `admin`, `role`, `roleName`, `roleLevel`, `permissions`, `login`, `logout`, `checkAuth` |
| `useFormDraft()` | `Admin/src/components/wizard/useFormDraft.js` | localStorage-backed draft persistence |

`hasRole()` is the one to know: it treats `'buyer'` and `'user'` as equivalent in both directions, because the backend uses both spellings for the same role.

---

## Naming Conventions

| Thing | Convention | Example |
|---|---|---|
| Component file | PascalCase `.jsx`, often in a same-named folder | `components/Footer/Footer.jsx` |
| Route page (server) | `page.js` — Next.js requirement | `app/properties/page.js` |
| Route body (client) | `<Route>Content.jsx` | `PropertyListContent.jsx` |
| Auth wrapper | `<Route>Wrapper.jsx` | `AddPropertyWrapper.jsx` |
| Context | `<Domain>Context.jsx`, exports `<Domain>Provider` + `use<Domain>` | `AuthContext.jsx` |
| Hook | `useX` camelCase | `useFormDraft` |
| Util | camelCase `.js`, named exports | `formatPrice.js` |
| API group | `<domain>Api` object in `utils/api.js` | `propertyApi.markInterested()` |
| Admin page | PascalCase `.jsx` directly in `pages/` | `pages/Dashboard.jsx` |
| Admin schema | `<domain>Schema.js` | `schemas/projectSchema.js` |

Admin routes are kebab-case (`/lead-monitoring`, `/deal-verifications`); client routes are kebab-case too (`/my-properties`, `/saved-properties`).

---

## Rules for Adding Components

1. New route → create **both** `page.js` and `*Content.jsx`. Never put `'use client'` on `page.js`.
2. Data needed for SEO or first paint → fetch in `page.js` with `ssrFetch`, pass as `initial*`. Handle `null`.
3. Anything using `useSearchParams` must be inside `<Suspense>`.
4. Leaflet, and anything touching `window` at module scope, must be `next/dynamic` with `ssr: false`.
5. Rendering a reward → use `RewardRevealRouter`, not its children.
6. New admin creation flow → use the wizard kit and add a zod schema.
7. Structured data → render `JsonLd` exports from the server component.
8. Before creating a component, **grep for the name** — there may already be an orphaned implementation (see the orphan table).
