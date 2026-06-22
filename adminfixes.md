# Admin Panel — Weak Points & Improvement Plan

> **Scope:** This report audits `Admin/` (Vite + React 19 admin dashboard for DealDirect).
> **Context:** The admin panel is being repositioned to be the **sole** builder-management surface — no separate builder side. Below are the weak points found, then a consolidated improvement plan (UX, security, builder-management consolidation, code health, performance, testing).

---

## 1. Executive Summary

| Area | Status | Severity |
|---|---|---|
| Authentication & MFA | Solid (cookie-based) | Low |
| Role-based UI gating | **Missing** (all admins see all menus) | High |
| Builder-side consolidation | Partial — there is still a `builder-management` flow that looks like a builder portal | High |
| Form wizards (Create Project / Unit Type / Campaign) | Functional but heavy, duplicated, no schema validation | Medium |
| Listings/dashboard mock data | **Hard-coded mock history** mixed with real data | High (integrity) |
| Legacy/unused code | `ListingsTable.jsx` ships 12 KB of hard-coded base64 mock data | Medium |
| UX polish (sidebar, dashboard, mobile) | Good, but several pages have no error/empty boundaries | Medium |
| Performance (large page files) | 100KB+ page files cause slow HMR; code-splitting missing | Medium |
| Security (CSRF, file uploads, secret exposure) | Mostly fine; minor issues | Low–Medium |
| Testing | **No tests** in the Admin app | Medium |

---

## 2. Authentication, Session & Authorization

### 2.1 Strengths
- HttpOnly cookies via `axios.defaults.withCredentials = true` (`src/main.jsx:11`).
- Centralized 401/403 interceptor in `src/api/adminApi.js:98-132` that delegates to `AdminContext`.
- `AdminContext.checkAuth()` validates with the server on mount (`src/context/AdminContext.jsx:40-61`).
- MFA setup / verify / disable endpoints exposed (`src/api/adminApi.js:341-361`).
- CSRF token automatically attached to state-changing requests (`src/api/adminApi.js:73-92`).

### 2.2 Weak points

| # | Issue | File | Impact |
|---|---|---|---|
| A1 | `setAdminAuthErrorHandler` is a **module-level mutable singleton** that the React context uses, but it is not removed/replaced when the `AdminProvider` unmounts. Cleanup `return () => setAdminAuthErrorHandler(null)` works in dev, but if the provider remounts in the same tick, races are possible. | `src/context/AdminContext.jsx:94-106` | Minor — auth errors could briefly target a stale handler |
| A2 | **No role-based UI gating.** `Sidebar.jsx` shows *all* menu items to *every* authenticated admin, with the comment “Backend handles permission enforcement” (`src/components/Sidebar.jsx:24-26`). The header `getRoleBadgeColor` recognises roles but the menu doesn’t. | `src/components/Sidebar.jsx:26-103` | A junior admin can see and visit `/deal-verifications`, `/rewards-management`, etc. The protected route will not block — backend is the only line of defence. |
| A3 | `AdminContext` exposes `roleLevel`, `roleName`, `permissions` but **no consumer uses them**. They are dead code that looks like an unfinished RBAC system. | `src/context/AdminContext.jsx:122-149` | Code smell; future maintainers may believe RBAC is wired in. |
| A4 | `AdminLogin.jsx` handles `requiresMfa`, `requiresMfaSetup`, `mustChangePassword` branches correctly, but the `from` redirect from `AdminProtectedRoute` is lost in the `requiresMfaSetup` branch (line 49-53) — after MFA setup, the user lands on `/dashboard` instead of where they were going. | `src/pages/AdminLogin.jsx:49-67` | Minor UX bug. |
| A5 | No **session timeout / idle warning** in the admin UI. Backend has session-versioning, but the user is never warned before being kicked out. | global | UX gap. |
| A6 | `axios.defaults.timeout = 30000` is set globally, but the long-running `projectApi.create` and `adminAddProperty` correctly override it to 120-180 s. There is **no client-side indication of progress** for those long uploads. | `src/api/adminApi.js:18-25` | UX gap during slow uploads. |

---

## 3. Sidebar, Header & Navigation

### 3.1 Weak points

| # | Issue | File | Impact |
|---|---|---|---|
| N1 | `Sidebar` uses `<NavLink onClick={() => isOpen && toggleSidebar()}>` so on **desktop the menu collapses on every click** when the sidebar is open (`true`). That means after clicking an item on desktop, the user has to re-open the sidebar to use it again — but `getInitialSidebarState` re-opens on resize. The behaviour is confusing. | `src/components/Sidebar.jsx:154-155` | Bad UX — see verification: line 154 says `onClick={() => isOpen && toggleSidebar()}` which auto-collapses even on desktop. |
| N2 | The sidebar contains an **empty header strip** when closed (`flex items-center ${isOpen ? 'justify-end' : 'justify-center'}`) but no logo placeholder — the close button floats in white space. | `src/components/Sidebar.jsx:120-128` | Visual: looks broken when collapsed. |
| N3 | Logout: both `Header.jsx:26-29` and `Sidebar.jsx:111-115` call `await logout(); window.location.href = "/admin/login"`. This works, but a `useNavigate("/admin/login")` would be cleaner. Also, the auth interceptor already handles 401 — `window.location.reload` is overkill. | `src/components/Header.jsx`, `Sidebar.jsx` | Inconsistent logout flow. |
| N4 | The **route `/admin-add-property?builderId=…` is a legacy path** (see `BuilderManagement.jsx:401-404`). It coexists with the new `/create-project` flow. Admin now has two ways to add a property for a builder, which is exactly the duplication the client wants to eliminate. | `src/pages/BuilderManagement.jsx:401-407` | Confusion / inconsistent UX. |
| N5 | Two sidebar items map to the same component: `/owners-projects` → `BuilderProjects` and `/builder-management` → `BuilderManagement`. The `BuilderProjects` page is therefore *both* a sidebar entry and reachable only from the dashboard. | `src/App.jsx:197-203`, `:321-328` | Duplicated entry point. |
| N6 | Sidebar items use `key={idx}` (line 151) — `idx` as key is acceptable only because the list is static, but it is a lint smell. | `src/components/Sidebar.jsx:151` | Minor. |
| N7 | There is no 404 page. `*` route redirects to `/dashboard`, so a typo silently sends the admin to the dashboard. | `src/App.jsx:392` | Minor. |

---

## 4. Builder Management (the main consolidation target)

> Per client direction, **no separate builder portal** is needed — admin must do everything.

### 4.1 Current state
- `BuilderManagement.jsx` — list of builders (CRUD via `builderApi`), each row offers three “create” actions: legacy property, new project, edit. This is fine.
- `BuilderProjects.jsx` — used by sidebar `/owners-projects`; this appears to be the old flow.
- `BuilderProjectsList.jsx` — newer flow at `/builder/:builderId/projects`.
- `BuilderVerification.jsx` — actually an **owner verification/block list** (misnamed — it lists all `role=owner` users with block/unblock).
- `BuilderProjects.jsx` vs `BuilderProjectsList.jsx` look like they may overlap.

### 4.2 Weak points

| # | Issue | File | Impact |
|---|---|---|---|
| B1 | **Two different “builder project” list pages** exist (`BuilderProjects.jsx` 28 KB and `BuilderProjectsList.jsx` 11 KB) serving overlapping purposes. Both are routed. | `src/App.jsx:197-203`, `:357-363` | Code duplication; client has explicitly asked to remove this duplication. |
| B2 | `BuilderVerification.jsx` is misnamed. It is **not** a builder-kyc module — it is a generic user-management table filtering on `role=owner`. The name confuses the client. | `src/pages/BuilderVerification.jsx:1-200` | Should be renamed `AllOwners.jsx` (matches the existing `AllClients.jsx` convention). |
| B3 | Builder CRUD (`builderApi.create / update / delete / getAll`) lives at `/api/builders` and is **inconsistent** with the rest of the project structure. `BuilderManagement.jsx` makes it look like a separate portal (`'Contact card — no login required'`). | `src/pages/BuilderManagement.jsx:115-117` | Even though the client wants admin to handle builders, the page is styled and copy-written as a builder-side console. |
| B4 | No **builder detail page** beyond the projects list. Admin cannot see a builder’s RERA, GST, contact, all projects, all units, all campaigns in one place. | missing | Workflow gap. |
| B5 | There is no concept of **builder activation history / audit trail** on the admin side. | missing | Compliance / debugging gap. |
| B6 | Builder “deactivate” uses `DELETE` HTTP verb (`builderApi.delete`) but the action is a soft-deactivate (`isActive=false`). REST semantically this should be a `PATCH /api/builders/:id { isActive: false }` or a soft-delete endpoint. The current setup makes it impossible to differentiate "deleted" from "deactivated" in logs. | `src/pages/BuilderManagement.jsx:251-261`, `src/api/adminApi.js:514-517` | Audit / forensic weakness. |
| B7 | There is **no builder-import bulk action** — admin must create each builder one by one. For a real-estate platform onboarding many builders at once, this is a productivity bottleneck. | missing | Scalability. |
| B8 | Builder logo upload has **no client-side file-size / dimension cap**. A 50 MB logo will be uploaded before backend rejects it. | `src/pages/BuilderManagement.jsx:36-42` | Performance / cost. |
| B9 | The builder search bar filters by `name, company, phone` client-side after one server call (`BuilderManagement.jsx:234-244`) — that means typing a query triggers a server call with the search term, but the response is used to populate the list, then a **400 ms debounce** retries. The two are redundant. | `src/pages/BuilderManagement.jsx:246-249` | Unnecessary network traffic. |
| B10 | `BuilderManagement.jsx` row click navigates with `onClick={() => navigate(...)}` on the **whole row**, but there are multiple buttons inside the row that call `e.stopPropagation()`. Keyboard users get a confusing `Enter` key experience because there is no visible focus on the row. | `src/pages/BuilderManagement.jsx:344-354` | A11y. |
| B11 | `BuilderProjectsList.jsx` has no pagination — `projectApi.getByBuilder` may return many items, and the filter is purely client-side. | `src/pages/BuilderProjectsList.jsx:37-43` | Scalability. |

### 4.3 What the “consolidated” admin-side builder flow should look like

```
Sidebar (admin role)
└─ Builders                       → /builder-management
   ├─ All Builders                → /builder-management
   ├─ [Click row]                 → /builder/:builderId         (NEW: detail page)
   │    ├─ Profile (logo, RERA, GST, contacts, address)
   │    ├─ Projects (list with status, units, campaigns)
   │    ├─ Units (across all projects)
   │    ├─ Documents
   │    └─ Activity log
   └─ Add Builder                 → /builder-management?new=1  (modal already exists)

Sidebar (admin role)
└─ Owners (legacy)                → /all-owners                  (rename from BuilderVerification)
   └─ Block / unblock, view properties
```

---

## 5. Create Project / Unit Type / Campaign Wizards

These three pages are the **core builder-management surfaces** that the admin must operate. They are functional, but they have systemic issues.

### 5.1 Weak points common to all three wizards

| # | Issue | Files | Impact |
|---|---|---|---|
| W1 | **No schema validation library** (Zod, Yup, Joi). Each page has its own `validateStep()` ad-hoc implementation. | `CreateProject.jsx:100-153`, `CreateUnitType.jsx:89-158`, `CreateCampaign.jsx:59-65` | Bug-prone, inconsistent error messages. |
| W2 | The "Next" button gates each step *and* the final submit re-runs all validators — but the step-indicator buttons allow the admin to **jump to any step** freely. `CreateProject.jsx`’s indicator does *not* gate on reachability (line 858) while `CreateUnitType.jsx` does (line 754). Inconsistency. | `CreateProject.jsx:855-865` vs `CreateUnitType.jsx:750-767` | UX inconsistency; an admin can jump to step 9 in `CreateProject` and submit. The submit guard catches it but the experience is poor. |
| W3 | **Auto-save to localStorage with files excluded**. On reload, file selections are gone, so the admin has to re-pick all images/docs. This is the #1 frustration with the current wizards. | `CreateProject.jsx:199-208`, `CreateUnitType.jsx:277-306` | Heavy rework risk. |
| W4 | All three forms have **near-duplicate step-renderer boilerplate, `inp`/`lbl` class strings, `set` helper, error-clearing on edit**. Should be a shared `<Wizard />` + `<Stepper />` + `<FormField />` kit. | All 3 files | Maintenance debt. |
| W5 | The **dropdown lists** (subTypes, status, ownership, furnishing, facing, etc.) are hard-coded in component bodies. Adding a new value requires a code change + redeploy. | `CreateProject.jsx:397-432`, `CreateUnitType.jsx:41, :489-495` | No flexibility. |
| W6 | `handleSubmit` for CreateProject builds a `FormData` and then serializes every array as JSON string. Server must parse these in a specific order. A single `[]` array will be sent as `"[]"`. There is no documented schema contract. | `CreateProject.jsx:329-340` | Fragile. |
| W7 | `CreateCampaign.jsx` is the **only wizard that does not use per-step validation**. It uses a single `if (!form.name || !form.startDate …)` at submit. Admins can advance through steps with empty fields. | `CreateCampaign.jsx:59-65`, `:90-225` | Validation gap. |
| W8 | The token-amount warning in `CreateCampaign.jsx:171` is hard-coded copy. There is no policy block explaining admin verification rules. | `CreateCampaign.jsx:169-172` | Knowledge gap. |
| W9 | The **two DFloorPlan / threeDFloorPlan in CreateUnitType are single-file slots** with no preview, no multi-image support, no drag-and-drop. | `CreateUnitType.jsx:580-617` | Limited UX. |
| W10 | In `CreateProject.jsx`, **the amenities validation** says "select at least one" but the schema is `[{category, name}]`. The same check exists in `validateStep` and in the button `onClick`, but if the user removes all amenities the error does not re-appear until they click Next. | `CreateProject.jsx:130`, `:541-548` | Minor UX. |
| W11 | `CreateCampaign.jsx` does not gate on `minBuyers < 3` even though the input has `min="3"`. Validation is HTML-only and bypassable. | `CreateCampaign.jsx:118-124` | Weak. |
| W12 | `CreateUnitType.jsx` parking validates `Number.isInteger(Number(v))`, but `min="0"` permits non-integers via paste/keyboard. | `CreateUnitType.jsx:118-124` | Weak. |
| W13 | There is no **unsaved-changes guard** when navigating away. Refreshing the page or clicking the back link discards everything. | All 3 wizards | Data loss. |
| W14 | No **server-side image dimension / file-type sniffing** client-side (the project accepts any `image/*` but the wizard never enforces a min/max width/height). | `CreateProject.jsx:571-571` | Quality. |
| W15 | The `walkthroughVideoUrl` field is a free text input with no URL-pattern check. | `CreateProject.jsx:625-626` | Weak. |
| W16 | In `CreateProject.jsx` step 7, `if (!form.titleClear) e.titleClear = "Title must be clear to publish";` — but `titleClear` defaults to `true` in the form init (line 70). The validation will never fire on a fresh form, only on edit if the admin unticks it. | `CreateProject.jsx:138-139, :69-70` | Logic quirk. |

---

## 6. Listing / Property Management

### 6.1 Weak points

| # | Issue | File | Impact |
|---|---|---|---|
| L1 | `AllProperty.jsx`'s `clearFilters()` uses `setTimeout(() => window.location.reload(), 100)` — a full page reload. | `src/pages/AllProperty.jsx:102-108` | Slow + loses state. |
| L2 | The page's data extraction is fragile: `extractList` tries to handle `Array`, `{ data: [...] }`, and `null`. There should be a single backend contract. | `src/pages/AllProperty.jsx:41-46` | API coupling. |
| L3 | `fetchProperties` has 3 different triggers: status/date change, URL `?search=` change, and Enter key — with no clear precedence. | `src/pages/AllProperty.jsx:80-100` | Confusing. |
| L4 | **No bulk actions** (select multiple → approve / reject / delete). | `AllProperty.jsx` | Scalability. |
| L5 | **No pagination** at all on the properties page — relies on backend default limit. | `AllProperty.jsx:69` | Will degrade. |
| L6 | `Dashboard.jsx:101-103` injects **hard-coded mock data** (`mockPropHistory`, `mockLeadHistory`, `mockUserHistory`) into the chart series. This is misleading and possibly illegal in regulated contexts. | `src/pages/Dashboard.jsx:101-144` | **High severity — data integrity**. |
| L7 | `Dashboard.jsx` mixes two distinct endpoints (`/api/admin/dashboard/stats` and the legacy `adminApi.put` approval) inconsistently — sometimes via the wrapper `dashboardApi`, sometimes via raw `adminApi.put`. | `src/pages/Dashboard.jsx:90, :160-167` | Inconsistent API usage. |
| L8 | `AllClients.jsx` and `BuilderVerification.jsx` are **near-duplicates** (filter, search, block modal, drawer, export). | `src/pages/AllClients.jsx`, `src/pages/BuilderVerification.jsx` | DRY violation. |
| L9 | `ListingsTable.jsx` is a **dead, mock-only component** (12 KB of inline base64 image data) and is never imported anywhere. | `src/components/ListingsTable.jsx` (entire file) | Bundle bloat, misleads developers. |

---

## 7. Forms & Data Integrity

| # | Issue | File | Impact |
|---|---|---|---|
| F1 | `BuilderManagement.jsx` form does **not** normalize phone numbers (no +91 prefix, no length check). | `src/pages/BuilderManagement.jsx:53` | Data quality. |
| F2 | `CreateProject.jsx` RERA number field is free-text. The actual RERA format (`P<state-code><registration-number>`) is not validated. | `src/pages/CreateProject.jsx:437-438` | Compliance. |
| F3 | `CreateProject.jsx` GST field is free-text with no format check (15-char alphanumeric). | `src/pages/CreateProject.jsx:185-188` | Compliance. |
| F4 | Pincode is a free-text 6-digit field; no client-side numeric constraint. | `CreateProject.jsx:359-368` | Weak. |
| F5 | In `CreateProject.jsx`, `microMarket`, `addressLine`, `landmark`, `distanceToMetro/Airport/Railway/BusStop` are accepted but never validated, never displayed in Review, never shown in `ProjectDetail.jsx` info tab. | `CreateProject.jsx:328-336, :773-789`, `ProjectDetail.jsx:212-240` | Inconsistency. |
| F6 | The lat/lng pair can be set manually to bogus values; the only check is range. | `LocationPicker.jsx:111-116` | Weak. |
| F7 | `BuilderManagement.jsx` `company` is optional, but `BuilderProjectsList.jsx` line 127 displays it as if always present. | two files | Minor UI. |

---

## 8. UX & Accessibility

| # | Issue | File | Impact |
|---|---|---|---|
| U1 | **No skeleton loaders / no error boundaries** on most pages. A failed fetch shows a blank page or stuck spinner. | All `pages/*.jsx` | Resilience. |
| U2 | `window.confirm()` is used for destructive actions (delete builder, delete unit type, delete property). Should be a styled confirmation modal. | `BuilderManagement.jsx:252`, `ProjectDetail.jsx:54`, `AllProperty.jsx:112` | UX inconsistency. |
| U3 | `toast.error(err.response?.data?.message || "…")` is used everywhere but errors are sometimes shown as `err.response?.data?.message || "Failed"` without ever surfacing the response code. | widespread | Debugging. |
| U4 | No **keyboard shortcuts** for power users (e.g. `Cmd+K` search across admin). | global | Productivity. |
| U5 | Mobile sidebar uses `w-64` fixed positioning; on very small screens the close button can be missed. | `src/App.jsx:80-86` | Mobile UX. |
| U6 | The sidebar `role="link"` on table rows is not a valid pattern — screen readers won’t announce the row as a link, and the entire row is keyboard-focusable which interferes with nested buttons. | `BuilderManagement.jsx:344-354` | A11y. |
| U7 | Color-only indicators (red border for error) — no `aria-invalid` or `aria-describedby`. | All forms | A11y. |
| U8 | `<input>` placeholders are sometimes used as labels (e.g. `placeholder="e.g. 500 m"`). | widespread | A11y. |
| U9 | No **empty-state CTAs** on `LeadMonitoring`, `ContactInquiries`, `RewardsManagement`, etc. — they just show a blank table. | various | UX gap. |
| U10 | Toasts overlap the header in the right corner (`position="top-right"`). | `main.jsx:15` | Minor. |
| U11 | `react-leaflet` icons are loaded from `cdnjs.cloudflare.com` — requires a network call, and on offline / restricted networks the map markers render as broken images. | `LocationPicker.jsx:13-26`, `AdminAddProperty.jsx:21-35` | Reliability. |
| U12 | The dashboard mock-history data is also shown in real chart axes labelled "Jan", "Feb", etc. — looks like real data. | `Dashboard.jsx:101-145` | Trust. |
| U13 | No **dark mode** for admins working at night. | global | UX. |
| U14 | The BuilderManagement row "Properties" column shows `b.propertyCount || 0`. The data is `propertyCount` — but the API also has `projects` per builder. Are these synced? | `BuilderManagement.jsx:387-393` | Possible stale data. |
| U15 | The header dropdown is **not keyboard-navigable** (no `ArrowDown`/`Enter`/`Escape` handlers). | `Header.jsx:7-138` | A11y. |
| U16 | The "Saved draft" banner says "Your progress is auto-saved in this browser" — but it disappears on mobile because the parent uses `flex-col sm:flex-row` and the close button is squeezed. | `CreateProject.jsx:811-852` | Mobile UX. |

---

## 9. Performance

| # | Issue | File | Impact |
|---|---|---|---|
| P1 | `AdminAddProperty.jsx` is **115 KB / ~2 600 lines**. Vite code-splits per route, but the file is so large that HMR is slow and parsing is slow on first load. | `src/pages/AdminAddProperty.jsx` | Performance / DX. |
| P2 | `Dashboard.jsx` is 29 KB and includes the same `MetricCard` as `src/components/MetricCard.jsx` — a **different MetricCard** is defined inside the page. Duplicate component. | `src/components/MetricCard.jsx` vs `src/pages/Dashboard.jsx:20-46` | Bundle / DRY. |
| P3 | `recharts`, `chart.js`, `react-chartjs-2`, and `leaflet` + `react-leaflet` are all loaded on the same bundle. None of the chart libs are lazy-loaded. | `vite.config.js:14-22` | TTI. |
| P4 | `LeadMonitoring.jsx` (38 KB) does not lazy-load. It probably should be route-split (it already is, but the chunk includes the whole bundle group). | `src/pages/LeadMonitoring.jsx` | DX. |
| P5 | `Sidebar.jsx` imports `react-icons/ci` and `lucide-react` together — duplicate icon libraries. | `Sidebar.jsx:3-19` | Bundle size. |
| P6 | `BuilderManagement.jsx` has 4 different icon libraries in the same file (`lucide-react` + no others, but the whole file is huge). | `BuilderManagement.jsx:5-8` | DX. |
| P7 | `axios.defaults.withCredentials = true` is global — every request includes cookies, including any **non-authenticated** public requests. Not currently an issue but a footgun. | `src/main.jsx:11` | Minor. |
| P8 | `ListingsTable.jsx` (12 KB) is in the bundle because it's imported *somewhere* (or tree-shaking is failing on the inline base64). | `src/components/ListingsTable.jsx` | Bundle size. |

---

## 10. Security

| # | Issue | File | Severity |
|---|---|---|---|
| S1 | **Vite dev server has `host: true`** which binds to all interfaces. Combined with `cookie-based auth`, an admin who runs `npm run dev` on a laptop exposes the entire admin app to the LAN. | `vite.config.js:24-26` | Medium |
| S2 | No **Content-Security-Policy** for the production build. There is no `<meta http-equiv>` for CSP, so the app is wide open for XSS via any reflected string (toast messages, builder name, project name). | `index.html` | Medium |
| S3 | `axios.defaults.withCredentials = true` + lack of CSRF refresh on 403. If a CSRF token expires, the next POST 403s — there is no automatic re-fetch of `/csrf-token` and retry. | `src/api/adminApi.js:98-132` | Medium |
| S4 | **Image URLs from Cloudinary** are rendered directly via `<img src>`. There is no `referrerpolicy="no-referrer"` or sandboxing. | `Dashboard.jsx`, `AllProperty.jsx`, etc. | Low |
| S5 | The login page shows the specific error code `ACCOUNT_LOCKED` and the **lockout expiry time in minutes**. While this is useful UX, an attacker can use it to enumerate locked accounts. | `AdminLogin.jsx:73-79` | Low |
| S6 | `localStorage` is used for drafts. Draft data is plain text, not encrypted. Builders' RERA numbers and project details sit in localStorage in clear text. | `CreateProject.jsx:181-235` | Low |
| S7 | `window.confirm` and `alert` are used in `LocationPicker.jsx:244, 263`. The browser default alerts are blockable but not stylable and they leak the message to the OS-level "find in page". | `LocationPicker.jsx` | Low |
| S8 | `ProjectDetail.jsx:80` back button hardcodes `/builder-management` — but if the user came from `/project/:id/...` deep-link, this loses context. | `ProjectDetail.jsx:80` | Low (UX) |
| S9 | The `AdminBlogEditor.jsx` and `BlogManagement.jsx` were not deeply audited here, but the route `/blog-editor/:id` accepts arbitrary IDs without `loader` validation. | `App.jsx:268-275` | Low |
| S10 | The CSRF token is read from a cookie. If the cookie's `SameSite` is not `Strict`, the token can be sent cross-site in some configurations. Backend must enforce. | `src/api/adminApi.js:41-54` | Low |

---

## 11. Code Health & Maintainability

| # | Issue | File | Recommendation |
|---|---|---|---|
| C1 | **No TypeScript.** The codebase is pure JSX. Adding a `tsconfig.json` (or at least JSDoc types) would catch role/permission mismatches and API shape mismatches at build time. | repo-wide | Adopt TS incrementally, starting with `api/adminApi.js`. |
| C2 | **No tests.** Zero unit, zero integration, zero e2e. | repo-wide | Add Vitest + React Testing Library; add Playwright for happy-path admin flows. |
| C3 | **No ESLint rule for hooks deps / exhaustive-deps.** `eslint.config.js` enables `react-hooks` but `CreateUnitType.jsx:238` and `CreateProject.jsx:92` disable it inline. | `eslint.config.js`, many files | Tighten rules; add a custom rule. |
| C4 | **Duplicated `inp` / `lbl` Tailwind class strings** in 4-5 files. | `CreateProject.jsx:352-353`, `CreateUnitType.jsx:408-409`, etc. | Extract a `<Field />` component. |
| C5 | **Magic strings** for status, role, and category are spread across pages. | widespread | Move to `src/constants/*.js`. |
| C6 | **Direct `useState` + `useEffect` for fetching** in every page. A small `useApi` / `useQuery` hook (or React Query / SWR) would dedupe loading/error states. | widespread | Adopt TanStack Query. |
| C7 | **No JSDoc on any exported function.** | repo-wide | Add. |
| C8 | `axios` and `adminApi` are mixed throughout the codebase. `Dashboard.jsx:90` uses raw `adminApi.get`, but other pages use `dashboardApi.getStats`. | `Dashboard.jsx` | Standardise on the wrapper objects. |
| C9 | `adminApi.js` has **15 distinct API namespaces** in one 678-line file. Splitting per domain (auth, properties, builders, etc.) would improve discoverability. | `src/api/adminApi.js` | Split. |
| C10 | `CreateProject.jsx:185-208` has a hand-rolled `setTimeout`-based debounce. | `CreateProject.jsx:199-208` | Use a hook or `useDebouncedCallback`. |
| C11 | `AdminContext.jsx` line 67-69 — `login` accepts adminData OR re-fetches. The signature is ambiguous. | `AdminContext.jsx:66-74` | Split into `setAdmin(admin)` and `refreshAuth()`. |
| C12 | `useAdmin` throws if used outside provider — good — but the error is generic. | `AdminContext.jsx:163-169` | Add the provider name in the error. |
| C13 | `appProperty/propertyConstants.js` exists but I did not see it imported anywhere from `pages/`. Dead code or used only by `adminProperty/`? | `src/pages/adminProperty/propertyConstants.js` | Verify. |
| C14 | `ProjectDetail.jsx:194` `navigate(\`/campaign/${c._id}\`)` references a route that does not exist in `App.jsx`. | `ProjectDetail.jsx:194`, `App.jsx` | Add the route or remove the click handler. |
| C15 | The `rewards-management` sidebar item uses the icon `BarChart3` for 4 different menu items. | `Sidebar.jsx:35, 45, 51, 81` | Distinct icons. |
| C16 | `App.css` is empty. | `src/App.css` | Remove or move global styles to `index.css`. |

---

## 12. Builder-side Consolidation — Concrete Plan

Since the client has confirmed there is **no separate builder side**, the admin app must own the full builder lifecycle. Suggested plan:

### Phase 1 — Cleanup (no new features)
1. **Delete** `ListingsTable.jsx` (dead, 12 KB of mock data).
2. **Delete or repurpose** `src/pages/BuilderProjects.jsx` (the older 28 KB file). Use `BuilderProjectsList.jsx` as the single source of truth.
3. **Rename** `BuilderVerification.jsx` → `AllOwners.jsx`. Update the route label to "All Owners" (it already routes to `/all-owners`).
4. **Update** sidebar: remove the duplicate `/owners-projects` entry. Keep only `/builder-management` and `/all-owners`.
5. **Add** a real `<NotFound />` route and a `loader`-style `RouteErrorElement`.
6. **Remove** the `/admin-add-property?builderId=…` shortcut from the builder row, OR keep it but route to a deprecation notice pointing at `/create-project?builderId=…`.

### Phase 2 — Builder detail page
1. Add `/builder/:builderId` route. Render a tabbed page with: Profile, Projects, Documents, Activity.
2. Move the projects list logic from `BuilderProjectsList.jsx` to the "Projects" tab on the detail page.
3. Show totals (units, active campaigns, total sales) at the top.
4. Show "Deactivate" / "Reactivate" + "Add Project" + "Add Legacy Property" CTAs in the page header.
5. Add an audit log section (which admin created/edited what, when).

### Phase 3 — Shared wizard kit
Extract the duplicated wizard logic into a shared kit:
```
src/components/wizard/
  Wizard.jsx        // step state, validation runner, submit
  Stepper.jsx       // the indicator
  FormField.jsx     // label + input + error + char counter
  FileDropzone.jsx  // drag/drop, size cap, preview, multi-file
  ConfirmModal.jsx  // replace window.confirm/alert
  useDebouncedCallback.js
  useFormDraft.js   // localStorage save/load with file exclusion
```
- `CreateProject.jsx`, `CreateUnitType.jsx`, `CreateCampaign.jsx` then each become thin step-renderer files.
- Add Zod schemas (one per wizard) — backend can validate the same schemas independently.

### Phase 4 — RBAC (closing the menu-gating gap)
1. Use the role/permission data already in `AdminContext` to filter `Sidebar` items.
2. Add a `<RequireRole roles={['super_admin','content_admin']} />` wrapper that 404s on insufficient role.
3. Centralise role keys in `src/constants/roles.js`.

### Phase 5 — Data integrity
1. Remove `mockPropHistory` etc. from `Dashboard.jsx`. If the backend doesn't have history, show "No historical data available" rather than fake numbers.
2. Add `phone` formatter (libphonenumber-js) for builders and project sales contact.
3. Add RERA and GST regex validation to the project form.
4. Cap logo file size client-side (e.g. 2 MB, 1024×1024).

### Phase 6 — UX polish
1. Add `react-error-boundary` at the route level.
2. Add skeleton loaders.
3. Add bulk actions to AllProperty and AllClients.
4. Add pagination (cursor-based) on all list pages.
5. Add TanStack Query (or SWR) for data fetching — handles caching, refetch, stale data, and dedupes across pages.
6. Convert all `window.confirm`/`alert` to styled modals.
7. Add keyboard nav for the user dropdown (Up/Down/Enter/Esc).
8. Add `aria-invalid`, `aria-describedby`, `aria-required` on all form fields.
9. Replace `useState + useEffect` for data fetching with the new `useQuery` hook.
10. Self-host Leaflet marker images (`import markerIcon from "leaflet/dist/images/marker-icon.png"`) so maps work offline.

### Phase 7 — Testing
1. **Unit:** `validateStep` for each wizard; `effectivePrice`, `savings` helpers; `formatDate`; auth context reducer.
2. **Component:** Wizard kit components (Field, Stepper, FileDropzone) with RTL.
3. **Integration:** Admin login → MFA setup → dashboard load.
4. **E2E (Playwright):** admin creates builder → creates project → creates unit type → creates campaign.

---

## 13. Quick-win Patches (1-2 days)

If a more limited pass is required, these are the **highest signal-to-effort** changes:

1. **Delete `ListingsTable.jsx`** — pure dead code.
2. **De-duplicate `BuilderProjects.jsx` and `BuilderProjectsList.jsx`** — keep one.
3. **Remove mock history from `Dashboard.jsx`** — replace with an empty-state.
4. **Remove `window.location.reload()` in `AllProperty.clearFilters`** — use state reset.
5. **Convert `window.confirm` to a shared modal** — one component, many call sites.
6. **Add `aria-invalid` and `aria-describedby`** on the form fields in `CreateProject.jsx` and `CreateUnitType.jsx`.
7. **Cap logo upload size** in `BuilderManagement.jsx`.
8. **Sidebar: remove the duplicate `/owners-projects` item.**
9. **Standardise `useNavigate` for logout** instead of `window.location.href`.
10. **Add a `<NotFound />` route** instead of `*` → `/dashboard`.

---

## 14. Files That Should Be Considered for Deletion or Major Refactor

| File | Reason |
|---|---|
| `src/components/ListingsTable.jsx` | Dead code, 12 KB of mock data |
| `src/pages/BuilderProjects.jsx` | Superseded by `BuilderProjectsList.jsx` |
| `src/pages/BuilderVerification.jsx` | Misnamed — should be `AllOwners.jsx` |
| `src/App.css` | Empty |
| `src/components/MetricCard.jsx` (page-local) | Duplicate of the one in `Dashboard.jsx`; pick one |

---

## 15. Summary Recommendations (Priority Order)

| # | Recommendation | Effort | Impact |
|---|---|---|---|
| 1 | Delete `ListingsTable.jsx` and `BuilderProjects.jsx` | XS | High |
| 2 | Remove hard-coded mock chart data in `Dashboard.jsx` | S | High (data integrity) |
| 3 | Build a builder detail page (`/builder/:builderId`) | M | High (UX) |
| 4 | Introduce a shared Wizard + Stepper + FormField kit | L | High (maintainability) |
| 5 | Add Zod schemas for all three wizards | M | High (correctness) |
| 6 | Filter Sidebar by admin role | S | High (security) |
| 7 | Replace `window.confirm`/`alert` with shared modal | S | Medium |
| 8 | Add bulk actions + pagination to list pages | M | Medium |
| 9 | Adopt TanStack Query for data fetching | M | Medium |
| 10 | Add unit + integration tests | L | High (long-term) |

---

*Generated as a code-review report — no code in `Admin/` was modified by this audit.*
