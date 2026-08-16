# DEPENDENCIES.md — Package Inventory

For each package: **why it's here, where it's used, whether it's load-bearing, and whether it can be swapped.**

Related: [ARCHITECTURE.md](ARCHITECTURE.md) · [ENVIRONMENT.md](ENVIRONMENT.md)

---

## Backend — `backend/package.json`

ESM (`"type": "module"`), Node ≥18. **31 runtime dependencies, 1 dev dependency, zero test tooling.**

### Load-bearing — removing these breaks the app

| Package | Version | Used in | Notes |
|---|---|---|---|
| `express` | ^5.1.0 | everywhere | **Express 5**, not 4. Async errors auto-forward to the error handler; `req.query` is a getter; wildcard route syntax changed. Do not paste Express 4 middleware without checking |
| `mongoose` | ^8.19.2 | all 32 models | Schema, validation, hooks, transactions. Completely irreplaceable here |
| `jsonwebtoken` | ^9.0.2 | `authUser.js`, `chatRoutes.js`, `server.js` socket auth | Bearer fallback + 5-min socket tokens |
| `bcryptjs` | ^3.0.2 | user + admin password hashing, MFA backup codes | Pure JS — no native build. Slower than `bcrypt` but Hostinger-safe |
| `cookie-parser` | ^1.4.7 | `server.js` | Every auth path reads `req.cookies` |
| `cors` | ^2.8.5 | `server.js` | Dynamic origin whitelist |
| `dotenv` | ^17.2.3 | `server.js`, `upload.js` | Loaded twice, independently |
| `socket.io` | ^4.8.1 | `server.js` | Real-time chat + presence |
| `multer` | ^2.0.2 | `upload.js`, `documentUpload.js` | **v2**. `memoryStorage` only |
| `cloudinary` | ^2.8.0 | `upload.js`, controllers | All images and PDFs |

### Security stack

| Package | Purpose | Replaceable? |
|---|---|---|
| `helmet` ^8.1.0 | CSP, HSTS, frameguard, noSniff, referrer policy | Only by hand-writing the same headers |
| `express-rate-limit` ^8.2.1 | 6 limiter tiers | Yes — but you'd want a Redis store anyway |
| `hpp` ^0.2.3 | Parameter-pollution guard | Trivially |
| `express-validator` ^7.3.1 | Validation schemas + `whitelistFields` | Yes (zod/joi) — the Admin app already uses zod |
| `speakeasy` ^2.0.0 | Admin TOTP + backup codes | Yes (`otplib`), but it is unmaintained-adjacent and worth watching |
| `qrcode` ^1.5.4 | MFA enrolment QR data-URL | Yes |

### Integrations & output

| Package | Purpose | Notes |
|---|---|---|
| `@google/generative-ai` ^0.24.1 | Gemini `gemini-2.0-flash` for agreements | **Optional at runtime** — falls back to a local template |
| `nodemailer` ^7.0.10 | Gmail SMTP | Load-bearing for all email |
| `axios` ^1.13.6 | HTTP client | ⚠️ **Unused.** Verified: no import anywhere in `controllers/`, `routes/`, `services/`, `utils/`, `models/`, `middleware/`, `config/`, or `server.js`. SMS, WhatsApp, and RewardPort all use native `fetch` |
| `pdfkit` ^0.17.2 | User/owner PDF exports | Used in `userController` |
| `jspdf` + `jspdf-autotable` | PDF generation | ⚠️ **Unused.** Browser-oriented libraries in a Node backend, with no import anywhere in backend source. `pdfkit` does the actual PDF work |
| `exceljs` ^4.4.0 | Lead XLSX export | `leadController.exportLeadsToExcel` |
| `@json2csv/plainjs` ^7.0.6 | CSV exports | `userController` |
| `@sentry/node` ^10.38.0 | Error tracking | ✅ **Wired up 2026-08-01.** `backend/instrument.js` calls `Sentry.init()` and **must stay the first import in `server.js`**; `npm start`/`dev` pass `--import ./instrument.js` so ESM patches express before it loads. Reports 5xx only. Own Sentry project, separate from the frontend |
| `slugify` ^1.6.6 | Blog slugs | `blogController` |
| `file-type` ^21.3.0 | MIME detection | ⚠️ Not imported — `upload.js` implements magic-byte checks **by hand** with its own signature table |
| `morgan` ^1.10.1 | HTTP logging | ⚠️ Not wired into `server.js`. Dead |
| `body-parser` ^2.2.0 | Body parsing | ⚠️ Redundant — Express 5 has `express.json`/`express.urlencoded` built in, which is what `server.js` actually uses |
| `multer-storage-cloudinary` ^2.2.1 | Direct-to-Cloudinary storage | **Legacy path only.** The secure flow is memory → magic-byte validation → manual `upload_stream`. Kept for backward compatibility |

### Backend cleanup candidates — all verified unused
`jspdf`, `jspdf-autotable`, `morgan`, `body-parser`, `file-type`, and `axios` have **no import anywhere in backend source**. Six of 31 runtime dependencies are dead weight.

*(`@sentry/node` was on this list until 2026-08-01 and is now genuinely in use — see the row above.)*

**`nodemon` is the only devDependency.** No linter, no formatter, no test runner on the backend.

---

## client-next — `client-next/package.json`

Next.js **16.1.6**, React **19.2.3**, Tailwind **4**.

### Framework

| Package | Notes |
|---|---|
| `next` ^16.1.6 | App Router, server components, middleware, ISR, `sitemap.js`/`robots.js` conventions, Turbopack |
| `react` / `react-dom` 19.2.3 | React 19 — `use()`, improved Suspense, ref-as-prop |
| `tailwindcss` ^4 (dev) + `@tailwindcss/postcss` | **Tailwind 4** — CSS-first config via `@import "tailwindcss"` and `@theme inline`. There is **no `tailwind.config.js`** |
| `@tailwindcss/typography` | `prose` classes for blog post rendering |

### Data & state
| Package | Notes |
|---|---|
| `axios` ^1.13.5 | The entire client API layer (`utils/api.js`). Interceptors do CSRF header injection and error sanitization — a `fetch` migration would have to reimplement both |
| `socket.io-client` ^4.8.3 | `ChatContext`. Must stay version-compatible with server `socket.io` 4.x |

No Redux / Zustand / React Query on web — just Context + `useState`.

### UI
| Package | Notes |
|---|---|
| `framer-motion` ^12.34.0 | Animation throughout, notably the reward reveals |
| `lucide-react` ^0.563.0 | Primary icon set |
| `react-icons` ^5.5.0 | ⚠️ **Second icon library.** Overlaps with lucide and heroicons |
| `@heroicons/react` ^2.2.0 | ⚠️ **Third icon library** |
| `react-toastify` ^11.0.5 | Toasts, mounted in `ClientLayout` |
| `react-image-crop` ^11.0.10 | Profile-image cropping |

**Three icon libraries** ship in the same bundle. Consolidating on lucide-react is the single easiest bundle win.

### Content & data display
| Package | Notes |
|---|---|
| `react-markdown` + `remark-gfm` + `rehype-highlight` | Blog and agreement rendering |
| `@uiw/react-md-editor` ^4.0.11 | ⚠️ **Unused.** Verified: no import anywhere under `client-next/src/`. A heavy markdown *editor* left over from before the blog editor moved to the `Admin` app. Safe to remove |
| `recharts` ^3.7.0 | Charts |
| `date-fns` ^4.1.0 | Date formatting |
| `leaflet` + `react-leaflet` 5.0.0 | Property maps. Must be dynamically imported — Leaflet touches `window` at module scope |

### Observability
`@sentry/nextjs` ^10.38.0 — genuinely wired: `sentry.client/server/edge.config.js`, `instrumentation.js`, `instrumentation-client.js`, and `withSentryConfig` in `next.config.mjs` with `tunnelRoute: "/monitoring"` (ad-blocker evasion), `hideSourceMaps`, and `transpileClientSDK` (IE11 — almost certainly removable in 2026).

---

## Admin — `Admin/package.json`

Vite 6, React 19, React Router 7.

| Package | Notes |
|---|---|
| `vite` ^6.0.0 + `@vitejs/plugin-react` | Build. Manual chunks: `vendor`, `antd`, `charts` |
| `react-router-dom` ^7.9.5 | ~30 routes in `App.jsx` |
| `antd` ^5.27.6 + `@ant-design/icons` ^6.1.0 | Component library |
| `tailwindcss` ^4.1.16 + `@tailwindcss/vite` | ⚠️ **Used alongside antd.** Two competing styling systems in one app |
| `recharts` ^3.5.1 | Charts |
| `chart.js` ^4.5.1 + `react-chartjs-2` ^5.3.1 | ⚠️ **Second charting library** |
| `zod` ^4.4.3 | Wizard schemas — `schemas/projectSchema.js`, `unitTypeSchema.js`, `campaignSchema.js`. The only structured validation in any frontend |
| `leaflet` + `react-leaflet` | `LocationPicker`, `LocationAutocomplete` |
| `axios` ^1.13.1 | `api/adminApi.js`. `withCredentials` set globally in `main.jsx` |
| `lucide-react` + `react-icons` + `@heroicons/react` | ⚠️ **Three icon libraries again** |
| `react-toastify` ^11.0.5 | Toasts |

**Duplication tally for Admin:** 2 styling systems, 2 charting libraries, 3 icon libraries. The `charts` manual chunk exists specifically because both charting libraries ship. Standardising on recharts + Tailwind + lucide would cut the bundle materially.

Dev: eslint 9 + react-hooks/react-refresh plugins. **No tests.**

---

## Mobile — `dealdirect-mobile/package.json`

Expo **54**, React Native **0.81.5**, expo-router **6**, New Architecture enabled.

| Package | Why |
|---|---|
| `expo-router` ~6.0.0 | File-based routing, typed routes enabled |
| `@tanstack/react-query` ^5.101.4 | Server-state cache. **The web apps have no equivalent** |
| `react-hook-form` ^7.83.0 + `@hookform/resolvers` + `zod` ^4.4.3 | Forms with schema validation |
| `react-native-mmkv` ^4.3.2 | Fast KV storage. **Native module — needs a dev client, not Expo Go** |
| `expo-secure-store` ~15.0.8 | Keychain/Keystore for the mirrored session cookie |
| `@react-native-cookies/cookies` ^6.2.1 | Native cookie-jar bridge. Load-bearing for cold-start auth (see `src/auth/cookies.ts`) |
| `nativewind` ^4.2.1 + `tailwindcss` ^3.4.17 | Tailwind for RN. **Tailwind 3 here, 4 on web** — class support differs |
| `react-native-reanimated` ~4.1.0 + `react-native-worklets` | Animation |
| `react-native-gesture-handler` ~2.28.0 | Gestures |
| `expo-image` ~3.0.11 | Cached image component |
| `axios` ^1.19.0 | Two clients: 30 s JSON, 120 s upload |
| `react-native-nitro-modules` ^0.36.4 | MMKV v4 peer requirement |

Typed with TypeScript ~5.9.2. `npm run contract:check` type-checks the hand-written API contract in `src/types/backend/`.

---

## Cross-Cutting Observations

### Version alignment
| Package | backend | client-next | Admin | mobile |
|---|---|---|---|---|
| react | — | 19.2.3 | ^19.1.1 | 19.1.0 |
| axios | ^1.13.6 | ^1.13.5 | ^1.13.1 | ^1.19.0 |
| tailwindcss | — | ^4 | ^4.1.16 | ^3.4.17 |
| zod | — | — | ^4.4.3 | ^4.4.3 |
| socket.io | ^4.8.1 (server) | ^4.8.3 (client) | — | — |

Nothing is dangerously mismatched. The Tailwind 3-vs-4 split between mobile and web is the only real divergence, and it is unavoidable (NativeWind 4 targets Tailwind 3).

### There is no shared code
No monorepo tool, no workspaces, no shared package. API types, enum values, validation rules, price-formatting logic, and role checks are duplicated by hand across four codebases. `formatPrice.js` (client-next) and `PriceLabel.tsx` (mobile) implement the same Lakh/Crore rules independently.

### Zero test infrastructure
No jest, vitest, playwright, supertest, or testing-library anywhere. `backend/package.json` has the npm-init placeholder `"test": "echo \"Error: no test specified\" && exit 1"`. Every change is verified manually.

### Recommended cleanup, highest value first
1. **Backend:** drop `jspdf`, `jspdf-autotable`, `morgan`, `body-parser`, `file-type`; either wire up or remove `@sentry/node`.
2. **Both frontends:** consolidate to one icon library (lucide-react).
3. **Admin:** pick one charting library (recharts) and drop `chart.js` + `react-chartjs-2`.
4. **client-next:** confirm `@uiw/react-md-editor` is still used; it is heavy for a public site.
5. Add a test runner. There is currently no automated safety net for any of the fixes in [KNOWN_BUGS.md](KNOWN_BUGS.md).
