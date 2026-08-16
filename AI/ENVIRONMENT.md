# ENVIRONMENT.md — Configuration & Deployment

Related: [SECURITY.md](SECURITY.md) · [ARCHITECTURE.md](ARCHITECTURE.md) · [DEPENDENCIES.md](DEPENDENCIES.md)

---

## 1. How the Backend Loads Configuration

`backend/server.js:26-38` — a Hostinger workaround, and the first thing to understand:

```js
if (fs.existsSync('.env'))                dotenv.config({ path: '.env' });
else if (fs.existsSync('.env.production')) dotenv.config({ path: '.env.production' });
else                                       dotenv.config();
```

`.env` **wins whenever it exists.** Both files are present in this working tree, so local development always reads `.env` and `.env.production` is inert. The deploy procedure (per the comment at the top of `.env.production`) is to *copy* `.env.production` to `.env` in `public_html` after each deployment.

`middleware/upload.js` repeats the same fallback logic independently, because it needs `CLOUDINARY_URL` at module load.

### Boot-time validation (`validateEnvironment()`)
| Check | Behaviour |
|---|---|
| `JWT_SECRET`, `MONGO_URI` missing | **`process.exit(1)`** in every environment |
| `CLIENT_URL`, `ADMIN_URL`, `AGREEMENT_SECRET_KEY` missing | warning in production only |
| `JWT_SECRET` < 32 chars | **exit** in production, warning in dev |
| `NODE_ENV !== 'production'` | warning: "security features relaxed" |

Everything else is optional and degrades silently. That silence is the main operational hazard — see §4.

---

## 2. Backend Variables (`backend/.env`)

### Required — server will not start without these
| Var | Notes |
|---|---|
| `MONGO_URI` | MongoDB Atlas SRV string. Must be a replica set — `addProperty` uses a transaction |
| `JWT_SECRET` | ≥32 chars in production. Also the fallback for `COOKIE_SECRET`, `OTP_SECRET`, and `AGREEMENT_SECRET_KEY` |

### Strongly recommended in production
| Var | Consumed by | If missing |
|---|---|---|
| `NODE_ENV=production` | everywhere | **Secure cookies off, HSTS off, CSP relaxed, `/debug-startup` exposed, `SameSite=lax` instead of `none` (cross-origin auth breaks)** |
| `PORT` | `server.js` | defaults 9000 |
| `CLIENT_URL` | CORS whitelist | browser requests from the site are blocked |
| `ADMIN_URL` | CORS whitelist | admin panel blocked |
| `COOKIE_DOMAIN` | both cookie configs | cookies bind to the exact API host; cross-subdomain auth breaks |
| `TRUSTED_PROXIES` | `app.set('trust proxy')` | falls back to `'loopback'` — behind a CDN, rate limits key on the CDN IP |
| `AGREEMENT_SECRET_KEY` | Agreement HMAC | falls back to `JWT_SECRET`; rotating JWT_SECRET then invalidates every agreement signature |
| `OTP_SECRET` | OTP hashing | falls back to `JWT_SECRET` — same coupling |

### Integrations — each fails **silently** when unconfigured
| Var(s) | Service | Behaviour when missing |
|---|---|---|
| `CLOUDINARY_URL` | Cloudinary | Logs `❌ CLOUDINARY_URL not found`; all uploads return **503 `STORAGE_NOT_CONFIGURED`**. Format: `cloudinary://key:secret@cloud_name`. Pings on boot to verify |
| `SMTP_USER`, `SMTP_PASS`, `SMTP_EMAIL`, `SENDER_EMAIL`, `SMTP_HOST`, `SMTP_PORT` | Gmail SMTP via nodemailer | All email silently fails. `getTransporter()` verifies on first use and logs the error |
| `GEMINI_API_KEY` | Google Gemini | `genAI = null` → agreement generation falls back to the local template. **Not fatal** |
| `EQUENCE_USERNAME`, `EQUENCE_PASSWORD`, `EQUENCE_SENDER_ID`, `EQUENCE_PE_ID`, `EQUENCE_BASE_URL`, `EQUENCE_OTP_TMPL_ID`, `EQUENCE_RESET_TMPL_ID` | Equence SMS (DLT-compliant) | **Registration and password reset return 500.** This is the one integration whose absence breaks a core flow |
| `WAHA_API_URL`, `WAHA_API_KEY`, `WAHA_SESSION`, `WAHA_ADMIN_PHONE` | WhatsApp (WAHA on Railway) | Notifications skipped, warning logged |
| `REWARDPORT_USERNAME`, `REWARDPORT_PASSWORD` | RewardPort catalogue | Catalogue endpoints return `{success:false, products:[]}` |
| `HUBBLE_CLIENT_ID`, `HUBBLE_APP_SECRET`, `HUBBLE_WEBHOOK_SECRET`, `HUBBLE_SDK_BASE_URL`, `HUBBLE_THEME` | Hubble gift cards | `/hubble/sso` returns 500 (fails closed) |
| `SENTRY_DSN` | Sentry (`instrument.js`) | **No backend error reporting at all.** Logs a startup warning. ⚠️ **Absent from `.env.production` — must be added on the server.** Uses a Sentry project separate from the frontend |
| `MAPPLES_API_KEY` | Maps | — |
| `DEALDIRECT_PAYMENT_QR_URL`, `DEALDIRECT_UPI_ID` | Booking payments | `GET /api/bookings/payment-config` returns **503** — bookings cannot be paid |
| `PAYMENT_WEBHOOK_SECRET` | Agreement webhook | ⚠️ **Signature verification is skipped entirely.** See [SECURITY.md](SECURITY.md) H2 |
| `ADMIN_NOTIFY_EMAIL` | booking alerts | — |
| `REDIS_URL` | `config/redis.js` | Uses `MemoryCache` regardless — the real client is commented out |

---

## 3. Frontend Variables

### `client-next/.env.local` (dev) · `.env.production` (prod)
| Var | Purpose |
|---|---|
| `NEXT_PUBLIC_API_BASE` | Origin without `/api`. Also the Socket.IO URL |
| `NEXT_PUBLIC_API_URL` | Origin **with** `/api`. Takes priority in `getApiBaseUrl()` |
| `NEXT_PUBLIC_MAPPLES_API_KEY` | Maps — **shipped in the bundle** |
| `NEXT_PUBLIC_SENTRY_DSN` | Sentry browser SDK |
| `SENTRY_AUTH_TOKEN` | **Build-time only**, source-map upload. Not `NEXT_PUBLIC_` so it stays server-side — but it is a real credential sitting in the working tree |
| `API_INTERNAL_BASE` | *Optional, server-only.* If set, `ssrFetch` uses it so SSR reaches the backend over the internal network instead of DNS + reverse proxy. **Not currently set — worth adding on Hostinger** |

Fallback chain when unset: `NEXT_PUBLIC_API_URL` → `NEXT_PUBLIC_API_BASE + '/api'` → `window.location.hostname:9000/api` → `http://localhost:9000/api`.

### `Admin/.env` · `.env.production`
| Var | Purpose |
|---|---|
| `VITE_API_BASE_URL` | Backend origin. The only variable this app needs |

⚠️ `Admin/.env.production` **is tracked in git** (unlike every other env file). It contains only the public API URL, so this is safe, but note the inconsistency.

### `dealdirect-mobile/.env`
| Var | Purpose |
|---|---|
| `EXPO_PUBLIC_API_URL` | **With** `/api` — e.g. `https://backend.dealdirect.in/api` |
| `EXPO_PUBLIC_SOCKET_URL` | **Without** `/api` — Socket.IO attaches at the server root |

Both are validated at module load in `src/config/env.ts` and **throw** if missing, rather than producing requests to `undefined/api/...`. Both are inlined into the bundle — public by definition. On a physical device, `localhost` is the *device*; use the host machine's LAN IP.

---

## 4. Environment Drift — Read Before Deploying

`.env` (dev) and `.env.production` hold **different variable sets**. This is the single most important operational fact in this document.

**Present in `.env` but absent from `.env.production`:**
`SENTRY_DSN`, all `EQUENCE_*`, all `WAHA_*`, all `REWARDPORT_*`, all `HUBBLE_*`, `DEALDIRECT_PAYMENT_QR_URL`, `SMTP_HOST`, `SMTP_PORT`, `ADMIN_NOTIFY_EMAIL`.

**Present in `.env.production` but absent from `.env`:**
`NODE_ENV`, `CLIENT_URL`, `COOKIE_DOMAIN`, `AGREEMENT_SECRET_KEY`.

If `.env.production` is copied verbatim to `.env` on the server, the deployed backend has **no SMS** (registration and password reset return 500), **no WhatsApp**, **no RewardPort catalogue**, **no Hubble**, **no booking QR**, and **no Sentry**.

Either that file is incomplete and the real server `.env` was assembled by hand, or those features are currently dead in production. **Verify against the live server before changing anything here.**

Missing from **both** files: `TRUSTED_PROXIES`, `PAYMENT_WEBHOOK_SECRET`, `OTP_SECRET`, `COOKIE_SECRET`, `DEALDIRECT_UPI_ID`, `REDIS_URL`, `API_INTERNAL_BASE`.

---

## 5. Local Development

```bash
# Terminal 1 — backend
cd backend && npm install && npm run dev      # nodemon, :9000
```
```bash
# Terminal 2 — main site
cd client-next && npm install && npm run dev  # :3000
```
```bash
# Terminal 3 — admin
cd Admin && npm install && npm run dev        # :5174
```
```bash
# Verify the backend is healthy
curl http://localhost:9000/health
```
```bash
# Env presence check (dev only — hidden in production)
curl http://localhost:9000/debug-startup
```

Notes:
- CORS in dev whitelists `localhost:3000/3001/5173/5174` and `127.0.0.1:3000/5173`.
- Cookies use `SameSite=lax` and `secure:false` in dev, so cross-origin auth works over plain HTTP on localhost.
- **A standalone `mongod` will fail** on `POST /api/properties/add` — the one-listing-per-owner check runs in a transaction, which requires a replica set. Use Atlas or `mongod --replSet`.
- Registration requires working Equence SMS credentials. Without them you cannot create a test account through `/register`; use `/register-direct` (no OTP) instead.

Mobile:
```bash
cd dealdirect-mobile && npm install && npm start   # expo --dev-client
```
Requires a dev client build (`expo run:ios` / `expo run:android`) — `react-native-mmkv` and `@react-native-cookies/cookies` are native modules, so Expo Go will not work.

---

## 6. Production Deployment (Hostinger)

Reference: `HOSTINGER_DEPLOYMENT.md` at the repo root.

| App | Host | Build | Serve |
|---|---|---|---|
| backend | `backend.dealdirect.in` | none | `npm start` (Node, port 9000) |
| client-next | `dealdirect.in` | `npm run build` | `npm start` (Node server — **not** static; SSR + middleware + ISR are required) |
| Admin | `admin.dealdirect.in` | `npm run build` | static `dist/` + SPA rewrite |

Hostinger-specific artifacts in the repo:
- `.htaccess` files in `backend/`, `Admin/`, and `Admin/public/`
- `Admin/public/_redirects` (SPA fallback)
- `.nvmrc` in `backend/` and `Admin/`
- the `.env` → `.env.production` fallback in `server.js`

### Deployment checklist
1. Copy `.env.production` → `.env` on the backend host — **after reconciling the drift in §4**.
2. Confirm `NODE_ENV=production` (drives secure cookies, HSTS, CSP, and hides `/debug-startup`).
3. Confirm `CLIENT_URL` and `ADMIN_URL` match the real origins exactly — trailing slashes are stripped, and www/non-www variants are auto-added.
4. Set `COOKIE_DOMAIN=.dealdirect.in` for cross-subdomain cookies.
5. Set `TRUSTED_PROXIES` to the actual proxy IPs if anything sits in front of Node.
6. `curl https://backend.dealdirect.in/health` → expect `database: connected`.
7. `client-next` build needs `SENTRY_AUTH_TOKEN` present, or configure `withSentryConfig` to skip upload.
8. Verify `/debug-startup` returns **404** in production.

### Scaling constraint
The backend **cannot run more than one instance** as written — Socket.IO presence, Hubble SSO tokens, rate-limit counters, the upload-concurrency gate, and the cache are all in-process. See [ARCHITECTURE.md](ARCHITECTURE.md) §8 and [PERFORMANCE.md](PERFORMANCE.md).

---

## 7. Third-Party Accounts

| Service | Purpose | Dashboard |
|---|---|---|
| MongoDB Atlas | Primary datastore | cloud.mongodb.com |
| Cloudinary | All images + PDFs | cloudinary.com |
| Google Gemini | Agreement drafting (`gemini-2.0-flash`) | aistudio.google.com |
| Equence Technologies | DLT-compliant Indian SMS | api.equence.in |
| WAHA | WhatsApp HTTP API, self-hosted on Railway | railway.app |
| RewardPort | Voucher/product catalogue (HTTP Basic) | catalogue.rewardzpromo.com |
| Hubble | Gift-card SDK + coin economy | partners.myhubble.money |
| Sentry | Errors, org `opscores`, project `dealdirect-frontend` | sentry.io |
| Gmail SMTP | Transactional email (app password) | — |
| Mapples | Maps | — |
| Hostinger | Hosting | — |
| EAS / Expo | Mobile builds, project `9d0ec43d-f62d-4bf2-8c59-549fb239b8a0` | expo.dev |

**Indian regulatory note:** Equence SMS requires DLT registration. `EQUENCE_PE_ID` (Principal Entity ID) and per-template ids are mandatory, and the message body must match the registered template **exactly** — the strings are hardcoded in `services/smsService.js` for that reason. Changing the wording without re-registering the template causes silent delivery failure.
