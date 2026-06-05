# DealDirect — Secure Real Estate Platform

[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Next.js](https://img.shields.io/badge/Next.js-16-000000?logo=next.js)](https://nextjs.org)
[![MongoDB](https://img.shields.io/badge/MongoDB-6%2B-47A248?logo=mongodb&logoColor=white)](https://mongodb.com)
[![Express](https://img.shields.io/badge/Express-5-000000?logo=express)](https://expressjs.com)
[![Socket.IO](https://img.shields.io/badge/Socket.IO-4-010101?logo=socket.io)](https://socket.io)
[![Sentry](https://img.shields.io/badge/Sentry-Monitored-362D59?logo=sentry)](https://sentry.io)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-2ea44f)]()
[![License](https://img.shields.io/badge/License-Proprietary-red)]()

> **DealDirect** is a production-grade real estate marketplace that connects property **Owners** directly with **Buyers**, eliminating intermediary agents. The platform features AI-powered agreement generation, real-time chat, a rewards ecosystem, and enterprise-grade security hardening.

**Live URLs:**

| Environment | URL |
|---|---|
| Client (Buyers) | `https://dealdirect.in` |
| Admin Panel | `https://admin.dealdirect.in` |
| Backend API | `https://backend.dealdirect.in` |

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Repository Structure](#repository-structure)
- [Tech Stack](#tech-stack)
- [New Developer Setup](#new-developer-setup)
- [Environment Variables](#environment-variables)
- [Running Locally](#running-locally)
- [Project Modules Deep Dive](#project-modules-deep-dive)
- [API Reference](#api-reference)
- [Security Architecture](#security-architecture)
- [Deployment](#deployment)
- [Monitoring & Error Tracking](#monitoring--error-tracking)
- [Coding Conventions](#coding-conventions)
- [Troubleshooting](#troubleshooting)
- [Key Documentation](#key-documentation)
- [Team Contacts](#team-contacts)

---

## Architecture Overview

DealDirect follows a **layered Service-Oriented Architecture (SOA)** with four tiers:

```
┌──────────────────────────────────────────────────────────┐
│                    CLIENT LAYER                          │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────┐   │
│  │ client-next  │  │    client    │  │     Admin     │   │
│  │  (Next.js)   │  │ (Vite/React) │  │ (Vite/React)  │   │
│  │  Buyers SSR  │  │  Buyers SPA  │  │  Admin Panel  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────┬────────┘   │
└─────────┼─────────────────┼─────────────────┼────────────┘
          │   HTTPS / WSS   │                 │
┌─────────▼─────────────────▼─────────────────▼────────────┐
│               API GATEWAY (Express.js 5)                 │
│  Helmet CSP │ CORS Lockdown │ Rate Limiting │ JWT Auth   │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                   SERVICES LAYER                         │
│  ┌────────┐ ┌──────────┐ ┌──────┐ ┌──────────┐          │
│  │  Auth  │ │ Property │ │ Lead │ │Agreement │          │
│  │Service │ │ Service  │ │Mgmt  │ │ Service  │          │
│  └────────┘ └──────────┘ └──────┘ └──────────┘          │
│  ┌────────┐ ┌──────────┐ ┌────────────┐ ┌───────────┐   │
│  │  Chat  │ │  Notify  │ │  Rewards   │ │   Blog    │   │
│  │(WS/IO) │ │Email/SMS │ │ RewardPort │ │  Service  │   │
│  └────────┘ └──────────┘ └────────────┘ └───────────┘   │
└──────────────────────────┬───────────────────────────────┘
                           │
┌──────────────────────────▼───────────────────────────────┐
│                    DATA & PROVIDERS                      │
│  MongoDB Atlas │ Cloudinary │ Gemini AI │ Sentry         │
│  Equence SMS   │ WAHA WhatsApp │ RewardPort │ Nodemailer │
└──────────────────────────────────────────────────────────┘
```

> For the full SOA analysis, see [`DealDirect_SOA_Report.md`](./DealDirect_SOA_Report.md).

---

## Repository Structure

This is a **monorepo** with four independent applications:

```
DealDirectSecure/
├── backend/                 # Express.js 5 API server (ES Modules)
│   ├── config/              #   db.js (MongoDB), redis.js
│   ├── controllers/         #   14 controller files (business logic)
│   ├── middleware/           #   Auth, CSRF, upload, error handling, role guard
│   │   └── validators/      #   Express-validator schemas
│   ├── models/              #   26 Mongoose schemas
│   ├── routes/              #   14 route files
│   ├── services/            #   Reward, SMS, WhatsApp services
│   ├── utils/               #   Email service
│   ├── scripts/             #   Data migration scripts
│   ├── server.js            #   Main entry point (820 lines, heavily documented)
│   └── .env.example         #   ⬅ Template — copy to .env
│
├── client-next/             # Next.js 16 frontend (PRIMARY client, SSR/SEO)
│   ├── src/app/             #   App Router with 19 route directories
│   │   ├── properties/      #     Property search & details
│   │   ├── agreements/      #     Agreement management
│   │   ├── rewards/         #     Rewards dashboard & storefront
│   │   ├── blog/            #     Blog with markdown rendering
│   │   ├── profile/         #     User profile management
│   │   └── ...              #     login, register, contact, about, faq, etc.
│   ├── sentry.*.config.js   #   Sentry integration (client, server, edge)
│   └── next.config.mjs      #   Next.js + Sentry webpack config
│
├── client/                  # Vite + React 19 frontend (LEGACY SPA)
│   ├── src/
│   │   ├── Components/      #   Reusable UI components (Footer, Navbar, etc.)
│   │   ├── Pages/           #   17 page directories
│   │   ├── context/         #   React context providers
│   │   └── utils/           #   API helpers, formatters
│   └── vite.config.js
│
├── Admin/                   # Vite + React 19 admin dashboard
│   ├── src/
│   │   ├── pages/           #   22 admin pages (Dashboard, Leads, Rewards, etc.)
│   │   ├── components/      #   Shared admin components
│   │   ├── api/             #   API client layer
│   │   └── context/         #   Auth context
│   └── vite.config.js
│
├── DealDirect_SOA_Report.md          # Full architecture documentation
├── HOSTINGER_DEPLOYMENT.md           # Production deployment guide
├── SECURITY_FIXES_SUMMARY.md         # Security audit results
├── TECHNICAL_REVIEW_FIXES.md         # Technical review remediation
├── CLIENT_APP_IMPLEMENTATION_GUIDE.md # Next.js migration guide
├── BLOG_IMPLEMENTATION_PLAN.md       # Blog feature specs
└── MIGRATION_EXECUTION_PLAN.md       # Database migration plan
```

> **Note:** `client/` (Vite SPA) is the **legacy** frontend. `client-next/` (Next.js 16) is the **active primary** frontend with SSR and SEO. Both share the same backend API.

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **Primary Frontend** | Next.js 16, React 19, TailwindCSS 4 | SSR, SEO, buyer-facing UI |
| **Legacy Frontend** | Vite 6, React 19, TailwindCSS 4 | SPA, buyer-facing UI |
| **Admin Dashboard** | Vite 6, React 19, Ant Design 5 | Property/lead/rewards management |
| **Backend** | Express.js 5, Node.js 18+ (ES Modules) | REST API, WebSocket server |
| **Database** | MongoDB 6+ (Atlas), Mongoose 8 | Document storage |
| **Authentication** | JWT + HttpOnly Cookies, Speakeasy 2FA | Stateless auth, MFA |
| **Real-time** | Socket.IO 4 | Live chat, presence, typing |
| **File Storage** | Cloudinary | Image upload, CDN delivery |
| **AI** | Google Gemini (`@google/generative-ai`) | Agreement document generation |
| **Email** | Nodemailer (SMTP) | Transactional emails |
| **SMS** | Equence API | OTP, lead notifications |
| **WhatsApp** | WAHA (Railway-hosted) | WhatsApp notifications |
| **Rewards** | RewardPort Catalogue API | Reward storefront integration |
| **Maps** | Leaflet + React-Leaflet + Mapples | Property location maps |
| **Charts** | Recharts, Chart.js | Analytics dashboards |
| **Monitoring** | Sentry (frontend + backend) | Error tracking, performance |
| **Security** | Helmet, express-rate-limit, hpp | CSP, rate limiting, HPP protection |
| **PDF** | PDFKit, jsPDF | Agreement document generation |

---

## New Developer Setup

### Prerequisites

| Tool | Version | Installation |
|---|---|---|
| **Node.js** | ≥ 18.0.0 | [nodejs.org](https://nodejs.org) (use LTS) |
| **npm** | ≥ 9 | Bundled with Node.js |
| **Git** | Latest | [git-scm.com](https://git-scm.com) |
| **MongoDB** | 6+ | Use [MongoDB Atlas](https://cloud.mongodb.com) (cloud) |
| **VS Code** | Latest | Recommended editor |

### Recommended VS Code Extensions

- ESLint
- Tailwind CSS IntelliSense
- ES7+ React/Redux/React-Native snippets
- MongoDB for VS Code
- Thunder Client (API testing)

### Step 1 — Clone the Repository

```bash
git clone https://github.com/chirag-says/DealDirectSecure.git
cd DealDirectSecure
```

### Step 2 — Install Dependencies

Each sub-project has its own `node_modules`. Install them separately:

```bash
# Backend
cd backend && npm install

# Primary Client (Next.js)
cd ../client-next && npm install

# Legacy Client (Vite)
cd ../client && npm install

# Admin Panel
cd ../Admin && npm install
```

### Step 3 — Configure Environment Variables

Copy `.env.example` to `.env` in each sub-project and fill in your values:

```bash
# Backend
cp backend/.env.example backend/.env

# Client (legacy)
cp client/.env.example client/.env

# Admin
cp Admin/.env.example Admin/.env

# Client-next (create manually — see section below)
```

> ⚠️ **NEVER commit `.env` files.** They are in `.gitignore`. Ask a team lead for production credentials.

---

## Environment Variables

### Backend (`backend/.env`)

| Variable | Required | Description |
|---|---|---|
| `PORT` | Yes | Server port (default: `9000`) |
| `NODE_ENV` | Yes | `development` or `production` |
| `MONGO_URI` | Yes | MongoDB Atlas connection string |
| `JWT_SECRET` | Yes | 64+ character secret for JWT signing |
| `CLOUDINARY_URL` | Yes | Cloudinary connection URL |
| `CLIENT_URL` | Prod | Frontend origin for CORS (e.g., `https://dealdirect.in`) |
| `ADMIN_URL` | Prod | Admin origin for CORS (e.g., `https://admin.dealdirect.in`) |
| `COOKIE_DOMAIN` | Prod | Cookie domain (e.g., `.dealdirect.in`) |
| `SMTP_USER` / `SMTP_PASS` | Yes | Gmail SMTP for transactional emails |
| `GEMINI_API_KEY` | Yes | Google Gemini AI for agreement generation |
| `AGREEMENT_SECRET_KEY` | Prod | HMAC-SHA256 key for agreement signing |
| `EQUENCE_USERNAME` / `PASSWORD` | Yes | Equence SMS API credentials |
| `WAHA_API_URL` / `API_KEY` | Opt | WhatsApp HTTP API |
| `REWARDPORT_USERNAME` / `PASSWORD` | Opt | RewardPort catalogue API |
| `SENTRY_DSN` | Opt | Sentry error tracking DSN |

### Client-Next (`client-next/.env.local`)

| Variable | Description |
|---|---|
| `NEXT_PUBLIC_API_BASE` | Backend base URL (e.g., `http://localhost:9000`) |
| `NEXT_PUBLIC_API_URL` | Backend API URL (e.g., `http://localhost:9000/api`) |
| `NEXT_PUBLIC_MAPPLES_API_KEY` | Mapples maps API key |
| `NEXT_PUBLIC_SENTRY_DSN` | Sentry DSN for frontend |

### Client Legacy (`client/.env`)

| Variable | Description |
|---|---|
| `VITE_API_BASE` | Backend base URL |
| `VITE_MAPPLES_API_KEY` | Mapples maps API key |

### Admin (`Admin/.env`)

| Variable | Description |
|---|---|
| `VITE_API_BASE_URL` | Backend base URL |

---

## Running Locally

Open **four terminal windows** and start each service:

```bash
# Terminal 1 — Backend API
cd backend
npm run dev          # Uses nodemon for hot-reload

# Terminal 2 — Primary Client (Next.js)
cd client-next
npm run dev          # Starts at http://localhost:3000

# Terminal 3 — Legacy Client (Vite)
cd client
npm run dev          # Starts at http://localhost:5173

# Terminal 4 — Admin Panel
cd Admin
npm run dev          # Starts at http://localhost:5174
```

### Local Service URLs

| Service | URL | Notes |
|---|---|---|
| Backend API | `http://localhost:9000` | Health check: `/health` |
| Client (Next.js) | `http://localhost:3000` | Primary frontend |
| Client (Vite) | `http://localhost:5173` | Legacy frontend |
| Admin | `http://localhost:5174` | Login with admin credentials |

### Verifying the Backend is Running

```bash
curl http://localhost:9000/health
# Expected: {"success":true,"status":"healthy","database":"connected"}

curl http://localhost:9000/debug-startup
# Shows env var status (values hidden) and DB connection state
```

---

## Project Modules Deep Dive

### Backend Controllers (14 modules)

| Controller | File | Responsibilities |
|---|---|---|
| **User** | `userController.js` | Registration, login, logout, profile, password reset, OTP |
| **Admin** | `adminController.js` | Admin auth, user management, analytics, MFA setup |
| **Property** | `propertyController.js` | CRUD, search, filters, suggestions, image upload |
| **Lead** | `leadController.js` | Lead lifecycle, status tracking, analytics |
| **Agreement** | `agreementController.js` | AI generation (Gemini), signatures, HMAC verification, PDF |
| **Chat** | `chatController.js` | Conversations, message history |
| **Contact** | `contactController.js` | Contact form inquiries |
| **Blog** | `blogController.js` | Blog CRUD with markdown |
| **Rewards** | `rewardsController.js` | Points, redemption, RewardPort integration |
| **Notification** | `notificationController.js` | In-app notification feed |
| **Saved Search** | `savedSearchController.js` | Save/manage search filters |
| **Category** | `categoryController.js` | Property categories CRUD |
| **SubCategory** | `subcategoryController.js` | Property sub-categories CRUD |
| **Property Type** | `propertyTypeController.js` | Property types CRUD |

### Database Models (26 schemas)

Key models and their relationships:

| Model | Key Fields | Relations |
|---|---|---|
| `User` | email, password (bcrypt), role, phone | → Properties, Leads, Agreements |
| `Property` | title, price, location, images[], amenities | → User (owner), Category, Leads |
| `Lead` | propertyId, buyerId, status, message | → Property, User |
| `Agreement` | parties, terms, signatures[], hmacHash | → Property, Users |
| `Conversation` | participants[], isActive | → Users, Messages |
| `Message` | conversationId, sender, content | → Conversation |
| `Notification` | userId, type, message, read | → User |
| `Reward` | userId, points, transactions[] | → User |
| `Blog` | title, content (markdown), slug, author | → Admin |
| `Admin` | email, password, role | → AdminSession |
| `AdminSession` | adminId, token, device fingerprint | → Admin |
| `UserSession` | userId, token, device fingerprint | → User |

### Middleware Stack

| Middleware | File | Purpose |
|---|---|---|
| `authUser.js` | JWT validation for user routes | Extracts user from HttpOnly cookie |
| `authAdmin.js` | JWT validation for admin routes | Admin-specific auth + session checks |
| `csrfProtection.js` | CSRF token management | Set/validate CSRF tokens |
| `upload.js` | Multer + Cloudinary | Image upload with magic byte validation |
| `documentUpload.js` | Document file handling | Agreement/document uploads |
| `errorHandler.js` | Global error boundary | Zero info leakage in production |
| `roleGuard.js` | Role-based access control | Block retired roles, enforce permissions |
| `validators/` | express-validator schemas | Input validation per route |

---

## API Reference

### Authentication (`/api/users`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/register` | No | Register new user (Owner/Buyer) |
| POST | `/login` | No | Login → sets HttpOnly JWT cookie |
| POST | `/logout` | Yes | Clears auth cookie |
| POST | `/forgot-password` | No | Send password reset email |
| POST | `/reset-password/:token` | No | Reset password with token |
| GET | `/profile` | Yes | Get current user profile |
| PUT | `/profile` | Yes | Update profile |

### Properties (`/api/properties`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/list` | No | List all properties (paginated) |
| GET | `/search` | No | Advanced search with filters |
| GET | `/suggestions` | No | Autocomplete suggestions |
| GET | `/:id` | No | Single property details |
| POST | `/add` | Owner | Add new property with images |
| PUT | `/my-properties/:id` | Owner | Update own property |
| DELETE | `/:id` | Owner | Delete own property |

### Leads (`/api/leads`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/` | Buyer | Submit lead inquiry |
| GET | `/` | Owner | Get leads for own properties |
| PUT | `/:id/status` | Owner | Update lead status |
| GET | `/analytics` | Owner | Lead conversion analytics |

### Agreements (`/api/agreements`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/generate` | Yes | AI-generate agreement (Gemini) |
| GET | `/my-agreements` | Yes | List user's agreements |
| POST | `/:id/sign` | Yes | Digitally sign agreement |
| GET | `/:id/verify` | Yes | Verify agreement integrity (HMAC) |

### Chat (`/api/chat`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/conversations` | Yes | Create/get conversation |
| GET | `/conversations` | Yes | List user's conversations |
| GET | `/messages/:conversationId` | Yes | Get message history |
| POST | `/messages` | Yes | Send message (REST fallback) |

### Admin (`/api/admin`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| POST | `/login` | No | Admin login with MFA |
| GET | `/dashboard` | Admin | Dashboard analytics |
| GET | `/users` | Admin | User management |
| GET | `/properties` | Admin | Property management |
| PUT | `/properties/:id/verify` | Admin | Verify/reject property |

### Rewards (`/api/rewards`)

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/balance` | Yes | Get reward points balance |
| GET | `/catalogue` | Yes | Browse RewardPort catalogue |
| POST | `/redeem` | Yes | Redeem points for reward |

---

## Security Architecture

The backend implements **defense-in-depth** security. Key layers:

### Authentication & Authorization
- **JWT tokens** stored in `HttpOnly`, `Secure`, `SameSite` cookies
- **Session versioning** — invalidate all sessions on password change
- **MFA** — TOTP-based 2FA for admin accounts via Speakeasy
- **IDOR protection** — all operations verify ownership from database

### Rate Limiting (Multi-Tier)

| Tier | Limit | Scope |
|---|---|---|
| Global | 500 req / 15 min | All routes |
| Auth | 5 req / 15 min | Login, register, forgot-password |
| Transactional | 20 req / hour | Agreement generation |
| Search | 20 req / min | Property search endpoints |
| Webhook | 30 req / min | Payment webhooks |

### Request Security
- **Helmet** — CSP, HSTS, X-Frame-Options: DENY, X-Content-Type-Options
- **CORS lockdown** — strict domain whitelist, no wildcards
- **HPP protection** — HTTP parameter pollution blocking
- **Payload limits** — 10KB auth, 50KB agreements, 100KB general
- **Request ID tracking** — cryptographic IDs for distributed tracing

### File Upload Security
- **Magic byte validation** — verifies actual file content, not just extension
- **Blocked executables** — `.exe`, `.sh`, `.bat`, etc. rejected
- **Cloudinary upload** — files never stored on application server

### Agreement Integrity
- **HMAC-SHA256 signing** — tamper detection on all agreements
- **Idempotency keys** — prevent duplicate agreement creation

> Full details: [`SECURITY_FIXES_SUMMARY.md`](./SECURITY_FIXES_SUMMARY.md)

---

## Deployment

Production is deployed on **Hostinger** as three separate websites:

| App | Domain | Type |
|---|---|---|
| Backend | `backend.dealdirect.in` | Node.js (Express) |
| Client | `dealdirect.in` | Next.js (SSR) |
| Admin | `admin.dealdirect.in` | Static (Vite build) |

### Production Checklist

- [ ] `NODE_ENV=production` set on backend
- [ ] JWT_SECRET is 64+ characters
- [ ] `CLIENT_URL` and `ADMIN_URL` match deployed domains
- [ ] `COOKIE_DOMAIN` set to `.dealdirect.in`
- [ ] MongoDB Atlas IP whitelist configured
- [ ] Sentry DSN configured for both frontend and backend
- [ ] SSL certificates active (Hostinger provides free SSL)
- [ ] Rate limits tested and appropriate

### Build Commands

```bash
# Backend — no build step, runs directly
cd backend && npm start

# Client-Next — build for production
cd client-next && npm run build && npm start

# Client (legacy) — static build
cd client && npm run build
# Output: client/dist/

# Admin — static build
cd Admin && npm run build
# Output: Admin/dist/
```

> Full deployment guide: [`HOSTINGER_DEPLOYMENT.md`](./HOSTINGER_DEPLOYMENT.md)

---

## Monitoring & Error Tracking

### Sentry Integration

Both frontend (Next.js) and backend (Express) report to **Sentry**:

- **Organization:** `opscores`
- **Frontend Project:** `dealdirect-frontend`
- **Tunnel Route:** `/monitoring` (bypasses ad-blockers)

Config files:
- `client-next/sentry.client.config.js`
- `client-next/sentry.server.config.js`
- `client-next/sentry.edge.config.js`

### Health Endpoints

| Endpoint | Description |
|---|---|
| `GET /ping` | Ultra-lightweight liveness check |
| `GET /health` | Health + DB connection status |
| `GET /api/health` | API-prefixed health check |
| `GET /debug-startup` | Env var status (values hidden) + DB state |

---

## Coding Conventions

### General Rules
- **ES Modules** throughout (`import`/`export`, not `require`)
- Backend uses `"type": "module"` in package.json
- Async/await for all asynchronous operations
- All controller functions wrapped in try/catch with error forwarding

### File Naming
- **Backend:** camelCase (`userController.js`, `authUser.js`)
- **Frontend components:** PascalCase (`HomeContent.jsx`, `RewardStorefront.jsx`)
- **Routes/pages (Next.js):** kebab-case directories (`saved-properties/`, `add-property/`)

### Git Workflow
1. Create feature branch from `main`: `git checkout -b feature/your-feature`
2. Make changes with clear, descriptive commits
3. Push and open a Pull Request
4. Get code review before merging

### Environment Variable Rules
- **Backend:** accessed via `process.env.VARIABLE_NAME`
- **Next.js:** must be prefixed with `NEXT_PUBLIC_` for client access
- **Vite apps:** must be prefixed with `VITE_` for client access

---

## Troubleshooting

### Backend won't start
| Symptom | Cause | Fix |
|---|---|---|
| `ENVIRONMENT VALIDATION FAILED` | Missing `JWT_SECRET` or `MONGO_URI` | Check your `backend/.env` file |
| `JWT_SECRET must be at least 32 characters` | Secret too short | Generate: `node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"` |
| `MongooseServerSelectionError` | MongoDB not reachable | Check Atlas whitelist, connection string |

### Frontend issues
| Symptom | Cause | Fix |
|---|---|---|
| CORS errors in browser | Backend `CLIENT_URL` mismatch | Ensure URL matches exactly (no trailing slash) |
| API calls returning 401 | Cookie not sent | Check `credentials: 'include'` on fetch/axios |
| Images not loading | Cloudinary not configured | Verify `CLOUDINARY_URL` in backend `.env` |
| 404 on page refresh (Vite) | SPA routing | Ensure `_redirects` file exists in `public/` |

### Socket.IO / Chat issues
| Symptom | Cause | Fix |
|---|---|---|
| Chat not connecting | Socket URL wrong | Check `NEXT_PUBLIC_API_BASE` / `VITE_API_BASE` |
| Messages not sending | Not authenticated | Client must emit `authenticate` with JWT first |

---

## Key Documentation

| Document | Description |
|---|---|
| [`DealDirect_SOA_Report.md`](./DealDirect_SOA_Report.md) | Full SOA architecture analysis |
| [`HOSTINGER_DEPLOYMENT.md`](./HOSTINGER_DEPLOYMENT.md) | Step-by-step production deployment |
| [`SECURITY_FIXES_SUMMARY.md`](./SECURITY_FIXES_SUMMARY.md) | Security audit results and fixes |
| [`TECHNICAL_REVIEW_FIXES.md`](./TECHNICAL_REVIEW_FIXES.md) | Technical review remediation log |
| [`CLIENT_APP_IMPLEMENTATION_GUIDE.md`](./CLIENT_APP_IMPLEMENTATION_GUIDE.md) | Next.js migration guide |
| [`BLOG_IMPLEMENTATION_PLAN.md`](./BLOG_IMPLEMENTATION_PLAN.md) | Blog feature specification |
| [`MIGRATION_EXECUTION_PLAN.md`](./MIGRATION_EXECUTION_PLAN.md) | Database migration plan |
| [`backend/.env.example`](./backend/.env.example) | Backend env variable template |
| [`client/.env.example`](./client/.env.example) | Client env variable template |
| [`Admin/.env.example`](./Admin/.env.example) | Admin env variable template |

---

## Team Contacts

| Role | Contact |
|---|---|
| Project Lead / Full-Stack | Chirag |
| Support Email | support@dealdirect.in |
| Issue Tracker | GitHub Issues |

---

<p align="center"><sub>Built and maintained by <strong>Team DealDirect</strong> · Last updated May 2026</sub></p>
