# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## ⚠️ READ THIS FIRST: `AI/MASTER_MEMORY.md`

A complete AI knowledge base lives in **[`AI/`](AI/MASTER_MEMORY.md)** — 16 documents produced by a full-repository audit covering architecture, all 32 database models, both auth systems, every API endpoint, business logic, security, performance, and 20 verified bugs.

**Start every session by reading [`AI/MASTER_MEMORY.md`](AI/MASTER_MEMORY.md)**, then the specific document for your area before changing code. After any architectural change, append an entry to [`AI/CHANGELOG_AI.md`](AI/CHANGELOG_AI.md).

The rest of this file is a quick command reference. Where it disagrees with `AI/`, **`AI/` is more current** — it was written by reading the source.

## Project Overview

DealDirect is a real estate marketplace platform connecting property owners directly with buyers. It features:
- AI-powered agreement generation using Google Gemini
- Real-time chat via Socket.IO
- Rewards system integration with RewardPort
- Enterprise-grade security (JWT, MFA, rate limiting)
- Next.js frontend with SSR/SEO

## Repository Structure

Four independent applications. No monorepo tooling, no shared package — each has its own `package.json` and `node_modules`, and types/enums/validation are duplicated by hand across all four.

- `backend/` - Express 5 API server (port 9000)
- `client-next/` - Next.js 16 primary frontend (port 3000)
- `Admin/` - Vite admin dashboard (port 5174)
- `dealdirect-mobile/` - Expo/React Native app — **scaffolding only** (milestones M1–M2 of 14; all feature screens are placeholder stubs)

A legacy `client/` directory is referenced in older docs but no longer exists.

## Common Commands

### Backend Development
```bash
cd backend
npm run dev         # Start with nodemon (hot reload)
npm start           # Start production server
npm run normalize-categories  # Normalize category names in DB
```

### Frontend Development
```bash
# Primary Client (Next.js)
cd client-next
npm run dev         # Starts at http://localhost:3000
npm run build       # Build for production
npm run start       # Start production server

# Admin Dashboard
cd Admin
npm run dev         # Starts at http://localhost:5174
npm run build       # Build for production
```

### Testing Backend
```bash
# Health check
curl http://localhost:9000/health

# Debug startup status (env vars are hidden)
curl http://localhost:9000/debug-startup
```

## Key Architecture Notes

### Authentication
- JWT tokens stored in HttpOnly, Secure, SameSite cookies
- Session versioning - all sessions invalidated on password change
- Admin accounts use TOTP-based 2FA via Speakeasy
- All operations verify ownership from database (IDOR protection)

### Middleware Stack
1. `authUser.js` - JWT validation for user routes
2. `authAdmin.js` - JWT validation for admin routes + session checks
3. `csrfProtection.js` - CSRF token management
4. `upload.js` - Multer + Cloudinary for image uploads
5. `documentUpload.js` - Agreement/document uploads
6. `errorHandler.js` - Global error boundary with no info leakage

### Controllers (19 modules)
Controllers hold **all** business logic — routes only compose middleware, and there is no service layer for domain logic. The largest:
- `propertyController.js` (2396 L) - CRUD, search, interest, close-deal, claim-reward
- `adminController.js` (1665 L) - Admin auth, MFA, dashboard, verifications, audit logs
- `userController.js` (1447 L) - Registration, OTP, login, reset, profile, exports
- `agreementController.js` (1365 L) - Gemini generation, signing, payment webhook
- `leadController.js` (741 L) - Lead lifecycle, analytics, XLSX export

Full list in [`AI/FILE_MAP.md`](AI/FILE_MAP.md); every endpoint in [`AI/API_REFERENCE.md`](AI/API_REFERENCE.md).

### Database Models (32 schema files)
Key relationships:
- User → Properties, Leads, Agreements, Reward wallet (1:1)
- Property → Category, **Owner *or* Builder** (mutually exclusive — drives two separate feeds), Leads
- Lead → Property, Buyer, Status (unique per user+property)
- Agreement → Property, Signatures, HMAC signature + content hash
- Builder → Project → UnitType → GroupBuyCampaign → CampaignMember

Full schema reference, indexes, and integrity warnings in [`AI/DATABASE.md`](AI/DATABASE.md).

### Security Features
- Multi-tier rate limiting (global: 500/15min, auth: 5/15min, search: 20/min)
- Helmet CSP, strict CORS, HPP protection
- Magic byte validation for uploads
- HMAC-SHA256 signing for agreements

### Frontend Architecture
- Next.js App Router with 19 route directories
- TailwindCSS 4 for styling
- Recharts/Chart.js for dashboards
- React-Leaflet for property maps
- Sentry integration for error tracking

### External Services
- MongoDB Atlas for database
- Cloudinary for image storage
- Gemini AI for agreement generation
- Equence SMS for notifications
- RewardPort for rewards catalog
- WAHA for WhatsApp API

## Environment Variables

### Backend (.env)
Required: PORT, NODE_ENV, MONGO_URI, JWT_SECRET, CLOUDINARY_URL, SMTP_USER/PASS, GEMINI_API_KEY

### Client-Next (.env.local)
Required: NEXT_PUBLIC_API_BASE, NEXT_PUBLIC_API_URL

### Admin (.env)
Required: VITE_API_BASE_URL

## Development Workflow

1. **Start Backend**: `cd backend && npm run dev`
2. **Verify**: Check `http://localhost:9000/health` returns healthy status
3. **Start Frontends**: Four terminals needed for full development
4. **Authentication**: All API routes require JWT cookies with `credentials: 'include'`

## Key Files to Understand

- `backend/server.js` - Main entry point (820 lines, heavily documented)
- `backend/config/db.js` - MongoDB connection
- `backend/middleware/errorHandler.js` - Global error handling
- `client-next/src/app/layout.js` - Root layout component
- `Admin/src/pages/Dashboard.jsx` - Admin main dashboard

## Security Constraints

- Never commit `.env` files
- Backend validation uses express-validator schemas in `middleware/validators/`
- All file uploads go through Cloudinary, never stored locally
- Agreement documents are signed with HMAC-SHA256
- Rate limits are enforced per IP, not per user