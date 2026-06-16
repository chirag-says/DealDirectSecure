# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DealDirect is a real estate marketplace platform connecting property owners directly with buyers. It features:
- AI-powered agreement generation using Google Gemini
- Real-time chat via Socket.IO
- Rewards system integration with RewardPort
- Enterprise-grade security (JWT, MFA, rate limiting)
- Next.js frontend with SSR/SEO

## Repository Structure

This is a monorepo with four independent applications:

- `backend/` - Express.js API server (port 9000)
- `client-next/` - Next.js 16 primary frontend (port 3000)
- `Admin/` - Vite admin dashboard (port 5174)
- `client/` - Legacy Vite client (no longer exists)

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

### Controllers (14 modules)
Each controller handles specific business logic:
- `userController.js` - Registration, login, profile management
- `propertyController.js` - CRUD, search, image uploads
- `leadController.js` - Lead lifecycle and analytics
- `agreementController.js` - AI generation, signatures, PDF export
- `chatController.js` - Real-time conversations

### Database Models (26 schemas)
Key relationships:
- User → Properties, Leads, Agreements
- Property → Category, Owner, Leads
- Lead → Property, Buyer, Status
- Agreement → Property, Signatures, HMAC hash

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