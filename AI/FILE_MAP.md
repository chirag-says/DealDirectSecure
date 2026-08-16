# FILE_MAP.md — Repository Map

One line per file, ordered by application. Line counts are approximate and indicate weight, not quality.

Related: [MASTER_MEMORY.md](MASTER_MEMORY.md) · [COMPONENT_INDEX.md](COMPONENT_INDEX.md) · [ARCHITECTURE.md](ARCHITECTURE.md)

---

## Repository Root

| Path | Purpose |
|---|---|
| `CLAUDE.md` | Project instructions for Claude Code. **Partly stale** — says 26 schemas (32 files), 14 controllers (19), and references a `client/` directory that no longer exists |
| `README.md` | Human-facing project readme (27 KB) |
| `AI/` | **This knowledge base** |
| `backend/` | Express API |
| `client-next/` | Next.js public site |
| `Admin/` | Vite admin SPA |
| `dealdirect-mobile/` | Expo app (scaffolding) |
| `Brochure/` | Two builder brochure PDFs + `extract.py` (page→PNG). Sample content, not app code |
| `docs/PROJECT_FIXES_PLAN.md` | Fix plan |
| `HOSTINGER_DEPLOYMENT.md` | Deployment runbook |
| `MOBILE_APP_ARCHITECTURE_PLAN.md` | 65 KB mobile plan — the milestone source (M1–M12) |
| `MIGRATION_EXECUTION_PLAN.md` | Vite→Next.js migration record |
| `CLIENT_APP_IMPLEMENTATION_GUIDE.md` | 49 KB client implementation guide |
| `SECURITY_FIXES_SUMMARY.md`, `TECHNICAL_REVIEW_FIXES.md`, `Technical_Review_Response.md` | Security/review remediation records — the origin of the `H4`/`C2`/`SECURITY FIX:` markers in source |
| `BLOG_IMPLEMENTATION_PLAN.md`, `group_buying_implementation_plan.md`, `implementation_plan.md`, `PLAN.md` | Feature plans |
| `mongodb_vs_postgresql_analysis.md` | DB choice rationale |
| `adminfixes.md` | Admin fix log |
| `DealDirect_SOA_Report.md` + `.png` | Service-oriented architecture report |
| `DealDirect_Project_Completion_Report*.md`, `*.xlsx`, `BRD_*` | Client deliverables |
| `generate_task_sheet.py` | Report generator |
| `head_check.txt`, `page_source_check.txt`, `any.md` | Scratch artifacts — ignore |
| `AMC_Support_Agreement.docx`, `Infrastructure_Exclusions_Addendum.docx` | Contracts |

---

## backend/ — Express API

### Entry & config
| File | ~L | Purpose |
|---|---|---|
| `server.js` | 859 | **Start here.** Env validation, DB connect, 20-step middleware stack, Socket.IO server, route mounting, graceful shutdown |
| `config/db.js` | 22 | Mongoose connect. Does **not** exit on failure in production |
| `config/redis.js` | 196 | `MemoryCache` shim shaped like ioredis. Real client commented out. Exports `cacheOrCompute`, `invalidateCache` |
| `package.json` | 55 | 31 deps, 7 unused. No test runner |
| `.env` / `.env.production` / `.env.example` | | See [ENVIRONMENT.md](ENVIRONMENT.md) §4 for the drift between them |
| `.htaccess`, `.nvmrc` | | Hostinger artifacts |

### middleware/
| File | ~L | Purpose |
|---|---|---|
| `authUser.js` | 549 | `authMiddleware`, `optionalAuth`, `requireRole`, `requireVerified`, `requireOwnership`, cookie helpers, `sanitizeUser` |
| `authAdmin.js` | 616 | `protectAdmin`, `attachAdminIfPresent`, `requirePermission`, `requireRoleLevel`, `requireSuperAdmin`, `createSession`, MFA cookies |
| `upload.js` | 630 | Magic-byte table, `memoryUpload`, `memoryUploadWithDocs`, `validateAndUploadToCloudinary`, `uploadConcurrencyGuard`, Cloudinary config |
| `documentUpload.js` | 173 | PDF+image uploads (`resource_type: raw` for PDFs) for deal-closure proof |
| `errorHandler.js` | 449 | `AppError`, `globalErrorHandler`, `notFoundHandler`, `catchAsync`, log sanitization, process-level handlers |
| `csrfProtection.js` | 229 | Double-submit cookie. `validateCsrfToken` is **not wired in** |
| `roleGuard.js` | 264 | `blockRetiredRoles` (global), `requireUserRole`, `ownerOnlyListingAccess`, a second `requireOwnership` |
| `validators/index.js` | 363 | express-validator schemas + `whitelistFields`. `PROPERTY_CREATE_FIELDS` disagrees with the controller's list |

### models/ (32 files)
| File | ~L | Purpose |
|---|---|---|
| `userModel.js` | 308 | End users. Referral-code pre-save hook, lockout/session helpers |
| `UserSession.js` | 451 | Hashed session tokens, lenient fingerprinting, TTL index |
| `PasswordResetToken.js` | 188 | **Dead** — see [KNOWN_BUGS.md](KNOWN_BUGS.md) B8 |
| `Admin.js` | 354 | MFA, `Mixed` role, `getPermissions()` fail-closed logic, soft delete |
| `AdminSession.js` | 489 | `mfaVerified` gate, three fingerprint validators (one used) |
| `Role.js` / `Permission.js` | 67 / 94 | RBAC. `Permission.resource` is a closed enum missing `verifications` |
| `AuditLog.js` | 272 | Admin trail, `log()`/`logAuth()`/`logAccess()` statics |
| `Property.js` | 208 | The hot collection. Dual ownership, categorized images, 9 indexes |
| `PropertyType.js` / `Category.js` / `SubCategory.js` | 10/16/23 | Taxonomy |
| `Lead.js` | 83 | Snapshots + unique `{user, property}` |
| `Conversation.js` / `Message.js` | 49 / 64 | Chat. `unreadCount` is a Map |
| `Report.js` | 58 | Message + property moderation |
| `Notification.js` | 64 | **Post-save hooks send email** |
| `SavedSearch.js` | 22 | Filters + alert prefs |
| `ContactInquiry.js` | 96 | Support tickets |
| `Agreement.js` | 432 | HMAC signing, idempotency, tamper detection, payment validation |
| `TransactionVerification.js` | 84 | Deal proof + per-party claim flags |
| `Reward.js` | 202 | Wallet, embedded transactions, tiers, optimistic concurrency |
| `Referral.js` | 59 | Two unique indexes |
| `RedemptionRequest.js` | 98 | Plaintext `bankDetails` |
| `LoginTracker.js` | 42 | **Never written** — B12 |
| `Blog.js` | 112 | Slug, readTime hook, text index |
| `Builder.js` | 95 | No login. Unique phone |
| `Project.js` | 258 | Deeply nested; **nothing required by design** |
| `UnitType.js` | 218 | Pricing pre-save, specs tree, inventory |
| `GroupBuyCampaign.js` | 129 | Flat ₹ discount |
| `CampaignMember.js` | 101 | Post-save recount hook |
| `ProjectBooking.js` | 117 | QR/UTR payment lifecycle |

### controllers/ (19 files)
| File | ~L | Purpose |
|---|---|---|
| `propertyController.js` | **2396** | Largest file. CRUD, search/filter/suggestions, interest, close-deal, claim-reward, admin views |
| `adminController.js` | 1665 | Admin auth, MFA, sessions, dashboard, leads, reports, deal verifications, audit logs, `createDefaultRoles` |
| `userController.js` | 1447 | Register (×2), OTP, login, reset, profile, sessions, upgrade, exports, `deleteAccount` |
| `agreementController.js` | 1365 | Gemini generation, prompt-injection defence, local template, sign, payment webhook |
| `leadController.js` | 741 | Owner + admin lead views, analytics, XLSX export |
| `projectController.js` | 503 | Project CRUD, Cloudinary uploads, construction updates |
| `rewardsController.js` | 447 | Wallet, transactions, referrals, redeem, RewardPort proxy, admin ops |
| `bookingController.js` | 460 | Booking lifecycle, atomic inventory, `syncBookingToCampaign` |
| `hubbleController.js` | 392 | SSO + coin APIs |
| `campaignController.js` | 379 | Campaign CRUD, atomic join, payment verify |
| `unitTypeController.js` | 370 | Unit CRUD + parent `priceRange` recalculation |
| `contactController.js` | 321 | Inquiries |
| `chatController.js` | 296 | Conversations, messages, unread |
| `builderController.js` | 296 | Builder CRUD |
| `blogController.js` | 281 | Public + admin blog |
| `savedSearchController.js` | 236 | Saved searches |
| `subcategoryController.js` / `categoryController.js` / `propertyTypeController.js` | 73/57/52 | Taxonomy CRUD |
| `notificationController.js` | 63 | List + mark read |

### routes/ (20 files)
Thin composition layers. Only `chatRoutes.js` (socket-token handler), `projectRoutes.js` (`organizeProjectFiles`, `handleMulterError`), and `blogRoutes.js` (inline upload response) contain inline logic.
`propertyRoutes.js` (163) and `userRoutes.js` (127) are the largest.
**Route ordering matters** — literal paths must precede `/:id`.

### services/ & utils/
| File | ~L | Purpose |
|---|---|---|
| `services/rewardService.js` | 741 | **The one real domain service.** Weighted tiers, `awardPoints`, `redeemPoints`, referrals, store |
| `services/whatsappService.js` | 299 | WAHA. Lead/user/property/inquiry templates |
| `services/smsService.js` | 282 | Equence. DLT template ids, phone normalisation |
| `services/rewardPortService.js` | 161 | Catalogue proxy (HTTP Basic, native fetch) |
| `services/hubbleService.js` | 91 | **In-process** SSO token Map with a sweeper |
| `utils/emailService.js` | 484 | HTML templates + `sendNewLeadNotification`, `sendGeneralNotification`, `sendWelcomeEmail`, `sendBookingAlert` |

### scripts/ (manual, no migration framework)
`seedBlogs.js` (1183) · `migrateLegacyUsers.js` (177) · `sync-bookings-to-campaigns.js` (107) · `normalizeCategoryName.js` (60, wired to `npm run normalize-categories`)

---

## client-next/ — Next.js Public Site

### Infrastructure
| File | ~L | Purpose |
|---|---|---|
| `src/app/layout.js` | 73 | Root layout, Inter font, global metadata, dark-mode anti-flash script, Cloudinary preconnect |
| `src/app/ClientLayout.jsx` | 49 | `AuthProvider` + Navbar + Footer + ToastContainer + ScrollToTop |
| `src/middleware.js` | 81 | Edge auth hint via `session_exists`; guards 6 protected paths |
| `src/utils/api.js` | 758 | **The client API surface.** axios instance + 11 grouped API objects + interceptors |
| `src/utils/ssrFetch.js` | 99 | `ssrFetch`/`ssrFetchAll` — 8 s timeout, returns `null` on failure |
| `src/utils/config.js` | 54 | `getApiBase`, `getApiUrl`, `resolveImageUrl` |
| `src/utils/formatPrice.js` | 76 | Lakh/Crore formatting (+ `formatPriceParts`) |
| `src/context/AuthContext.jsx` | 594 | Auth state, role helpers, `ProtectedRoute`. Contains dead MFA code (B9/B10) |
| `src/context/ChatContext.jsx` | 369 | Socket.IO lifecycle, conversations, presence |
| `next.config.mjs` | 72 | Sentry wrapper, image remote patterns, Turbopack root |
| `sentry.*.config.js`, `instrumentation*.js` | | Sentry wiring |
| `src/app/globals.css` | 56 | Tailwind 4 import, CSS vars, scrollbar + mobile-nav utilities |

### Routes — every one is `page.js` (server) + `*Content.jsx` (client)
| Route | Content file | ~L |
|---|---|---|
| `/` | `HomeContent.jsx` | 614 |
| `/properties` | `PropertyListContent.jsx` | **2536** |
| `/properties/[id]` | `PropertyDetailsContent.jsx` | 1623 |
| `/add-property` | `AddPropertyContent.jsx` (+ Wrapper) | 2040 |
| `/edit-property/[id]` | `EditPropertyContent.jsx` (+ Wrapper) | 1536 |
| `/my-properties` | `MyPropertiesContent.jsx` | 1359 |
| `/agreements` | `AgreementsContent.jsx` | 1284 |
| `/profile` | `ProfileContent.jsx` | 1442 |
| `/login` · `/register` | `LoginContent.jsx` 872 · `RegisterContent.jsx` 886 | |
| `/projects` · `/projects/[id]` · `/projects/[id]/units/[unitTypeId]` | 523 · 354 · 488 (+ `BookingModal.jsx` 234) | |
| `/rewards` · `/rewards/dashboard` · `/rewards/terms` | 505 · 464 (+ `RewardStorefront.jsx` 218) · 127 | |
| `/blog` · `/blog/[slug]` | 171 · 218 | |
| `/saved-properties` · `/notifications` · `/my-bookings` | 398 · 294 · 308 | |
| `/contact` · `/about` · `/faq` · `/why-us` · `/terms` · `/privacy` · `/press-impressions` · `/coming-soon` | 273 · 339 · 291 · 187 · 420 · 227 · 199 · 166 | |
| `/sitemap.xml` · `/robots.txt` | `sitemap.js` 112 · `robots.js` 25 | dynamic |
| 404 / error | `not-found.js` 29 · `global-error.jsx` 40 | |

### Data
`src/data/pressReleases.json` (1069) · `src/data/real-estate-locations.json` (811) · `src/assets/` (~50 city/builder images)

---

## Admin/ — Vite SPA

| File | ~L | Purpose |
|---|---|---|
| `src/main.jsx` | 17 | Sets `axios.defaults.withCredentials`, mounts App + ToastContainer |
| `src/App.jsx` | 409 | Layout shell + ~30 routes, all wrapped in `AdminProtectedRoute` except 4 auth routes |
| `src/api/adminApi.js` | 641 | Entire admin API surface + auth interceptors |
| `src/context/AdminContext.jsx` | 172 | Verifies session via `GET /api/admin/profile` on mount |
| `src/components/AdminProtectedRoute.jsx` | 48 | Route guard |
| `src/components/Sidebar.jsx` / `Header.jsx` | 183 / 141 | Navigation shell |
| `src/components/LocationPicker.jsx` | 540 | Leaflet map picker |
| `src/components/LocationAutocomplete.jsx` | 157 | Location search |
| `src/components/wizard/` | | `Wizard.jsx` 173, `FileDropzone.jsx` 171, `ConfirmModal.jsx` 87, `FormField.jsx` 61, `Stepper.jsx` 54, `useFormDraft.js` 72 — the multi-step project/unit/campaign creation kit |
| `src/components/ChartCard.jsx` / `GrowthChart.jsx` / `FunnelChart.jsx` / `MetricCard.jsx` | | Dashboard widgets |
| `src/schemas/*.js` | | zod schemas: `projectSchema` 111, `unitTypeSchema` 148, `campaignSchema` 97 |

### Pages (~30)
`AdminAddProperty.jsx` **2013** · `CreateUnitType.jsx` 870 · `CreateProject.jsx` 833 · `ContactInquiries.jsx` 686 · `Dashboard.jsx` 631 · `LeadMonitoring.jsx` 610 · `RewardsManagement.jsx` 597 · `BuilderDetail.jsx` 582 · `AdminBlogEditor.jsx` 567 · `BuilderManagement.jsx` 549 · `BuilderVerification.jsx` 541 · `AllClients.jsx` 512 · `DealVerifications.jsx` 429 · `AllProperty.jsx` 361 · `BookingManagement.jsx` 361 · `ProjectDetail.jsx` 355 · `BlogManagement.jsx` 296 · `CreateCampaign.jsx` 264 · `AllCategory.jsx` 246 · `BuilderProjectsList.jsx` 235 · `PropertyReports.jsx` 214 · `SiteVisitManagement.jsx` 213 · `PopularProperties.jsx` 209 · `ReportedMessages.jsx` 201 · `MfaSetup.jsx` 172 · `ChangePassword.jsx` 171 · `AddSubCategory.jsx` 166 · `AdminLogin.jsx` 159 · `AddCategory.jsx` 106 · `MfaVerify.jsx` 97 · `GroupBuyManagement.jsx` 38
Plus `pages/adminProperty/propertyConstants.js` (266) — shared option lists.

---

## dealdirect-mobile/ — Expo (scaffolding)

| Path | ~L | Purpose |
|---|---|---|
| `app.config.js` | 68 | **Bundle ids frozen**: `in.dealdirect.mobile` |
| `app/_layout.tsx` · `app/index.tsx` | 50 · 38 | Root providers · bootstrap gate |
| `app/(auth)/` | | `login` 171, `register` 230, `verify-otp` 159, `forgot-password` 127 — **the only implemented screens** |
| `app/(tabs)/` | | 5 tabs, all 11-line `<Placeholder>` stubs |
| `app/property/`, `app/owner/`, `app/projects/`, `app/chat/`, `app/agreements/`, `app/rewards/`, `app/settings/` | | ~25 stub routes |
| `app/(dev)/gallery.tsx` | 236 | Design-system gallery |
| `src/api/client.ts` | 84 | Two axios instances (30 s / 120 s) |
| `src/api/endpoints/*.ts` | | 11 typed endpoint modules + `_contract.ts` |
| `src/api/errors.ts` | 186 | Error normalisation |
| `src/api/userAgent.ts` | 65 | **Version must never enter the UA** — it would revoke every session |
| `src/auth/AuthProvider.tsx` · `cookies.ts` · `schemas.ts` | 222 · 108 · 78 | Session restore, native cookie-jar bridge |
| `src/types/backend/*.ts` | ~1500 | 13 files — **the only written API contract in the repo** |
| `src/ui/*.tsx` | | 18 primitives: Button, Input, Sheet, RangeSlider, Skeleton, PriceLabel… |
| `src/theme/*.ts` | | colors 154, typography 105, motion 98, layout 92 |
| `docs/API_CONTRACT.md` 400 · `docs/MAP_IMPLEMENTATION.md` 274 | | Design docs |

---

## Reading Order for a New Session

1. `AI/MASTER_MEMORY.md`
2. `backend/server.js` — the whole backend shape
3. `backend/middleware/authUser.js` + `authAdmin.js` — the two auth systems
4. `backend/models/Property.js` + `userModel.js` — the core data
5. `backend/controllers/propertyController.js` — the dominant business logic
6. `client-next/src/utils/api.js` + `context/AuthContext.jsx` — the frontend contract
7. `client-next/src/app/page.js` — the `page.js`/`*Content.jsx` pattern in miniature
