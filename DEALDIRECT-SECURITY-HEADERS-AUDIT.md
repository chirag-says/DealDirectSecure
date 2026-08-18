# Security headers — audit and proposal (Phase 5.8)

Report-only first, as instructed. This records what was already configured,
what was missing, what shipped, and what deliberately did not.

---

## The finding in one line

The backend's helmet configuration is thorough and it protects the wrong origin.
It applies to JSON API responses. A Content-Security-Policy on a JSON body
governs nothing — there is no document to constrain. The headers that matter are
the ones on the HTML, and `client-next/next.config.mjs` had no `headers()` at
all.

So every page a user actually loaded was served with no CSP, no HSTS, no
`X-Content-Type-Options`, no `Referrer-Policy`, no `Permissions-Policy` and no
frame protection. The only security-relevant setting on the HTML origin was
`poweredByHeader: false`.

---

## Before

### API origin — `backend/server.js`, helmet (`server.js:285`)

| Header | State |
|---|---|
| Content-Security-Policy | Set, strict. `script-src 'self'`, no unsafe-inline, `frame-src 'none'` |
| Strict-Transport-Security | Set, production-only (`server.js:330`) |
| X-Content-Type-Options | `nosniff` |
| Referrer-Policy | `strict-origin-when-cross-origin` |
| X-Frame-Options | `DENY` (frameguard) |
| Permissions-Policy | **Not set.** `permittedCrossDomainPolicies` is a different header (`X-Permitted-Cross-Domain-Policies`) |
| frame-ancestors | `'none'` |
| Cross-Origin-Resource-Policy | `cross-origin` |

Sound for an API. Two notes: `expectCt` is a deprecated header that modern
browsers ignore, and the CSP here can never do the job people assume it does,
because it is not on the documents.

### HTML origin — `client-next/next.config.mjs`

| Header | State |
|---|---|
| Content-Security-Policy | **Missing** |
| Strict-Transport-Security | **Missing** |
| X-Content-Type-Options | **Missing** |
| Referrer-Policy | **Missing** |
| Permissions-Policy | **Missing** |
| X-Frame-Options / frame-ancestors | **Missing** |
| X-Powered-By | Suppressed (`poweredByHeader: false`) |

### Admin origin — `Admin/`

Vite builds a static bundle; headers come from whatever serves `dist/`. There is
no header configuration in the repository, and adding one would mean picking a
host-specific mechanism. Left alone in this batch, and recorded below.

---

## What shipped

Enforced, because none of these can break a page that already worked:

| Header | Value | Why it is safe |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | Only affects mislabelled responses |
| `Referrer-Policy` | `strict-origin-when-cross-origin` | The value the backend already sends, and the browser default |
| `X-Frame-Options` | `SAMEORIGIN` | The site is not embedded anywhere; first-party embedding still works |
| `X-DNS-Prefetch-Control` | `off` | Matches the backend |
| `Permissions-Policy` | camera, microphone, payment, usb, magnetometer, gyroscope denied; `geolocation=(self)` | Denies APIs the app never calls. Geolocation is kept for the property map |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | **Production only** |

Report-only, because enforcing it today would break the site:

| Header | Value |
|---|---|
| `Content-Security-Policy-Report-Only` | See `next.config.mjs` |

Verified at runtime against a production build on port 3101: all seven headers
present on `/`.

---

## Why the CSP is not enforced

The site embeds four real iframes:

```
app/contact/ContactContent.jsx                    Google Maps
app/properties/[id]/PropertyDetailsContent.jsx    Google Maps, YouTube
app/rewards/dashboard/RewardStorefront.jsx        rewards SDK
```

Copying the backend's `frame-src 'none'` onto the HTML origin would blank all
four. A test asserts the count is still exactly 4, so if the embeds ever go, the
policy gets tightened rather than left permissive forever.

Two more reasons it is not ready to enforce:

1. **`'unsafe-inline'` and `'unsafe-eval'` are in `script-src`.** Next.js injects
   inline bootstrap scripts and the app has not been audited for nonces. Until
   these two go, the policy is not meaningful XSS protection — it is a
   compatibility exercise. This is the first thing to fix before promoting it.
2. **The origin list is derived from source, not from observed traffic.** It was
   built by scanning for `https://` literals in `client-next/src`. Report-only
   mode is how that list gets corrected against reality.

### Promoting it later

1. Add a `report-uri` / `report-to` endpoint and collect for a full traffic cycle
   including a rewards redemption and a property detail view with the map open.
2. Remove origins that never appear. Add any that do.
3. Replace `'unsafe-inline'` on `script-src` with a nonce; keep it on
   `style-src` unless every inline style is removed.
4. Only then rename the header to `Content-Security-Policy`. A test currently
   fails if that rename happens prematurely.

## Why HSTS is production-only, and without `preload`

Sent from a local http dev server, HSTS pins `localhost` to https in the browser
for the whole `max-age` — painful to diagnose, worse to undo, and it affects
every other project on localhost. `preload` is absent deliberately: it is
effectively irreversible and requires a considered submission to the browser
preload list, not a config default someone copied.

---

## Not done, and why

| Item | Reason |
|---|---|
| Enforcing the CSP | Would break four live iframes. Report first |
| Removing `'unsafe-inline'` / `'unsafe-eval'` | Needs a nonce strategy across the app; a project, not a cleanup |
| A CSP report collection endpoint | Needs a decision on where reports go (Sentry can take them) |
| Headers on the Admin origin | Static Vite bundle; the mechanism is host-specific and the host is not configured in this repo |
| Removing the backend's `expectCt` | Deprecated and ignored, but harmless, and it is outside 5.8's scope |
| Retiring the backend CSP | It costs nothing and would be needed if the API ever served HTML |

---

## Verification

```
tests                     61 pass, 0 fail  (suite 25)
mutation harness          14 killed, 0 survived
runtime header check      7/7 present on a production build
client-next build         succeeds
Admin build               succeeds
production writes         = 0
```

Two mutations specifically guard this item: promoting the CSP to enforcing, and
making HSTS unconditional. Both are killed.
