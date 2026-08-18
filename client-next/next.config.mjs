import { withSentryConfig } from "@sentry/nextjs";

const isProduction = process.env.NODE_ENV === 'production';

/**
 * Content Security Policy — REPORT ONLY.
 *
 * The backend sets a strict CSP through helmet, and it protects the wrong
 * origin: it lands on JSON API responses, where a CSP governs nothing. The
 * policy that matters is the one on the HTML document, and this file had no
 * `headers()` at all, so the pages users actually load carried no CSP, no
 * Referrer-Policy, no X-Content-Type-Options and no frame protection.
 *
 * This is deliberately Report-Only, not enforced. Copying the backend's
 * `frame-src 'none'` here would break four live embeds — Google Maps on
 * /contact and on the property detail page, a YouTube player, and the rewards
 * storefront SDK. Report first, read the reports, then enforce.
 *
 * 'unsafe-inline' and 'unsafe-eval' on script-src are present because Next.js
 * injects inline bootstrap scripts and the app has not been audited for nonce
 * adoption. They are the first thing to remove before promoting this to
 * enforcing; the policy is not meaningful protection against XSS until they go.
 */
const CSP_REPORT_ONLY = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com https://sdk.myhubble.money https://sdk.dev.myhubble.money",
  "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com",
  "img-src 'self' data: blob: https://res.cloudinary.com https://*.cloudinary.com https://images.unsplash.com https://plus.unsplash.com https://*.tile.openstreetmap.org https://*.gstatic.com https://raw.githubusercontent.com",
  "font-src 'self' data: https://fonts.gstatic.com https://cdnjs.cloudflare.com",
  "connect-src 'self' https://nominatim.openstreetmap.org https://res.cloudinary.com https://*.sentry.io",
  // The four live embeds. Narrow this list before enforcing, do not widen it.
  "frame-src 'self' https://www.google.com https://www.youtube.com https://youtube.com https://sdk.myhubble.money https://sdk.dev.myhubble.money",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
].join('; ');

/**
 * Headers that are safe to enforce today. None of these can break a page that
 * was already working:
 *
 *   X-Content-Type-Options  stops MIME sniffing; only affects mislabelled files
 *   Referrer-Policy         same value the backend already sends
 *   X-Frame-Options         the site is not embedded anywhere; SAMEORIGIN keeps
 *                           any first-party embed working
 *   Permissions-Policy      denies APIs the app never calls
 *   X-DNS-Prefetch-Control  matches the backend's dnsPrefetchControl
 *
 * HSTS is production-only on purpose. Sent from a local http dev server it
 * pins localhost to https in the browser for its max-age, which is a hard
 * problem to debug and a worse one to undo. `preload` is deliberately absent:
 * it is effectively irreversible and needs a deliberate submission, not a
 * config default.
 */
const SECURITY_HEADERS = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  { key: 'X-Frame-Options', value: 'SAMEORIGIN' },
  { key: 'X-DNS-Prefetch-Control', value: 'off' },
  {
    key: 'Permissions-Policy',
    value: 'camera=(), microphone=(), payment=(), usb=(), magnetometer=(), gyroscope=(), geolocation=(self)',
  },
  { key: 'Content-Security-Policy-Report-Only', value: CSP_REPORT_ONLY },
  ...(isProduction
    ? [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' }]
    : []),
];

/** @type {import('next').NextConfig} */
const nextConfig = {
  // Security: Don't expose Next.js in headers
  poweredByHeader: false,

  async headers() {
    return [{ source: '/:path*', headers: SECURITY_HEADERS }];
  },

  // Fix Turbopack workspace root detection — prevents it from using stray
  // lockfiles (e.g., D:\bun.lock) as the root and failing to find tailwindcss
  turbopack: {
    root: '.',
  },

  // Image optimization
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'res.cloudinary.com',
      },
      {
        protocol: 'https',
        hostname: '*.cloudinary.com',
      },
      {
        protocol: 'https',
        hostname: 'images.unsplash.com',
      },
      {
        protocol: 'https',
        hostname: 'plus.unsplash.com',
      },
      {
        protocol: 'http',
        hostname: 'localhost',
      },
    ],
  },
};

export default withSentryConfig(
  nextConfig,
  {
    // For all available options, see:
    // https://github.com/getsentry/sentry-webpack-plugin#options

    // Suppress source map uploading logs during build
    silent: true,
    org: "opscores", // Sentry Organization Slug
    project: "dealdirect-frontend",
  },

  {
    // For all available options, see:
    // https://docs.sentry.io/platforms/javascript/guides/nextjs/manual-setup/

    // Upload a larger set of source maps for prettier stack traces (increases build time)
    widenClientFileUpload: true,

    // Transpiles SDK to be compatible with IE11 (increases bundle size)
    transpileClientSDK: true,

    // Routes browser requests to Sentry through a Next.js rewrite to circumvent ad-blockers
    tunnelRoute: "/monitoring",

    // Hides source maps from generated client bundles
    hideSourceMaps: true,

    // Automatically tree-shake Sentry logger statements to reduce bundle size
    disableLogger: true,
  }
);
