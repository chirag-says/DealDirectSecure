/**
 * Mutation harness for Phase 5 batch 2.
 *
 *   node scripts/mutate-phase5-batch2.mjs
 *
 * Each mutation reintroduces one defect, or breaks the thing the fix was most
 * likely to break by accident. A survivor means the test asserted the shape of
 * the fix rather than its effect.
 *
 * The 5.7 mutations are the interesting ones. `if (!property) notFound()` is
 * the obvious fix and the wrong one — it answers 404 for every live listing
 * while the backend is unreachable, and search engines drop URLs that 404. So
 * that specific wrong fix is mutated in deliberately, and must be caught.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(backend);
const p = (rel) => join(repo, rel);

const MUTATIONS = [
  // -- 5.3 -----------------------------------------------------------------
  {
    id: '5.3-flag',
    label: 'the dead requiresMfa flag comes back',
    file: 'client-next/src/context/AuthContext.jsx',
    from: '        // Auth status',
    to: '        requiresMfa: false,\n        // Auth status',
  },
  {
    id: '5.3-admin',
    label: 'admin MFA is deleted by mistake (over-deletion)',
    file: 'backend/controllers/adminController.js',
    from: 'requiresMfa: true,',
    to: 'requiresMfa_removed: true,',
  },
  // -- 5.5 -----------------------------------------------------------------
  {
    id: '5.5-dep',
    label: 'morgan is re-declared as a dependency',
    file: 'backend/package.json',
    from: '"mongoose"',
    to: '"morgan": "^1.10.1",\n    "mongoose"',
  },
  {
    id: '5.5-pdfkit',
    label: 'pdfkit is removed too (over-removal)',
    file: 'backend/package.json',
    from: '"pdfkit"',
    to: '"pdfkit_removed"',
  },
  // -- 5.6 -----------------------------------------------------------------
  {
    id: '5.6-field',
    label: 'sessionVersion is re-added to the schema',
    file: 'backend/models/userModel.js',
    from: '    // Referral System — DealDirect Rewards',
    to: '    sessionVersion: { type: Number, default: 0 },\n    // Referral System — DealDirect Rewards',
  },
  {
    id: '5.6-TRAP',
    label: 'session revocation on password change is removed',
    file: 'backend/controllers/userController.js',
    from: 'revokeOtherSessions(',
    to: 'revokeOtherSessions_disabled(',
  },
  // -- 5.7 -----------------------------------------------------------------
  {
    id: '5.7-soft404',
    label: 'the property page goes back to rendering 200 for a missing id',
    file: 'client-next/src/app/properties/[id]/page.js',
    from: '    if (missing) notFound();',
    to: '',
  },
  {
    id: '5.7-TRAP-naive',
    label: 'the NAIVE fix: notFound() on any null, outage included',
    file: 'client-next/src/app/properties/[id]/page.js',
    from: '    if (missing) notFound();',
    to: '    if (!property) notFound();',
  },
  {
    id: '5.7-cast',
    label: 'a malformed id answers 500 again',
    file: 'backend/controllers/propertyController.js',
    from: "    if (err.name === 'CastError') {",
    to: "    if (err.name === 'CastError_disabled') {",
  },
  {
    id: '5.7-sitemap',
    label: 'the projects vertical drops out of the sitemap again',
    file: 'client-next/src/app/sitemap.js',
    from: '            url: `${SITE_URL}/projects`,',
    to: '            url: `${SITE_URL}/projects-removed`,',
  },
  {
    id: '5.7-robots',
    label: 'a private route becomes crawlable again',
    file: 'client-next/src/app/robots.js',
    from: "'/my-bookings',",
    to: '',
  },
  // -- 5.8 -----------------------------------------------------------------
  {
    id: '5.8-header',
    label: 'X-Content-Type-Options is dropped',
    file: 'client-next/next.config.mjs',
    from: "{ key: 'X-Content-Type-Options', value: 'nosniff' },",
    to: '',
  },
  {
    id: '5.8-TRAP-enforce',
    label: 'the CSP is promoted to ENFORCING (would break four live iframes)',
    file: 'client-next/next.config.mjs',
    from: "{ key: 'Content-Security-Policy-Report-Only', value: CSP_REPORT_ONLY },",
    to: "{ key: 'Content-Security-Policy', value: CSP_REPORT_ONLY },",
  },
  {
    id: '5.8-TRAP-hsts',
    label: 'HSTS is sent unconditionally, breaking http://localhost',
    file: 'client-next/next.config.mjs',
    from: '  ...(isProduction\n    ? [{ key: \'Strict-Transport-Security\', value: \'max-age=31536000; includeSubDomains\' }]\n    : []),',
    to: "  { key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains' },",
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test', 'tests/integration/phase5-cleanup-batch2.test.js'],
      { cwd: backend, stdio: 'pipe', timeout: 500000 });
    return { failed: 0 };
  } catch (e) {
    const out = String(e.stdout || '') + String(e.stderr || '');
    const m = out.match(/^# fail (\d+)$/m) || out.match(/fail (\d+)/);
    return { failed: m ? Number(m[1]) : -1 };
  }
};

let killed = 0, survived = 0;

for (const m of MUTATIONS) {
  const target = p(m.file);
  const original = readFileSync(target, 'utf8');

  try {
    // Patterns are written with \n; this repo is CRLF.
    const anchor = original.includes(m.from)
      ? m.from
      : m.from.replace(/\n/g, '\r\n');

    if (!original.includes(anchor)) {
      console.log(`  ERROR    ${m.id.padEnd(18)} anchor not found: ${m.from.slice(0, 45)}`);
      survived += 1;
      continue;
    }
    writeFileSync(target, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(18)} ${m.label}  (${failed} failing)`);
  } finally {
    writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
