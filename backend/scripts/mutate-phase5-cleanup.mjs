/**
 * Mutation harness for the Phase 5 batch-1 cleanup.
 *
 *   node scripts/mutate-phase5-cleanup.mjs
 *
 * Each mutation reintroduces one of the five defects — or, for 5.4, breaks the
 * thing the fix was most likely to break by accident. A mutation that survives
 * means the test asserted the fix's shape rather than its effect.
 *
 * The 5.4 mutations matter most. Deleting a duplicate index DECLARATION is
 * invisible at runtime unless you delete the wrong half: the two session models
 * declare `expiresAt` twice, and in each one a different half carries the TTL.
 * Get it backwards and sessions stop expiring — silently, forever.
 *
 * Files are restored from an in-memory copy in a finally block.
 */

import { readFileSync, writeFileSync, unlinkSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(backend);
const p = (rel) => join(repo, rel);

const MUTATIONS = [
  {
    id: '5.10-a',
    label: 'search $or queries address.locality again',
    file: 'backend/controllers/propertyController.js',
    from: '{ locality: regex },',
    to: '{ "address.locality": regex },',
  },
  {
    id: '5.10-b',
    label: 'the locality facet groups by address.locality again',
    file: 'backend/controllers/propertyController.js',
    from: '$group: { _id: "$locality", city: { $first: "$address.city" } }',
    to: '$group: { _id: "$address.locality", city: { $first: "$address.city" } }',
  },
  {
    id: '5.9',
    label: 'the properties page stops handling the bare array',
    file: 'client-next/src/app/properties/page.js',
    from: 'const properties = Array.isArray(propsData)',
    to: 'const properties = (false && propsData)',
  },
  {
    id: '5.11',
    label: 'the fabricated subscription message comes back',
    file: 'client-next/src/components/Footer/Footer.jsx',
    from: '<footer',
    to: '<footer data-x="Subscribed successfully"',
  },
  {
    id: '5.4-a',
    label: 'Admin re-declares its email index',
    file: 'backend/models/Admin.js',
    from: 'export default mongoose.model',
    to: 'adminSchema.index({ email: 1 });\nexport default mongoose.model',
  },
  {
    id: '5.4-TRAP-user',
    label: 'UserSession loses its TTL (the wrong half deleted)',
    file: 'backend/models/UserSession.js',
    // UserSession's TTL is the INLINE one — the opposite of AdminSession.
    from: 'index: { expireAfterSeconds: 0 }',
    to: 'index: true',
  },
  {
    id: '5.4-TRAP-admin',
    label: 'AdminSession loses its TTL (the wrong half deleted)',
    file: 'backend/models/AdminSession.js',
    from: 'expireAfterSeconds: 0',
    to: 'expireAfterSeconds_x: 0',
  },
  {
    id: '5.2',
    label: 'an orphaned component is restored',
    create: 'client-next/src/components/MiddelComp.jsx',
    content: 'export default function MiddelComp() { return null; }\n',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test', 'tests/integration/phase5-cleanup.test.js'],
      { cwd: backend, stdio: 'pipe', timeout: 400000 });
    return { failed: 0 };
  } catch (e) {
    const out = String(e.stdout || '') + String(e.stderr || '');
    const m = out.match(/^# fail (\d+)$/m) || out.match(/fail (\d+)/);
    return { failed: m ? Number(m[1]) : -1 };
  }
};

let killed = 0, survived = 0;

for (const m of MUTATIONS) {
  const target = p(m.file || m.create);
  const original = m.create ? null : readFileSync(target, 'utf8');

  try {
    if (m.create) {
      writeFileSync(target, m.content);
    } else {
      if (!original.includes(m.from)) {
        console.log(`  ERROR  ${m.id.padEnd(16)} anchor not found: ${m.from.slice(0, 50)}`);
        survived += 1;
        continue;
      }
      writeFileSync(target, original.replace(m.from, m.to));
    }

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(16)} ${m.label}  (${failed} failing)`);
  } finally {
    if (m.create) { if (existsSync(target)) unlinkSync(target); }
    else writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
