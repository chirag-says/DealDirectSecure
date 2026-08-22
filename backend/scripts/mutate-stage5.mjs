/**
 * Mutation harness for Stage 5 — media lifecycle, flags and cleanups.
 *
 *   node scripts/mutate-stage5.mjs
 *
 * The media mutations are the interesting ones. An asset leak is invisible from
 * inside the application — the document looks right, the page renders, and the
 * only symptom is a Cloudinary bill and an orphaned payment screenshot. Several
 * mutations therefore attack the destroy call rather than the array edit.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(backend);

const ASSETS = join(backend, 'utils/cloudinaryAssets.js');
const PROJ = join(backend, 'controllers/projectController.js');
const PROP = join(backend, 'controllers/propertyController.js');
const CAMP = join(backend, 'controllers/campaignController.js');
const HUB = join(backend, 'controllers/hubbleController.js');
const BOOK = join(backend, 'controllers/bookingController.js');
const SERVER = join(backend, 'server.js');
const VISIT = join(repo, 'client-next/src/components/VisitModal/VisitModal.jsx');

const MUTATIONS = [
  // ── media ────────────────────────────────────────────────────────────────
  {
    id: 'media-no-destroy',
    label: 'removal stops destroying the asset (the leak returns)',
    file: PROJ,
    from: '    const assets = await destroyAssets(',
    to: '    const assets = await Promise.resolve(',
  },
  {
    id: 'media-field-allowlist-gone',
    label: 'any media key can be targeted from the URL',
    file: PROJ,
    from: '    if (!MEDIA_ARRAY_FIELDS.has(field)) {',
    to: '    if (false) {',
  },
  {
    id: 'reorder-not-permutation',
    label: 'reorder becomes an unaudited replace',
    file: PROJ,
    from: '    if (!sameSet) {',
    to: '    if (false) {',
  },
  {
    id: 'reorder-allows-duplicates',
    label: 'reorder accepts the same image twice, dropping another',
    file: PROJ,
    from: '      new Set(urls).size === urls.length &&',
    to: '      true &&',
  },
  {
    id: 'publicid-accepts-foreign-urls',
    label: 'a non-Cloudinary URL is treated as ours to delete',
    file: ASSETS,
    from: 'if (parsed.hostname !== "res.cloudinary.com") return null;',
    to: 'if (!url.includes("res.cloudinary.com")) return null;',
  },
  {
    id: 'publicid-keeps-version',
    label: 'the version segment is left in the public_id',
    file: ASSETS,
    from: '    if (rest[0] && /^v\\d+$/.test(rest[0])) rest = rest.slice(1);',
    to: '',
  },
  {
    id: 'destroy-throws',
    label: 'a failed destroy takes the whole request down',
    file: ASSETS,
    from: '    } catch (err) {\n      console.error(`[cloudinary] destroy failed for ${publicId}: ${err.message}`);\n      result.failed.push(publicId);\n    }',
    to: '    } catch (err) {\n      throw err;\n    }',
  },
  // ── chat flag ────────────────────────────────────────────────────────────
  {
    id: 'chat-mounted-anyway',
    label: 'the chat routes mount regardless of the flag',
    file: SERVER,
    from: 'if (CHAT_ENABLED) app.use("/api/chat", chatRoutes);',
    to: 'app.use("/api/chat", chatRoutes);',
  },
  {
    id: 'chat-on-by-default',
    label: 'chat defaults to on',
    file: SERVER,
    from: "const CHAT_ENABLED = process.env.CHAT_ENABLED === 'true';",
    to: "const CHAT_ENABLED = process.env.CHAT_ENABLED !== 'false';",
  },
  // ── site visits ──────────────────────────────────────────────────────────
  {
    id: 'visit-fake-success-back',
    label: 'the modal fabricates a scheduled visit again',
    file: VISIT,
    from: '        setLoading(false);\n        toast.error("Site visits can only be requested from a property conversation.");',
    to: '        setLoading(false);\n        toast.success("Visit scheduled successfully! Check your email for details.");',
  },
  // ── cleanups ─────────────────────────────────────────────────────────────
  {
    id: 'interest-cap-counts-dead',
    label: 'sold listings consume interest slots again',
    file: PROP,
    from: '      status: { $nin: ["sold", "rented", "inactive"] },\n      isActive: { $ne: false },',
    to: '',
  },
  {
    id: 'inactive-visible-again',
    label: 'a property marked inactive is publicly readable again',
    file: PROP,
    from: "    const HIDDEN_STATUSES = ['pending', 'inactive'];",
    to: "    const HIDDEN_STATUSES = ['pending'];",
  },
  {
    id: 'pending-visible',
    label: 'a pending property becomes publicly readable',
    file: PROP,
    from: "    const HIDDEN_STATUSES = ['pending', 'inactive'];",
    to: "    const HIDDEN_STATUSES = [];",
  },
  {
    id: 'campaign-cancel-unguarded',
    label: 'a campaign with paid members can be cancelled silently',
    file: CAMP,
    from: '        if (paidMembers > 0) {',
    to: '        if (false) {',
  },
  {
    id: 'campaign-guard-blocks-everything',
    label: 'the guard fires on ordinary status changes too',
    file: CAMP,
    from: '      if (TERMINAL.includes(body.status)) {',
    to: '      if (true) {',
  },
  {
    id: 'notes-overwrite-again',
    label: 'admin notes overwrite the previous note',
    file: BOOK,
    from: 'const appendNote = (existing, addition) => {\n  const next = addition?.trim();\n  if (!next) return existing;',
    to: 'const appendNote = (existing, addition) => {\n  const next = addition?.trim();\n  if (!next) return existing;\n  if (true) return next;',
  },
  {
    id: 'project-limit-uncapped',
    label: 'the public project list accepts an unbounded limit',
    file: PROJ,
    from: '    const safeLimit = Math.min(Math.max(parseInt(limit, 10) || 20, 1), 60);',
    to: '    const safeLimit = parseInt(limit, 10) || 20;',
  },
  {
    id: 'hubble-not-timing-safe',
    label: 'the shared secret is compared with !== again',
    file: HUB,
    from: '  return a.length === b.length && crypto.timingSafeEqual(a, b);',
    to: '  return String(provided ?? "") === String(expected ?? "");',
  },
  {
    id: 'hubble-fail-open',
    label: 'an unconfigured secret lets every caller through',
    file: HUB,
    from: '  if (!expectedSecret) {',
    to: '  if (false) {',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test',
       'tests/integration/stage5-cleanups.test.js', 'tests/stage5-units.test.js'],
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
  const original = readFileSync(m.file, 'utf8');
  try {
    const anchor = original.includes(m.from) ? m.from : m.from.replace(/\n/g, '\r\n');
    if (!original.includes(anchor)) {
      console.log(`  ERROR    ${m.id.padEnd(30)} anchor not found`);
      survived += 1;
      continue;
    }
    writeFileSync(m.file, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(30)} ${m.label}  (${failed})`);
  } finally {
    writeFileSync(m.file, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
