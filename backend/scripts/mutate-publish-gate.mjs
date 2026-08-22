/**
 * Mutation harness for Stage 3 — the project publish gate.
 *
 *   node scripts/mutate-publish-gate.mjs
 *
 * The gate's failure modes are asymmetric and both are silent:
 *   - too loose → half-typed projects go public again (the original defect)
 *   - too tight → every live project 404s on deploy (the migration trap)
 * Mutations cover both directions, not just "does the rule fire".
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const GUARD = 'utils/projectPublishGuard.js';
const MODEL = 'models/Project.js';
const CTRL = 'controllers/projectController.js';
const ROUTES = 'routes/projectRoutes.js';

const MUTATIONS = [
  // ── the lifecycle itself ─────────────────────────────────────────────────
  {
    id: 'default-published',
    label: 'projects go back to being public on create',
    file: MODEL,
    from: 'enum: ["draft", "published"],\n        default: "draft",',
    to: 'enum: ["draft", "published"],\n        default: "published",',
  },
  {
    id: 'draft-publicly-readable',
    label: 'a draft becomes publicly readable again',
    file: CTRL,
    from: 'if (!isAdmin && !isPubliclyVisible(project)) {',
    to: 'if (!isAdmin && false) {',
  },
  {
    id: 'draft-listed',
    label: 'drafts appear in the public list',
    file: CTRL,
    from: 'Object.assign(filter, publicProjectFilter());\n    }',
    to: '// filter removed\n    }',
  },
  // ── the migration trap ───────────────────────────────────────────────────
  {
    id: 'MIGRATION-strict-read',
    label: 'legacy projects (no publication field) vanish from the site',
    file: GUARD,
    from: '  if (project.publication?.status) return project.publication.status === "published";\n  return project.isActive !== false;',
    to: '  return project.publication?.status === "published";',
  },
  {
    id: 'MIGRATION-strict-filter',
    label: 'the list query drops every pre-existing project',
    file: GUARD,
    from: '      { "publication.status": { $exists: false }, isActive: { $ne: false } },',
    to: '      { "publication.status": { $exists: false }, isActive: false, _nope: true },',
  },
  // ── BLOCK rules ──────────────────────────────────────────────────────────
  {
    id: 'block-name-gone',
    label: 'a nameless project can be published',
    file: GUARD,
    from: '(p) => Boolean(p.basics?.name?.trim())),',
    to: '(p) => true),',
  },
  {
    id: 'block-city-gone',
    label: 'a project with no city can be published',
    file: GUARD,
    from: '(p) => Boolean(p.location?.city?.trim())),',
    to: '(p) => true),',
  },
  {
    id: 'block-image-gone',
    label: 'an imageless listing card can be published',
    file: GUARD,
    from: '(p) => anyImage(p)),',
    to: '(p) => true),',
  },
  {
    id: 'block-builder-gone',
    label: 'a deactivated builder\'s project can be published',
    file: GUARD,
    from: '(p, { builder }) => Boolean(builder) && builder.isActive !== false),',
    to: '(p, { builder }) => true),',
  },
  {
    id: 'block-sellable-gone',
    label: 'a project with nothing buyable can be published',
    file: GUARD,
    from: '      unitTypes.some((ut) => isUnitTypePublishable(ut, { category: p.basics?.subType || p.basics?.category }).ok)',
    to: '      true',
  },
  // ── unit-type rules ──────────────────────────────────────────────────────
  {
    id: 'unit-zero-token',
    label: 'a unit type with no booking amount counts as sellable',
    file: GUARD,
    from: '  if (!(unitType.paymentTerms?.bookingAmount > 0)) {',
    to: '  if (false) {',
  },
  {
    id: 'unit-carpet-gone',
    label: 'carpet area stops blocking (the ratified RERA rule)',
    file: GUARD,
    from: "  } else if (!(unitType.area?.carpetSqft > 0)) {",
    to: '  } else if (false) {',
  },
  {
    id: 'unit-carpet-demanded-of-plots',
    label: 'a plotted development is asked for a carpet area it cannot have',
    file: GUARD,
    from: 'const PLOT_CATEGORIES = ["Plotted Development"];',
    to: 'const PLOT_CATEGORIES = [];',
  },
  {
    id: 'unit-soldout-rejected',
    label: 'a sold-out configuration is treated as unpublishable',
    file: GUARD,
    from: '  if (unitType.inventory?.availableUnits == null) {',
    to: '  if (!(unitType.inventory?.availableUnits > 0)) {',
  },
  {
    id: 'unit-unset-inventory-ok',
    label: 'a unit type that never declared inventory counts as sellable',
    file: GUARD,
    from: '  if (unitType.inventory?.availableUnits == null) {',
    to: '  if (false) {',
  },
  {
    id: 'unit-basePrice-gone',
    label: 'a priceless unit type counts as sellable',
    file: GUARD,
    from: '  if (!(unitType.pricing?.basePrice > 0)) reasons.push("needs a base price");',
    to: '  if (false) reasons.push("needs a base price");',
  },
  // ── WARN must stay non-blocking ──────────────────────────────────────────
  {
    id: 'RERA-became-blocker',
    label: 'RERA is promoted to a blocker (contradicts the ratified decision)',
    file: GUARD,
    from: 'rule("rera", "warn",',
    to: 'rule("rera", "block",',
  },
  {
    id: 'brochure-became-blocker',
    label: 'the brochure becomes a blocker — no live project could publish',
    file: GUARD,
    from: 'rule("brochure", "warn",',
    to: 'rule("brochure", "block",',
  },
  // ── the endpoint ─────────────────────────────────────────────────────────
  {
    id: 'publish-ignores-gate',
    label: 'the publish endpoint stops consulting the checklist',
    file: CTRL,
    from: 'if (!readiness.canPublish) {',
    to: 'if (false) {',
  },
  {
    id: 'publish-no-blockers-in-body',
    label: 'the refusal stops telling the admin what is missing',
    file: CTRL,
    from: '        blockers: readiness.blockers,\n        warnings: readiness.warnings,',
    to: '        warnings: readiness.warnings,',
  },
  {
    id: 'unpublish-route-gone',
    label: 'a published project can no longer be taken down',
    file: ROUTES,
    from: 'router.post("/:id/unpublish", protectAdmin, unpublishProject);',
    to: '',
  },
  {
    id: 'unpublish-nukes-bookings',
    label: 'unpublishing also cancels the bookings taken against the project',
    file: CTRL,
    from: '      { $set: { "publication.status": "draft", isActive: false } }\n    );',
    to: '      { $set: { "publication.status": "draft", isActive: false } }\n    );\n    await (await import("../models/ProjectBooking.js")).default.updateMany({ project: project._id }, { $set: { status: "cancelled" } });',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test',
       'tests/integration/project-publish-gate.test.js'],
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
  const target = join(backend, m.file);
  const original = readFileSync(target, 'utf8');

  try {
    const anchor = original.includes(m.from) ? m.from : m.from.replace(/\n/g, '\r\n');
    if (!original.includes(anchor)) {
      console.log(`  ERROR    ${m.id.padEnd(30)} anchor not found`);
      survived += 1;
      continue;
    }
    writeFileSync(target, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(30)} ${m.label}  (${failed})`);
  } finally {
    writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
