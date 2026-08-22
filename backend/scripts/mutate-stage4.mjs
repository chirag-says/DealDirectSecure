/**
 * Mutation harness for Stage 4 — funnel and inventory.
 *
 *   node scripts/mutate-stage4.mjs
 *
 * The inventory mutations matter most. The invariant's failure mode is silent
 * drift: counters that no longer describe reality, discovered weeks later when
 * a booking cannot be confirmed. Several mutations break only the COUNTERPART
 * of a delta, which is the half a naive test never looks at.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const INV = 'utils/inventoryInvariant.js';
const BOOK = 'controllers/bookingController.js';
const UT = 'controllers/unitTypeController.js';
const PROJ = 'controllers/projectController.js';
const PROP = 'controllers/propertyController.js';
const BROUTES = 'routes/bookingRoutes.js';

const MUTATIONS = [
  // ── enquiry ──────────────────────────────────────────────────────────────
  {
    id: 'enquiry-not-distinguished',
    label: 'enquiries and bookings become indistinguishable',
    file: BOOK,
    from: 'source: isEnquiry ? "enquiry" : "booking",',
    to: 'source: "booking",',
  },
  {
    id: 'enquiry-gated-on-price',
    label: 'an enquiry is refused when no booking amount is set',
    file: BOOK,
    from: 'if (!isEnquiry && !(tokenAmount > 0)) {',
    to: 'if (!(tokenAmount > 0)) {',
  },
  {
    id: 'booking-token-guard-lost',
    label: 'the enquiry exemption leaks into real bookings',
    file: BOOK,
    from: 'if (!isEnquiry && !(tokenAmount > 0)) {',
    to: 'if (false) {',
  },
  {
    id: 'enquiry-ignores-inventory',
    label: 'enquiries are accepted on sold-out units',
    file: BOOK,
    from: 'if (!(unitType.inventory?.availableUnits >= 1)) {',
    to: 'if (isEnquiry ? false : !(unitType.inventory?.availableUnits >= 1)) {',
  },
  {
    id: 'source-filter-gone',
    label: 'the admin queue cannot separate enquiries from bookings',
    file: BOOK,
    from: 'if (source) filter.source = source;',
    to: '',
  },
  // ── pipeline ─────────────────────────────────────────────────────────────
  {
    id: 'contact-overwrites',
    label: 'contact history overwrites instead of appending',
    file: BOOK,
    from: '    booking.contactHistory.push({\n      action, note: note.trim(), by: req.admin._id, at: new Date(),\n    });',
    to: '    booking.contactHistory = [{ action, note: note.trim(), by: req.admin._id, at: new Date() }];',
  },
  {
    id: 'contact-no-author',
    label: 'a contact record no longer says who made it',
    file: BOOK,
    from: 'action, note: note.trim(), by: req.admin._id, at: new Date(),',
    to: 'action, note: note.trim(), at: new Date(),',
  },
  {
    id: 'contact-note-optional',
    label: 'an empty contact record can be filed',
    file: BOOK,
    from: '    if (!note?.trim()) {',
    to: '    if (false) {',
  },
  {
    id: 'assign-unvalidated',
    label: 'a booking can be assigned to an admin that does not exist',
    file: BOOK,
    from: '      const exists = await mongoose.model("Admin").exists({ _id: adminId });',
    to: '      const exists = true;',
  },
  {
    id: 'contact-route-public',
    label: 'the pipeline endpoints lose their admin guard',
    file: BROUTES,
    from: 'router.post("/:id/contact", protectAdmin, addBookingContact);',
    to: 'router.post("/:id/contact", addBookingContact);',
  },
  // ── inventory invariant ──────────────────────────────────────────────────
  {
    id: 'INV-no-counterpart-blocked',
    label: 'blocking a unit stops taking it out of available',
    file: INV,
    from: '    next.availableUnits = n(next.availableUnits) - delta;',
    to: '    next.availableUnits = n(next.availableUnits);',
  },
  {
    id: 'INV-counterpart-wrong-sign',
    label: 'blocking a unit ADDS to available',
    file: INV,
    from: '    next.availableUnits = n(next.availableUnits) - delta;',
    to: '    next.availableUnits = n(next.availableUnits) + delta;',
  },
  {
    id: 'INV-stock-no-counterpart',
    label: 'new stock arrives but is never sellable',
    file: INV,
    from: '    next.availableUnits = n(next.availableUnits) + delta;\n  } else if (field === "availableUnits") {',
    to: '    next.availableUnits = n(next.availableUnits);\n  } else if (field === "availableUnits") {',
  },
  {
    id: 'INV-sum-check-gone',
    label: 'the books no longer have to add up',
    file: INV,
    from: '    if (sum !== total) {',
    to: '    if (false) {',
  },
  {
    id: 'INV-negative-allowed',
    label: 'counters can be driven negative',
    file: INV,
    from: '    if (next[key] != null && next[key] < 0) {',
    to: '    if (false) {',
  },
  {
    id: 'INV-counterpart-negative-allowed',
    label: 'only the named field is checked, not what it moved',
    file: INV,
    from: '  for (const key of ADJUSTABLE_FIELDS) {',
    to: '  for (const key of [field]) {',
  },
  {
    id: 'INV-tower-overallocation',
    label: 'towers can be allocated more units than exist',
    file: INV,
    from: '    if (total != null && allocated > total) {',
    to: '    if (false) {',
  },
  {
    id: 'INV-duplicate-towers',
    label: 'the same tower can be listed twice',
    file: INV,
    from: '    if (new Set(names).size !== names.length) {',
    to: '    if (false) {',
  },
  {
    id: 'INV-zero-delta-ok',
    label: 'a no-op adjustment is accepted',
    file: INV,
    from: '  if (!Number.isFinite(delta) || delta === 0) {',
    to: '  if (!Number.isFinite(delta)) {',
  },
  {
    id: 'INV-unset-adjustable',
    label: 'an unconfigured unit type can be adjusted into existence',
    file: INV,
    from: '  if (next.totalUnits == null && next.availableUnits == null) {',
    to: '  if (false) {',
  },
  // ── the adjust endpoint ──────────────────────────────────────────────────
  {
    id: 'adjust-no-reason',
    label: 'an unexplained inventory correction is accepted',
    file: UT,
    from: '    if (!reason?.trim()) {',
    to: '    if (false) {',
  },
  {
    id: 'adjust-not-audited',
    label: 'inventory corrections stop being audited',
    file: UT,
    from: '    await AuditLog.log({\n      admin: req.admin._id,\n      category: "booking_management",\n      action: "unit_inventory_adjusted",',
    to: '    await Promise.resolve({\n      admin: req.admin._id,\n      category: "booking_management",\n      action: "unit_inventory_adjusted",',
  },
  {
    id: 'wholesale-overwrite-back',
    label: 'the update form can overwrite inventory wholesale again',
    file: UT,
    from: 'const directFields = ["config", "area", "furnishing", "parking", "specifications", "floorPlans", "pricing", "highlights"];',
    to: 'const directFields = ["config", "area", "furnishing", "parking", "specifications", "floorPlans", "pricing", "inventory", "highlights"];',
  },
  // ── legacy stratum ───────────────────────────────────────────────────────
  {
    id: 'legacy-void-back',
    label: 'interest on a builder-feed listing silently vanishes again',
    file: PROP,
    from: '    if (property.builder && !property.owner) {',
    to: '    if (false) {',
  },
  {
    id: 'legacy-catches-owner-props',
    label: 'the guard swallows ordinary owner properties too',
    file: PROP,
    from: '    if (property.builder && !property.owner) {',
    to: '    if (true) {',
  },
  // ── views ────────────────────────────────────────────────────────────────
  {
    id: 'views-not-counted',
    label: 'project views stop being counted',
    file: PROJ,
    from: '      Project.updateOne({ _id: project._id }, { $inc: { views: 1 } })',
    to: '      Promise.resolve({ _id: project._id }, { $inc: { views: 1 } })',
  },
  {
    id: 'views-count-admins',
    label: 'admin previews inflate the funnel',
    file: PROJ,
    from: '    if (!isAdmin) {\n      Project.updateOne({ _id: project._id }, { $inc: { views: 1 } })',
    to: '    if (true) {\n      Project.updateOne({ _id: project._id }, { $inc: { views: 1 } })',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test',
       'tests/integration/stage4-funnel-inventory.test.js'],
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
      console.log(`  ERROR    ${m.id.padEnd(32)} anchor not found`);
      survived += 1;
      continue;
    }
    writeFileSync(target, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(32)} ${m.label}  (${failed})`);
  } finally {
    writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
