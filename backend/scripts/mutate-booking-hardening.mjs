/**
 * Mutation harness for Stage 2 — booking money-path hardening.
 *
 *   node scripts/mutate-booking-hardening.mjs
 *
 * Each mutation restores one of the defects, or breaks a guard in the specific
 * way a careless edit would. The reverted-to-`=== 0` case matters most: that
 * is the exact code that shipped, and it fails only for undefined inventory —
 * a test seeded with 0 passes either way.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const CTRL = 'controllers/bookingController.js';
const ROUTES = 'routes/bookingRoutes.js';
const SERVER = 'server.js';

const MUTATIONS = [
  {
    id: 'inventory-old-check',
    label: 'inventory guard reverts to the shipped `=== 0`',
    file: CTRL,
    from: 'if (!(unitType.inventory?.availableUnits >= 1)) {',
    to: 'if (unitType.inventory?.availableUnits === 0) {',
  },
  {
    id: 'inventory-gone',
    label: 'the inventory guard is removed entirely',
    file: CTRL,
    from: 'if (!(unitType.inventory?.availableUnits >= 1)) {',
    to: 'if (false) {',
  },
  {
    id: 'token-guard-gone',
    label: '₹0 bookings are accepted again',
    file: CTRL,
    from: 'if (!(tokenAmount > 0)) {',
    to: 'if (false) {',
  },
  {
    id: 'token-fallback-lost',
    label: 'the legacy project-level booking amount stops being read',
    file: CTRL,
    from: 'unitType.paymentTerms?.bookingAmount ?? project.financials?.bookingAmount ?? 0;',
    to: 'unitType.paymentTerms?.bookingAmount ?? 0;',
  },
  {
    id: 'enquiry-cap-gone',
    label: 'a user can open unlimited enquiries on one unit type',
    file: CTRL,
    from: 'if (alreadyOpen > 0) {',
    to: 'if (false) {',
  },
  {
    id: 'enquiry-cap-counts-cancelled',
    label: 'cancelled enquiries keep blocking the slot',
    file: CTRL,
    from: 'const openStates = ["enquiry", "payment_submitted"];',
    to: 'const openStates = ["enquiry", "payment_submitted", "cancelled"];',
  },
  {
    id: 'utr-check-gone',
    label: 'duplicate UTRs pass verification unseen',
    file: CTRL,
    from: 'if (duplicates.length > 0 && !overrideDuplicateUtr) {',
    to: 'if (false) {',
  },
  {
    id: 'utr-override-needs-no-note',
    label: 'a duplicate can be approved with no explanation',
    file: CTRL,
    from: 'if (duplicates.length > 0 && overrideDuplicateUtr && !adminNotes?.trim()) {',
    to: 'if (false) {',
  },
  {
    id: 'utr-includes-cancelled',
    label: 'a cancelled booking blocks a legitimate re-submission',
    file: CTRL,
    from: 'status: { $nin: ["cancelled"] },',
    to: 'status: { $nin: [] },',
  },
  {
    id: 'utr-matches-self',
    label: 'the booking being verified counts as its own duplicate',
    file: CTRL,
    from: '_id: { $ne: booking._id },',
    to: '_id: { $exists: true },',
  },
  {
    id: 'audit-verify-gone',
    label: 'payment approval stops writing an audit record',
    file: CTRL,
    from: 'await auditBooking(req, booking, "booking_payment_verified", {',
    // Promise.resolve(...) swallows the args and writes nothing. An earlier
    // version used `Promise.resolve(0) && auditBooking(...)`, which does NOT
    // disable it — a Promise is truthy, so the real call still ran and the
    // mutation survived by doing nothing at all.
    to: 'await Promise.resolve(req, booking, "booking_payment_verified", {',
  },
  {
    id: 'audit-status-gone',
    label: 'status changes stop writing an audit record',
    file: CTRL,
    from: 'await auditBooking(req, booking, "booking_status_changed", {',
    to: 'await Promise.resolve(req, booking, "booking_status_changed", {',
  },
  {
    id: 'cancel-no-ownership',
    label: 'anyone can cancel anyone else\'s booking',
    file: CTRL,
    from: "if (!booking.user || booking.user.toString() !== req.user._id.toString()) {",
    to: 'if (false) {',
  },
  {
    id: 'cancel-allows-confirmed',
    label: 'a user can self-cancel a confirmed booking, stranding inventory',
    file: CTRL,
    from: 'export const USER_CANCELLABLE_STATES = ["enquiry", "payment_submitted"];',
    to: 'export const USER_CANCELLABLE_STATES = ["enquiry", "payment_submitted", "confirmed"];',
  },
  {
    id: 'cancel-destroys-evidence',
    label: 'cancelling wipes the UTR that proves the money moved',
    file: CTRL,
    from: '    booking.status = "cancelled";\n    booking.statusHistory.push({',
    to: '    booking.status = "cancelled";\n    booking.payment.utrNumber = undefined;\n    booking.statusHistory.push({',
  },
  {
    id: 'cancel-attributed-to-admin',
    label: 'a user cancellation is recorded as an admin action',
    file: CTRL,
    from: '      changedBy: "user",\n      note: reason ? `Cancelled by user: ${reason}` : "Cancelled by user",',
    to: '      changedBy: "admin",\n      note: reason ? `Cancelled by user: ${reason}` : "Cancelled by user",',
  },
  {
    id: 'csrf-create-gone',
    label: 'booking creation loses its CSRF guard',
    file: SERVER,
    from: 'app.post("/api/bookings", csrfGuard);',
    to: '',
  },
  {
    id: 'csrf-payment-gone',
    label: 'payment submission loses its CSRF guard',
    file: SERVER,
    from: 'app.post("/api/bookings/:id/payment", csrfGuard);',
    to: '',
  },
  {
    id: 'cancel-route-gone',
    label: 'the self-cancel route is removed',
    file: ROUTES,
    from: 'router.post("/:id/cancel", authMiddleware, cancelOwnBooking);',
    to: '',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath,
      ['--env-file=tests/integration/test.env', '--test',
       'tests/integration/booking-hardening.test.js'],
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
      console.log(`  ERROR    ${m.id.padEnd(28)} anchor not found`);
      survived += 1;
      continue;
    }
    writeFileSync(target, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(28)} ${m.label}  (${failed})`);
  } finally {
    writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
