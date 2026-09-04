/**
 * Stage 1 — truth in UI.
 *
 * Two changes, both client-only:
 *
 *   1. The group-buy sections come off the project and unit pages. The terms
 *      are stored and displayed today, and NOTHING enforces them: no code
 *      reads `paidMemberCount >= minBuyers`, applies `discountPerBuyer` to any
 *      price, or notifies anyone when a goal is met. Showing a discounted
 *      price that no code will ever honour is the defect.
 *
 *   2. The orphaned BookingModal.jsx goes. The live modal is defined inline in
 *      UnitDetailContent; the standalone file is a second, diverging copy of a
 *      money flow that nothing imports.
 *
 * The admin side is untouched — campaigns are still authorable, still stored,
 * still verifiable. Only the buyer-facing claim is withdrawn.
 *
 * NOT included, and worth recording: an earlier draft of the audit called the
 * /agreements page a live-UI-over-dead-API defect. It is not. The page calls
 * notFound(), the navbar links sit inside JSX comments, and the backend mount
 * is off — a correct three-place retirement. The finding came from a grep that
 * counted matches inside comments. `guards the retirement stays intact` below
 * pins the real state so a future change cannot half-restore it.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const repo = (rel) => new URL(`../../${rel}`, import.meta.url);
const readRepo = (rel) => readFileSync(repo(rel), 'utf8');

/**
 * Strip both JS and JSX comments.
 *
 * The JSX form matters more than usual here: `{/* ... *\/}` is how this
 * codebase disables UI, so a raw source match cannot tell "rendered" from
 * "commented out". Getting that wrong is what produced a retracted audit
 * finding, and these assertions exist precisely to not repeat it.
 */
const stripComments = (src) =>
  src
    .replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, '')  // JSX comment blocks
    .replace(/\/\*[\s\S]*?\*\//g, '')            // block comments
    .replace(/\/\/[^\r\n]*/g, '');               // line comments

const PROJECT_PAGE = 'client-next/src/app/projects/[id]/ProjectDetailContent.jsx';
const UNIT_PAGE = 'client-next/src/app/projects/[id]/units/[unitTypeId]/UnitDetailContent.jsx';

// ---------------------------------------------------------------------------
// The comment-stripper itself. It is load-bearing, so it is tested.
// ---------------------------------------------------------------------------

test('the JSX comment stripper distinguishes rendered from commented', async (t) => {
  await t.test('a JSX comment block is removed', () => {
    assert.equal(stripComments('{/* <Link href="/x">hi</Link> */}').trim(), '');
  });

  await t.test('real JSX survives', () => {
    assert.match(stripComments('<Link href="/x">hi</Link>'), /href="\/x"/);
  });

  await t.test('a multi-line JSX comment is removed whole', () => {
    const src = `{/* NOTE
      <Link href="/gone" />
    */}
    <Link href="/kept" />`;
    const out = stripComments(src);
    assert.doesNotMatch(out, /\/gone/);
    assert.match(out, /\/kept/);
  });
});

// ---------------------------------------------------------------------------
// Group buy: withdrawn from the buyer-facing pages
// ---------------------------------------------------------------------------

test('group-buy claims are off the buyer-facing pages', async (t) => {
  await t.test('the project page renders no campaign banner', () => {
    const src = stripComments(readRepo(PROJECT_PAGE));
    assert.doesNotMatch(src, /campaigns\.map/, 'the campaign banner still renders');
    assert.doesNotMatch(src, /discountPerBuyer/, 'a discount is still being displayed');
    assert.doesNotMatch(src, /Group Buy/i, 'group-buy copy survives');
  });

  await t.test('the unit page renders no campaign card', () => {
    const src = stripComments(readRepo(UNIT_PAGE));
    assert.doesNotMatch(src, /CampaignCard/, 'the campaign card still renders');
    assert.doesNotMatch(src, /discountPerBuyer/, 'a discount is still being displayed');
    assert.doesNotMatch(src, /groupBuyPrice/, 'a discounted price is still computed');
  });

  await t.test('THE POINT: no page computes a price the backend will not honour', () => {
    // The specific arithmetic that made the claim: effectivePrice - discount.
    for (const page of [PROJECT_PAGE, UNIT_PAGE]) {
      const src = stripComments(readRepo(page));
      assert.doesNotMatch(
        src, /effectivePrice\s*-\s*discount/,
        `${page} still advertises a group-buy price`
      );
    }
  });

  await t.test('the admin side is untouched — campaigns remain authorable', () => {
    // Withdrawing the buyer claim must not delete the feature.
    for (const rel of [
      'Admin/src/pages/CreateCampaign.jsx',
      'Admin/src/pages/GroupBuyManagement.jsx',
    ]) {
      assert.ok(existsSync(repo(rel)), `${rel} was deleted — only the buyer claim should go`);
    }
    assert.ok(existsSync(repo('backend/controllers/campaignController.js')));
    assert.ok(existsSync(repo('backend/models/GroupBuyCampaign.js')));
  });

  await t.test('and the campaign API still works', () => {
    // Nothing about this stage touches the backend.
    const routes = readRepo('backend/routes/campaignRoutes.js');
    assert.match(routes, /join/, 'the join route went');
    assert.match(readRepo('backend/server.js'), /app\.use\("\/api\/campaigns"/);
  });
});

// ---------------------------------------------------------------------------
// The orphaned money modal
// ---------------------------------------------------------------------------

test('the duplicate booking modal is gone', async (t) => {
  const ORPHAN = 'client-next/src/app/projects/[id]/units/[unitTypeId]/BookingModal.jsx';

  await t.test('the standalone file is deleted', () => {
    assert.equal(existsSync(repo(ORPHAN)), false, 'the second copy of the money flow is back');
  });

  await t.test('the live inline modal still exists and is still used', () => {
    // Guards against deleting the wrong one.
    const src = readRepo(UNIT_PAGE);
    assert.match(src, /function BookingModal/, 'the live modal was deleted');
    assert.match(src, /<BookingModal/, 'the live modal is no longer rendered');
  });

  await t.test('the booking flow it drives is intact', () => {
    const src = readRepo(UNIT_PAGE);
    assert.match(src, /bookingApi\.create/, 'booking creation went');
    assert.match(src, /bookingApi\.submitPayment/, 'payment submission went');
  });
});

// ---------------------------------------------------------------------------
// Agreements: pin the correct retirement (the retracted finding)
// ---------------------------------------------------------------------------

test('the agreements retirement stays intact on all three sides', async (t) => {
  await t.test('the page answers 404', () => {
    const src = stripComments(readRepo('client-next/src/app/agreements/page.js'));
    assert.match(src, /notFound\(\)/, 'the agreements page renders again');
  });

  await t.test('no navbar link is live', () => {
    const src = stripComments(readRepo('client-next/src/components/Navbar/Navbar.jsx'));
    assert.doesNotMatch(src, /href="\/agreements"/, 'a live agreements link is back');
  });

  await t.test('the backend mount is off by default', () => {
    // Phase 2 (2026-09-04) re-opened D1 behind AGREEMENTS_ENABLED. The mount
    // exists in source but only runs when the flag is the literal "true".
    const src = readRepo('backend/server.js')
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
    assert.match(src, /if \(AGREEMENTS_ENABLED\) app\.use\("\/api\/agreements", agreementRoutes\);/);
    assert.match(src, /const AGREEMENTS_ENABLED = process\.env\.AGREEMENTS_ENABLED === 'true'/);
    assert.doesNotMatch(src, /^\s*app\.use\("\/api\/agreements",\s*agreementRoutes\)/m,
      'the agreements API is mounted unconditionally — check PAYMENT_WEBHOOK_SECRET first');
  });

  await t.test('and all three would have to move together', () => {
    // If one side is restored without the others, the previous half-state
    // returns. The page comment documents this; the test enforces it.
    const page = stripComments(readRepo('client-next/src/app/agreements/page.js'));
    const nav = stripComments(readRepo('client-next/src/components/Navbar/Navbar.jsx'));
    const server = readRepo('backend/server.js')
      .replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');

    const pageLive = !/notFound\(\)/.test(page);
    const navLive = /href="\/agreements"/.test(nav);
    // An unconditional mount is "live"; the flag-gated mount is not.
    const apiLive = /^\s*app\.use\("\/api\/agreements",\s*agreementRoutes\)/m.test(server);

    assert.equal(
      new Set([pageLive, navLive, apiLive]).size, 1,
      `agreements is half-restored (page:${pageLive} nav:${navLive} api:${apiLive}) — ` +
      `restore all three or none`
    );
  });
});
