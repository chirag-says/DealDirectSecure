/**
 * Stage 3b — render what admins already fill.
 *
 * The audit's field census found a third of what admins diligently enter never
 * reaches a buyer. These are not new fields and not new admin work: every one
 * of them is already collected, already stored, and simply never rendered.
 *
 *   coordinates        7/7 filled   no map on the page at all
 *   connectivity       5/7 filled   never rendered
 *   bank approvals     1/7 filled   never rendered
 *   CC / OC / approvals            never rendered
 *   builder profile    filled       only name + logo ever shown
 *   constructionUpdates            admin can post them; nothing displays them
 *   walkthrough video  1/7 filled   never rendered
 *   RERA number        5/7 filled   badge says "verified", number never shown
 *   master plan        3/7 filled   rendered into a 12rem crop that destroys it
 *
 * Asserted at source with comments stripped, because `{/* ... *\/}` is how this
 * codebase disables UI and a raw match cannot tell rendered from commented —
 * the mistake that produced a retracted audit finding.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const repo = (rel) => new URL(`../../${rel}`, import.meta.url);
const read = (rel) => readFileSync(repo(rel), 'utf8');

const stripComments = (src) =>
  src
    .replace(/\{\s*\/\*[\s\S]*?\*\/\s*\}/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/[^\r\n]*/g, '');

const PROJECT = 'client-next/src/app/projects/[id]/ProjectDetailContent.jsx';
const UNIT = 'client-next/src/app/projects/[id]/units/[unitTypeId]/UnitDetailContent.jsx';
const MAP = 'client-next/src/components/Projects/ProjectLocationMap.jsx';

const projectSrc = () => stripComments(read(PROJECT));

// ---------------------------------------------------------------------------
// The map — the highest-value gap: collected on every project, shown on none
// ---------------------------------------------------------------------------

test('the project location map renders', async (t) => {
  await t.test('a map component exists', () => {
    assert.ok(existsSync(repo(MAP)), 'no ProjectLocationMap component');
  });

  await t.test('it is loaded without SSR', () => {
    // Leaflet touches `window` at import time. Rendering it on the server is
    // the standard way this breaks, and it breaks the whole page, not the map.
    const src = stripComments(projectSrc());
    assert.match(src, /dynamic\(/, 'the map is not dynamically imported');
    assert.match(src, /ssr:\s*false/, 'the map would be server-rendered and crash the page');
  });

  await t.test('the project page renders it', () => {
    assert.match(projectSrc(), /<ProjectLocationMap/, 'the map component is never rendered');
  });

  // The next three are properties of the COMPONENT, not the page — the page
  // only mounts it and hands over the project. Asserting them against the page
  // source would be asserting against the wrong file and would pass or fail for
  // reasons unrelated to the behaviour.
  const mapSrc = () => stripComments(read(MAP));

  await t.test('it is driven by the coordinates admins already fill', () => {
    assert.match(mapSrc(), /location\?\.coordinates/, 'the stored coordinates are still unused');
  });

  await t.test('and it is skipped when there is no pin', () => {
    // 7/7 have coordinates today, but a map centred on undefined is a grey box.
    const src = mapSrc();
    assert.match(src, /hasPin/, 'nothing guards the missing-coordinate case');
    assert.match(src, /Number\.isFinite/, 'the pin check would accept a non-numeric coordinate');
  });

  await t.test('connectivity distances render with the map', () => {
    const src = mapSrc();
    assert.match(src, /connectivity/, 'the connectivity distances are still unrendered');
    for (const field of ['distanceToMetro', 'distanceToAirport', 'distanceToRailway', 'distanceToBusStop']) {
      assert.match(src, new RegExp(field), `${field} is not shown`);
    }
  });

  await t.test('the component renders nothing when it has nothing to show', () => {
    // An empty framed box with a heading is worse than no section.
    assert.match(mapSrc(), /if \(!hasPin && links\.length === 0\) return null/);
  });
});

// ---------------------------------------------------------------------------
// RERA — ratified: display the number, do not gate on it
// ---------------------------------------------------------------------------

test('the RERA registration number is displayed, not just badged', async (t) => {
  await t.test('the number itself appears', () => {
    // "RERA Verified" with no number is the pattern regulators penalise.
    const src = projectSrc();
    assert.match(src, /basics\?\.reraNumber\}/,
      'the badge still shows no registration number');
  });

  await t.test('with a link to the state register', () => {
    assert.match(projectSrc(), /rera|maharera/i);
    assert.match(projectSrc(), /href=/);
  });
});

// ---------------------------------------------------------------------------
// Construction updates — the model's best dark feature
// ---------------------------------------------------------------------------

test('construction updates render as a timeline', async (t) => {
  await t.test('the page reads them', () => {
    assert.match(projectSrc(), /constructionUpdates/,
      'admins can post construction updates and buyers still cannot see them');
  });

  await t.test('with the fields that make them useful', () => {
    const src = projectSrc();
    for (const field of ['percentComplete', 'images']) {
      assert.match(src, new RegExp(field), `${field} is not shown`);
    }
  });
});

// ---------------------------------------------------------------------------
// Documents and approvals
// ---------------------------------------------------------------------------

test('every uploaded document is reachable', async (t) => {
  const DOCS = [
    'commencementCertificateUrl',
    'occupancyCertificateUrl',
    'environmentalClearanceUrl',
    'approvalDocumentUrls',
  ];

  for (const doc of DOCS) {
    await t.test(`${doc} is rendered`, () => {
      assert.match(projectSrc(), new RegExp(doc), `${doc} is uploaded but never shown`);
    });
  }

  await t.test('the brochure and RERA certificate still render', () => {
    // Guards against a rewrite dropping what already worked.
    const src = projectSrc();
    assert.match(src, /brochureUrl/);
    assert.match(src, /reraCertificateUrl/);
  });
});

test('bank approvals render', async (t) => {
  await t.test('the section exists', () => {
    assert.match(projectSrc(), /bankApprovals/,
      'the home-loan trust signal every portal shows is still unrendered');
  });

  await t.test('and names the banks', () => {
    assert.match(projectSrc(), /bankName/);
  });
});

// ---------------------------------------------------------------------------
// Developer profile
// ---------------------------------------------------------------------------

test('the developer profile renders', async (t) => {
  const FIELDS = ['yearEstablished', 'totalProjectsDelivered', 'operatingCities'];

  for (const field of FIELDS) {
    await t.test(`builder.${field} is shown`, () => {
      assert.match(projectSrc(), new RegExp(field),
        `builder.${field} is stored and never displayed`);
    });
  }

  await t.test('the builder description is shown', () => {
    assert.match(projectSrc(), /builder\?\.description|builder\.description/);
  });

  await t.test('but the builder\'s direct contact details are NOT', () => {
    // DealDirect is the sole point of contact — that is the product. The
    // public API already strips these; the UI must not reintroduce them.
    const src = projectSrc();
    assert.doesNotMatch(src, /builder\?\.phone|builder\.phone/, 'the builder phone leaked into the UI');
    assert.doesNotMatch(src, /builder\?\.email|builder\.email/, 'the builder email leaked into the UI');
  });
});

// ---------------------------------------------------------------------------
// Master plan — a display bug, not a missing section
// ---------------------------------------------------------------------------

test('the master plan is legible', async (t) => {
  await t.test('it is not cropped', () => {
    // `h-48 object-cover` crushed a site-layout drawing into decorative noise.
    const src = projectSrc();
    const at = src.indexOf('Master Plan');
    assert.notEqual(at, -1, 'the master plan section went');
    const block = src.slice(at, at + 700);
    assert.doesNotMatch(block, /object-cover/, 'the master plan is still cropped');
    assert.match(block, /object-contain/, 'the master plan does not preserve its aspect ratio');
  });

  await t.test('every master-plan image is reachable, not only the first', () => {
    const src = projectSrc();
    assert.doesNotMatch(src, /masterPlanImages\[0\]\s*&&[\s\S]{0,200}masterPlanImages\[0\]\s*\}/,
      'only the first master-plan image renders');
  });
});

// ---------------------------------------------------------------------------
// Video
// ---------------------------------------------------------------------------

test('walkthrough and unit tour videos render', async (t) => {
  await t.test('the project walkthrough is shown', () => {
    assert.match(projectSrc(), /walkthroughVideoUrl/,
      'the walkthrough video is stored and never shown');
  });

  await t.test('the unit video tour is shown', () => {
    assert.match(stripComments(read(UNIT)), /floorPlans\?\.videoUrl|videoUrl/,
      'the per-unit video tour is stored and never shown');
  });
});

// ---------------------------------------------------------------------------
// Regressions: what already worked must keep working
// ---------------------------------------------------------------------------

test('the sections that already worked are intact', async (t) => {
  const KEEP = [
    ['gallery', /ImageGallery/],
    ['overview stats', /Project Overview/],
    ['nearby places', /nearbyPlaces/],
    ['unit type cards', /UnitTypeCard/],
    ['amenities', /amenities\.map|amenities\.length/],
    ['payment plans', /paymentPlans/],
    ['highlights', /highlights/],
    ['DealDirect contact', /6360122696/],
  ];

  for (const [label, pattern] of KEEP) {
    await t.test(`${label} still renders`, () => {
      assert.match(projectSrc(), pattern, `${label} was lost in the rewrite`);
    });
  }

  await t.test('the group-buy withdrawal from Stage 1 holds', () => {
    // The render pack must not quietly restore what Stage 1 removed.
    const src = projectSrc();
    assert.doesNotMatch(src, /discountPerBuyer/);
    assert.doesNotMatch(src, /campaigns\.map/);
  });
});
