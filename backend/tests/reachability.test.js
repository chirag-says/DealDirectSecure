/**
 * Reachability repairs (Phase 2.9)
 *
 * Four confirmed broken user-facing paths. Each test names the behaviour a user
 * would have hit.
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §20.4 (F-FE7 dead agreements link,
 * F-FE13 unreachable /rewards, F-FE15 orphaned admin taxonomy, F-FE5 Popular
 * Properties).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const CLIENT = new URL('../../client-next/src/', import.meta.url);
const ADMIN = new URL('../../Admin/src/', import.meta.url);
const readClient = (rel) => readFileSync(new URL(rel, CLIENT), 'utf8');
const readAdmin = (rel) => readFileSync(new URL(rel, ADMIN), 'utf8');
const readBackend = (rel) => readFileSync(new URL(rel, import.meta.url), 'utf8');

/**
 * Strip JSX comment blocks and line comments.
 *
 * The agreements links are hidden by wrapping them in {@literal /* ... *}/, so a
 * raw text search finds them and reports a dead link that no user can reach.
 */
const stripJsxComments = (src) =>
  src
    .replace(new RegExp('\\{/\\*[\\s\\S]*?\\*/\\}', 'g'), '')
    .replace(new RegExp('/\\*[\\s\\S]*?\\*/', 'g'), '')
    .replace(new RegExp('//[^\\r\\n]*', 'g'), '');

describe('no live link points at the hidden /agreements page', () => {
  const agreementsPage = readClient('app/agreements/page.js');

  test('the page still returns notFound()', () => {
    // If this ever stops being true, the links below may be restored.
    assert.match(agreementsPage, /notFound\(\)/);
  });

  const SURFACES = [
    'app/profile/ProfileContent.jsx',
    'components/Navbar/Navbar.jsx',
  ];

  for (const file of SURFACES) {
    test(`${file} has no reachable /agreements link`, () => {
      const live = stripJsxComments(readClient(file));
      assert.doesNotMatch(
        live,
        /href="\/agreements"/,
        `${file} sends users to a page that calls notFound()`
      );
    });
  }

  test('the links still exist commented, so the feature can be restored', () => {
    // Deleting them would lose the restore path the hide comments describe.
    const raw = readClient('app/profile/ProfileContent.jsx');
    assert.match(raw, /href="\/agreements"/, 'the commented link was deleted rather than hidden');
    assert.match(raw, /AGREEMENTS — HIDDEN/);
  });

  test('the backend mount is still commented out', () => {
    assert.match(readBackend('../server.js'), /\/\/ app\.use\("\/api\/agreements", agreementRoutes\);/);
  });
});

describe('/rewards is reachable when logged out', () => {
  const footer = readClient('components/Footer/Footer.jsx');

  test('the footer links to it', () => {
    assert.match(
      footer,
      /path:\s*"\/rewards"/,
      'the rewards marketing page has no inbound link a guest can follow'
    );
  });

  test('the footer is not behind auth', () => {
    // It renders in ClientLayout for every visitor.
    const layout = readClient('app/ClientLayout.jsx');
    assert.match(layout, /Footer/);
    assert.doesNotMatch(layout, /isAuthenticated\s*&&\s*<Footer/);
  });

  test('the page itself is public', () => {
    const middleware = readClient('middleware.js');
    const list = middleware
      .slice(middleware.indexOf('const PROTECTED_ROUTES'), middleware.indexOf('];', middleware.indexOf('const PROTECTED_ROUTES')))
      .match(/'([^']+)'/g)
      .map((s) => s.replace(/'/g, ''));
    const protects = (p) => list.some((r) => p === r || p.startsWith(r + '/'));
    assert.equal(protects('/rewards'), false, '/rewards must stay public');
    assert.equal(protects('/rewards/dashboard'), true, 'the dashboard must stay private');
  });

  test('the marketing page exists', () => {
    assert.ok(existsSync(new URL('app/rewards/page.js', CLIENT)));
  });
});

describe('admin taxonomy pages have a navigation path', () => {
  const sidebar = readAdmin('components/Sidebar.jsx');
  const app = readAdmin('App.jsx');

  for (const [path, label] of [
    ['/all-category', 'Categories'],
    ['/add-category', 'Add Category'],
    ['/add-subcategory', 'Add Subcategory'],
  ]) {
    test(`${path} is linked from the sidebar`, () => {
      assert.match(sidebar, new RegExp(`path:\\s*"${path}"`), `${path} is reachable only by typing the URL`);
    });

    test(`${path} is still routed`, () => {
      assert.match(app, new RegExp(`path="${path}"`), `${path} lost its route`);
    });

    test(`${path} has a label`, () => {
      assert.match(sidebar, new RegExp(`name:\\s*"${label}"`));
    });
  }

  test('taxonomy management matters because add-property depends on it', () => {
    const addProperty = readAdmin('pages/AdminAddProperty.jsx');
    assert.match(addProperty, /list-category/);
    assert.match(addProperty, /list-propertytype/);
  });
});

describe('Popular Properties no longer offers a control that cannot work', () => {
  const page = readAdmin('pages/PopularProperties.jsx');
  const propertyRoutes = readBackend('../routes/propertyRoutes.js');
  const propertyModel = readBackend('../models/Property.js');

  test('the backend genuinely has no support for it', () => {
    // The basis for disabling rather than wiring: there is nothing to wire to.
    assert.doesNotMatch(propertyRoutes, /popular/i, 'a popular route appeared — revisit this decision');
    assert.doesNotMatch(propertyModel, /isPopular/, 'an isPopular field appeared — revisit this decision');
  });

  test('the toggle is disabled', () => {
    assert.match(page, /disabled/);
    assert.match(page, /cursor-not-allowed/);
  });

  test('the page says the feature is unavailable', () => {
    assert.match(page, /not available yet/i);
  });

  test('no fake endpoint was invented to make it work', () => {
    assert.doesNotMatch(propertyRoutes, /router\.put\("\/popular/);
  });

  test('it is deliberately still absent from the sidebar', () => {
    // Linking to a page whose only control is disabled would be worse.
    const sidebar = readAdmin('components/Sidebar.jsx');
    assert.doesNotMatch(sidebar, /path:\s*"\/popular-properties"/);
  });
});

describe('nothing else regressed', () => {
  test('the footer still carries its existing sections', () => {
    const footer = readClient('components/Footer/Footer.jsx');
    for (const label of ['About Us', 'Why Us?', 'FAQs', 'Contact Us', 'Privacy Policy', 'Terms of Use']) {
      assert.ok(footer.includes(label), `the footer lost "${label}"`);
    }
  });

  test('the sidebar still carries its existing entries', () => {
    const sidebar = readAdmin('components/Sidebar.jsx');
    for (const path of ['/dashboard', '/all-properties', '/lead-monitoring', '/deal-verifications', '/rewards-management', '/builder-management']) {
      assert.match(sidebar, new RegExp(`path:\\s*"${path}"`), `the sidebar lost ${path}`);
    }
  });

  test('the profile support card kept its other links', () => {
    const profile = stripJsxComments(readClient('app/profile/ProfileContent.jsx'));
    assert.match(profile, /href="\/contact"/);
    assert.match(profile, /href="\/privacy"/);
  });
});
