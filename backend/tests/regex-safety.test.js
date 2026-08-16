/**
 * Regex safety — user search input must be matched literally, never interpreted.
 *
 * These drive the real shared helper and build real RegExp objects from its
 * output, so they test behaviour: what still matches, what no longer explodes.
 *
 * Search semantics are deliberately unchanged. Escaping alters how input is
 * INTERPRETED, not what it matches literally — "3+1 BHK" still finds "3+1 BHK".
 *
 * Reference: DEALDIRECT-SYSTEM-FLOW-AUDIT.md §22.3 M4/M5, REMEDIATION_PLAN P0.1/P0.2.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { escapeRegExp } from '../utils/escapeRegExp.js';

const stripComments = (s) =>
  s.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/[^\r\n]*/g, '');
const read = (rel) => stripComments(readFileSync(new URL(rel, import.meta.url), 'utf8'));

/** Search the way the controllers do: case-insensitive substring match. */
const search = (haystack, term) => new RegExp(escapeRegExp(term), 'i').test(haystack);

describe('normal search behaviour is unchanged', () => {
  test('plain terms still match, case-insensitively', () => {
    assert.equal(search('3 BHK Apartment in Andheri', 'andheri'), true);
    assert.equal(search('3 BHK Apartment in Andheri', 'BHK'), true);
    assert.equal(search('3 BHK Apartment in Andheri', 'apartment'), true);
  });

  test('substring matching still works', () => {
    assert.equal(search('Whitefield, Bangalore', 'field'), true);
    assert.equal(search('Whitefield, Bangalore', 'bang'), true);
  });

  test('non-matching terms still do not match', () => {
    assert.equal(search('3 BHK in Andheri', 'Pune'), false);
  });

  test('terms containing metacharacters match themselves literally', () => {
    // The behaviour that matters to a real user typing a real listing title.
    assert.equal(search('3+1 BHK Villa', '3+1'), true);
    assert.equal(search('Price (negotiable)', '(negotiable)'), true);
    assert.equal(search('Block C-12', 'C-12'), true);
    assert.equal(search('50% off maintenance', '50%'), true);
    assert.equal(search('Sector 7 [Phase II]', '[Phase II]'), true);
    assert.equal(search('A.K. Road', 'A.K.'), true);
  });

  test('a metacharacter term does not match something it should not', () => {
    // Unescaped, "3+1" would match "31", "331", "3331" — wrong results, silently.
    assert.equal(search('331 BHK', '3+1'), false);
    // Unescaped, "." matches any character.
    assert.equal(search('AXK Road', 'A.K.'), false);
  });

  test('empty and non-string input degrade to an empty pattern', () => {
    assert.equal(escapeRegExp(''), '');
    assert.equal(escapeRegExp(null), '');
    assert.equal(escapeRegExp(undefined), '');
    assert.equal(escapeRegExp(42), '');
    assert.equal(escapeRegExp({}), '');
  });
});

describe('regex metacharacters are neutralised', () => {
  test('every metacharacter is escaped', () => {
    for (const ch of ['.', '*', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\']) {
      const out = escapeRegExp(ch);
      assert.equal(out, '\\' + ch, `"${ch}" was not escaped`);
      assert.doesNotThrow(() => new RegExp(out), `"${ch}" produced an invalid pattern`);
    }
  });

  test('input that is not a valid pattern no longer throws', () => {
    // Unescaped, each of these makes `new RegExp()` throw — a 500 from a search box.
    for (const bad of ['(', '[', '*', '+', '?', ')(', '[a-', '\\']) {
      assert.doesNotThrow(() => new RegExp(escapeRegExp(bad), 'i'), `"${bad}" still throws`);
    }
  });

  test('an anchor cannot be injected', () => {
    // "^Mum" unescaped anchors to the start; escaped it is a literal.
    assert.equal(search('Mumbai', '^Mum'), false);
    assert.equal(search('^Mum is literal', '^Mum'), true);
  });

  test('a wildcard cannot be injected', () => {
    assert.equal(search('anything at all', '.*'), false);
    assert.equal(search('literally .* here', '.*'), true);
  });

  test('alternation cannot be injected', () => {
    assert.equal(search('Pune', 'Mumbai|Pune'), false);
    assert.equal(search('Mumbai|Pune', 'Mumbai|Pune'), true);
  });

  test('a catastrophic-backtracking pattern is defused', () => {
    // (a+)+$ against a long non-matching string is the classic ReDoS. Escaped,
    // it is a 6-character literal and the match is immediate.
    const payload = '(a+)+$';
    const target = 'a'.repeat(40) + 'b';
    const started = process.hrtime.bigint();
    const result = search(target, payload);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    assert.equal(result, false);
    assert.ok(elapsedMs < 50, `escaped match took ${elapsedMs}ms — expected immediate`);
  });

  test('a nested-quantifier payload is also defused', () => {
    const payload = '(x+x+)+y';
    const target = 'x'.repeat(40);
    const started = process.hrtime.bigint();
    search(target, payload);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(elapsedMs < 50, `took ${elapsedMs}ms`);
  });
});

describe('one shared implementation, applied everywhere', () => {
  const files = {
    projectController: read('../controllers/projectController.js'),
    leadController: read('../controllers/leadController.js'),
    builderController: read('../controllers/builderController.js'),
    contactController: read('../controllers/contactController.js'),
    rewardsController: read('../controllers/rewardsController.js'),
    propertyController: read('../controllers/propertyController.js'),
  };

  test('no controller defines its own copy', () => {
    for (const [name, src] of Object.entries(files)) {
      assert.doesNotMatch(
        src,
        /const escapeRegExp\s*=/,
        `${name} declares a local escapeRegExp — there must be exactly one`
      );
    }
  });

  test('every search controller imports the shared helper', () => {
    for (const [name, src] of Object.entries(files)) {
      assert.match(src, /from "\.\.\/utils\/escapeRegExp\.js"/, `${name} does not import it`);
    }
  });

  test('the public projects city filter is escaped', () => {
    // The only unauthenticated one, and the only endpoint where this was
    // remotely exploitable.
    assert.match(files.projectController, /\$regex:\s*escapeRegExp\(city\)/);
  });

  test('the admin lead search is escaped', () => {
    assert.match(files.leadController, /new RegExp\(escapeRegExp\(search\), 'i'\)/);
  });

  test('builder, contact and rewards searches are escaped', () => {
    assert.match(files.builderController, /\$regex:\s*escapeRegExp\(search\.trim\(\)\)/);
    assert.match(files.contactController, /\$regex:\s*escapeRegExp\(search\)/);
    assert.match(files.rewardsController, /\$regex:\s*escapeRegExp\(search\)/);
  });

  test('no unescaped user-input regex remains in any controller', () => {
    for (const [name, src] of Object.entries(files)) {
      const raw = src.match(/\$regex:\s*(search|city|q|term|name|query)\b/g) || [];
      assert.deepEqual(raw, [], `${name} still interpolates raw input: ${raw.join(', ')}`);
    }
  });

  test('hardcoded literal patterns are left alone', () => {
    // adminController counts listings with /rent/i and /sell|sale|buy/i. Those
    // take no user input; escaping them would break the counts.
    const adminSrc = read('../controllers/adminController.js');
    assert.match(adminSrc, /\$regex:\s*\/rent\/i/);
    assert.match(adminSrc, /\$regex:\s*\/sell\|sale\|buy\/i/);
  });
});
