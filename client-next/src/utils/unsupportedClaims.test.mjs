/**
 * Verification claims the platform cannot back.
 *
 * Nothing checks a listing, an owner's ownership, a developer or a RERA number
 * before it is shown. What IS checked: an owner confirms a mobile number by
 * one-time code before posting, and an admin can mark an account's identity
 * as verified (shown as "Identity verified"). Copy that promises more than
 * that was removed in privacy phase 1 (2026-10-17); this keeps it out.
 *
 * Comments are ignored, so code can still explain why a badge is not there.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..');

const UNSUPPORTED = [
  /100%\s*verified/i,
  /every (property )?listing is verified/i,
  /RERA[\s-]+verified/i,
  /verified (listings|properties|developers|builder projects?|owners)/i,
  /verified property/i,
  /verified,\s*(high-intent|intent-based|professional)/i,
  /verified carpenters/i,
  /RERA-registered developers/i,
];

function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(jsx?|mjs)$/.test(name) && !name.endsWith('.test.mjs') ? [path] : [];
  });
}

/** Block comments, JSX comments and whole-line // comments removed. */
function withoutComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .filter((line) => !line.trim().startsWith('//'))
    .join('\n');
}

test('no page or component claims verification the platform does not perform', () => {
  const found = [];
  for (const file of sourceFiles(SRC)) {
    // Not rendered anywhere (no importer); its own copy is listed in the
    // privacy phase 1 handover instead.
    if (file.endsWith(join('SampleAgreement', 'SampleAgreement.jsx'))) continue;
    const text = withoutComments(readFileSync(file, 'utf8'));
    for (const pattern of UNSUPPORTED) {
      const match = text.match(pattern);
      if (match) found.push(`${relative(SRC, file)}: "${match[0]}"`);
    }
  }
  assert.deepEqual(found, []);
});

test('the profile no longer tells every account its email is verified', () => {
  const source = withoutComments(readFileSync(join(SRC, 'app', 'profile', 'ProfileContent.jsx'), 'utf8'));
  assert.ok(!/Email Verified/.test(source));
  assert.ok(!/Email Verification/.test(source));
});
