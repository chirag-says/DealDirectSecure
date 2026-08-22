/**
 * Stage 5 — the pure helpers, tested as functions rather than as source text.
 *
 * Written because mutation testing killed only 11 of 19: eight mutations
 * survived against assertions that merely checked a source file MENTIONED the
 * right identifier. "The file contains the word timingSafeEqual" is not the
 * same claim as "the comparison is timing-safe", and the gap between those two
 * is exactly where a regression lives.
 */

import test from 'node:test';
import assert from 'node:assert/strict';

import { publicIdFromUrl } from '../utils/cloudinaryAssets.js';

// ---------------------------------------------------------------------------
// publicIdFromUrl — decides what gets DELETED, so its edges matter
// ---------------------------------------------------------------------------

test('publicIdFromUrl', async (t) => {
  await t.test('extracts the id from a standard delivery URL', () => {
    assert.equal(
      publicIdFromUrl('https://res.cloudinary.com/dd/image/upload/v1699999999/dealdirect/projects/abc.jpg'),
      'dealdirect/projects/abc'
    );
  });

  await t.test('strips the version segment', () => {
    // Leaving `v1699999999/` in the public_id means the destroy silently
    // targets nothing: the API returns "not found" and the asset survives, so
    // the leak persists while the code looks correct.
    const id = publicIdFromUrl('https://res.cloudinary.com/dd/image/upload/v123/folder/x.png');
    assert.equal(id, 'folder/x');
    assert.ok(!id.startsWith('v123'), 'the version was left in the public_id');
  });

  await t.test('handles a URL with no version', () => {
    assert.equal(
      publicIdFromUrl('https://res.cloudinary.com/dd/image/upload/folder/x.png'),
      'folder/x'
    );
  });

  await t.test('keeps nested folders intact', () => {
    assert.equal(
      publicIdFromUrl('https://res.cloudinary.com/dd/image/upload/v1/a/b/c/name.webp'),
      'a/b/c/name'
    );
  });

  await t.test('handles raw resources (brochures)', () => {
    assert.equal(
      publicIdFromUrl('https://res.cloudinary.com/dd/raw/upload/v1/dealdirect/docs/brochure.pdf'),
      'dealdirect/docs/brochure'
    );
  });

  await t.test('REFUSES a URL that is not ours', () => {
    // The dangerous direction. Deriving a public_id from someone else's URL and
    // handing it to destroy is at best a no-op and at worst deletes an
    // unrelated asset whose id happens to collide.
    for (const url of [
      'https://images.unsplash.com/photo-123/x.jpg',
      'https://a-builder-cdn.example.com/upload/v1/plan.jpg',
      'https://evil.test/res.cloudinary.com.attacker.net/image/upload/v1/x.jpg',
    ]) {
      assert.equal(publicIdFromUrl(url), null, `${url} was treated as ours to delete`);
    }
  });

  await t.test('refuses junk without throwing', () => {
    for (const v of [null, undefined, '', 42, {}, 'not a url', 'https://res.cloudinary.com/']) {
      assert.equal(publicIdFromUrl(v), null);
    }
  });

  await t.test('refuses a Cloudinary URL with no upload segment', () => {
    assert.equal(publicIdFromUrl('https://res.cloudinary.com/dd/image/fetch/v1/x.jpg'), null);
  });
});
