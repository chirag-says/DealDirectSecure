/**
 * cloudinaryImage inserts a resize transformation into Cloudinary image URLs
 * and leaves every other URL alone.
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { cloudinaryImage, isCloudinaryImageUrl } from './cloudinaryImage.js';

const BASE = 'https://res.cloudinary.com/demo/image/upload/';
const ORIGINAL = `${BASE}v1712345678/properties/abc123.jpg`;

test('inserts the size profile after /image/upload/', () => {
  assert.equal(cloudinaryImage(ORIGINAL, 'thumb'), `${BASE}f_auto,q_auto,w_400/v1712345678/properties/abc123.jpg`);
  assert.equal(cloudinaryImage(ORIGINAL, 'medium'), `${BASE}f_auto,q_auto,w_900/v1712345678/properties/abc123.jpg`);
  assert.equal(cloudinaryImage(ORIGINAL, 'full'), `${BASE}f_auto,q_auto/v1712345678/properties/abc123.jpg`);
});

test('defaults to medium', () => {
  assert.equal(cloudinaryImage(ORIGINAL), `${BASE}f_auto,q_auto,w_900/v1712345678/properties/abc123.jpg`);
});

test('works on unversioned public ids and http URLs', () => {
  assert.equal(cloudinaryImage(`${BASE}folder/x.png`, 'thumb'), `${BASE}f_auto,q_auto,w_400/folder/x.png`);
  assert.equal(
    cloudinaryImage('http://res.cloudinary.com/demo/image/upload/v1/x.jpg', 'thumb'),
    'http://res.cloudinary.com/demo/image/upload/f_auto,q_auto,w_400/v1/x.jpg',
  );
});

test('does not stack a second transformation', () => {
  for (const segment of ['w_300', 'c_fill,w_200,h_200', 'f_auto,q_auto,w_400', 'ar_16:9,c_fill', 'dpr_2.0', 't_card', '$w_100']) {
    const url = `${BASE}${segment}/v1/x.jpg`;
    assert.equal(cloudinaryImage(url, 'thumb'), url, segment);
  }
});

test('leaves non-Cloudinary and non-image URLs unchanged', () => {
  const untouched = [
    'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800',
    'http://localhost:9000/uploads/abc.jpg',
    '/uploads/abc.jpg',
    'blob:http://localhost:3000/5f1d2c1e-0000-0000-0000-000000000000',
    'data:image/png;base64,iVBORw0KGgo=',
    'https://res.cloudinary.com/demo/raw/upload/v1/docs/plan.pdf',
    'https://res.cloudinary.com/demo/video/upload/v1/tour.mp4',
    'https://evil.example.com/res.cloudinary.com/demo/image/upload/x.jpg',
    'https://res.cloudinary.com.evil.example/demo/image/upload/x.jpg',
  ];
  for (const url of untouched) {
    assert.equal(cloudinaryImage(url, 'thumb'), url, url);
  }
});

test('passes empty values and unknown sizes through', () => {
  assert.equal(cloudinaryImage(undefined, 'thumb'), undefined);
  assert.equal(cloudinaryImage(null, 'thumb'), null);
  assert.equal(cloudinaryImage('', 'thumb'), '');
  assert.equal(cloudinaryImage(ORIGINAL, 'huge'), ORIGINAL);
});

test('isCloudinaryImageUrl', () => {
  assert.equal(isCloudinaryImageUrl(ORIGINAL), true);
  assert.equal(isCloudinaryImageUrl('https://images.unsplash.com/x.jpg'), false);
  assert.equal(isCloudinaryImageUrl({ url: ORIGINAL }), false);
});
