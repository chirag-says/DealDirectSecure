/**
 * Payment-lure detection (Phase 2, F13).
 *
 * The detector is a warning, not a block, so the bar is "catches the shapes
 * every classifieds platform documents" and "does not fire on ordinary
 * conversation". Both halves are pinned here.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { detectLure, LURE_WARNING } from '../utils/scamHeuristics.js';

describe('detectLure catches the documented lure shapes', () => {
  const lures = [
    ['pay a token amount of 5000 to hold the flat', 'token_advance'],
    ['Please transfer the advance before I can block it for you', 'token_advance'],
    ['send booking amount via gpay', 'token_advance'],
    ['token de do 2000 phonepe pe', 'token_advance'],
    ['security deposit pay karo Rs 15000 pehle', 'token_advance'],
    ['my upi id is rahul123@okaxis send there', 'upi_request'],
    ['send it to 9876543210@ybl', 'upi_request'],
    ['share your UPI id so I can send the refund', 'upi_request'],
    ['scan this QR code and pay', 'qr_code'],
    ['you need to pay before visiting, sorry', 'off_platform_payment'],
  ];

  for (const [text, flag] of lures) {
    test(`"${text}" -> ${flag}`, () => {
      const hit = detectLure(text);
      assert.ok(hit, 'expected a flag');
      assert.equal(hit.flag, flag);
      assert.ok(hit.matched.length <= 80);
    });
  }
});

describe('detectLure stays quiet on ordinary conversation', () => {
  const clean = [
    'Hi, is the flat still available?',
    'Can we visit on Saturday at 11?',
    'The rent is 25000 and maintenance is extra',
    'What is the carpet area?',
    'I liked the balcony, will discuss with family',
    'Parking token is provided by the society office',
    'Is there a security guard at night?',
    'We can sign the agreement after the visit',
    '',
  ];

  for (const text of clean) {
    test(`"${text}" -> null`, () => {
      assert.equal(detectLure(text), null);
    });
  }

  test('non-string input never throws', () => {
    assert.equal(detectLure(null), null);
    assert.equal(detectLure(undefined), null);
    assert.equal(detectLure(42), null);
    assert.equal(detectLure({}), null);
  });

  test('only the first 2000 characters are inspected, so a huge message cannot stall a send', () => {
    const padding = 'a'.repeat(5000);
    const late = `${padding} pay token amount to gpay now`;
    assert.equal(detectLure(late), null);
    const early = `pay token amount to gpay now ${padding}`;
    assert.equal(detectLure(early)?.flag, 'token_advance');
  });
});

describe('the warning copy', () => {
  test('names the rule and the remedy', () => {
    assert.match(LURE_WARNING, /never asks/i);
    assert.match(LURE_WARNING, /report/i);
    assert.ok(LURE_WARNING.length < 400);
  });
});
