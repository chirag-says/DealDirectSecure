/**
 * Configuration checks for Session Replay privacy.
 *
 * These prove what the site ASKS the SDK to do. They do not prove what a real
 * replay contains: that needs a recording captured from a running page, which
 * is a separate check (see the privacy phase 1 handover).
 *
 *   npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  REPLAY_PRIVACY_OPTIONS,
  dropConsoleBreadcrumb,
  scrubRecordingEvent,
  scrubReplayEvent,
  withoutQuery,
  maskSelectorValues,
} from './sentryReplayPrivacy.js';

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..');

test('text, form values and media are all masked, stated explicitly', () => {
  assert.equal(REPLAY_PRIVACY_OPTIONS.maskAllText, true);
  assert.equal(REPLAY_PRIVACY_OPTIONS.maskAllInputs, true);
  assert.equal(REPLAY_PRIVACY_OPTIONS.blockAllMedia, true);
});

test('attributes that carry text are masked, the SDK defaults included', () => {
  for (const attr of ['title', 'placeholder', 'aria-label', 'alt', 'value', 'label']) {
    assert.ok(REPLAY_PRIVACY_OPTIONS.maskAttributes.includes(attr), attr);
  }
});

test('href, src and srcset are not left to maskAttributes, which rrweb skips for them', () => {
  // rrweb's transformAttribute returns before the mask hook for these three,
  // so listing them would look like protection and give none.
  for (const attr of ['href', 'src', 'srcset']) {
    assert.ok(!REPLAY_PRIVACY_OPTIONS.maskAttributes.includes(attr), attr);
  }
});

test('iframes and links carrying contact details or query strings are blocked', () => {
  const block = [...REPLAY_PRIVACY_OPTIONS.block];
  for (const selector of [
    'iframe',
    'a[href^="tel:"]',
    'a[href^="mailto:"]',
    'a[href^="sms:"]',
    'a[href*="wa.me"]',
    'a[href*="whatsapp"]',
    'a[href*="?"]',
  ]) {
    assert.ok(block.includes(selector), selector);
  }
});

test('nothing is unmasked or unblocked', () => {
  assert.deepEqual([...REPLAY_PRIVACY_OPTIONS.unmask], []);
  assert.deepEqual([...REPLAY_PRIVACY_OPTIONS.unblock], []);
});

test('no network request or response detail is captured for any URL', () => {
  assert.deepEqual([...REPLAY_PRIVACY_OPTIONS.networkDetailAllowUrls], []);
  assert.equal(REPLAY_PRIVACY_OPTIONS.networkCaptureBodies, false);
});

test('the options cannot be changed at runtime', () => {
  assert.ok(Object.isFrozen(REPLAY_PRIVACY_OPTIONS));
  assert.ok(Object.isFrozen(REPLAY_PRIVACY_OPTIONS.maskAttributes));
  assert.ok(Object.isFrozen(REPLAY_PRIVACY_OPTIONS.block));
  assert.equal(REPLAY_PRIVACY_OPTIONS.beforeAddRecordingEvent, scrubRecordingEvent);
});

test('instrumentation-client.js uses these options and registers the replay scrubber', () => {
  const source = readFileSync(join(SRC, 'instrumentation-client.js'), 'utf8');
  assert.match(source, /Sentry\.replayIntegration\(REPLAY_PRIVACY_OPTIONS\)/);
  assert.match(source, /Sentry\.addEventProcessor\(scrubReplayEvent\)/);
  for (const optOut of ['maskAllText: false', 'maskAllInputs: false', 'blockAllMedia: false']) {
    assert.ok(!source.includes(optOut), `instrumentation-client.js must not contain "${optOut}"`);
  }
});

test('instrumentation-client.js drops console breadcrumbs from every event', () => {
  const source = readFileSync(join(SRC, 'instrumentation-client.js'), 'utf8');
  assert.match(source, /import\s*\{[^}]*\bdropConsoleBreadcrumb\b[^}]*\}\s*from\s*["']\.\/utils\/sentryReplayPrivacy["']/);
  assert.match(source, /^\s*beforeBreadcrumb:\s*dropConsoleBreadcrumb\s*,/m);
});

/** Every source file under src, this test excepted. */
function sourceFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.(jsx?|mjs|tsx?)$/.test(name) && !name.endsWith('.test.mjs') ? [path] : [];
  });
}

test('no element on the site opts out of masking or blocking', () => {
  const optOuts = /sentry-unmask|sentry-unblock|data-sentry-unmask|data-sentry-unblock/;
  const offenders = sourceFiles(SRC).filter((file) => optOuts.test(readFileSync(file, 'utf8')));
  assert.deepEqual(offenders, []);
});

// ---------------------------------------------------------------------------
// Custom recording events (the only ones beforeAddRecordingEvent receives)

test('console breadcrumbs are dropped from the recording', () => {
  const event = { type: 5, data: { tag: 'breadcrumb', payload: { category: 'console', message: 'user asha@example.test' } } };
  assert.equal(scrubRecordingEvent(event), null);
});

test('click breadcrumbs keep the element path but not attribute values', () => {
  const event = {
    type: 5,
    data: {
      tag: 'breadcrumb',
      payload: {
        category: 'ui.click',
        message: 'div.card > a.call[href="tel:9876543210"][aria-label="Call Asha Rao"]',
        data: { nodeId: 42 },
      },
    },
  };
  const out = scrubRecordingEvent(event);
  assert.equal(out.data.payload.message, 'div.card > a.call[href="***"][aria-label="***"]');
  assert.equal(out.data.payload.data.nodeId, 42, 'the player still highlights the element');
  assert.match(event.data.payload.message, /9876543210/, 'the input event is not mutated');
});

test('navigation breadcrumbs lose their query strings', () => {
  const event = {
    type: 5,
    data: { tag: 'breadcrumb', payload: { category: 'navigation', data: { from: '/properties?q=Asha', to: '/login?redirect=%2Fprofile#x' } } },
  };
  const out = scrubRecordingEvent(event);
  assert.deepEqual(out.data.payload.data, { from: '/properties', to: '/login' });
});

test('network and navigation spans lose their query strings', () => {
  for (const op of ['resource.fetch', 'navigation.push', 'navigation.navigate']) {
    const event = {
      type: 5,
      data: { tag: 'performanceSpan', payload: { op, description: 'https://nominatim.openstreetmap.org/search?q=12+MG+Road' } },
    };
    assert.equal(scrubRecordingEvent(event).data.payload.description, 'https://nominatim.openstreetmap.org/search', op);
  }
});

test('other events pass through untouched', () => {
  const options = { type: 5, data: { tag: 'options', payload: { maskAllText: true } } };
  assert.equal(scrubRecordingEvent(options), options);
  const snapshot = { type: 2, data: { node: { id: 1 } } };
  assert.equal(scrubRecordingEvent(snapshot), snapshot);
});

// ---------------------------------------------------------------------------
// Breadcrumbs on error and performance events (beforeBreadcrumb)

test('console breadcrumbs are dropped before any event can carry them', () => {
  for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    const crumb = { category: 'console', level, message: 'Flat in Indiranagar 12.9716,77.6412' };
    assert.equal(dropConsoleBreadcrumb(crumb), null, level);
  }
});

test('other breadcrumbs pass through as the same object', () => {
  for (const category of ['ui.click', 'ui.input', 'navigation', 'fetch', 'xhr', 'sentry.event']) {
    const crumb = { category, message: 'x', data: { a: 1 } };
    assert.equal(dropConsoleBreadcrumb(crumb), crumb, category);
  }
  const uncategorised = { message: 'manual breadcrumb' };
  assert.equal(dropConsoleBreadcrumb(uncategorised), uncategorised);
});

// ---------------------------------------------------------------------------
// The replay event

test('the replay event loses query strings from its page list and request', () => {
  const out = scrubReplayEvent({
    type: 'replay_event',
    urls: ['https://dealdirect.in/a?x=1', 'https://dealdirect.in/b#frag'],
    request: { url: 'https://dealdirect.in/a?x=1', headers: { Referer: 'https://dealdirect.in/c?q=2', 'User-Agent': 'UA' } },
  });
  assert.deepEqual(out.urls, ['https://dealdirect.in/a', 'https://dealdirect.in/b']);
  assert.equal(out.request.url, 'https://dealdirect.in/a');
  assert.equal(out.request.headers.Referer, 'https://dealdirect.in/c');
  assert.equal(out.request.headers['User-Agent'], 'UA');
});

test('error and transaction events are returned as they came', () => {
  const error = { type: undefined, request: { url: 'https://dealdirect.in/a?x=1' } };
  assert.equal(scrubReplayEvent(error), error);
  const transaction = { type: 'transaction' };
  assert.equal(scrubReplayEvent(transaction), transaction);
});

test('helpers leave non-strings and plain values alone', () => {
  assert.equal(withoutQuery(undefined), undefined);
  assert.equal(withoutQuery('/plain/path'), '/plain/path');
  assert.equal(maskSelectorValues(undefined), undefined);
  assert.equal(maskSelectorValues('div.a > span#b'), 'div.a > span#b');
  assert.equal(maskSelectorValues("a[title='x']"), 'a[title="***"]');
});
