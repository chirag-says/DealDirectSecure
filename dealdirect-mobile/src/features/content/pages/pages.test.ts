import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import { aboutPage } from './about.ts';
import { contactPage } from './contact.ts';
import { faqPage } from './faq.ts';
import { parseRichText, type Block, type ContentPage, type Section } from './model.ts';
import { privacyPage } from './privacy.ts';
import { rewardsTermsPage } from './rewardsTerms.ts';
import { termsPage } from './terms.ts';
import { whyUsPage } from './whyUs.ts';

/**
 * Two kinds of guard.
 *
 * The first is structural and always runs: every page is well formed, every
 * bold marker is closed, every id is unique. The renderer trusts all of that.
 *
 * The second is PARITY WITH THE WEBSITE and runs only when the website
 * checkout sits beside this one (`../client-next`), which it does in the
 * monorepo-style layout this repo is developed in and does not on CI for the
 * mobile repo alone. It reads each page's website source and checks that every
 * sentence in the app's copy still appears there. That is the drift alarm the
 * module doc in `../index.ts` promises: change a clause on the website and
 * forget the app, and this fails.
 */

const here = dirname(fileURLToPath(import.meta.url));
const mobileRoot = resolve(here, '../../../..');
const websiteApp = resolve(mobileRoot, '../client-next/src/app');

const PAGES: ContentPage[] = [
  aboutPage,
  contactPage,
  faqPage,
  privacyPage,
  rewardsTermsPage,
  termsPage,
  whyUsPage,
];

function sectionsOf(page: ContentPage): Section[] {
  return page.parts ? page.parts.flatMap((part) => part.sections) : page.sections;
}

function blocksOf(page: ContentPage): Block[] {
  const partIntros = page.parts?.flatMap((part) => part.blocks ?? []) ?? [];
  return [...partIntros, ...sectionsOf(page).flatMap((section) => section.blocks)];
}

/** Every reader-facing string in a block, so the parity check misses nothing. */
function textsOf(block: Block): string[] {
  switch (block.type) {
    case 'paragraph':
    case 'quote':
      return [block.text];
    case 'heading':
      return [block.text];
    case 'bullets':
    case 'tags':
      return block.items;
    case 'callout':
      return [block.title, block.text, ...(block.items ?? [])].filter((s): s is string => !!s);
    case 'cards':
      return block.items.flatMap((item) =>
        [item.title, item.meta, item.footnote, ...item.text.split('\n\n')].filter(
          (s): s is string => !!s
        )
      );
    case 'stats':
      return block.items.flatMap((item) => [item.value, item.label]);
    case 'faq':
      return block.items.flatMap((item) => [item.question, item.answer]);
    case 'contact':
      return [];
    case 'actions':
      return [];
  }
}

describe('parseRichText', () => {
  it('splits bold runs out of the surrounding text', () => {
    assert.deepEqual(parseRichText('a **b** c'), [
      { text: 'a ', bold: false },
      { text: 'b', bold: true },
      { text: ' c', bold: false },
    ]);
  });

  it('keeps an unbalanced marker as literal text instead of bolding the rest', () => {
    assert.deepEqual(parseRichText('rate is 5**'), [{ text: 'rate is 5**', bold: false }]);
    assert.deepEqual(parseRichText('**open'), [{ text: '**open', bold: false }]);
  });

  it('returns nothing for an empty string and drops empty runs', () => {
    assert.deepEqual(parseRichText(''), []);
    assert.deepEqual(parseRichText('**only**'), [{ text: 'only', bold: true }]);
  });
});

describe('content pages are well formed', () => {
  it('have unique ids and website paths', () => {
    const ids = PAGES.map((page) => page.id);
    assert.equal(new Set(ids).size, ids.length, 'duplicate page id');
    for (const page of PAGES) {
      assert.match(page.webPath, /^\/[a-z-/]+$/, `${page.id}: webPath`);
      assert.ok(page.title.trim(), `${page.id}: title`);
      assert.ok(page.eyebrow.trim(), `${page.id}: eyebrow`);
    }
  });

  it('have at least one block in every section, and unique section ids', () => {
    for (const page of PAGES) {
      const sections = sectionsOf(page);
      assert.ok(sections.length > 0, `${page.id}: no sections`);
      const ids = sections.map((section) => section.id);
      assert.equal(new Set(ids).size, ids.length, `${page.id}: duplicate section id`);
      for (const section of sections) {
        assert.ok(section.blocks.length > 0, `${page.id}/${section.id}: empty section`);
        if (section.collapsible) {
          assert.ok(section.title, `${page.id}/${section.id}: an accordion needs a title`);
        }
      }
    }
  });

  it('never leave a list, a card or an FAQ entry empty', () => {
    for (const page of PAGES) {
      for (const block of blocksOf(page)) {
        if (block.type === 'bullets' || block.type === 'tags' || block.type === 'cards') {
          assert.ok(block.items.length > 0, `${page.id}: empty ${block.type}`);
        }
        if (block.type === 'faq') {
          const ids = block.items.map((item) => item.id);
          assert.equal(new Set(ids).size, ids.length, `${page.id}: duplicate FAQ id`);
          for (const item of block.items) {
            assert.ok(item.question.trim() && item.answer.trim(), `${page.id}/${item.id}`);
          }
        }
        for (const text of textsOf(block)) {
          assert.ok(text.trim().length > 0, `${page.id}: blank text`);
        }
      }
    }
  });

  it('close every bold marker', () => {
    for (const page of PAGES) {
      const all = [page.intro ?? '', ...blocksOf(page).flatMap(textsOf)];
      for (const text of all) {
        const markers = text.split('**').length - 1;
        assert.equal(markers % 2, 0, `${page.id}: unbalanced ** in "${text.slice(0, 60)}"`);
      }
    }
  });

  it('give the terms their three parts, general first', () => {
    assert.deepEqual(
      termsPage.parts?.map((part) => part.id),
      ['general', 'buyer', 'seller']
    );
    for (const part of termsPage.parts ?? []) {
      assert.ok(part.sections.every((section) => section.collapsible), `${part.id}: accordions`);
      assert.ok(part.sections[0]?.defaultOpen, `${part.id}: first clause opens by default`);
    }
  });

  it('never invent a date', () => {
    // The website computes this page's "last updated" as today. That is not a
    // date, so the app shows none. If a real one is added there, add it here.
    assert.equal(rewardsTermsPage.meta, undefined);
    assert.equal(privacyPage.meta, 'Last updated: February 2026');
    assert.equal(termsPage.meta, 'Effective date: 21 February 2026');
  });
});

/* ---------------------------------------------------- parity with the site */

/**
 * The website file each page mirrors. Contact is absent on purpose: see the
 * note in `contact.ts` on why its phone numbers deliberately differ.
 */
const FAQ_SOURCE = 'faq/faqData.js';
const WEBSITE_SOURCE: Record<string, string> = {
  about: 'about/AboutContent.jsx',
  'why-us': 'why-us/WhyUsContent.jsx',
  faq: FAQ_SOURCE,
  privacy: 'privacy/PrivacyContent.jsx',
  terms: 'terms/TermsContent.jsx',
  'rewards-terms': 'rewards/terms/RewardsTermsContent.jsx',
};

/** Reader-facing text of a JSX/JS source: tags gone, entities decoded, spaces collapsed. */
function readableWebsiteText(source: string): string {
  return source
    .replace(/<[^>]+>/g, ' ')
    .replace(/&apos;/g, "'")
    .replace(/&quot;/g, '"')
    .replace(/&amp;/g, '&')
    .replace(/\\'/g, "'")
    .replace(/\s+/g, ' ')
    .toLowerCase();
}

/**
 * The app's text, as fragments the website must contain. Bold runs are
 * checked one at a time because the website often renders a label and its
 * sentence from two separate data fields.
 */
function fragmentsOf(text: string): string[] {
  return parseRichText(text)
    .map((run) => run.text.replace(/^[\s:—–-]+|[\s:—–-]+$/g, '').replace(/\s+/g, ' ').toLowerCase())
    .filter((fragment) => fragment.length >= 3);
}

const websitePresent = existsSync(websiteApp);

describe('content pages match the website', { skip: !websitePresent && 'website checkout not beside this one' }, () => {
  for (const page of PAGES) {
    const relative = WEBSITE_SOURCE[page.id];
    if (!relative) continue;

    it(`${page.id} says what ${relative} says`, () => {
      const website = readableWebsiteText(readFileSync(resolve(websiteApp, relative), 'utf8'));

      // The FAQ's intro line is the app's own; the website's is its page title.
      const texts = [...(page.id === 'faq' ? [] : [page.intro ?? '']), ...blocksOf(page).flatMap(textsOf)];

      const missing: string[] = [];
      for (const text of texts) {
        for (const fragment of fragmentsOf(text)) {
          if (!website.includes(fragment)) missing.push(fragment);
        }
      }
      assert.deepEqual(missing, [], `${page.id}: text not found on the website`);
    });
  }

  it('faq carries every question the website has, by id', { skip: !websitePresent }, () => {
    const source = readFileSync(resolve(websiteApp, FAQ_SOURCE), 'utf8');
    const websiteIds = [...source.matchAll(/^\s*id:\s*'([^']+)',\s*\r?\n\s*q:/gm)].map((m) => m[1]);
    const appIds = blocksOf(faqPage)
      .filter((block): block is Extract<Block, { type: 'faq' }> => block.type === 'faq')
      .flatMap((block) => block.items.map((item) => item.id));
    assert.ok(websiteIds.length > 0, 'could not read the website FAQ ids');
    assert.deepEqual(appIds.sort(), websiteIds.sort());
  });
});

/* ------------------------------------------------------------- the screens */

describe('the screens behind the pages', () => {
  const read = (relative: string) => readFileSync(resolve(mobileRoot, relative), 'utf8');

  it('render natively, with no WebView left in the legal route', () => {
    // Comments stripped: the file is allowed to SAY it used to be a WebView.
    const source = read('app/legal/[id].tsx').replace(/\/\*[\s\S]*?\*\//g, '');
    assert.doesNotMatch(source, /react-native-webview|WebView/);
  });

  it('list every registered page on the support screen from the registry', () => {
    const support = read('app/support.tsx');
    assert.match(support, /contentPagesByGroup\(\)/);
    assert.match(support, /\/legal\/contact/);
  });
});
