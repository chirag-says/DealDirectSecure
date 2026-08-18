/**
 * Mutation harness for the related-properties restoration.
 *
 *   node scripts/mutate-related-properties.mjs
 *
 * The regression this feature suffered was invisible: the section stopped
 * rendering and nothing failed. So the mutations focus on the ways it can go
 * quietly dead again, not just on the scoring arithmetic.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const backend = dirname(dirname(fileURLToPath(import.meta.url)));
const repo = dirname(backend);
const p = (rel) => join(repo, rel);

const UTIL = 'client-next/src/utils/relatedProperties.js';
const PAGE = 'client-next/src/app/properties/PropertyListContent.jsx';

const MUTATIONS = [
  {
    id: 'threshold-off',
    label: 'the "fewer than six" rule becomes "six or fewer"',
    file: UTIL,
    from: 'return hasActiveFilters(filters) && matchCount < RELATED_THRESHOLD;',
    to: 'return hasActiveFilters(filters) && matchCount <= RELATED_THRESHOLD;',
  },
  {
    id: 'no-filter-check',
    label: 'suggestions appear on an unfiltered browse',
    file: UTIL,
    from: 'return hasActiveFilters(filters) && matchCount < RELATED_THRESHOLD;',
    to: 'return matchCount < RELATED_THRESHOLD;',
  },
  {
    id: 'THE-REGRESSION',
    label: 'the pool is ranked against itself again (the original bug)',
    file: UTIL,
    from: '.filter((p) => p && p._id && !matchedIds.has(String(p._id)))',
    to: '.filter((p) => p && p._id)',
    // Inverted: this mutation makes already-shown properties reappear, so the
    // "nothing already shown is suggested again" test must catch it.
  },
  {
    id: 'pool-over-cap',
    label: 'the pool asks for more than the endpoint allows',
    file: UTIL,
    from: 'export const RELATED_POOL_SIZE = 50;',
    to: 'export const RELATED_POOL_SIZE = 500;',
  },
  {
    id: 'pool-filtered',
    label: 'the pool request reapplies the search that already returned too few',
    file: UTIL,
    from: 'return { page: 1, limit: RELATED_POOL_SIZE };',
    to: 'return { page: 1, limit: RELATED_POOL_SIZE, search: "x" };',
  },
  {
    id: 'limit-ignored',
    label: 'more than six suggestions are returned',
    file: UTIL,
    from: '.slice(0, RELATED_LIMIT);',
    to: '.slice(0, 100);',
  },
  {
    id: 'cutoff-gone',
    label: 'irrelevant properties clear the relevance cutoff',
    file: UTIL,
    from: '.filter((p) => p.relevanceScore >= RELEVANCE_CUTOFF)',
    to: '.filter((p) => p.relevanceScore >= 0)',
  },
  {
    id: 'sort-reversed',
    label: 'the least relevant is shown first',
    file: UTIL,
    from: '.sort((a, b) => b.relevanceScore - a.relevanceScore)',
    to: '.sort((a, b) => a.relevanceScore - b.relevanceScore)',
  },
  {
    id: 'bhk-exact-lost',
    label: 'an exact BHK match no longer outranks an adjacent one',
    file: UTIL,
    from: 'if (propBhk === searchBhk) score += 20;',
    to: 'if (propBhk === searchBhk) score += 10;',
  },
  {
    id: 'city-lost',
    label: 'the matching city stops outranking another city',
    file: UTIL,
    from: 'if (pCity === filters.city.toLowerCase()) score += 20;',
    to: 'if (pCity === filters.city.toLowerCase()) score += 5;',
  },
  {
    id: 'intent-lost',
    label: 'rent-vs-sale intent stops mattering',
    file: UTIL,
    from: 'score += 25;',
    to: 'score += 0;',
  },
  {
    id: 'category-crossover',
    label: 'a shop is suggested to someone searching for a flat',
    file: UTIL,
    from: 'if (isLookingForResidential && isCommercial && !isResidential) return false;',
    to: 'if (false) return false;',
  },
  {
    id: 'fields-dropped',
    label: 'scoring returns bare scores instead of properties',
    file: UTIL,
    from: 'return { ...p, relevanceScore: score };',
    to: 'return { _id: p._id, relevanceScore: score };',
  },
  {
    id: 'crash-on-null',
    label: 'a null entry in the pool throws',
    file: UTIL,
    from: '.filter((p) => p && p._id && !matchedIds.has(String(p._id)))',
    to: '.filter((p) => !matchedIds.has(String(p._id)))',
  },
  // -- the wiring, which is where it died last time --------------------------
  {
    id: 'WIRING-no-fetch',
    label: 'the pool request is removed, leaving nothing to rank',
    file: PAGE,
    from: 'const res = await api.get("/properties/search", { params: relatedPoolParams() });',
    to: 'const res = { data: {} };',
  },
  {
    id: 'WIRING-unconditional',
    label: 'the pool is fetched on every search, ignoring the rule',
    file: PAGE,
    from: 'if (!shouldSuggestRelated(filters, properties.length)) {',
    to: 'if (false) {',
  },
];

const run = () => {
  try {
    execFileSync(process.execPath, ['--test', 'tests/related-properties.test.js'],
      { cwd: backend, stdio: 'pipe', timeout: 300000 });
    return { failed: 0 };
  } catch (e) {
    const out = String(e.stdout || '') + String(e.stderr || '');
    const m = out.match(/^# fail (\d+)$/m) || out.match(/fail (\d+)/);
    return { failed: m ? Number(m[1]) : -1 };
  }
};

let killed = 0, survived = 0;

for (const m of MUTATIONS) {
  const target = p(m.file);
  const original = readFileSync(target, 'utf8');

  try {
    const anchor = original.includes(m.from) ? m.from : m.from.replace(/\n/g, '\r\n');
    if (!original.includes(anchor)) {
      console.log(`  ERROR    ${m.id.padEnd(20)} anchor not found: ${m.from.slice(0, 45)}`);
      survived += 1;
      continue;
    }
    writeFileSync(target, original.replace(anchor, m.to.replace(/\n/g, '\r\n')));

    const { failed } = run();
    const dead = failed > 0;
    dead ? (killed += 1) : (survived += 1);
    console.log(`  ${dead ? 'KILLED  ' : 'SURVIVED'} ${m.id.padEnd(20)} ${m.label}  (${failed} failing)`);
  } finally {
    writeFileSync(target, original);
  }
}

console.log(`\n${killed} killed, ${survived} survived, of ${MUTATIONS.length}`);
process.exit(survived === 0 ? 0 : 1);
