/**
 * The 59-query benchmark, re-run against the SHIPPED parser.
 *
 *   A. current  — replicates the backend's `search` regex exactly
 *   B. parsed   — query understanding gates, existing sort orders
 *
 * The prototype parser used for the original investigation is gone; this
 * imports `dealdirect-mobile/src/features/search/understanding` directly, so
 * the numbers describe the code that actually ships.
 *
 * Run:  node research/semantic-search/benchmark-parser.mjs
 * Node 24+ (strips TypeScript natively; no build step, no dependency).
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { QUERIES } from './queries.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MODULE = path.resolve(HERE, '../../dealdirect-mobile/src/features/search/understanding');

// pathToFileURL, because a Windows absolute path is not a valid ESM specifier.
const { parseQuery } = await import(pathToFileURL(path.join(MODULE, 'parse.ts')).href);

const corpus = JSON.parse(readFileSync(path.join(HERE, 'corpus-2026-08-24.json'), 'utf8')).data;

/* ── Normalised corpus, from real fields only ─────────────────────────────── */
const CITY_ALIASES = {
  mumbai: ['mumbai', 'navi mumbai', 'panvel', 'bombay'],
  bangalore: ['bangalore', 'bengaluru'],
  kolkata: ['kolkata', 'calcutta', 'howrah'],
  pune: ['pune', 'pimpri', 'chinchwad'],
  ahmedabad: ['ahmedabad', 'ahmadabad'],
};
const cityId = (raw) => {
  const t = String(raw ?? '').toLowerCase().trim();
  for (const [id, a] of Object.entries(CITY_ALIASES)) if (a.includes(t)) return id;
  return t;
};

/** Compound words first — "warehouse" and "penthouse" both contain "house". */
const canon = (type) => {
  const t = String(type ?? '').toLowerCase();
  if (/\bpenthouse\b/.test(t)) return 'penthouse';
  if (/\bwarehouse\b|\bgodown\b/.test(t)) return 'warehouse';
  if (/\bapartment\b|\bflat\b/.test(t)) return 'apartment';
  if (/\bhouse\b/.test(t)) return 'house';
  if (/\bvilla\b/.test(t)) return 'villa';
  if (/\boffice\b/.test(t)) return 'office';
  if (/\bshowroom\b/.test(t)) return 'showroom';
  if (/\bshop\b|\bretail\b/.test(t)) return 'shop';
  if (/\brestaurant\b|\bcafe\b/.test(t)) return 'restaurant';
  return t;
};

const docs = corpus.map((p) => ({
  title: p.title ?? '',
  description: p.description ?? '',
  price: Number(p.price) || 0,
  transaction: /rent/i.test(p.listingType ?? '') ? 'rent' : 'sale',
  bhk: typeof p.bedrooms === 'number' ? p.bedrooms : null,
  city: cityId(p.address?.city ?? p.city),
  locality: String(p.locality ?? p.address?.area ?? '').toLowerCase().replace(/\s+/g, ' ').trim(),
  category: String(p.categoryName ?? '').toLowerCase(),
  propertyType: canon(p.propertyTypeName),
  construction: String(p.constructionStatus ?? '').toLowerCase(),
  createdAt: p.createdAt,
}));

const CONTEXT = {
  cities: Object.entries(CITY_ALIASES).map(([id, aliases]) => ({
    id,
    label: id[0].toUpperCase() + id.slice(1),
    aliases,
  })),
  localities: [...new Set(docs.map((d) => d.locality).filter((l) => l.length >= 3))],
};

/** Does a listing satisfy a constraint set? Used for both truth and gating. */
function satisfies(doc, c) {
  if (c.bhk !== undefined && doc.bhk !== c.bhk) return false;
  if (c.maxPrice !== undefined && doc.price > c.maxPrice) return false;
  if (c.minPrice !== undefined && doc.price < c.minPrice) return false;
  if (c.transaction !== undefined && doc.transaction !== c.transaction) return false;
  if (c.intent !== undefined && doc.transaction !== c.intent) return false;
  if (c.city !== undefined && doc.city !== c.city) return false;
  if (c.locality !== undefined && !doc.locality.includes(c.locality)) return false;
  if (c.category !== undefined && doc.category !== c.category) return false;
  if (c.propertyType !== undefined && doc.propertyType !== c.propertyType) return false;
  if (c.construction !== undefined) {
    const ready = doc.construction.includes('ready');
    if (c.construction === 'ready' && !ready) return false;
    if (c.construction === 'construction' && ready) return false;
  }
  return true;
}

/* ── Arm A: the backend regex ─────────────────────────────────────────────── */
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const armCurrent = (q) => {
  const re = new RegExp(escape(q), 'i');
  return docs.filter((d) => [d.title, d.description, d.city, d.locality].some((v) => re.test(String(v))));
};

/* ── Arm B: parse, gate, then the app's existing newest-first order ───────── */
const armParsed = (q) => {
  const parsed = parseQuery(q, CONTEXT);
  const gated = docs.filter((d) => satisfies(d, parsed.hard));
  const residual = parsed.residual.trim();

  // Residual text still goes to the server's regex, exactly as it does in the
  // app. Applied here as an AND so the benchmark matches shipped behaviour.
  const withText = residual
    ? gated.filter((d) => new RegExp(escape(residual), 'i').test(`${d.title} ${d.locality} ${d.city}`))
    : gated;

  return {
    results: [...withText].sort((a, b) => String(b.createdAt ?? '').localeCompare(String(a.createdAt ?? ''))),
    parsed,
  };
};

/* ── Run ──────────────────────────────────────────────────────────────────── */
const K = 5;
const rows = [];
let parseTotalMs = 0;

for (const spec of QUERIES) {
  const truth = spec.truth ?? {};
  const eligible = docs.filter((d) => satisfies(d, truth));

  const a = armCurrent(spec.q).slice(0, K);

  const t0 = process.hrtime.bigint();
  const { results, parsed } = armParsed(spec.q);
  parseTotalMs += Number(process.hrtime.bigint() - t0) / 1e6;
  const b = results.slice(0, K);

  const viol = (list) => list.filter((d) => !satisfies(d, truth)).length;
  const recall = (list) =>
    eligible.length === 0 ? null : list.filter((d) => eligible.includes(d)).length / Math.min(K, eligible.length);

  rows.push({
    q: spec.q,
    group: spec.group,
    eligible: eligible.length,
    a: { n: a.length, viol: viol(a), recall: recall(a) },
    b: { n: b.length, viol: viol(b), recall: recall(b) },
    parsed,
  });
}

const pct = (x) => (x * 100).toFixed(0) + '%';
const avg = (xs) => (xs.length ? xs.reduce((s, x) => s + x, 0) / xs.length : 0);
const zero = (k) => rows.filter((r) => r[k].n === 0).length;
const violTotal = (k) => rows.reduce((s, r) => s + r[k].viol, 0);
const shown = (k) => rows.reduce((s, r) => s + r[k].n, 0);
const recalls = (k) => rows.map((r) => r[k].recall).filter((x) => x !== null);
const answerable = rows.filter((r) => r.eligible > 0);

console.log('DealDirect query-understanding benchmark');
console.log(`corpus ${docs.length} live listings · ${rows.length} queries · top-${K}`);
console.log(`parse cost: ${(parseTotalMs / rows.length).toFixed(3)} ms per query (mean)\n`);

console.log('metric'.padEnd(38) + 'A: current'.padEnd(14) + 'B: understood');
console.log('-'.repeat(66));
const line = (label, f) => console.log(label.padEnd(38) + String(f('a')).padEnd(14) + String(f('b')));
line('queries returning nothing', (k) => `${zero(k)}/${rows.length}`);
line('results shown (total)', (k) => shown(k));
line('HARD CONSTRAINT VIOLATIONS', (k) => violTotal(k));
line('violation rate of shown results', (k) => (shown(k) ? pct(violTotal(k) / shown(k)) : '-'));
line('mean recall@5', (k) => pct(avg(recalls(k))));
line('answerable queries missed', (k) => `${answerable.filter((r) => r[k].n === 0).length}/${answerable.length}`);

console.log('\nBY QUERY TYPE');
console.log('type'.padEnd(18) + 'n'.padEnd(4) + 'A empty'.padEnd(10) + 'B empty'.padEnd(10) + 'A recall'.padEnd(10) + 'B recall');
const groups = {};
for (const r of rows) (groups[r.group] ??= []).push(r);
for (const [name, list] of Object.entries(groups)) {
  const ar = list.map((r) => r.a.recall).filter((x) => x !== null);
  const br = list.map((r) => r.b.recall).filter((x) => x !== null);
  console.log(
    name.padEnd(18) +
      String(list.length).padEnd(4) +
      `${list.filter((r) => r.a.n === 0).length}/${list.length}`.padEnd(10) +
      `${list.filter((r) => r.b.n === 0).length}/${list.length}`.padEnd(10) +
      pct(avg(ar)).padEnd(10) +
      pct(avg(br))
  );
}

const fixed = rows.filter((r) => r.a.n === 0 && r.b.n > 0);
console.log(`\nQueries the current search answers with NOTHING, now answered: ${fixed.length}`);
for (const r of fixed.slice(0, 12)) console.log(`  "${r.q}" → ${r.b.n} result(s)`);
if (fixed.length > 12) console.log(`  … and ${fixed.length - 12} more`);

const stillEmpty = rows.filter((r) => r.b.n === 0);
console.log(`\nStill empty under understanding: ${stillEmpty.length}`);
for (const r of stillEmpty) {
  console.log(`  "${r.q}" — ${r.eligible} eligible ${r.eligible === 0 ? '(correctly empty)' : '(MISSED)'}`);
}

const violating = rows.filter((r) => r.b.viol > 0);
console.log(`
Queries where understanding shows a result violating the hand label: ${violating.length}`);
for (const r of violating) {
  console.log(`  "${r.q}" — ${r.b.viol}/${r.b.n}  parsed=${JSON.stringify(r.parsed.hard)}`);
}

const regressions = rows.filter((r) => r.a.n > 0 && r.b.n === 0 && r.eligible > 0);
console.log(`\nRegressions (current answered, understanding does not, inventory exists): ${regressions.length}`);
for (const r of regressions) console.log(`  "${r.q}"`);
