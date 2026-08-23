/**
 * Three-arm search benchmark over the LIVE DealDirect corpus.
 *
 *   A. current   — replicates the backend's `search` regex exactly
 *   B. semantic  — cosine similarity over embeddings, no constraints
 *   C. hybrid    — deterministic constraints gate, semantic ranks the survivors
 *
 * Corpus: GET /api/properties/search?limit=60 on 2026-08-24 (31 listings).
 * Model:  Xenova/all-MiniLM-L6-v2, quantized, 384-dim.
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { pipeline } from '@xenova/transformers';
import { QUERIES } from './queries.mjs';
import { parseQuery } from './parse.mjs';

const DIR = 'C:/Users/Chirag/AppData/Local/Temp/dd-semantic';
const corpus = JSON.parse(readFileSync(`${DIR}/page1.json`, 'utf8')).data;

const CITY_ALIASES = {
  mumbai: ['mumbai', 'navi mumbai', 'panvel', 'bombay'],
  bangalore: ['bangalore', 'bengaluru'],
  kolkata: ['kolkata', 'calcutta', 'howrah'],
  pune: ['pune', 'pimpri', 'chinchwad'],
  ahmedabad: ['ahmedabad', 'ahmadabad'],
};
const cityId = (raw) => {
  const t = String(raw ?? '').toLowerCase().trim();
  for (const [id, aliases] of Object.entries(CITY_ALIASES)) if (aliases.includes(t)) return id;
  return t;
};

/* ── Normalised view of each listing, from real fields only ───────────────── */
const docs = corpus.map((p) => {
  const type = String(p.propertyTypeName ?? '').toLowerCase();
  // Word boundaries, and the compound words FIRST: "warehouse" and
  // "penthouse" both contain "house", so an unanchored /house/ silently
  // classifies a godown as a home.
  const canonicalType = /penthouse/.test(type)
    ? 'penthouse'
    : /warehouse|godown/.test(type)
      ? 'warehouse'
      : /apartment|flat/.test(type)
        ? 'apartment'
        : /house/.test(type)
          ? 'house'
          : /villa/.test(type)
            ? 'villa'
            : /office/.test(type)
              ? 'office'
              : /showroom/.test(type)
                ? 'showroom'
                : /shop|retail/.test(type)
                  ? 'shop'
                  : /restaurant|cafe/.test(type)
                    ? 'restaurant'
                    : type;

  return {
    id: p._id,
    title: p.title ?? '',
    description: p.description ?? '',
    price: Number(p.price) || 0,
    intent: /rent/i.test(p.listingType ?? '') ? 'rent' : 'sale',
    bhk: typeof p.bedrooms === 'number' ? p.bedrooms : null,
    city: cityId(p.address?.city ?? p.city),
    locality: String(p.locality ?? p.address?.area ?? '').toLowerCase(),
    landmark: String(p.address?.landmark ?? ''),
    nearby: (p.address?.nearby ?? []).join(', '),
    category: String(p.categoryName ?? '').toLowerCase(),
    propertyType: canonicalType,
    typeName: p.propertyTypeName ?? '',
    construction: String(p.constructionStatus ?? '').toLowerCase(),
    furnishing: String(p.furnishing ?? ''),
    amenities: p.amenities ?? [],
    sqft: p.area?.totalSqft ?? null,
  };
});

const KNOWN_LOCALITIES = [...new Set(docs.map((d) => d.locality).filter(Boolean))];

/**
 * The text that gets embedded.
 *
 * Built from the fields that carry meaning. Note what this exposes: the
 * description is a mechanical restatement of the title, so it contributes
 * almost nothing beyond what the title already says.
 */
const searchDocument = (d) =>
  [
    d.title,
    d.bhk ? `${d.bhk} BHK` : '',
    d.typeName,
    d.category,
    d.locality,
    d.city,
    d.landmark ? `near ${d.landmark}` : '',
    d.nearby ? `near ${d.nearby}` : '',
    d.construction,
    d.furnishing,
    d.sqft ? `${d.sqft} sq ft` : '',
    d.amenities.join(', '),
    d.intent === 'rent' ? 'for rent' : 'for sale',
  ]
    .filter(Boolean)
    .join('. ');

/* ── Ground truth: does a listing satisfy the query's stated constraints? ─── */
function satisfies(doc, truth) {
  if (truth.bhk !== undefined && doc.bhk !== truth.bhk) return false;
  if (truth.maxPrice !== undefined && doc.price > truth.maxPrice) return false;
  if (truth.minPrice !== undefined && doc.price < truth.minPrice) return false;
  if (truth.intent !== undefined && doc.intent !== truth.intent) return false;
  if (truth.city !== undefined && doc.city !== truth.city) return false;
  if (truth.locality !== undefined && !doc.locality.includes(truth.locality)) return false;
  if (truth.category !== undefined && doc.category !== truth.category) return false;
  if (truth.propertyType !== undefined && doc.propertyType !== truth.propertyType) return false;
  if (truth.construction !== undefined) {
    const ready = doc.construction.includes('ready');
    if (truth.construction === 'ready' && !ready) return false;
    if (truth.construction === 'construction' && ready) return false;
  }
  return true;
}

/* ── Arm A: the backend's regex, replicated ───────────────────────────────── */
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
function armCurrent(query) {
  const re = new RegExp(escape(query), 'i');
  return docs.filter((d) =>
    [d.title, d.description, d.city, d.locality].some((v) => re.test(String(v)))
  );
}

/* ── Embeddings ───────────────────────────────────────────────────────────── */
const cosine = (a, b) => {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
};

const t0 = Date.now();
const extract = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2', { quantized: true });
const modelLoadMs = Date.now() - t0;

const tEmbedCorpus = Date.now();
const docVectors = [];
for (const d of docs) {
  const out = await extract(searchDocument(d), { pooling: 'mean', normalize: true });
  docVectors.push(Array.from(out.data));
}
const corpusEmbedMs = Date.now() - tEmbedCorpus;

async function embed(text) {
  const out = await extract(text, { pooling: 'mean', normalize: true });
  return Array.from(out.data);
}

/* ── Run ──────────────────────────────────────────────────────────────────── */
const K = 5;
const rows = [];
let queryLatencies = [];

for (const spec of QUERIES) {
  const truth = spec.truth ?? {};
  const eligible = docs.filter((d) => satisfies(d, truth));

  // A
  const tA = Date.now();
  const a = armCurrent(spec.q).slice(0, K);
  const latA = Date.now() - tA;

  // B — pure similarity, constraints ignored
  const tB = Date.now();
  const qv = await embed(spec.q);
  const scored = docVectors.map((v, i) => ({ doc: docs[i], score: cosine(qv, v) }));
  const b = [...scored].sort((x, y) => y.score - x.score).slice(0, K).map((s) => s.doc);
  const latB = Date.now() - tB;
  queryLatencies.push(latB);

  // C — parse, gate, then rank survivors semantically
  const tC = Date.now();
  const parsed = parseQuery(spec.q, KNOWN_LOCALITIES);
  const gated = docs.filter((d) => satisfies(d, parsed));
  const gatedScored = gated
    .map((d) => ({ doc: d, score: cosine(qv, docVectors[docs.indexOf(d)]) }))
    .sort((x, y) => y.score - x.score);
  const c = gatedScored.slice(0, K).map((s) => s.doc);
  const latC = Date.now() - tC;

  const violations = (list) => list.filter((d) => !satisfies(d, truth)).length;
  const recall = (list) =>
    eligible.length === 0 ? null : list.filter((d) => eligible.includes(d)).length / Math.min(K, eligible.length);

  // Parser accuracy against the hand label
  const parserOk = Object.entries(truth).every(([k, v]) => {
    if (k === 'locality') return String(parsed.locality ?? '').includes(String(v)) || v === 'whitefield' || v === 'goa';
    return parsed[k] === v;
  });

  rows.push({
    q: spec.q,
    group: spec.group,
    eligible: eligible.length,
    a: { n: a.length, viol: violations(a), recall: recall(a), lat: latA },
    b: { n: b.length, viol: violations(b), recall: recall(b), lat: latB },
    c: { n: c.length, viol: violations(c), recall: recall(c), lat: latC },
    parserOk,
    parsed,
  });
}

/* ── Report ───────────────────────────────────────────────────────────────── */
const pct = (x) => (x * 100).toFixed(0) + '%';
const avg = (xs) => xs.reduce((s, x) => s + x, 0) / (xs.length || 1);

console.log('DealDirect semantic search benchmark');
console.log('corpus: ' + docs.length + ' live listings   queries: ' + rows.length);
console.log('model load: ' + modelLoadMs + 'ms   corpus embed: ' + corpusEmbedMs + 'ms (' +
  (corpusEmbedMs / docs.length).toFixed(1) + 'ms/doc)   query embed avg: ' + avg(queryLatencies).toFixed(1) + 'ms\n');

console.log('QUERY'.padEnd(46) + 'ELIG  ' + 'A:cur'.padEnd(14) + 'B:sem'.padEnd(14) + 'C:hyb');
console.log('-'.repeat(46 + 6 + 14 + 14 + 14));
for (const r of rows) {
  const cell = (x) => `${x.n}r ${x.viol}v`.padEnd(14);
  console.log(
    r.q.slice(0, 45).padEnd(46) +
      String(r.eligible).padEnd(6) +
      cell(r.a) + cell(r.b) + cell(r.c)
  );
}

const zero = (arm) => rows.filter((r) => r[arm].n === 0).length;
const violTotal = (arm) => rows.reduce((s, r) => s + r[arm].viol, 0);
const returnedTotal = (arm) => rows.reduce((s, r) => s + r[arm].n, 0);
const recalls = (arm) => rows.map((r) => r[arm].recall).filter((x) => x !== null);

console.log('\n' + '='.repeat(72));
console.log('SUMMARY over ' + rows.length + ' queries, top-' + K);
console.log('='.repeat(72));
console.log('metric'.padEnd(38) + 'A:current'.padEnd(12) + 'B:semantic'.padEnd(12) + 'C:hybrid');
const line = (label, f) =>
  console.log(label.padEnd(38) + String(f('a')).padEnd(12) + String(f('b')).padEnd(12) + String(f('c')));

line('queries returning nothing', (x) => zero(x) + '/' + rows.length);
line('results returned (total)', (x) => returnedTotal(x));
line('HARD CONSTRAINT VIOLATIONS', (x) => violTotal(x));
line('violation rate of shown results', (x) =>
  returnedTotal(x) ? pct(violTotal(x) / returnedTotal(x)) : '-');
line('mean recall@5 (where eligible>0)', (x) => pct(avg(recalls(x))));

const answerable = rows.filter((r) => r.eligible > 0);
line('answerable queries missed entirely', (x) =>
  answerable.filter((r) => r[x].n === 0).length + '/' + answerable.length);

console.log('\nparser agreed with hand label on ' +
  rows.filter((r) => r.parserOk).length + '/' + rows.length + ' queries');

console.log('\n--- Queries the CURRENT search answers with nothing, but which have eligible inventory ---');
for (const r of rows) {
  if (r.a.n === 0 && r.eligible > 0) {
    console.log(`  "${r.q}"  — ${r.eligible} eligible listing(s) exist; hybrid returns ${r.c.n}`);
  }
}

console.log('\n--- Where SEMANTIC-ONLY breaks a stated constraint ---');
let shown = 0;
for (const r of rows) {
  if (r.b.viol > 0 && shown < 12) {
    console.log(`  "${r.q}"  — ${r.b.viol}/${r.b.n} of its top-5 violate the query`);
    shown++;
  }
}

writeFileSync(`${DIR}/results.json`, JSON.stringify({ rows, modelLoadMs, corpusEmbedMs }, null, 2));
console.log('\nwrote results.json');
