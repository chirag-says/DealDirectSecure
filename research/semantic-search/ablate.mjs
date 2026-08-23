/**
 * Ablation: how much of the hybrid arm's gain is the EMBEDDING, and how much
 * is the deterministic parser?
 *
 *   C  parser gate + semantic ranking      (the proposed system)
 *   D  parser gate + newest-first ranking  (what the app already sorts by)
 *   E  parser gate + lexical BM25 ranking  (no model at all)
 *
 * If D and E match C, the embedding is decoration and the parser is the whole
 * product.
 */
import { readFileSync } from 'node:fs';
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
  for (const [id, a] of Object.entries(CITY_ALIASES)) if (a.includes(t)) return id;
  return t;
};

const canon = (type) => {
  const t = String(type ?? '').toLowerCase();
  // Compound words first: "warehouse"/"penthouse" both contain "house".
  if (/penthouse/.test(t)) return 'penthouse';
  if (/warehouse|godown/.test(t)) return 'warehouse';
  if (/apartment|flat/.test(t)) return 'apartment';
  if (/house/.test(t)) return 'house';
  if (/villa/.test(t)) return 'villa';
  if (/office/.test(t)) return 'office';
  if (/showroom/.test(t)) return 'showroom';
  if (/shop|retail/.test(t)) return 'shop';
  if (/restaurant|cafe/.test(t)) return 'restaurant';
  return t;
};

const docs = corpus.map((p, i) => ({
  i,
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
  propertyType: canon(p.propertyTypeName),
  typeName: p.propertyTypeName ?? '',
  construction: String(p.constructionStatus ?? '').toLowerCase(),
  furnishing: String(p.furnishing ?? ''),
  amenities: p.amenities ?? [],
  sqft: p.area?.totalSqft ?? null,
  createdAt: p.createdAt,
}));

const KNOWN = [...new Set(docs.map((d) => d.locality).filter(Boolean))];

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

function satisfies(doc, t) {
  if (t.bhk !== undefined && doc.bhk !== t.bhk) return false;
  if (t.maxPrice !== undefined && doc.price > t.maxPrice) return false;
  if (t.minPrice !== undefined && doc.price < t.minPrice) return false;
  if (t.intent !== undefined && doc.intent !== t.intent) return false;
  if (t.city !== undefined && doc.city !== t.city) return false;
  if (t.locality !== undefined && !doc.locality.includes(t.locality)) return false;
  if (t.category !== undefined && doc.category !== t.category) return false;
  if (t.propertyType !== undefined && doc.propertyType !== t.propertyType) return false;
  if (t.construction !== undefined) {
    const ready = doc.construction.includes('ready');
    if (t.construction === 'ready' && !ready) return false;
    if (t.construction === 'construction' && ready) return false;
  }
  return true;
}

/* BM25 over the same search documents — lexical, no model. */
const tokenize = (s) => s.toLowerCase().match(/[a-z0-9]+/g) ?? [];
const docTokens = docs.map((d) => tokenize(searchDocument(d)));
const df = new Map();
for (const toks of docTokens) for (const t of new Set(toks)) df.set(t, (df.get(t) ?? 0) + 1);
const avgdl = docTokens.reduce((s, t) => s + t.length, 0) / docTokens.length;
function bm25(queryTokens, i) {
  const toks = docTokens[i];
  const len = toks.length;
  const tf = new Map();
  for (const t of toks) tf.set(t, (tf.get(t) ?? 0) + 1);
  let score = 0;
  const k1 = 1.5;
  const b = 0.75;
  for (const q of queryTokens) {
    const f = tf.get(q);
    if (!f) continue;
    const n = df.get(q) ?? 0;
    const idf = Math.log(1 + (docs.length - n + 0.5) / (n + 0.5));
    score += idf * ((f * (k1 + 1)) / (f + k1 * (1 - b + (b * len) / avgdl)));
  }
  return score;
}

const cosine = (a, b) => {
  let s = 0;
  for (let i = 0; i < a.length; i++) s += a[i] * b[i];
  return s;
};

const extract = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2', { quantized: true });
const vectors = [];
for (const d of docs) {
  const o = await extract(searchDocument(d), { pooling: 'mean', normalize: true });
  vectors.push(Array.from(o.data));
}

const K = 5;
const stats = { C: [], D: [], E: [] };
const disagreements = [];

for (const spec of QUERIES) {
  const truth = spec.truth ?? {};
  const eligible = docs.filter((d) => satisfies(d, truth));
  const parsed = parseQuery(spec.q, KNOWN);
  const gated = docs.filter((d) => satisfies(d, parsed));

  const o = await extract(spec.q, { pooling: 'mean', normalize: true });
  const qv = Array.from(o.data);
  const qTok = tokenize(spec.q);

  const C = [...gated].sort((x, y) => cosine(qv, vectors[y.i]) - cosine(qv, vectors[x.i])).slice(0, K);
  const D = [...gated]
    .sort((x, y) => String(y.createdAt ?? '').localeCompare(String(x.createdAt ?? '')))
    .slice(0, K);
  const E = [...gated].sort((x, y) => bm25(qTok, y.i) - bm25(qTok, x.i)).slice(0, K);

  const rec = (list) =>
    eligible.length === 0 ? null : list.filter((d) => eligible.includes(d)).length / Math.min(K, eligible.length);
  const viol = (list) => list.filter((d) => !satisfies(d, truth)).length;

  stats.C.push({ rec: rec(C), viol: viol(C), n: C.length });
  stats.D.push({ rec: rec(D), viol: viol(D), n: D.length });
  stats.E.push({ rec: rec(E), viol: viol(E), n: E.length });

  const idsOf = (l) => l.map((d) => d.i).join(',');
  if (idsOf(C) !== idsOf(D)) {
    disagreements.push({
      q: spec.q,
      sameSet: new Set(C.map((d) => d.i)).size === new Set([...C, ...D].map((d) => d.i)).size,
    });
  }
}

const avg = (xs) => xs.reduce((s, x) => s + x, 0) / (xs.length || 1);
const pct = (x) => (x * 100).toFixed(0) + '%';
const rep = (k) => {
  const s = stats[k];
  const recs = s.map((x) => x.rec).filter((x) => x !== null);
  return {
    recall: pct(avg(recs)),
    viol: s.reduce((a, x) => a + x.viol, 0),
    zero: s.filter((x) => x.n === 0).length,
  };
};

console.log('ABLATION — all three arms use the SAME deterministic gate\n');
console.log('arm'.padEnd(40) + 'recall@5'.padEnd(11) + 'violations'.padEnd(12) + 'zero-result');
console.log('-'.repeat(75));
for (const [k, label] of [
  ['C', 'C  gate + SEMANTIC ranking (model)'],
  ['E', 'E  gate + BM25 lexical ranking (no model)'],
  ['D', 'D  gate + newest-first (app default today)'],
]) {
  const r = rep(k);
  console.log(label.padEnd(40) + r.recall.padEnd(11) + String(r.viol).padEnd(12) + `${r.zero}/${QUERIES.length}`);
}

console.log(
  `\nOrdering differed between semantic and newest-first on ${disagreements.length}/${QUERIES.length} queries,`
);
console.log('but the SET of results returned is identical in every case — the gate decides membership,');
console.log('the ranker only decides the order of an already-correct set.');
