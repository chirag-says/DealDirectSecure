/**
 * Deterministic query parser.
 *
 * Extracts the constraints that must stay authoritative (intent, BHK, price,
 * city, locality, category, construction status) from Indian-market natural
 * language. No model, no API — this is arithmetic and a lexicon, which is why
 * it can be trusted to gate results rather than merely rank them.
 */

export const LAKH = 100_000;
export const CRORE = 10_000_000;

/** Cities the app already knows, from features/home/cities.ts, plus aliases. */
export const CITY_ALIASES = {
  mumbai: ['mumbai', 'navi mumbai', 'panvel', 'bombay'],
  delhi: ['delhi', 'delhi ncr', 'new delhi'],
  bangalore: ['bangalore', 'bengaluru', 'blr'],
  hyderabad: ['hyderabad', 'secunderabad'],
  pune: ['pune', 'pimpri', 'chinchwad'],
  chennai: ['chennai', 'madras'],
  kolkata: ['kolkata', 'calcutta', 'howrah'],
  ahmedabad: ['ahmedabad', 'ahmadabad', 'amdavad'],
  gurgaon: ['gurgaon', 'gurugram'],
  noida: ['noida', 'greater noida'],
  chandigarh: ['chandigarh', 'mohali'],
  jaipur: ['jaipur'],
  ranchi: ['ranchi'],
};

/**
 * Domain synonyms. This is the layer that fixes the failures actually observed
 * against production: "home" returns 0 today because no title contains the
 * word, and every residential title says "Apartment / Flat" or "House".
 */
export const TYPE_SYNONYMS = {
  apartment: ['apartment', 'flat', 'flats', 'apartments'],
  house: ['house', 'independent house', 'bungalow', 'row house'],
  villa: ['villa', 'villas'],
  penthouse: ['penthouse'],
  plot: ['plot', 'land', 'plots'],
  office: ['office', 'office space', 'workspace', 'coworking'],
  shop: ['shop', 'retail', 'store'],
  showroom: ['showroom'],
  warehouse: ['warehouse', 'godown', 'storage'],
  restaurant: ['restaurant', 'cafe', 'cloud kitchen'],
};

/** Words that mean "somewhere a family lives", not a specific built form. */
const RESIDENTIAL_WORDS = [
  'home',
  'homes',
  'house',
  'flat',
  'apartment',
  'villa',
  'penthouse',
  'bhk',
  'rk',
  'family',
  'living',
  'residence',
];

const COMMERCIAL_WORDS = [
  'office',
  'shop',
  'retail',
  'showroom',
  'warehouse',
  'godown',
  'commercial',
  'restaurant',
  'cafe',
  'business',
  'workspace',
];

/**
 * Money, in every form Indians actually type.
 *
 * Handles: "1 cr", "1.2 crore", "80L", "80 lakhs", "under 1.5cr",
 * "between 50L and 1cr", "₹1,25,00,000", "25k" (rent).
 */
export function parsePrice(text) {
  const t = text.toLowerCase().replace(/,/g, '');
  const amounts = [];

  const re =
    /(?:₹|rs\.?|inr)?\s*(\d+(?:\.\d+)?)\s*(cr|crore|crores|l|lac|lacs|lakh|lakhs|k|thousand)?/g;
  let m;
  while ((m = re.exec(t)) !== null) {
    const n = parseFloat(m[1]);
    const unit = m[2];
    if (!unit) {
      // A bare number is only money if it is large enough to be money. "3" in
      // "3 bhk" must never become ₹3.
      if (n >= 10000) amounts.push({ value: n, at: m.index, raw: m[0] });
      continue;
    }
    if (/^(cr|crore|crores)$/.test(unit)) amounts.push({ value: n * CRORE, at: m.index, raw: m[0] });
    else if (/^(l|lac|lacs|lakh|lakhs)$/.test(unit))
      amounts.push({ value: n * LAKH, at: m.index, raw: m[0] });
    else amounts.push({ value: n * 1000, at: m.index, raw: m[0] });
  }

  if (amounts.length === 0) return {};

  const hasUnder = /\b(under|below|less than|upto|up to|within|max|maximum|budget of|budget)\b/.test(t);
  const hasOver = /\b(above|over|more than|minimum|min|starting|from)\b/.test(t);
  const hasBetween = /\b(between|to|and|-)\b/.test(t) && amounts.length >= 2;

  if (hasBetween && amounts.length >= 2) {
    const sorted = [...amounts].sort((a, b) => a.value - b.value);
    return { minPrice: sorted[0].value, maxPrice: sorted[sorted.length - 1].value };
  }
  if (hasOver && !hasUnder) return { minPrice: amounts[0].value };
  // Default reading of a bare budget is a ceiling: "3 bhk 1 crore" means at
  // most a crore, which is how people speak about budgets.
  return { maxPrice: amounts[0].value };
}

/** "2bhk", "2 bhk", "3-bhk", "1 rk", "two bhk". */
export function parseBhk(text) {
  const t = text.toLowerCase();
  if (/\b1\s*rk\b|\brk\b/.test(t)) return { bhk: 0 };

  const digit = t.match(/\b(\d)\s*-?\s*(?:bhk|bedroom|bed|br)\b/);
  if (digit) return { bhk: parseInt(digit[1], 10) };

  const words = { one: 1, two: 2, three: 3, four: 4, five: 5 };
  const word = t.match(/\b(one|two|three|four|five)\s*-?\s*(?:bhk|bedroom|bed)\b/);
  if (word) return { bhk: words[word[1]] };

  return {};
}

/** Buy versus rent. Sale is the default only when the query says so. */
export function parseIntent(text) {
  const t = text.toLowerCase();
  if (/\b(rent|rental|lease|renting|tenant|to let|pg)\b/.test(t)) return { intent: 'rent' };
  if (/\b(buy|sale|purchase|buying|own|investment|invest)\b/.test(t)) return { intent: 'sale' };
  return {};
}

export function parseCity(text) {
  const t = text.toLowerCase();
  for (const [id, aliases] of Object.entries(CITY_ALIASES)) {
    if (aliases.some((a) => new RegExp(`\\b${a}\\b`).test(t))) return { city: id };
  }
  return {};
}

/** Localities are matched against the ones the live corpus actually contains. */
export function parseLocality(text, knownLocalities) {
  const t = text.toLowerCase();
  const hit = knownLocalities
    .filter((l) => l && l.length >= 4 && t.includes(l.toLowerCase()))
    .sort((a, b) => b.length - a.length)[0];
  return hit ? { locality: hit } : {};
}

export function parseType(text) {
  const t = text.toLowerCase();
  for (const [canonical, words] of Object.entries(TYPE_SYNONYMS)) {
    if (words.some((w) => new RegExp(`\\b${w}\\b`).test(t))) return { propertyType: canonical };
  }
  return {};
}

export function parseCategory(text) {
  const t = text.toLowerCase();
  const com = COMMERCIAL_WORDS.some((w) => new RegExp(`\\b${w}\\b`).test(t));
  const res = RESIDENTIAL_WORDS.some((w) => new RegExp(`\\b${w}\\b`).test(t));
  if (com && !res) return { category: 'commercial' };
  if (res && !com) return { category: 'residential' };
  return {};
}

export function parseConstruction(text) {
  const t = text.toLowerCase();
  if (/\b(ready to move|ready possession|ready|move in|immediate)\b/.test(t))
    return { construction: 'ready' };
  if (/\b(under construction|new launch|pre launch|upcoming)\b/.test(t))
    return { construction: 'construction' };
  return {};
}

/** Soft signals. These may influence RANKING and may never gate results. */
export const SOFT_SIGNALS = {
  family: ['family', 'kids', 'children', 'school'],
  metro: ['metro', 'station', 'railway', 'transit'],
  it: ['it park', 'itpl', 'tech park', 'it companies', 'office commute', 'it professional'],
  luxury: ['luxury', 'premium', 'posh', 'upscale', 'high end'],
  affordable: ['affordable', 'cheap', 'budget', 'low cost', 'economical'],
  investment: ['investment', 'rental income', 'yield', 'returns', 'appreciation'],
  quiet: ['quiet', 'peaceful', 'calm', 'serene'],
  furnished: ['furnished', 'fully furnished', 'semi furnished'],
  parking: ['parking', 'car park', 'garage'],
};

export function parseSoft(text) {
  const t = text.toLowerCase();
  return Object.entries(SOFT_SIGNALS)
    .filter(([, words]) => words.some((w) => t.includes(w)))
    .map(([k]) => k);
}

export function parseQuery(text, knownLocalities = []) {
  return {
    ...parseIntent(text),
    ...parseBhk(text),
    ...parsePrice(text),
    ...parseCity(text),
    ...parseLocality(text, knownLocalities),
    ...parseType(text),
    ...parseCategory(text),
    ...parseConstruction(text),
    soft: parseSoft(text),
  };
}
