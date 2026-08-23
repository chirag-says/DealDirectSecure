/**
 * The evaluation set: 58 queries a DealDirect user could plausibly type.
 *
 * `truth` is hand-labelled: what the query MEANS, independent of any parser.
 * The parser's output is scored against it, so parser accuracy is measured
 * rather than assumed. Only the fields a user actually stated are listed —
 * an absent field means "the user did not constrain this".
 *
 * `soft` is the intent that may influence ranking and may never gate results.
 */
export const QUERIES = [
  // ── Exact / literal ──────────────────────────────────────────────────────
  { q: '3 bhk', group: 'exact', truth: { bhk: 3 } },
  { q: '2 BHK', group: 'exact', truth: { bhk: 2 } },
  { q: 'HSR Layout', group: 'exact', truth: { locality: 'hsr layout' } },
  { q: 'Koramangala', group: 'exact', truth: { locality: 'koramangala' } },
  { q: 'Yelahanka', group: 'exact', truth: { locality: 'yelahanka' } },
  { q: 'showroom', group: 'exact', truth: { propertyType: 'showroom', category: 'commercial' } },
  { q: 'office space', group: 'exact', truth: { propertyType: 'office', category: 'commercial' } },
  { q: 'warehouse', group: 'exact', truth: { propertyType: 'warehouse', category: 'commercial' } },
  { q: 'penthouse', group: 'exact', truth: { propertyType: 'penthouse', category: 'residential' } },
  { q: 'villa', group: 'exact', truth: { propertyType: 'villa', category: 'residential' } },

  // ── Synonyms: the words users use for the same thing ─────────────────────
  { q: 'flat', group: 'synonym', truth: { propertyType: 'apartment', category: 'residential' } },
  { q: 'apartment', group: 'synonym', truth: { propertyType: 'apartment', category: 'residential' } },
  { q: 'home', group: 'synonym', truth: { category: 'residential' } },
  { q: 'house', group: 'synonym', truth: { category: 'residential' } },
  { q: 'flats', group: 'synonym', truth: { propertyType: 'apartment', category: 'residential' } },
  { q: 'godown', group: 'synonym', truth: { propertyType: 'warehouse', category: 'commercial' } },
  { q: 'shop', group: 'synonym', truth: { propertyType: 'shop', category: 'commercial' } },
  { q: 'bungalow', group: 'synonym', truth: { propertyType: 'house', category: 'residential' } },

  // ── Indian shorthand and money ───────────────────────────────────────────
  { q: '2bhk', group: 'shorthand', truth: { bhk: 2 } },
  { q: '3bhk', group: 'shorthand', truth: { bhk: 3 } },
  { q: '1 cr', group: 'shorthand', truth: { maxPrice: 10_000_000 } },
  { q: '1.2 crore', group: 'shorthand', truth: { maxPrice: 12_000_000 } },
  { q: 'under 80 lakhs', group: 'shorthand', truth: { maxPrice: 8_000_000 } },
  { q: 'under 50L', group: 'shorthand', truth: { maxPrice: 5_000_000 } },
  { q: 'above 1 crore', group: 'shorthand', truth: { minPrice: 10_000_000 } },
  { q: 'ready possession', group: 'shorthand', truth: { construction: 'ready' } },
  { q: 'ready to move', group: 'shorthand', truth: { construction: 'ready' } },
  { q: '1 rk', group: 'shorthand', truth: { bhk: 0 } },

  // ── Intent: what the property is FOR ─────────────────────────────────────
  { q: 'good family home', group: 'intent', truth: { category: 'residential' }, soft: ['family'] },
  {
    q: 'investment property',
    group: 'intent',
    truth: { intent: 'sale' },
    soft: ['investment'],
  },
  {
    q: 'home for IT professional',
    group: 'intent',
    truth: { category: 'residential' },
    soft: ['it'],
  },
  {
    q: 'rental income property',
    group: 'intent',
    truth: { intent: 'sale' },
    soft: ['investment'],
  },
  {
    q: 'luxury apartment for a family',
    group: 'intent',
    truth: { propertyType: 'apartment', category: 'residential' },
    soft: ['luxury', 'family'],
  },
  {
    q: 'affordable home',
    group: 'intent',
    truth: { category: 'residential' },
    soft: ['affordable'],
  },
  {
    q: 'property suitable for rental income',
    group: 'intent',
    truth: { intent: 'sale' },
    soft: ['investment'],
  },
  {
    q: 'quiet residential area',
    group: 'intent',
    truth: { category: 'residential' },
    soft: ['quiet'],
  },
  { q: 'starter home for a couple', group: 'intent', truth: { category: 'residential' }, soft: ['family'] },
  { q: 'space for my business', group: 'intent', truth: { category: 'commercial' } },

  // ── Natural language: the whole sentence ─────────────────────────────────
  {
    q: 'home for family near metro',
    group: 'natural',
    truth: { category: 'residential' },
    soft: ['family', 'metro'],
  },
  {
    q: '3 bhk for my family near metro under 1.2 crore',
    group: 'natural',
    truth: { bhk: 3, maxPrice: 12_000_000, category: 'residential' },
    soft: ['family', 'metro'],
  },
  {
    q: 'ready to move apartment close to IT park',
    group: 'natural',
    truth: { propertyType: 'apartment', category: 'residential', construction: 'ready' },
    soft: ['it'],
  },
  {
    q: 'affordable home near schools and metro',
    group: 'natural',
    truth: { category: 'residential' },
    soft: ['affordable', 'family', 'metro'],
  },
  {
    q: 'luxury home for a family in a quiet area',
    group: 'natural',
    truth: { category: 'residential' },
    soft: ['luxury', 'family', 'quiet'],
  },
  {
    q: '3 bhk near IT companies',
    group: 'natural',
    truth: { bhk: 3 },
    soft: ['it'],
  },
  {
    q: 'affordable home close to office',
    group: 'natural',
    truth: { category: 'residential' },
    soft: ['affordable', 'it'],
  },
  {
    q: 'ready to move house near metro',
    group: 'natural',
    truth: { category: 'residential', construction: 'ready' },
    soft: ['metro'],
  },
  {
    q: 'furnished flat for a small family',
    group: 'natural',
    truth: { propertyType: 'apartment', category: 'residential' },
    soft: ['furnished', 'family'],
  },
  {
    q: 'i need a place to live with my parents',
    group: 'natural',
    truth: { category: 'residential' },
    soft: ['family'],
  },

  // ── Mixed: structured constraints inside a sentence ──────────────────────
  {
    q: '3 bhk in Yelahanka under 1.5 crore',
    group: 'mixed',
    truth: { bhk: 3, locality: 'yelahanka', maxPrice: 15_000_000 },
  },
  {
    q: '2 bhk near metro for rent',
    group: 'mixed',
    truth: { bhk: 2, intent: 'rent' },
    soft: ['metro'],
  },
  {
    q: 'villa under 2 crore',
    group: 'mixed',
    truth: { propertyType: 'villa', maxPrice: 20_000_000 },
  },
  {
    q: '3 bhk apartment for rent in Bangalore',
    group: 'mixed',
    truth: { bhk: 3, intent: 'rent', propertyType: 'apartment', city: 'bangalore' },
  },
  {
    q: 'office space for rent in HSR Layout',
    group: 'mixed',
    truth: { propertyType: 'office', intent: 'rent', locality: 'hsr layout', category: 'commercial' },
  },
  {
    q: '2 bhk flat in Mumbai under 1 crore',
    group: 'mixed',
    truth: { bhk: 2, propertyType: 'apartment', city: 'mumbai', maxPrice: 10_000_000 },
  },
  {
    q: 'independent house for rent in Bandra',
    group: 'mixed',
    truth: { propertyType: 'house', intent: 'rent', locality: 'bandra' },
  },
  {
    q: 'commercial property in Kolkata',
    group: 'mixed',
    truth: { category: 'commercial', city: 'kolkata' },
  },
  {
    q: '4 bhk for sale above 1 crore',
    group: 'mixed',
    truth: { bhk: 4, intent: 'sale', minPrice: 10_000_000 },
  },

  // ── Should legitimately return nothing ───────────────────────────────────
  {
    q: '3 bhk in Whitefield under 50 lakhs',
    group: 'empty-expected',
    truth: { bhk: 3, locality: 'whitefield', maxPrice: 5_000_000 },
  },
  { q: 'farmhouse in Goa', group: 'empty-expected', truth: { locality: 'goa' } },
];
