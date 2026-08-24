/**
 * DealDirect query understanding.
 *
 * ---------------------------------------------------------------------------
 * THIS MODULE HAS NO REACT NATIVE DEPENDENCY, AND THAT IS A CONTRACT
 *
 * Nothing in this folder imports `react`, `react-native`, `expo-*`, `@/api`,
 * `@/features/*` or `@/ui`. It is plain TypeScript over strings and numbers.
 *
 * The reason is the roadmap: the same understanding is meant to run on the
 * website, and the only way that stays true is for a violation to be visible
 * in review. If this folder ever needs app state, the app should pass it in
 * through `ParseContext` rather than this folder reaching out for it.
 *
 * The app-specific half — turning a `ParsedQuery` into the app's own
 * `SearchFilters` — lives one level up in `../queryUnderstanding.ts`, on the
 * other side of that boundary.
 *
 * ---------------------------------------------------------------------------
 * WHAT IT DOES, AND WHAT IT REFUSES TO DO
 *
 * It extracts what it can PROVE from a query — bedrooms, money, buy or rent,
 * property type, a locality that exists — and leaves everything else as text
 * for the existing server-side search. It never guesses a constraint, because
 * a wrong constraint empties the screen and looks like missing inventory.
 *
 * Soft signals ("family", "investment", "near metro") are carried but never
 * filtered on. They are also the seam a semantic ranking stage would attach to
 * later, without any other file changing.
 */

export { parseQuery, isStructured, describeParse } from './parse.ts';
export { normalizeQuery, stripStopWords, consume } from './normalize.ts';
export { extractPrice, formatRupees, LAKH, CRORE } from './price.ts';
export { extractBhk } from './bhk.ts';
export { extractPropertyType, PROPERTY_TYPES, wordBoundaryTest } from './propertyType.ts';
export { extractTransaction } from './transaction.ts';
export { extractLocation, normalizeLocality } from './location.ts';
export { extractSoftSignals, extractConstruction } from './softIntent.ts';

export type {
  ParsedQuery,
  ParseContext,
  CityEntry,
  HardConstraints,
  EntityMatch,
  SoftSignal,
  TransactionType,
  CanonicalPropertyType,
  PropertyCategory,
  ConstructionStage,
  Rupees,
} from './types.ts';
