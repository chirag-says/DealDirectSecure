/**
 * What a query is understood to MEAN.
 *
 * ---------------------------------------------------------------------------
 * THE HARD/SOFT SPLIT IS THE WHOLE DESIGN
 *
 * `hard` is what the user stated as fact. Every field in it filters, and
 * nothing may override it: a query for 3 BHK under a crore must never be
 * answered with a 4 BHK at 1.8 crore, however relevant that listing seems.
 *
 * `soft` is what the user meant but did not state as a constraint — "family",
 * "investment", "near metro". None of it filters. It is carried through so
 * ranking can use it and so a later semantic stage has somewhere to attach,
 * and it deliberately does NOT become a filter on a database field that does
 * not exist. There is no `family` column and inventing one would return an
 * empty screen for a query the corpus can answer.
 *
 * `residual` is the text left after every entity was removed. It is what still
 * goes to the server's regex, so a locality or builder name the parser does not
 * know about is not silently discarded — it just stays unstructured, which is
 * the honest outcome for language we cannot prove the meaning of.
 *
 * ---------------------------------------------------------------------------
 * NO REACT NATIVE ANYWHERE IN THIS FOLDER
 *
 * Every file here is pure TypeScript over strings and numbers. Nothing imports
 * from `react`, `react-native`, `expo-*` or `@/api`. That is a deliberate
 * constraint rather than an accident of the current code: the same module is
 * meant to run on the website unchanged, and the only way to keep that true is
 * to make a violation obvious in review.
 */

/** Rupees. Always an integer; see `price.ts` for why. */
export type Rupees = number;

export type TransactionType = 'rent' | 'sale';

/**
 * The canonical property types, derived from the live taxonomy rather than
 * invented. See `propertyType.ts` for the values actually present.
 */
export type CanonicalPropertyType =
  | 'apartment'
  | 'house'
  | 'villa'
  | 'penthouse'
  | 'plot'
  | 'office'
  | 'shop'
  | 'showroom'
  | 'warehouse'
  | 'restaurant';

export type PropertyCategory = 'residential' | 'commercial';

/** Two buckets over the backend's free-text construction status. */
export type ConstructionStage = 'ready' | 'construction';

/**
 * A soft signal. Never a filter.
 *
 * Kept as a closed union rather than free strings so that a ranker consuming
 * them cannot silently depend on a tag nothing produces.
 */
export type SoftSignal =
  | 'family'
  | 'investment'
  | 'luxury'
  | 'affordable'
  | 'metro'
  | 'workplace'
  | 'quiet'
  | 'furnished'
  | 'parking'
  | 'schools';

/** Constraints the user stated. Every one of these filters. */
export interface HardConstraints {
  transaction?: TransactionType;
  /** Bedrooms. `0` means 1 RK, which is a real value and not "unset". */
  bhk?: number;
  minPrice?: Rupees;
  maxPrice?: Rupees;
  /** A `City.id`, resolved against the app's own city table. */
  city?: string;
  /** A locality string, resolved against localities known to exist. */
  locality?: string;
  propertyType?: CanonicalPropertyType;
  category?: PropertyCategory;
  construction?: ConstructionStage;
}

export interface ParsedQuery {
  /** The query as typed, unchanged. */
  original: string;
  /** Lower-cased, punctuation-normalised. What the extractors actually read. */
  normalized: string;
  hard: HardConstraints;
  soft: SoftSignal[];
  /** Text no extractor claimed. Goes to the server as free text. */
  residual: string;
  /**
   * What was recognised, in order, for explaining the search back to the user
   * and for debugging a mis-parse without a debugger.
   */
  matches: EntityMatch[];
}

export interface EntityMatch {
  kind:
    | 'transaction'
    | 'bhk'
    | 'price'
    | 'city'
    | 'locality'
    | 'propertyType'
    | 'category'
    | 'construction'
    | 'soft';
  /** The exact substring that produced it. */
  text: string;
  /** Human-readable, for a "searching for…" summary. */
  label: string;
}

/**
 * Everything an extractor needs to know about the world it is parsing against.
 *
 * Passed in rather than imported so this module never reaches into app state,
 * and so tests can parse against a fixed vocabulary instead of whatever the
 * live corpus happens to contain today.
 */
export interface ParseContext {
  /** `{ id, label, aliases }` for every city the app knows. */
  cities: readonly CityEntry[];
  /**
   * Localities known to exist in the corpus, lower-cased.
   *
   * An unknown locality must NOT become a filter — it stays in the residual and
   * reaches the server's regex, which is the only component that can honestly
   * say whether it matches anything.
   */
  localities: readonly string[];
}

export interface CityEntry {
  id: string;
  label: string;
  aliases: readonly string[];
}
