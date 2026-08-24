import { extractBhk } from './bhk.ts';
import { extractLocation } from './location.ts';
import { consume, normalizeQuery, stripStopWords } from './normalize.ts';
import { extractPrice } from './price.ts';
import { extractPropertyType } from './propertyType.ts';
import { extractConstruction, extractSoftSignals } from './softIntent.ts';
import { extractTransaction } from './transaction.ts';
import type { EntityMatch, HardConstraints, ParseContext, ParsedQuery, SoftSignal } from './types.ts';

/**
 * The pipeline.
 *
 *   normalize → bhk → price → transaction → propertyType
 *             → location → construction → soft → residual
 *
 * ---------------------------------------------------------------------------
 * WHY THIS ORDER
 *
 * It is not arbitrary and it is not alphabetical. Each stage runs before any
 * stage that could mis-read the text it consumes:
 *
 *   bhk before price          "3 bhk" holds a 3 that is not three rupees. BHK
 *                             hands price the character spans it claimed.
 *   transaction before soft   "rental income" must be read as an investment
 *                             phrase before "rental" is seen as a rent word.
 *   location before residual  a resolved locality leaves the residual; an
 *                             unresolved one stays in it, on purpose.
 *
 * Every stage is independently testable and none of them knows about the
 * others, which is what keeps this from becoming one unmaintainable regex.
 *
 * ---------------------------------------------------------------------------
 * WHAT IS NOT CLAIMED STAYS TEXT
 *
 * The residual is everything no extractor could prove the meaning of. It is
 * passed to the existing server-side regex unchanged, so a builder name, a
 * project, or a locality spelled a way we have never seen still searches
 * exactly as well as it does today. Understanding the query is only ever
 * allowed to ADD structure, never to discard the user's words.
 */
export function parseQuery(input: string, context: ParseContext): ParsedQuery {
  const original = String(input ?? '');
  const normalized = normalizeQuery(original);

  const hard: HardConstraints = {};
  const matches: EntityMatch[] = [];
  const soft: SoftSignal[] = [];
  let residual = normalized;

  if (!normalized) {
    return { original, normalized, hard, soft, residual: '', matches };
  }

  // 1. Bedrooms. First, so its digits are protected from the price stage.
  const bhk = extractBhk(normalized);
  if (bhk.bhk !== undefined) hard.bhk = bhk.bhk;
  matches.push(...bhk.matches);
  for (const match of bhk.matches) residual = consume(residual, match.text);

  // 2. Money, told which spans the bedroom count already owns.
  const price = extractPrice(normalized, bhk.spans);
  if (price.minPrice !== undefined) hard.minPrice = price.minPrice;
  if (price.maxPrice !== undefined) hard.maxPrice = price.maxPrice;
  matches.push(...price.matches);
  for (const match of price.matches) residual = consume(residual, match.text);
  // The bound words themselves carry no search meaning once read.
  residual = residual.replace(
    /\b(under|below|less than|upto|up to|within|max|maximum|budget|above|over|more than|minimum|min|starting|between|from|at least|at most)\b/g,
    ' '
  );

  // 3. Buy or rent. Before soft signals, so "rental income" is not read as rent.
  const transaction = extractTransaction(normalized);
  if (transaction.transaction) hard.transaction = transaction.transaction;
  matches.push(...transaction.matches);
  for (const text of transaction.consumed) residual = consume(residual, text);

  // 4. What kind of property, and the category that follows from it.
  const type = extractPropertyType(normalized);
  if (type.propertyType) hard.propertyType = type.propertyType;
  if (type.category) hard.category = type.category;
  matches.push(...type.matches);
  for (const text of type.consumed) residual = consume(residual, text);

  // 5. Where — only when it resolves against something real.
  const location = extractLocation(normalized, context);
  if (location.city) hard.city = location.city;
  if (location.locality) hard.locality = location.locality;
  matches.push(...location.matches);
  for (const text of location.consumed) residual = consume(residual, text);

  // 6. Ready to move / under construction.
  const construction = extractConstruction(normalized);
  if (construction.construction) hard.construction = construction.construction;
  matches.push(...construction.matches);
  for (const text of construction.consumed) residual = consume(residual, text);

  // 7. Everything that colours the query without constraining it.
  const softResult = extractSoftSignals(normalized);
  soft.push(...softResult.soft);
  matches.push(...softResult.matches);
  for (const text of softResult.consumed) residual = consume(residual, text);

  /*
    An investment query is a purchase, and the soft signal should say so even
    when the transaction was stated some other way. `extractTransaction` already
    resolved it; this only makes the tag consistent so a ranker does not have to
    special-case the phrase again.
  */
  if (transaction.investment && !soft.includes('investment')) soft.push('investment');

  return {
    original,
    normalized,
    hard,
    soft,
    residual: stripStopWords(residual),
    matches,
  };
}

/**
 * True when the parse found anything worth acting on.
 *
 * A query that yields no constraints, no signals and only residual text is
 * exactly today's search, and callers use this to skip the new path entirely
 * rather than wrapping a no-op in ceremony.
 */
export function isStructured(parsed: ParsedQuery): boolean {
  return Object.keys(parsed.hard).length > 0 || parsed.soft.length > 0;
}

/**
 * A short human summary: "3 BHK · under ₹1.2 Cr · Yelahanka".
 *
 * For explaining a search back to the user — above all when it returns nothing,
 * where the honest thing is to show which constraints emptied the screen rather
 * than quietly dropping one.
 */
export function describeParse(parsed: ParsedQuery): string[] {
  const order: EntityMatch['kind'][] = [
    'bhk',
    'propertyType',
    'category',
    'transaction',
    'price',
    'locality',
    'city',
    'construction',
    'soft',
  ];

  return parsed.matches
    .slice()
    .sort((a, b) => order.indexOf(a.kind) - order.indexOf(b.kind))
    .map((match) => match.label)
    .filter((label, index, all) => all.indexOf(label) === index);
}
