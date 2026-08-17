/**
 * Exact-match resolution of a taxonomy name to its ObjectId.
 *
 * This function exists because its predecessor corrupted the property corpus.
 * The old resolver tried three strategies in order: exact, case-insensitive,
 * then substring. The substring step is what did the damage. Asked to resolve
 * the category "Residential", it matched the document named "Residential Plot",
 * because "residential plot".includes("residential") is true. "Commercial"
 * matched "Commercial Land" the same way. When even that failed, the caller fell
 * back to metadata.propertyTypes[0]._id, which is how apartments, villas and
 * penthouses were all recorded as type "Plot".
 *
 * The result: 25 of 47 listings carry taxonomy references that describe a
 * different property than the one they belong to, and every ObjectId-based
 * category filter returns the wrong set. Not one of those 25 refs is correct.
 *
 * So: exact `===` only. No case folding, no trimming, no substring, no
 * closest-match, no positional fallback. A name either is the canonical name or
 * it is not.
 *
 * WHAT HAPPENS ON NO MATCH
 *
 * `matched: false` and `id: null`. The caller omits the reference rather than
 * substituting one. That is deliberate and it is the safer failure: the
 * denormalised `categoryName` and `propertyTypeName` columns are correct on all
 * 47 rows and are what every read path actually uses, so a missing ref costs
 * nothing that a wrong ref does not cost more.
 *
 * Expect this to return `matched: false` for most types until the taxonomy
 * migration runs. The canonical vocabulary (`Apartment / Flat`) does not yet
 * exist in the database, which still holds `Apartment`. That is the migration's
 * job, not this function's, and unresolved-and-omitted is exactly the state the
 * corpus should be in until then.
 *
 * A twin of this file lives at `client-next/src/utils/taxonomyRef.js`. The repository
 * has no shared package, so the four apps duplicate helpers by hand; the
 * integration suite runs the same table against both copies to catch drift.
 */

/**
 * @param {string} name        the canonical taxonomy name to resolve
 * @param {Array<{_id: string, name: string}>} documents  taxonomy documents
 * @returns {{id: string|null, matched: boolean, reason: string|null}}
 */
export function resolveTaxonomyRef(name, documents) {
  if (typeof name !== 'string' || name.length === 0) {
    return { id: null, matched: false, reason: 'no name supplied' };
  }
  if (!Array.isArray(documents) || documents.length === 0) {
    return { id: null, matched: false, reason: 'taxonomy not loaded' };
  }

  // Exact, case-sensitive, unnormalised. Anything looser is how the corpus
  // broke the first time.
  const hit = documents.find((doc) => doc && doc.name === name);

  if (!hit) {
    return { id: null, matched: false, reason: `no document named "${name}"` };
  }
  if (!hit._id) {
    return { id: null, matched: false, reason: `document "${name}" has no _id` };
  }

  return { id: hit._id, matched: true, reason: null };
}

/**
 * Convenience wrapper for form submission: returns the id or null, and reports
 * a miss on the console so an unresolved taxonomy is visible during development
 * rather than silently absent.
 */
export function taxonomyRefOrNull(name, documents, label = 'taxonomy') {
  const result = resolveTaxonomyRef(name, documents);
  if (!result.matched) {
    console.warn(`[${label}] not sending a reference: ${result.reason}`);
  }
  return result.id;
}
