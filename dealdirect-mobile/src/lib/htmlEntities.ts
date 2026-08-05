/**
 * Undoes the specific HTML-entity escaping this backend applies before storage.
 *
 * Two independent code paths on the backend escape user text before saving it,
 * and both happen to produce the same five entities: express-validator's
 * `body().escape()` (saved-search names) and chatController's hand-rolled
 * `escapeHtml` (chat message text). Both encode `& < > "` the same way and
 * apostrophe as `&#x27;` (chat) or `&#39;` (validator.js) — this decodes both
 * spellings.
 *
 * Only these five characters are handled, deliberately. A general HTML-entity
 * decoder would also transform user text that legitimately contains something
 * entity-shaped (e.g. a listing named "Q&A Center" typed with a literal `&amp;`
 * in it), which is a different and worse bug than leaving an entity undecoded.
 */
const ESCAPED = /&(amp|lt|gt|quot|#x27|#39);/g;

const UNESCAPE: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  '#x27': "'",
  '#39': "'",
};

export function decodeHtmlEntities(text: string): string {
  return text.replace(ESCAPED, (match, entity: string) => UNESCAPE[entity] ?? match);
}
