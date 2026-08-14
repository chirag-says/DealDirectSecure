/**
 * One-shot codemod: hand-rolled back headers -> <ScreenHeader />.
 *
 * Twenty route files carried a byte-for-byte copy of the same header row (a
 * flex row, a back Pressable, a chevron, a title). This rewrites the ones that
 * match the canonical shape exactly and REPORTS the ones that do not, so the
 * variants with trailing actions or a close icon get handled by hand rather
 * than mangled by a regex.
 *
 * Kept in the repo rather than run and deleted: it documents what happened to
 * those twenty files, and re-running it is how you would check nothing has
 * regressed to the old pattern.
 *
 *   node scripts/adopt-screen-header.mjs           # report only
 *   node scripts/adopt-screen-header.mjs --write   # apply
 */

import { globSync, readFileSync, writeFileSync } from 'node:fs';

const WRITE = process.argv.includes('--write');

/**
 * The canonical block. Tolerant of the two class orderings in the wild
 * (`px-lg pt-md pb-sm` and `px-lg pb-sm pt-md`) and of either back-button
 * margin ordering, because those varied without meaning anything.
 */
const HEADER = new RegExp(
  String.raw`[ \t]*<View className="flex-row items-center px-lg (?:pt-md pb-sm|pb-sm pt-md)">\s*` +
    String.raw`<Pressable\s+` +
    String.raw`accessibilityRole="button"\s+` +
    String.raw`accessibilityLabel="Go back"\s+` +
    String.raw`onPress=\{([^}]+)\}\s+` +
    String.raw`hitSlop=\{12\}\s+` +
    String.raw`className="(?:mr-sm -ml-xs|-ml-xs mr-sm) h-9 w-9 items-center justify-center"\s*` +
    String.raw`>\s*` +
    String.raw`<Ionicons name="chevron-back" size=\{24\} color=\{theme\.colors\.textPrimary\} />\s*` +
    String.raw`</Pressable>\s*` +
    String.raw`<Text variant="title2"(?: className="flex-1")?>([^<]+)</Text>\s*` +
    String.raw`</View>`,
  'g'
);

/** Pulls the fallback route out of a `canGoBack() ? back() : replace('X')`. */
function backTarget(onPress) {
  const match = onPress.match(/router\.replace\('([^']+)'\)/);
  return match ? match[1] : null;
}

const files = globSync('app/**/*.tsx');
const converted = [];
const skipped = [];

for (const file of files) {
  const source = readFileSync(file, 'utf8');
  if (!source.includes('chevron-back')) continue;

  let touched = false;
  const next = source.replace(HEADER, (_full, onPress, title) => {
    touched = true;
    const target = backTarget(onPress);
    const backTo = target ? ` backTo="${target}"` : '';
    return `      <ScreenHeader title="${title.trim()}"${backTo} />`;
  });

  if (touched) {
    converted.push(file);
    if (WRITE) writeFileSync(file, next);
  } else {
    // Still has a chevron-back but did not match: a variant that needs a human.
    skipped.push(file);
  }
}

console.log(`converted (${converted.length}):`);
for (const file of converted) console.log(`  ${file}`);
console.log(`\nneeds manual handling (${skipped.length}):`);
for (const file of skipped) console.log(`  ${file}`);
if (!WRITE) console.log('\n(report only — pass --write to apply)');
