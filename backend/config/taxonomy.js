/**
 * The canonical property taxonomy.
 *
 * One definition, imported by the seed, the migration, the request-time
 * consistency contract and the tests. The reason it lives in one place is the
 * bug it replaces: the vocabulary existed in four hand-maintained copies (web
 * form, Admin form, mobile constants, database rows) that disagreed on nine
 * names, and nothing compared them.
 *
 * Two levels:
 *
 *   Category  ->  PropertyType
 *
 * Subcategory is retired (decision D9). The documents still exist in the
 * database and are deleted in a separate destructive stage; nothing reads them.
 *
 * Names here are exact and are the only accepted spellings. `Warehouse / Godown`
 * has spaces around the slash, `Co-Working Space` capitalises the W, and
 * `Apartment / Flat` is not `Apartment`. There is deliberately no alias table:
 * an alias layer removes the pressure to converge and guarantees the next
 * client invents a tenth spelling.
 */

export const CANONICAL_TAXONOMY = Object.freeze({
  'Residential': Object.freeze([
    'Apartment / Flat',
    'Independent House',
    'Villa',
    'Builder Floor',
    'Row House',
    'Studio Apartment',
    'Penthouse',
    'Farm House',
  ]),
  'Commercial': Object.freeze([
    'Office Space',
    'Shop / Retail',
    'Showroom',
    'Restaurant / Cafe',
    'Co-Working Space',
    'Warehouse / Godown',
    'Industrial Shed',
    'Commercial Building / Floor',
  ]),
  'Land & Plots': Object.freeze([
    'Residential Plot',
    'Commercial Land',
    'Industrial Land',
    'Agricultural Land',
  ]),
});

export const CANONICAL_CATEGORIES = Object.freeze(Object.keys(CANONICAL_TAXONOMY));

export const CANONICAL_PROPERTY_TYPES = Object.freeze(
  Object.values(CANONICAL_TAXONOMY).flat()
);


/**
 * Is this document part of the live taxonomy?
 *
 * The criterion is membership in the canonical definition above, not a list of
 * names to exclude. That matters: the migration is additive, so the database
 * still holds the obsolete rows, and a blacklist would have to be extended by
 * hand every time one more piece of history turned up. An allow-list derived
 * from the same constant the migration seeds from cannot drift out of step with
 * it, because there is only one constant.
 *
 * A property type is active only if its name is canonical FOR ITS PARENT. Name
 * alone is not enough: the same string under the wrong category is exactly the
 * inconsistency this whole phase exists to remove.
 */
export function isActiveCategoryName(name) {
  return CANONICAL_CATEGORIES.includes(name);
}

export function isActivePropertyType(typeName, parentCategoryName) {
  const types = CANONICAL_TAXONOMY[parentCategoryName];
  return Array.isArray(types) && types.includes(typeName);
}
/** The category a canonical property type belongs to, or undefined. */
export function categoryOfType(typeName) {
  for (const [category, types] of Object.entries(CANONICAL_TAXONOMY)) {
    if (types.includes(typeName)) return category;
  }
  return undefined;
}

/**
 * Listing intent. Not taxonomy, and the reason `Buy`, `Rental` and `Rent` are
 * removed from the type list: they answer "is this for sale or for rent",
 * which `Property.listingType` already answers on every row.
 */
export const CANONICAL_LISTING_TYPES = Object.freeze(['Rent', 'Sell']);

/**
 * The migration mapping table.
 *
 * Keyed on the exact `${categoryName}|${propertyTypeName}` pair as it exists in
 * the data today. Exact match only: no substring, no fuzzy scoring, no case
 * folding, no positional fallback, no nearest candidate. A pair that is not a
 * key here ABORTS the migration rather than being guessed at, because runtime
 * guessing is precisely what produced the corruption being repaired.
 *
 * Ten entries cover all 47 properties. Six are renames of an existing taxonomy
 * row, four target rows that did not exist under any name.
 */
export const MIGRATION_MAPPING = Object.freeze({
  'Residential|Apartment / Flat':           { category: 'Residential', propertyType: 'Apartment / Flat' },
  'Residential|Independent House':          { category: 'Residential', propertyType: 'Independent House' },
  'Residential|Villa':                      { category: 'Residential', propertyType: 'Villa' },
  'Residential|Penthouse':                  { category: 'Residential', propertyType: 'Penthouse' },
  'Commercial|Office Space':                { category: 'Commercial',  propertyType: 'Office Space' },
  'Commercial|Showroom':                    { category: 'Commercial',  propertyType: 'Showroom' },
  'Commercial|Warehouse / Godown':          { category: 'Commercial',  propertyType: 'Warehouse / Godown' },
  'Commercial|Shop / Retail':               { category: 'Commercial',  propertyType: 'Shop / Retail' },
  'Commercial|Commercial Building / Floor': { category: 'Commercial',  propertyType: 'Commercial Building / Floor' },
  'Commercial|Restaurant / Cafe':           { category: 'Commercial',  propertyType: 'Restaurant / Cafe' },
});

/** Exact lookup. Returns undefined for anything not in the table. */
export function mappingFor(categoryName, propertyTypeName) {
  return MIGRATION_MAPPING[`${categoryName}|${propertyTypeName}`];
}

/**
 * Taxonomy rows that exist only because listing intent was once modelled as a
 * property type, plus the case duplicate and the row superseded by splitting
 * Shop and Showroom. Recorded here so the destructive cleanup stage has a
 * reviewed list rather than a fresh judgement call.
 */
export const OBSOLETE_TAXONOMY_NAMES = Object.freeze([
  'Buy', 'Rental', 'Rent',   // listing intents, duplicated by listingType
  'Office space',            // case duplicate of Office Space
  'Shop / Showroom',         // replaced by Shop / Retail and Showroom
  'Plots',                   // superseded by the Land & Plots category
]);
