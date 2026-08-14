/**
 * Wire-format builders for `POST /properties/add` and
 * `PUT /properties/my-properties/:id`.
 *
 * These two endpoints do NOT share a contract despite both accepting "a
 * property". Read before changing either builder:
 *
 * ADD (`addProperty`, propertyController.js:258) sanitises through a strict
 * field-name WHITELIST (`PROPERTY_ALLOWED_FIELDS`) before `Property.create`.
 * Only fields in that whitelist reach the document at all, and several
 * whitelist entries (`floor`, `age`, `availability`, `builtUpArea` as a flat
 * field, `parkingCovered`/`parkingOpen` as flats, `flooring`, `ownershipType`…)
 * do not correspond to any real schema path — Mongoose's default strict mode
 * silently drops them. This builder only ever sends the INTERSECTION of the
 * whitelist and the real schema (`backend/models/Property.js`), because
 * anything outside that intersection is a field that looks like it saved and
 * did not. `address` is sent as a real nested object here; the whitelist and
 * the schema agree on that shape for this endpoint.
 *
 * EDIT (`updateMyProperty`, propertyController.js:1258) has NO whitelist —
 * whatever is on `req.body` reaches `Property.findByIdAndUpdate` directly,
 * filtered only by Mongoose schema binding. So real schema field names work
 * directly here (including `categoryName`/`propertyTypeName`, which the
 * whitelist also uses, so those two are the same on both paths). The one field
 * that is NOT safe to send as a nested object here is `address`: the
 * controller unconditionally REBUILDS `data.address` from flat top-level
 * `city`/`locality`/`landmark`/`latitude`/`longitude`, and stuffs whatever was
 * sent as `data.address` into a non-schema `address.full` string instead of
 * merging it. There is no way to edit `address.line`/`state`/`pincode` through
 * this endpoint — not a client limitation, a server one — so this app does not
 * offer to.
 *
 * IMAGES on edit are their own landmine: `updateMyProperty` unconditionally
 * REBUILDS `categorizedImages` from `existingCategorizedImages` (JSON) plus any
 * newly uploaded files, and then rebuilds the flat `images` array FROM that. A
 * request that omits `existingCategorizedImages` wipes every photo the listing
 * had, silently, because "no existing images were named" reads to that
 * controller as "there are now no images." This app always sends the current
 * photo set back as `existingCategorizedImages`, tagged with whichever bucket
 * key each photo actually carries (`existingCategorizedPhotos` in
 * `editAdapter.ts`), and new photos go in under the category the owner picked
 * for each one in the form's photo step.
 *
 * ---------------------------------------------------------------------------
 * ADD AND EDIT DISAGREE ON THE WIRE FORMAT FOR NEW CATEGORISED PHOTOS TOO —
 * read this before changing either photo builder below.
 *
 * ADD (`addProperty`, propertyController.js:315-363): new categorised photos
 * go under the file field `categorizedImages` (NOT `images` — that field is
 * "legacy", read separately). `imageCategoryMap` is an OBJECT,
 * `{ [categoryKey]: indices[] }`, and only `indices.length` is ever read —
 * the values inside the array are ignored. Photos are consumed by walking
 * `Object.entries(categoryMap)` in order and taking that many files
 * sequentially off `categorizedUrls`, so the FILES MUST BE UPLOADED PRE-GROUPED
 * BY CATEGORY, in the same order the map's keys are written, not in whatever
 * order the owner picked them. `buildCategorizedImageMap` does that grouping.
 *
 * EDIT (`updateMyProperty`, propertyController.js:1420-1440): new categorised
 * photos go under `images` (not `categorizedImages`). `imageCategoryMap` here
 * is an ARRAY, `[{index, category}, ...]`, but the controller's forEach keys
 * off its own loop index, not the `index` field inside each entry — so the
 * array's POSITION must match the upload order exactly, one entry per file, in
 * the order the owner added them. No pre-grouping needed here, unlike add.
 */

import type { CategorizedPhoto, ListingFormValues } from './types';
import { imagePart } from './imagePicker';

/**
 * Groups photos by category, preserving first-seen category order. ADD's
 * wire format needs this grouping — see the module doc above. Returns both
 * the flattened, group-ordered URI list (upload this, in this order) and the
 * map to send as `imageCategoryMap`.
 */
function buildCategorizedImageMap(photos: readonly CategorizedPhoto[]): {
  orderedUris: string[];
  categoryMap: Record<string, number[]>;
} {
  const byCategory = new Map<string, string[]>();
  for (const photo of photos) {
    const bucket = byCategory.get(photo.category);
    if (bucket) bucket.push(photo.uri);
    else byCategory.set(photo.category, [photo.uri]);
  }

  const orderedUris: string[] = [];
  const categoryMap: Record<string, number[]> = {};
  for (const [category, uris] of byCategory) {
    // Only `.length` is read server-side (see the module doc); the actual
    // values just need to be an array of the right length.
    categoryMap[category] = uris.map((_, i) => i);
    orderedUris.push(...uris);
  }

  return { orderedUris, categoryMap };
}

function appendIfPresent(form: FormData, key: string, value: string | undefined) {
  if (value !== undefined && value.trim() !== '') form.append(key, value.trim());
}

function num(value: string): number | undefined {
  const n = Number(value);
  return value.trim() !== '' && Number.isFinite(n) ? n : undefined;
}

function commonFields(form: FormData, values: ListingFormValues) {
  form.append('title', values.title.trim());
  appendIfPresent(form, 'description', values.description);
  form.append('categoryName', values.categoryName);
  form.append('propertyTypeName', values.propertyTypeName);
  form.append('listingType', values.listingType);
  form.append('negotiable', String(values.negotiable));

  const price = num(values.price);
  if (price !== undefined) form.append('price', String(price));
  appendIfPresent(form, 'deposit', values.deposit);
  appendIfPresent(form, 'maintenance', values.maintenance);
  const securityDeposit = num(values.securityDeposit);
  if (securityDeposit !== undefined) form.append('securityDeposit', String(securityDeposit));

  /**
   * Nested `area.*`, which is where the schema actually keeps these. The FLAT
   * `builtUpArea`/`carpetArea`/`superBuiltUpArea`/`plotArea` whitelist entries
   * are a trap — see the module doc; Mongoose drops them silently.
   *
   * `pricePerSqft` is DERIVED here rather than asked for, the way the website
   * derives it. Asking an owner for a number that is arithmetic over two
   * numbers they already gave invites a contradiction between the three.
   * Computed from super-built-up when present, since that is the area Indian
   * listings conventionally quote a rate against, else built-up, else total.
   */
  const area: Record<string, number> = {};
  const totalSqft = num(values.totalSqft);
  const carpetSqft = num(values.carpetSqft);
  const builtUpSqft = num(values.builtUpSqft);
  const superBuiltUpSqft = num(values.superBuiltUpSqft);
  const plotSqft = num(values.plotSqft);
  if (totalSqft !== undefined) area.totalSqft = totalSqft;
  if (carpetSqft !== undefined) area.carpetSqft = carpetSqft;
  if (builtUpSqft !== undefined) area.builtUpSqft = builtUpSqft;
  if (superBuiltUpSqft !== undefined) area.superBuiltUpSqft = superBuiltUpSqft;
  if (plotSqft !== undefined) area.plotSqft = plotSqft;

  const rateArea = superBuiltUpSqft ?? builtUpSqft ?? totalSqft;
  if (price !== undefined && rateArea !== undefined && rateArea > 0) {
    area.pricePerSqft = Math.round(price / rateArea);
  }

  if (Object.keys(area).length > 0) form.append('area', JSON.stringify(area));

  appendIfPresent(form, 'availableFrom', values.availableFrom);

  if (values.amenities.length > 0) form.append('amenities', JSON.stringify(values.amenities));

  if (values.parkingCovered || values.parkingOpen) {
    form.append(
      'parking',
      JSON.stringify({ covered: values.parkingCovered || '0', open: values.parkingOpen || '0' })
    );
  }

  /**
   * `legal` is sent whole or not at all — it is one nested object, so sending
   * only `reraId` (as this did before 2026-08-13) would leave the three
   * compliance booleans unsettable. They are only included when true: a
   * blanket `false` on every listing asserts "no fire NOC" where the owner
   * simply did not answer.
   */
  const legal: Record<string, string | boolean> = {};
  if (values.reraId.trim()) legal.reraId = values.reraId.trim();
  if (values.occupancyCertificate) legal.occupancyCertificate = true;
  if (values.tradeLicense) legal.tradeLicense = true;
  if (values.fireNoc) legal.fireNoc = true;
  if (Object.keys(legal).length > 0) form.append('legal', JSON.stringify(legal));

  if (values.categoryName === 'Residential') {
    appendIfPresent(form, 'bhk', values.bhk);
    const bedrooms = num(values.bedrooms);
    if (bedrooms !== undefined) form.append('bedrooms', String(bedrooms));
    const bathrooms = num(values.bathrooms);
    if (bathrooms !== undefined) form.append('bathrooms', String(bathrooms));
    const balconies = num(values.balconies);
    if (balconies !== undefined) form.append('balconies', String(balconies));
    appendIfPresent(form, 'furnishing', values.furnishing);
    appendIfPresent(form, 'totalFloors', values.totalFloors);
    appendIfPresent(form, 'facing', values.facing);
    appendIfPresent(form, 'constructionStatus', values.constructionStatus);
    form.append(
      'extras',
      JSON.stringify({
        servantRoom: values.servantRoom,
        poojaRoom: values.poojaRoom,
        studyRoom: values.studyRoom,
        storeRoom: values.storeRoom,
      })
    );
  } else {
    const washrooms = num(values.washrooms);
    if (washrooms !== undefined) form.append('washrooms', String(washrooms));
    appendIfPresent(form, 'pantry', values.pantry);
    appendIfPresent(form, 'meetingRooms', values.meetingRooms);
  }
}

/** `POST /properties/add`. New photos only — there is nothing to preserve yet. */
export function buildAddFormData(
  values: ListingFormValues,
  newPhotos: readonly CategorizedPhoto[]
): FormData {
  const form = new FormData();
  commonFields(form, values);

  form.append(
    'address',
    JSON.stringify({
      line: values.addressLine.trim(),
      city: values.city.trim(),
      area: values.locality.trim(),
      state: values.state.trim(),
      pincode: values.pincode.trim(),
      landmark: values.landmark.trim() || undefined,
      // `address.nearby: [String]`. Add-path only: `updateMyProperty` rebuilds
      // `data.address` from flat top-level fields and would discard this.
      nearby: values.nearby.length > 0 ? values.nearby : undefined,
    })
  );
  form.append('city', values.city.trim());
  form.append('locality', values.locality.trim());

  if (newPhotos.length > 0) {
    const { orderedUris, categoryMap } = buildCategorizedImageMap(newPhotos);
    form.append('imageCategoryMap', JSON.stringify(categoryMap));
    orderedUris.forEach((uri, index) => {
      form.append('categorizedImages', imagePart(uri, index));
    });
  }

  return form;
}

/**
 * `PUT /properties/my-properties/:id`. `existingPhotos` MUST be the complete
 * set of photos the listing should keep — see the module doc for why
 * omitting one wipes the gallery instead of leaving it alone.
 */
export function buildEditFormData(
  values: ListingFormValues,
  newPhotos: readonly CategorizedPhoto[],
  existingPhotos: readonly CategorizedPhoto[]
): FormData {
  const form = new FormData();
  commonFields(form, values);

  appendIfPresent(form, 'city', values.city);
  appendIfPresent(form, 'locality', values.locality);
  appendIfPresent(form, 'landmark', values.landmark);

  const bucket = values.categoryName === 'Residential' ? 'residential' : 'commercial';
  const existingByCategory: Record<string, string[]> = {};
  for (const photo of existingPhotos) {
    (existingByCategory[photo.category] ??= []).push(photo.uri);
  }
  form.append('existingCategorizedImages', JSON.stringify({ [bucket]: existingByCategory }));

  if (newPhotos.length > 0) {
    const categoryMap = newPhotos.map((photo, index) => ({ index, category: photo.category }));
    form.append('imageCategoryMap', JSON.stringify(categoryMap));
    newPhotos.forEach((photo, index) => {
      form.append('images', imagePart(photo.uri, index));
    });
  }

  return form;
}
