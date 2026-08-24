/**
 * Category / SubCategory / PropertyType contract.
 * Source: backend/models/{Category,SubCategory,PropertyType}.js and their
 * controllers.
 *
 * All three list endpoints are public and use the `{ success, data }` envelope.
 * Note the non-REST paths: `/categories/list-category`,
 * `/subcategories/list`, `/propertyTypes/list-propertytype`.
 */

import type { ObjectId, Timestamps } from './common';

export interface Category extends Partial<Timestamps> {
  _id: ObjectId;
  name: string;
  /**
   * Populated by `/categories/list-category`, verified against production on
   * 2026-07-31. Not declared in the Category schema file, so it is written by
   * the controller's populate rather than by the model; treat it as optional.
   */
  propertyType?: ObjectId | PropertyType;
}

export interface SubCategory extends Partial<Timestamps> {
  _id: ObjectId;
  name: string;
  category?: ObjectId;
}

export interface PropertyType extends Partial<Timestamps> {
  _id: ObjectId;
  name: string;
  /**
   * The owning category, as a raw id.
   *
   * `/propertyTypes/list-propertytype` returns `.lean()` documents, so this is
   * present and unpopulated. It is what makes the type list groupable: the
   * model's uniqueness constraint is `{ category, name }`, so a type name is
   * only meaningful under its category and must never be matched by name alone.
   */
  category?: ObjectId;
}
