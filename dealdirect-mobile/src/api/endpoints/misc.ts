/**
 * Taxonomy, blog and contact endpoints.
 *
 * Taxonomy paths are non-REST and differ per resource. They are written out
 * here exactly as mounted rather than being regularised, because guessing a
 * symmetrical path produces a 404.
 */

import type { Category, PropertyType, SubCategory } from '@/types/backend/taxonomy';
import type {
  Blog,
  BlogDetailResponse,
  BlogListParams,
  CreateInquiryRequest,
  CreateInquiryResponse,
  MyInquiriesResponse,
} from '@/types/backend/misc';
import type {
  DataEnvelope,
  ObjectId,
  PaginatedDataEnvelope,
} from '@/types/backend/common';
import { defineEndpoint } from './_contract';

export const taxonomyEndpoints = {
  categories: defineEndpoint<void, DataEnvelope<Category[]>>({
    method: 'GET',
    path: '/categories/list-category',
    auth: 'public',
    envelope: 'data',
    note: 'Path is `list-category`, singular suffix.',
  }),

  subcategories: defineEndpoint<void, DataEnvelope<SubCategory[]>>({
    method: 'GET',
    path: '/subcategories/list',
    auth: 'public',
    envelope: 'data',
    note: 'Path is plain `list` here, unlike categories.',
  }),

  subcategoriesByCategory: defineEndpoint<
    void,
    DataEnvelope<SubCategory[]>,
    { categoryId: ObjectId }
  >({
    method: 'GET',
    path: ({ categoryId }) => `/subcategories/byCategory/${categoryId}`,
    auth: 'public',
    envelope: 'data',
    note: 'camelCase segment `byCategory`.',
  }),

  propertyTypes: defineEndpoint<void, DataEnvelope<PropertyType[]>>({
    method: 'GET',
    path: '/propertyTypes/list-propertytype',
    auth: 'public',
    envelope: 'data',
    note:
      'The mount is camelCase (`/api/propertyTypes`) while the path segment is lowercase ' +
      '(`list-propertytype`). Both spellings are required exactly as written.',
  }),
} as const;

export const blogsEndpoints = {
  list: defineEndpoint<BlogListParams, PaginatedDataEnvelope<Blog> & { pagination: { limit: number } }>({
    method: 'GET',
    path: '/blogs',
    auth: 'public',
    envelope: 'paginated',
    note:
      'Free-text param is `q` here, NOT `search` as in property search. Default limit 10. ' +
      'Only posts with status `published` are returned.',
  }),

  bySlug: defineEndpoint<void, BlogDetailResponse, { slug: string }>({
    method: 'GET',
    path: ({ slug }) => `/blogs/${slug}`,
    auth: 'public',
    envelope: 'data',
    note: 'Keyed by SLUG, not by id. Also returns a `related` array alongside `data`.',
  }),

  categories: defineEndpoint<void, DataEnvelope<string[]>>({
    method: 'GET',
    path: '/blogs/meta/categories',
    auth: 'public',
    envelope: 'data',
  }),

  tags: defineEndpoint<void, DataEnvelope<string[]>>({
    method: 'GET',
    path: '/blogs/meta/tags',
    auth: 'public',
    envelope: 'data',
  }),
} as const;

export const contactEndpoints = {
  create: defineEndpoint<CreateInquiryRequest, CreateInquiryResponse>({
    method: 'POST',
    path: '/contact',
    auth: 'user',
    envelope: 'keyed',
    note: 'Requires authentication. Body capped at 20KB.',
  }),

  mine: defineEndpoint<void, MyInquiriesResponse>({
    method: 'GET',
    path: '/contact/my-inquiries',
    auth: 'user',
    envelope: 'keyed',
    note: 'Response key is `inquiries`, not `data`.',
  }),
} as const;
