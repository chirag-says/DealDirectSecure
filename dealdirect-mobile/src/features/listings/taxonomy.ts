import { useQuery } from '@tanstack/react-query';
import { useMemo } from 'react';

import { call, qk } from '@/api';
import { taxonomyEndpoints } from '@/api/endpoints/misc';

/**
 * The listing form's category and property-type options, FROM THE SERVER.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT A CONSTANT
 *
 * It was one: `types.ts` carried hardcoded `RESIDENTIAL_TYPES` and
 * `COMMERCIAL_TYPES` arrays, and they had drifted from the names the backend
 * actually accepts. Six of the twelve offered types — `Independent House /
 * Villa`, `Plot / Land`, `Farmhouse`, `Shop / Showroom`, `Co-working Space`,
 * `Commercial Plot` — matched nothing on the server, and `Land & Plots` could
 * not be reached at all.
 *
 * That is not a typo class of bug, because of how the server resolves taxonomy.
 * `utils/taxonomyResolver.js` states it outright: "There is no fallback of any
 * kind. No substring, no case folding, no nearest match, no first-document
 * default." An unknown name is a 400. So an owner filled in seven steps of a
 * wizard and was refused at submit, with the offending field five screens back.
 *
 * A corrected constant would have been the same bug with a later expiry date —
 * and worse, the corpus is mid-migration: the canonical list in
 * `backend/config/taxonomy.js` is what the taxonomy is BECOMING, while what the
 * server accepts today is the intersection of that list with the documents
 * actually in the database. Hardcoding either one is wrong on one side of the
 * cutover.
 *
 * `GET /propertyTypes/list-propertytype` returns exactly the right thing:
 * `findActivePropertyTypes()`, which is every canonical type that EXISTS as a
 * document under an active category. That is the same set the write path will
 * accept, by construction, before and after the migration. So the form asks.
 *
 * ---------------------------------------------------------------------------
 * WHAT HAPPENS WHEN THIS CANNOT LOAD
 *
 * The form shows an error and a retry on the step that needs it, and does not
 * advance. It deliberately does NOT fall back to a built-in list: a fallback
 * here is exactly the bug this replaces, and offering options the server will
 * reject wastes the owner's whole session rather than one tap on Retry.
 *
 * Both queries are public, cached for an hour, and shared by key — the taxonomy
 * changes on the order of never, and two screens (add and edit) mount this.
 */

export interface TaxonomyCategory {
  id: string;
  /** Exact `categoryName` the server accepts, e.g. `Residential`. */
  name: string;
  /** Exact `propertyTypeName`s valid UNDER this category. */
  types: string[];
}

export interface ListingTaxonomy {
  categories: TaxonomyCategory[];
  isLoading: boolean;
  error: unknown;
  retry: () => void;
}

/** An hour. The taxonomy is a fixed vocabulary, not content. */
const TAXONOMY_STALE_MS = 60 * 60_000;

export function useListingTaxonomy(): ListingTaxonomy {
  const categories = useQuery({
    queryKey: qk.categories(),
    queryFn: ({ signal }) => call(taxonomyEndpoints.categories, { signal }),
    staleTime: TAXONOMY_STALE_MS,
  });

  const propertyTypes = useQuery({
    queryKey: qk.propertyTypes(),
    queryFn: ({ signal }) => call(taxonomyEndpoints.propertyTypes, { signal }),
    staleTime: TAXONOMY_STALE_MS,
  });

  const grouped = useMemo<TaxonomyCategory[]>(() => {
    const cats = categories.data?.data ?? [];
    const types = propertyTypes.data?.data ?? [];
    if (cats.length === 0) return [];

    return cats
      .map((category) => ({
        id: String(category._id),
        name: category.name,
        /*
          Joined on the type's own `category` reference rather than on name,
          because the server's uniqueness constraint is per category — the same
          type name may legitimately exist under two categories, and matching by
          name would put it under both.
        */
        types: types
          .filter((type) => String(type.category ?? '') === String(category._id))
          .map((type) => type.name),
      }))
      // A category with no types cannot produce a valid listing, so offering it
      // is offering a dead end.
      .filter((category) => category.types.length > 0);
  }, [categories.data, propertyTypes.data]);

  return {
    categories: grouped,
    isLoading: categories.isPending || propertyTypes.isPending,
    // Either failing leaves the pair unusable: types without categories cannot
    // be grouped, categories without types have nothing to offer.
    error: categories.error ?? propertyTypes.error,
    retry: () => {
      void categories.refetch();
      void propertyTypes.refetch();
    },
  };
}
