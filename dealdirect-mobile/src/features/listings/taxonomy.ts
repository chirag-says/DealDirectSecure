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
 * WHAT HAPPENS WHEN THE SERVER OFFERS NOTHING — measured 2026-08-24
 *
 * Both endpoints return `{"success":true,"data":[]}` against production right
 * now. The taxonomy collections have not been seeded there; the migration that
 * does it is prepared and deliberately deferred. So "ask the server" alone
 * would replace a wizard that fails at the last step with a wizard that cannot
 * be started at all, which is not an improvement for an owner trying to list
 * today.
 *
 * Hence `CANONICAL_FALLBACK`, used only when the server's answer is empty. It
 * is NOT the guess the old constant was, and the distinction is the whole
 * justification: it mirrors `backend/config/taxonomy.js`, and production's own
 * listings are already stored against it — `/properties/search` returns
 * `Commercial`/`Showroom` and `Residential`/`Apartment / Flat` today. So the
 * fallback offers names the corpus demonstrably uses, rather than six names
 * that matched nothing.
 *
 * The order of preference is what matters: the server's live answer always
 * wins when it has one, so the day the migration runs this constant stops being
 * consulted without anyone editing it.
 *
 * A fetch failure takes the same path as an empty answer — the fallback — and
 * the form does not report it. That is deliberate. The owner came to list a
 * property, the fallback lets them, and an error banner above a working control
 * is noise that describes our problem rather than theirs. `usingFallback` and
 * `error` are both exposed for anything that wants to know.
 *
 * Both queries are public, cached for an hour, and shared by key — the taxonomy
 * changes on the order of never, and two screens (add and edit) mount this.
 */

/**
 * A mirror of `backend/config/taxonomy.js`'s `CANONICAL_TAXONOMY`.
 *
 * Consulted ONLY when the server returns an empty taxonomy. Any edit here has
 * to be made against that file — it is the source, this is a copy kept for the
 * window in which production has the code but not the data.
 */
const CANONICAL_FALLBACK: readonly TaxonomyCategory[] = [
  {
    id: 'fallback:Residential',
    name: 'Residential',
    types: [
      'Apartment / Flat',
      'Independent House',
      'Villa',
      'Builder Floor',
      'Row House',
      'Studio Apartment',
      'Penthouse',
      'Farm House',
    ],
  },
  {
    id: 'fallback:Commercial',
    name: 'Commercial',
    types: [
      'Office Space',
      'Shop / Retail',
      'Showroom',
      'Restaurant / Cafe',
      'Co-Working Space',
      'Warehouse / Godown',
      'Industrial Shed',
      'Commercial Building / Floor',
    ],
  },
  {
    id: 'fallback:Land & Plots',
    name: 'Land & Plots',
    types: ['Residential Plot', 'Commercial Land', 'Industrial Land', 'Agricultural Land'],
  },
];

export interface TaxonomyCategory {
  id: string;
  /** Exact `categoryName` the server accepts, e.g. `Residential`. */
  name: string;
  /** Exact `propertyTypeName`s valid UNDER this category. */
  types: string[];
}

export interface ListingTaxonomy {
  categories: readonly TaxonomyCategory[];
  /** True when the options came from the canonical mirror, not from the server. */
  usingFallback: boolean;
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

  const isLoading = categories.isPending || propertyTypes.isPending;

  /*
    The server's answer wins whenever it has one. The fallback covers only the
    "loaded successfully, but there is nothing there" case — see the note above.
  */
  const resolved = grouped.length > 0 ? grouped : isLoading ? [] : CANONICAL_FALLBACK;

  return {
    categories: resolved,
    /** True when the options came from the mirror rather than from the server. */
    usingFallback: resolved === CANONICAL_FALLBACK,
    isLoading,
    // Either failing leaves the pair unusable: types without categories cannot
    // be grouped, categories without types have nothing to offer.
    error: categories.error ?? propertyTypes.error,
    retry: () => {
      void categories.refetch();
      void propertyTypes.refetch();
    },
  };
}
