import { useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth } from '@/auth';
import { Button, Chip, Input, Sheet, Text } from '@/ui';
import { useCreateSavedSearch } from '../hooks';
import { PRICE_BAND_LABELS, PRICE_BAND_ORDER, type SavedSearchPriceBand } from '../types';

/**
 * Create a saved search.
 *
 * ---------------------------------------------------------------------------
 * ONLY THE FILTERS THAT ACTUALLY ALERT ARE OFFERED
 *
 * The backend will happily store five filter keys, but its alert matcher reads
 * three, and one of those is broken for half its values:
 *
 *   city         works
 *   priceRange   works, as "low" | "mid" | "high" only
 *   availableFor OMITTED. Compared to `listingType.toLowerCase()` exactly,
 *                and the schema stores three spellings of for-sale (`Sell`,
 *                `Sale`, `sale`). Saving "sale" silently misses every listing
 *                stored as "Sell". Offering a control that works for rent and
 *                quietly fails for sale is worse than not offering it: the
 *                user cannot tell the difference and blames the alerts.
 *                Enabling it needs the same alias expansion already applied to
 *                the search controller — a few lines, then this comes back.
 *   propertyType OMITTED. Matched on an ObjectId, and those refs are null or
 *                wrong across the live data.
 *   search       OMITTED. Never read by the matcher at all.
 *
 * The free-text term the user was searching with is deliberately NOT saved
 * into `filters.search`. It would satisfy the backend's "at least one filter"
 * check while guaranteeing the search never fires — the exact trap the inert
 * badge on the list exists to explain. It seeds the NAME instead, where it is
 * useful and honest.
 */

export interface SaveSearchSheetProps {
  visible: boolean;
  onClose: () => void;
  /** The search box contents, used to seed the name only. */
  seedTerm?: string;
  onSaved?: () => void;
}

/**
 * City is typed rather than seeded from the results screen: this app's search
 * filters carry no city field, because `/properties/search` matches `city`
 * exactly and case-sensitively against data holding both "Bangalore" and
 * "Bengaluru". There is nothing to prefill from.
 */
export function SaveSearchSheet({ visible, onClose, seedTerm, onSaved }: SaveSearchSheetProps) {
  const { status } = useAuth();
  const { create, isPending } = useCreateSavedSearch();

  const [name, setName] = useState(seedTerm ?? '');
  const [city, setCity] = useState('');
  const [band, setBand] = useState<SavedSearchPriceBand | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  const trimmedName = name.trim();
  const trimmedCity = city.trim();

  // Mirrors the server's rule so the button explains itself before the request
  // rather than after a 400.
  const hasFilter = !!trimmedCity || !!band;
  const canSubmit = trimmedName.length > 0 && hasFilter && !isPending;

  const reset = () => {
    setName(seedTerm ?? '');
    setCity('');
    setBand(undefined);
    setError(null);
    onClose();
  };

  const submit = async () => {
    setError(null);

    try {
      await create({
        name: trimmedName,
        filters: {
          city: trimmedCity,
          priceRange: band ?? '',
        },
      });
      reset();
      onSaved?.();
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 400
          ? err.message
          : 'Could not save this search. Please try again.'
      );
    }
  };

  if (status !== 'authenticated') {
    return (
      <Sheet visible={visible} onClose={reset} title="Save this search" heightRatio={0.3}>
        <Text variant="body" tone="secondary">
          Sign in to save a search and get alerted when new listings match it.
        </Text>
      </Sheet>
    );
  }

  return (
    <Sheet visible={visible} onClose={reset} title="Save this search" heightRatio={0.66}>
      <Text variant="footnote" tone="muted">
        We will alert you when a new listing matches. Alerts match on city and price range.
      </Text>

      <Input
        label="Name"
        value={name}
        onChangeText={setName}
        placeholder="e.g. Two-bed in Pune"
        containerClassName="mt-lg"
        maxLength={100}
      />

      <Input
        label="City"
        value={city}
        onChangeText={setCity}
        placeholder="e.g. Mumbai"
        autoCapitalize="words"
        containerClassName="mt-md"
        maxLength={100}
        hint="Matched exactly, so use the spelling the listings use."
      />

      <Text variant="footnote" tone="secondary" className="mt-lg">
        Price range
      </Text>
      <View className="mt-sm flex-row flex-wrap gap-sm">
        {PRICE_BAND_ORDER.map((option) => (
          <Chip
            key={option}
            label={PRICE_BAND_LABELS[option]}
            selected={band === option}
            // Pressing the selected band clears it, so a user can back out of
            // a choice without a separate "any price" control.
            onPress={() => setBand(band === option ? undefined : option)}
          />
        ))}
      </View>

      {error ? (
        <Text variant="footnote" tone="danger" className="mt-md">
          {error}
        </Text>
      ) : null}

      {!hasFilter ? (
        <Text variant="caption" tone="muted" className="mt-md">
          Add a city or a price range. A search with neither cannot be matched against new
          listings.
        </Text>
      ) : null}

      <Button
        label="Save search"
        onPress={submit}
        loading={isPending}
        disabled={!canSubmit}
        fullWidth
        className="mt-lg"
      />
    </Sheet>
  );
}
