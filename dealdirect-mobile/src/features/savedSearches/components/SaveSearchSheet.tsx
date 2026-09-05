import { useState } from 'react';
import { View } from 'react-native';

import { ApiError } from '@/api';
import { useAuth } from '@/auth';
import { Button, Chip, Input, Sheet, Text } from '@/ui';
import { track } from '@/analytics';
import { registerPushTokenIfPermitted, requestNotificationPermissionOnce } from '@/notifications';
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

interface AlertChannels {
  notifyInApp: boolean;
  notifyEmail: boolean;
  notifyPush: boolean;
}

/** All on, matching the server defaults. */
const DEFAULT_CHANNELS: AlertChannels = {
  notifyInApp: true,
  notifyEmail: true,
  notifyPush: true,
};

const ALERT_CHANNELS: readonly { key: keyof AlertChannels; label: string }[] = [
  { key: 'notifyInApp', label: 'In app' },
  { key: 'notifyEmail', label: 'Email' },
  { key: 'notifyPush', label: 'Push' },
];

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
  const [channels, setChannels] = useState<AlertChannels>(DEFAULT_CHANNELS);
  const [error, setError] = useState<string | null>(null);

  const muted = !channels.notifyInApp && !channels.notifyEmail && !channels.notifyPush;

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
    setChannels(DEFAULT_CHANNELS);
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
        ...channels,
      });
      reset();
      onSaved?.();
      track('saved_search_create', { city: trimmedCity || undefined });
      // The OS prompt, asked once ever and only now: the alert this sheet
      // promises is the first thing a notification would carry. Skipped when
      // the user has just turned push OFF, because asking for permission to
      // send something they declined is the kind of prompt people learn to
      // dismiss on sight.
      if (channels.notifyPush) {
        void requestNotificationPermissionOnce().then(registerPushTokenIfPermitted);
      }
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
    <Sheet visible={visible} onClose={reset} title="Save this search" heightRatio={0.8}>
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

      {/*
        WHERE THE ALERT ARRIVES (Phase 1, F8)

        All three channels are on by default, which matches the server and
        matches what somebody who has just pressed "save this search" wants.
        They are offered here rather than only on the list row because a user
        who does not want email is deciding that at the moment they save, not
        three days later after the first one lands.

        Turning all three off is allowed. It saves a search that alerts
        nowhere, which is a real thing to want — the list row calls that muted
        and says the search still runs.
      */}
      <Text variant="footnote" tone="secondary" className="mt-lg">
        Alert me
      </Text>
      <View className="mt-sm flex-row flex-wrap gap-sm">
        {ALERT_CHANNELS.map((channel) => (
          <Chip
            key={channel.key}
            label={channel.label}
            selected={channels[channel.key]}
            onPress={() =>
              setChannels((current) => ({ ...current, [channel.key]: !current[channel.key] }))
            }
          />
        ))}
      </View>
      {muted ? (
        <Text variant="caption" tone="muted" className="mt-sm">
          Nothing selected, so this search will be saved but will not alert you. You can turn a
          channel back on any time.
        </Text>
      ) : null}

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
