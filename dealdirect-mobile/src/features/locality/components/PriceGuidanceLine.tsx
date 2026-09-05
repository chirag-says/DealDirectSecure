import { useEffect, useRef } from 'react';

import { track } from '@/analytics';
import { useDebouncedValue } from '@/lib';
import { Text, formatPrice } from '@/ui';
import type { LocalityListingType } from '@/types/backend/locality';
import { configurationHeading } from '../format';
import { usePriceGuidance } from '../hooks';

/**
 * One muted line under the price field: what similar homes nearby ask.
 *
 * ---------------------------------------------------------------------------
 * IT IS A FACT, NOT ADVICE, AND IT NEVER TOUCHES THE FIELD
 *
 * It does not prefill the price, does not suggest one, does not warn that the
 * entered price is high or low, and does not block submission. An owner asking
 * above the local median usually has a reason, and a form that argues with
 * them is a form they abandon. The sentence states what the neighbours ask and
 * stops.
 *
 * That restraint is also what keeps the app out of trouble: DealDirect has no
 * transaction data, so any number it produced as a recommendation would be an
 * asking-price median wearing a valuation costume.
 *
 * ---------------------------------------------------------------------------
 * DEBOUNCED, AND SILENT WHEN THERE IS NOTHING TO SAY
 *
 * City and locality are typed, so the inputs are debounced before they become
 * a request. Below the sample floor the server answers 200 with a null body
 * and this renders nothing at all — no "no data available" line, because a
 * form is not the place to apologise for a database.
 */

export interface PriceGuidanceLineProps {
  city: string;
  locality: string;
  listingType: LocalityListingType;
  /** The configuration the owner has picked, when they have picked one. */
  bhk?: string;
}

const DEBOUNCE_MS = 500;

export function PriceGuidanceLine({ city, locality, listingType, bhk }: PriceGuidanceLineProps) {
  const debouncedCity = useDebouncedValue(city, DEBOUNCE_MS);
  const debouncedLocality = useDebouncedValue(locality, DEBOUNCE_MS);
  const debouncedBhk = useDebouncedValue(bhk ?? '', DEBOUNCE_MS);

  const { guidance } = usePriceGuidance({
    city: debouncedCity,
    locality: debouncedLocality,
    listingType,
    bhk: debouncedBhk,
  });

  // Once per city per mount. The hook is debounced but still re-renders on
  // every keystroke that resolves, and an event per keystroke would drown the
  // one signal this is for: how often the line is actually seen.
  const reported = useRef<string | null>(null);
  useEffect(() => {
    if (!guidance || reported.current === guidance.city) return;
    reported.current = guidance.city;
    track('price_guidance_shown', { city: guidance.city });
  }, [guidance]);

  if (!guidance) return null;

  const what =
    guidance.scope === 'configuration' && guidance.bhk
      ? `${configurationHeading(guidance.bhk)} homes`
      : 'Homes';

  return (
    <Text variant="caption" tone="muted" className="mt-sm">
      {what} in {guidance.locality} ask {formatBand(guidance.low, guidance.high)} on DealDirect,
      across {guidance.count} {guidance.count === 1 ? 'listing' : 'listings'}.
    </Text>
  );
}

/**
 * "28 Lakh to 34 Lakh", or a single figure when the band has collapsed.
 *
 * Same lakh and crore vocabulary as everything else that prints money in this
 * app, so a guidance line and a listing price cannot be read against each
 * other in different units.
 */
function formatBand(low: number, high: number): string {
  if (!(low > 0) || !(high > 0)) return formatPrice(Math.max(low, high));
  if (low === high) return formatPrice(low);
  return `${formatPrice(low)} to ${formatPrice(high)}`;
}
