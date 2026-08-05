import { View } from 'react-native';

import type { MixedValue } from '@/types/backend/common';
import { Text, type TextVariant } from './Text';

/**
 * Price display.
 *
 * `price` IS IN RUPEES. `priceUnit` is NOT a multiplier and must never be used
 * as one.
 *
 * ---------------------------------------------------------------------------
 * CORRECTED 2026-08-03, against live production data. The M1 version of this
 * file multiplied `price` by 1e5 whenever `priceUnit` contained "Lac" or
 * "Lakh", ported from the `normalizePrice` helper duplicated in the website's
 * HomeContent.jsx and PropertyListContent.jsx. That was wrong, and it would
 * have shown a ₹65,000 rental as "₹650 Crore" on a real listing.
 *
 * What the data actually shows (36 approved listings, sampled 2026-08-03):
 *
 *   priceUnit "Lac"     15 rows, 14 of them with a rupee-scale price
 *                       (65000, 17800000, 36000, 225000, …)
 *   priceUnit "Monthly" 13 rows, rupee-scale
 *   priceUnit "Total"    8 rows, rupee-scale
 *
 * `priceUnit` defaults to `"Lac"` in the Property schema
 * (`models/Property.js:23`) and nothing in the add-property flow overwrites it
 * for those rows, so on most listings it records the default rather than the
 * unit. It does not describe the number next to it.
 *
 * The website reaches the same place by a different route: it displays with
 * `formatPrice(property.price)`, which treats the raw value as rupees and never
 * consults `priceUnit`. Its `normalizePrice` is used only for client-side
 * sorting and its price-range filter, both of which are consequently wrong on
 * "Lac" rows. This client copies the website's DISPLAY, which is correct, and
 * not its filter, which is not. Do not reintroduce the multiplier to "match the
 * website" — it would match a bug users never see.
 * ---------------------------------------------------------------------------
 *
 * Formatting is Indian units: Crore at 1e7, Lakh at 1e5, grouped digits below.
 */

const CRORE = 10_000_000;
const LAKH = 100_000;

const trim = (value: number): string =>
  value % 1 === 0
    ? value.toFixed(0)
    : value.toFixed(2).replace(/0+$/, '').replace(/\.$/, '');

/** Rupees in, `{ value, unit }` out, so the unit can be styled separately. */
export function formatPriceParts(rupees: MixedValue | undefined): { value: string; unit: string } {
  const amount = Number(rupees) || 0;
  if (amount <= 0) return { value: '₹0', unit: '' };

  if (amount >= CRORE) return { value: `₹${trim(amount / CRORE)}`, unit: 'Crore' };
  if (amount >= LAKH) return { value: `₹${trim(amount / LAKH)}`, unit: 'Lakh' };

  return { value: `₹${amount.toLocaleString('en-IN')}`, unit: '' };
}

export function formatPrice(rupees: MixedValue | undefined): string {
  const { value, unit } = formatPriceParts(rupees);
  return unit ? `${value} ${unit}` : value;
}

export interface PriceLabelProps {
  /** Rupees. Pass the `price` field straight through; do not pre-scale it. */
  price?: MixedValue;
  variant?: TextVariant;
  /** Appended after the price, e.g. "/month" for rentals. */
  suffix?: string;
  className?: string;
}

export function PriceLabel({ price, variant = 'title3', suffix, className = '' }: PriceLabelProps) {
  const { value, unit } = formatPriceParts(price);

  return (
    <View className={`flex-row items-baseline ${className}`}>
      <Text variant={variant}>{value}</Text>
      {unit ? (
        <Text variant="subhead" tone="secondary" className="ml-xs">
          {unit}
        </Text>
      ) : null}
      {suffix ? (
        <Text variant="footnote" tone="muted" className="ml-xs">
          {suffix}
        </Text>
      ) : null}
    </View>
  );
}
