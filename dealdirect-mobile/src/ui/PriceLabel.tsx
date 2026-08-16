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

/**
 * The unit rate: "₹6,800 / sqft".
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS WORTH DERIVING
 *
 * It is the number that makes two listings comparable. A ₹1.18 crore flat and a
 * ₹1.4 crore flat tell you nothing about which is dearer until you know one is
 * 1,734 sqft and the other 2,230; ₹6,800 and ₹6,280 per sqft answers it
 * immediately. Every large Indian portal prints it on both the results card and
 * the detail screen for exactly that reason, and we had it computable from two
 * fields we already carry and were not showing.
 *
 * ---------------------------------------------------------------------------
 * WHY IT RETURNS NULL SO OFTEN
 *
 * A derived number inherits the reliability of the worst field it derives from,
 * and `areaSqft` is the worst field here: it is the best of five area columns
 * picked by the adapter, several listings carry none of them, and at least one
 * production row records an area small enough to be a typo. Dividing by that
 * unguarded prints "₹1.2 Crore / sqft" on a card, which is not a rounding error
 * the reader can discount — it is a number that destroys their trust in every
 * other number on the screen.
 *
 * So the guards are deliberately blunt: no area, no price, an implausibly small
 * area, or an implausible resulting rate all return null and the caller renders
 * nothing. A missing rate costs a line of useful information. A wrong one costs
 * the listing.
 *
 * The bounds are set to admit every real Indian listing and reject arithmetic
 * on bad data — ₹100/sqft is below any real sale anywhere in the country, and
 * ₹5,00,000/sqft is roughly ten times the dearest street in Mumbai.
 */
const MIN_PLAUSIBLE_AREA_SQFT = 50;
const MIN_PLAUSIBLE_RATE = 100;
const MAX_PLAUSIBLE_RATE = 500_000;

export function formatRatePerSqft(
  rupees: MixedValue | undefined,
  areaSqft: number | undefined
): string | null {
  const price = Number(rupees) || 0;
  if (price <= 0) return null;
  if (!areaSqft || areaSqft < MIN_PLAUSIBLE_AREA_SQFT) return null;

  const rate = Math.round(price / areaSqft);
  if (rate < MIN_PLAUSIBLE_RATE || rate > MAX_PLAUSIBLE_RATE) return null;

  return `₹${rate.toLocaleString('en-IN')} / sqft`;
}

export interface PriceLabelProps {
  /** Rupees. Pass the `price` field straight through; do not pre-scale it. */
  price?: MixedValue;
  variant?: TextVariant;
  /** Appended after the price, e.g. "/month" for rentals. */
  suffix?: string;
  /**
   * Caps every part at one line.
   *
   * Off by default, because on a card there is room and a wrapped price is
   * better than a truncated one. ON in the compact list row, where the row's
   * height is meant to be identical for every listing and a five-crore price
   * beside a per-sqft rate is the one thing that could add a line and make the
   * list jump.
   */
  numberOfLines?: number;
  className?: string;
}

export function PriceLabel({
  price,
  variant = 'title3',
  suffix,
  numberOfLines,
  className = '',
}: PriceLabelProps) {
  const { value, unit } = formatPriceParts(price);

  return (
    <View className={`flex-row items-baseline ${className}`}>
      <Text variant={variant} numberOfLines={numberOfLines}>
        {value}
      </Text>
      {unit ? (
        <Text variant="subhead" tone="secondary" numberOfLines={numberOfLines} className="ml-xs">
          {unit}
        </Text>
      ) : null}
      {suffix ? (
        <Text variant="footnote" tone="muted" numberOfLines={numberOfLines} className="ml-xs">
          {suffix}
        </Text>
      ) : null}
    </View>
  );
}
