/**
 * Display rules for the builder project card (components/Projects/ProjectCard.jsx),
 * kept free of JSX so node --test can check them.
 *
 * compactPrice: rupees as "₹37 L" or "₹1.56 Cr", rounded half up; nothing for a missing or
 * non-positive amount, so the card says "On request" instead of "₹0".
 *
 * projectPriceLabel: one price when min and max print the same, a range
 * otherwise.
 *
 * projectFacts: the possession / units / type strip. A fact with nothing to
 * say (missing, zero units, "N/A", an invalid date) is left out rather than
 * shown empty.
 *
 * projectRera: the registration number as entered, or null when blank.
 */

import { isBlankValue } from './listingDisplay.js';

export function compactPrice(n) {
  if (typeof n !== 'number' || !Number.isFinite(n) || n <= 0) return null;
  // Rounded in whole lakh first: (13550000 / 1e7).toFixed(2) gives "1.35"
  // because 1.355 has no exact binary form, so ₹1.355 Cr printed low.
  if (n >= 1e7) return `₹${(Math.round(n / 1e5) / 100).toFixed(2).replace(/\.?0+$/, '')} Cr`;
  if (n >= 1e5) return `₹${Math.round(n / 1e5)} L`;
  return `₹${n.toLocaleString('en-IN')}`;
}

export function projectPriceLabel(priceRange) {
  const min = compactPrice(priceRange?.min);
  const max = compactPrice(priceRange?.max);
  if (!min) return max;
  return max && max !== min ? `${min} – ${max}` : min;
}

function monthYear(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? null
    : date.toLocaleDateString('en-IN', { month: 'short', year: 'numeric', timeZone: 'Asia/Kolkata' });
}

export function projectFacts(project) {
  const units = project?.overview?.totalUnits;
  const type = [project?.basics?.subType, project?.basics?.category].find((v) => !isBlankValue(v));
  return [
    ['Possession', monthYear(project?.overview?.possessionDate)],
    ['Units', typeof units === 'number' && units > 0 ? units.toLocaleString('en-IN') : null],
    ['Type', type ? type.trim() : null],
  ].filter(([, value]) => !isBlankValue(value));
}

export function projectRera(project) {
  const rera = project?.basics?.reraNumber;
  return isBlankValue(rera) ? null : rera.trim();
}
