'use client';

import { useEffect, useState } from 'react';
import { InformationCircleIcon } from '@heroicons/react/24/outline';

import api from '../../utils/api';
import { formatCompactRupees } from '../../utils/priceIntelligence';
import { askVerb, formatPeriod, normalizeListingType } from '../../utils/localityFormat';

const DEBOUNCE_MS = 500;

/**
 * Map the listing form's own vocabulary ("Rent" / "Sell") onto the two values
 * the API accepts. Anything that is not rent is a sale.
 *
 * @param {string} formListingType
 * @returns {'sale'|'rent'}
 */
export function toApiListingType(formListingType) {
    return normalizeListingType(
        String(formListingType || '').toLowerCase() === 'rent' ? 'rent' : 'sale'
    );
}

/**
 * One muted line on the price step telling an owner what comparable homes in
 * their locality are asking.
 *
 * THREE THINGS IT DOES NOT DO, all deliberate:
 *   - It never blocks or gates submission. It has no callback into validation.
 *   - It never prefills the price field. The owner's number is the owner's.
 *   - It never phrases the range as a recommendation. "Similar homes ask X" is
 *     an observation; "you should ask X" would be advice DealDirect is not in a
 *     position to give, and would make the platform party to the price.
 *
 * Renders nothing until city, locality and a usable range all exist, so an
 * owner in a locality below the sample floor simply sees no line rather than a
 * "no data" message they can do nothing about.
 *
 * @param {{city?: string, locality?: string, listingType?: string, bhk?: string}} props
 */
export default function PriceGuidance({ city, locality, listingType, bhk }) {
    const apiListingType = toApiListingType(listingType);

    // The exact question the displayed answer belongs to. Storing it alongside
    // the result is what lets the line vanish the instant the owner edits the
    // locality, without clearing state from inside the effect body — a stale
    // range under a changed address is worse than no range at all.
    const key = `${city || ''}|${locality || ''}|${apiListingType}|${bhk || ''}`;

    const [result, setResult] = useState(null);

    useEffect(() => {
        if (!city || !locality) return undefined;

        const controller = new AbortController();

        const timer = setTimeout(async () => {
            try {
                const res = await api.get('/localities/guidance', {
                    params: {
                        city,
                        locality,
                        listingType: apiListingType,
                        ...(bhk ? { bhk } : {}),
                    },
                    signal: controller.signal,
                });
                setResult({ key, data: res.data?.data ?? null });
            } catch {
                // Guidance is a courtesy. A failure here is silent by design —
                // it must never interrupt someone in the middle of listing.
                if (!controller.signal.aborted) setResult({ key, data: null });
            }
        }, DEBOUNCE_MS);

        return () => {
            clearTimeout(timer);
            controller.abort();
        };
    }, [key, city, locality, apiListingType, bhk]);

    const guidance = result && result.key === key ? result.data : null;
    if (!guidance) return null;

    const low = formatCompactRupees(guidance.low);
    const high = formatCompactRupees(guidance.high);
    const median = formatCompactRupees(guidance.median);
    if (!low || !high) return null;

    const what = guidance.bhk ? `${guidance.bhk} homes` : 'Homes';
    const where = guidance.locality || locality;
    const period = formatPeriod(guidance.period);
    const count =
        typeof guidance.count === 'number' && guidance.count > 0 ? guidance.count : null;

    return (
        <p className="mt-2 flex items-start gap-1.5 text-xs leading-relaxed text-gray-500">
            <InformationCircleIcon className="mt-0.5 h-4 w-4 flex-shrink-0 text-gray-400" />
            <span>
                {what} in {where} {askVerb(apiListingType)} {low}–{high}
                {median ? `, median ${median}` : ''}
                {count ? ` — from ${count} live ${count === 1 ? 'listing' : 'listings'}` : ''}
                {period ? ` (${period})` : ''}. Asking prices on DealDirect, for reference only.
            </span>
        </p>
    );
}
