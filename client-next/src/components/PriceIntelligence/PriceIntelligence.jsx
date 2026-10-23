'use client';

import Link from 'next/link';
import {
    ArrowTrendingDownIcon,
    ArrowTrendingUpIcon,
    ClockIcon,
    ScaleIcon,
    TagIcon,
} from '@heroicons/react/24/outline';

import {
    describeDaysListed,
    describeMarketMedian,
    describeMarketPosition,
    describePriceDrop,
    formatPriceHistory,
} from '../../utils/priceIntelligence';
import { localityHref, normalizeListingType } from '../../utils/localityFormat';

const POSITION_TONE = {
    below: 'text-emerald-700',
    above: 'text-amber-700',
    inline: 'text-slate-700',
};

function Line({ icon, children, tone = 'text-slate-700' }) {
    return (
        <div className={`flex items-start gap-2 text-sm ${tone}`}>
            <span className="mt-0.5 flex-shrink-0 text-slate-400">{icon}</span>
            <span className="min-w-0">{children}</span>
        </div>
    );
}

/**
 * The "Price" block on a listing: what the price has done, how long the home
 * has been up, and where it sits against its locality.
 *
 * Every line is independently optional. `priceIntelligence` fields are all
 * nullable and the rule from the plan is to render nothing rather than a zero,
 * so an absent value drops its line and an entirely empty object renders
 * nothing at all — no headings, no dashes, no "N/A".
 *
 * All wording and arithmetic lives in `utils/priceIntelligence.js`; this file
 * only decides layout.
 *
 * @param {{
 *   data: object|null|undefined,
 *   listingType?: string
 * }} props
 */
export default function PriceIntelligence({ data, listingType }) {
    if (!data) return null;

    const dropLine = describePriceDrop(data.lastDrop);
    const daysLine = describeDaysListed(data.daysListed);
    const position = describeMarketPosition(data.market);
    const medianLine = describeMarketMedian(data.market);
    const history = formatPriceHistory(data.changes);

    if (!dropLine && !daysLine && !position && !medianLine && history.length === 0) return null;

    // Only "listed N days ago" to say: one quiet line under the price, not a
    // boxed panel with a heading around a single sentence.
    if (daysLine && !dropLine && !position && !medianLine && history.length === 0) {
        return (
            <p className="flex items-center gap-1.5 text-xs text-slate-500">
                <ClockIcon className="h-3.5 w-3.5 flex-shrink-0" />
                {daysLine}
            </p>
        );
    }

    const marketType = normalizeListingType(
        String(listingType || '').toLowerCase() === 'rent' ? 'rent' : 'sale'
    );
    const slug = data.market?.slug;

    return (
        <div className="rounded-2xl border border-slate-200 bg-slate-50/70 p-4">
            <p className="mb-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">
                Price
            </p>

            <div className="space-y-2">
                {dropLine && (
                    <Line
                        icon={<ArrowTrendingDownIcon className="h-4 w-4" />}
                        tone="text-emerald-700 font-semibold"
                    >
                        {dropLine}
                    </Line>
                )}

                {daysLine && <Line icon={<ClockIcon className="h-4 w-4" />}>{daysLine}</Line>}

                {position && (
                    <Line
                        icon={<ScaleIcon className="h-4 w-4" />}
                        tone={`${POSITION_TONE[position.position]} font-semibold`}
                    >
                        {slug ? (
                            <Link
                                href={localityHref(slug, marketType)}
                                className="underline decoration-slate-300 underline-offset-2 hover:decoration-current"
                            >
                                {position.text}
                            </Link>
                        ) : (
                            position.text
                        )}
                    </Line>
                )}

                {medianLine && (
                    <p className="pl-6 text-xs leading-relaxed text-slate-500">
                        {medianLine}. Asking prices from DealDirect listings, not a valuation.
                    </p>
                )}
            </div>

            {history.length > 0 && (
                <details className="group mt-3 border-t border-slate-200 pt-3">
                    <summary className="cursor-pointer list-none text-xs font-semibold text-[#0f4fb5] hover:underline">
                        <span className="group-open:hidden">
                            Show price history ({history.length}{' '}
                            {history.length === 1 ? 'change' : 'changes'})
                        </span>
                        <span className="hidden group-open:inline">Hide price history</span>
                    </summary>

                    <ul className="mt-3 space-y-2">
                        {history.map((row, i) => (
                            <li
                                key={`${row.date || 'change'}-${i}`}
                                className="flex items-center justify-between gap-3 text-xs"
                            >
                                <span className="text-slate-500">{row.date || 'Earlier'}</span>
                                <span className="flex items-center gap-1.5 font-medium text-slate-800">
                                    {row.direction === 'down' ? (
                                        <ArrowTrendingDownIcon className="h-3.5 w-3.5 text-emerald-600" />
                                    ) : (
                                        <ArrowTrendingUpIcon className="h-3.5 w-3.5 text-amber-600" />
                                    )}
                                    {row.from} → {row.to}
                                    {row.deltaText && (
                                        <span
                                            className={
                                                row.direction === 'down'
                                                    ? 'text-emerald-700'
                                                    : 'text-amber-700'
                                            }
                                        >
                                            ({row.deltaText})
                                        </span>
                                    )}
                                </span>
                            </li>
                        ))}
                    </ul>

                    <p className="mt-3 flex items-start gap-1.5 text-[11px] leading-relaxed text-slate-500">
                        <TagIcon className="mt-0.5 h-3.5 w-3.5 flex-shrink-0" />
                        Every figure is an asking price set by the owner on DealDirect.
                    </p>
                </details>
            )}
        </div>
    );
}
