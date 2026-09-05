'use client';

import Link from 'next/link';
import {
    ArrowDownRightIcon,
    ArrowUpRightIcon,
    MapPinIcon,
    MinusSmallIcon,
} from '@heroicons/react/24/outline';

import {
    askVerb,
    describeQoq,
    describeSample,
    describeSpread,
    disclaimerLines,
    formatMedianPerSqft,
    formatPeriod,
    formatQoqBadge,
    listingTypeLabel,
    localityHref,
    localityLabel,
    priceNoun,
    trendBars,
} from '../../../utils/localityFormat';
import { formatCompactRupees, formatFullRupees } from '../../../utils/priceIntelligence';

const QOQ_TONE = {
    up: { text: 'text-emerald-700', chip: 'bg-emerald-50 text-emerald-700 border-emerald-100' },
    down: { text: 'text-rose-700', chip: 'bg-rose-50 text-rose-700 border-rose-100' },
    flat: { text: 'text-slate-600', chip: 'bg-slate-50 text-slate-600 border-slate-200' },
};

const QOQ_ICON = {
    up: ArrowUpRightIcon,
    down: ArrowDownRightIcon,
    flat: MinusSmallIcon,
};

/** The calm state for "the API is down", which is never a 404. */
function Unavailable({ slug }) {
    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-xl px-4 py-20 text-center sm:px-6">
                <MapPinIcon className="mx-auto h-10 w-10 text-slate-300" />
                <h1 className="mt-4 text-2xl font-semibold tracking-tight text-slate-900">
                    These figures are not loading right now
                </h1>
                <p className="mt-3 text-sm leading-relaxed text-slate-600">
                    The locality data for {slug} is temporarily unavailable. Nothing is wrong with
                    the locality — try again in a moment.
                </p>
                <Link
                    href="/localities"
                    className="mt-7 inline-flex items-center gap-2 rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0c3f8f]"
                >
                    See published localities
                </Link>
            </div>
        </div>
    );
}

function TrendChart({ trend, listingType }) {
    const bars = trendBars(trend);
    if (bars.length < 2) return null;

    return (
        <section className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-7">
            <h2 className="text-lg font-semibold text-slate-900">
                Median {listingType === 'rent' ? 'asking rent' : 'asking price'} by quarter
            </h2>
            <p className="mt-1 text-xs text-slate-500">
                Bars are measured from zero. Each quarter is its own sample of live listings.
            </p>

            <div className="mt-6 flex h-48 items-end gap-2 sm:gap-4">
                {bars.map((bar) => (
                    <div key={bar.period} className="flex h-full flex-1 flex-col justify-end">
                        <p className="mb-1.5 text-center text-[11px] font-semibold text-slate-700 sm:text-xs">
                            {bar.money || '—'}
                        </p>
                        <div
                            className="w-full rounded-t-lg bg-[#0f4fb5]/85"
                            style={{ height: `${bar.heightPct}%` }}
                            role="img"
                            aria-label={`${bar.label}: median ${bar.money}${bar.count ? ` from ${bar.count} listings` : ''}`}
                        />
                    </div>
                ))}
            </div>

            <div className="mt-2 flex gap-2 border-t border-slate-100 pt-2 sm:gap-4">
                {bars.map((bar) => (
                    <div key={bar.period} className="flex-1 text-center">
                        <p className="text-[11px] font-medium text-slate-600">{bar.label}</p>
                        {bar.count !== null && (
                            <p className="text-[10px] text-slate-400">{bar.count} listings</p>
                        )}
                    </div>
                ))}
            </div>
        </section>
    );
}

function ConfigurationTable({ rows, listingType }) {
    const usable = Array.isArray(rows) ? rows.filter((r) => r && r.bhk) : [];
    if (usable.length === 0) return null;

    return (
        <section className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-7">
            <h2 className="text-lg font-semibold text-slate-900">By configuration</h2>
            <p className="mt-1 text-xs text-slate-500">
                Each row is its own sample. A row with few listings behind it moves more than the
                market does.
            </p>

            <div className="mt-5 -mx-5 overflow-x-auto sm:mx-0">
                <table className="w-full min-w-[520px] text-sm">
                    <thead>
                        <tr className="border-b border-slate-200 text-left">
                            <th className="px-5 pb-2 font-semibold text-slate-500 sm:px-0">Homes</th>
                            <th className="px-3 pb-2 text-right font-semibold text-slate-500">
                                Median
                            </th>
                            <th className="px-3 pb-2 text-right font-semibold text-slate-500">
                                Middle half
                            </th>
                            <th className="px-3 pb-2 text-right font-semibold text-slate-500">
                                Listings
                            </th>
                            <th className="px-5 pb-2 text-right font-semibold text-slate-500 sm:px-0">
                                vs last quarter
                            </th>
                        </tr>
                    </thead>
                    <tbody>
                        {usable.map((row) => {
                            const qoq = formatQoqBadge(row.qoqPct);
                            const p25 = formatCompactRupees(row.p25);
                            const p75 = formatCompactRupees(row.p75);
                            return (
                                <tr key={row.bhk} className="border-b border-slate-100 last:border-0">
                                    <td className="px-5 py-3 font-semibold text-slate-900 sm:px-0">
                                        {row.bhk}
                                    </td>
                                    <td className="px-3 py-3 text-right font-semibold text-slate-900">
                                        {formatCompactRupees(row.medianAsking) || '—'}
                                    </td>
                                    <td className="px-3 py-3 text-right text-slate-600">
                                        {p25 && p75 ? `${p25}–${p75}` : '—'}
                                    </td>
                                    <td className="px-3 py-3 text-right text-slate-600">
                                        {typeof row.count === 'number' ? row.count : '—'}
                                    </td>
                                    <td className="px-5 py-3 text-right sm:px-0">
                                        {qoq ? (
                                            <span
                                                className={`inline-block rounded-full border px-2 py-0.5 text-xs font-semibold ${QOQ_TONE[qoq.direction].chip}`}
                                            >
                                                {qoq.text}
                                            </span>
                                        ) : (
                                            <span className="text-slate-400">—</span>
                                        )}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>

            <p className="mt-4 text-xs text-slate-500">
                Medians are what homes {askVerb(listingType)} on DealDirect today.
            </p>
        </section>
    );
}

export default function LocalityContent({ detail, sampleFloor, slug, listingType, unavailable }) {
    if (!detail) return <Unavailable slug={slug} />;
    if (unavailable) return <Unavailable slug={slug} />;

    const place = localityLabel(detail);
    const headline = detail.headline || {};
    const period = formatPeriod(detail.period);

    const median = formatFullRupees(headline.medianAsking);
    const sample = describeSample(headline.count);
    const spread = describeSpread(headline.p25, headline.p75, listingType);
    const perSqft = formatMedianPerSqft(headline.medianPerSqft);
    const qoq = describeQoq(headline.qoqPct);
    const QoqIcon = qoq ? QOQ_ICON[qoq.direction] : null;

    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-4xl px-4 py-10 sm:px-6 sm:py-14">
                {/* Breadcrumb trail (visible; the machine-readable one is in page.js) */}
                <nav className="mb-6 flex items-center gap-1.5 text-xs text-slate-500">
                    <Link href="/localities" className="hover:text-[#0f4fb5]">
                        Locality prices
                    </Link>
                    <span aria-hidden="true">/</span>
                    <span className="font-medium text-slate-700">{place}</span>
                </nav>

                {/* Headline */}
                <header className="rounded-3xl border border-slate-200 bg-white p-6 sm:p-8">
                    <div className="flex flex-wrap items-center gap-2">
                        <span className="inline-flex items-center gap-1.5 rounded-full bg-[#0f4fb5]/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-[#0f4fb5]">
                            <MapPinIcon className="h-3.5 w-3.5" />
                            {detail.city || 'India'}
                        </span>
                        {period && (
                            <span className="rounded-full bg-slate-100 px-3 py-1 text-[11px] font-semibold text-slate-600">
                                {period}
                            </span>
                        )}
                    </div>

                    <h1 className="mt-4 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
                        {priceNoun(listingType) === 'asking rents' ? 'Asking rents' : 'Asking prices'}{' '}
                        in {place}
                    </h1>

                    <div className="mt-6">
                        <p className="text-xs font-semibold uppercase tracking-[0.08em] text-slate-500">
                            Median asking {listingType === 'rent' ? 'rent' : 'price'}
                        </p>
                        <div className="mt-1 flex flex-wrap items-baseline gap-3">
                            <span className="text-4xl font-semibold text-slate-900 sm:text-5xl">
                                {median || 'Not published'}
                            </span>
                            {listingType === 'rent' && median && (
                                <span className="text-base text-slate-500">a month</span>
                            )}
                            {perSqft && (
                                <span className="rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-700">
                                    {perSqft}
                                </span>
                            )}
                        </div>

                        <div className="mt-3 space-y-1.5">
                            {sample && <p className="text-sm text-slate-600">{sample}</p>}
                            {spread && <p className="text-sm text-slate-600">{spread}</p>}
                            {qoq && (
                                <p
                                    className={`inline-flex items-center gap-1.5 text-sm font-semibold ${QOQ_TONE[qoq.direction].text}`}
                                >
                                    {QoqIcon && <QoqIcon className="h-4 w-4" />}
                                    {qoq.text}
                                </p>
                            )}
                        </div>
                    </div>

                    {/* Sale / rent switch — real links, so both versions are crawlable */}
                    <div className="mt-7 inline-flex rounded-2xl border border-slate-200 bg-slate-50 p-1">
                        {['sale', 'rent'].map((t) => (
                            <Link
                                key={t}
                                href={localityHref(slug, t)}
                                aria-current={listingType === t ? 'page' : undefined}
                                className={`rounded-xl px-4 py-2 text-sm font-semibold transition-colors ${listingType === t
                                    ? 'bg-white text-[#0f4fb5] shadow-sm'
                                    : 'text-slate-600 hover:text-slate-900'
                                    }`}
                            >
                                {t === 'sale' ? 'For sale' : 'To rent'}
                            </Link>
                        ))}
                    </div>
                </header>

                <div className="mt-6 space-y-6">
                    <ConfigurationTable rows={detail.byConfiguration} listingType={listingType} />
                    <TrendChart trend={detail.trend} listingType={listingType} />

                    {/* Route back into inventory — the page exists to earn a visit */}
                    <section className="rounded-3xl border border-slate-200 bg-white p-6 sm:p-7">
                        <h2 className="text-lg font-semibold text-slate-900">
                            See what is actually listed in {detail.locality || place}
                        </h2>
                        <p className="mt-1.5 text-sm text-slate-600">
                            These medians come from listings you can open right now — direct from
                            owners, no brokerage.
                        </p>
                        <Link
                            href={`/properties?search=${encodeURIComponent(detail.locality || detail.city || '')}`}
                            className="mt-4 inline-flex items-center gap-2 rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0c3f8f]"
                        >
                            Browse homes {listingTypeLabel(listingType)} in{' '}
                            {detail.locality || detail.city}
                        </Link>
                    </section>
                </div>

                {/* Disclaimer — visible, not a tooltip */}
                <footer className="mt-8 rounded-2xl border border-slate-200 bg-white p-5">
                    <h2 className="text-xs font-semibold uppercase tracking-[0.1em] text-slate-500">
                        How to read these numbers
                    </h2>
                    <div className="mt-2 space-y-1.5">
                        {disclaimerLines(sampleFloor, listingType).map((line) => (
                            <p key={line} className="text-xs leading-relaxed text-slate-600">
                                {line}
                            </p>
                        ))}
                    </div>
                </footer>
            </div>
        </div>
    );
}
