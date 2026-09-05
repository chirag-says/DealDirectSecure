'use client';

import { useMemo, useState } from 'react';
import Link from 'next/link';
import { MapPinIcon, ArrowRightIcon } from '@heroicons/react/24/outline';

import {
    citiesIn,
    describeSample,
    disclaimerLines,
    formatPeriod,
    formatQoqBadge,
    groupByCity,
    listingTypeLabel,
    localityHref,
    normalizeListingType,
} from '../../utils/localityFormat';
import { formatCompactRupees } from '../../utils/priceIntelligence';

const QOQ_TONE = {
    up: 'text-emerald-700 bg-emerald-50 border-emerald-100',
    down: 'text-rose-700 bg-rose-50 border-rose-100',
    flat: 'text-slate-600 bg-slate-50 border-slate-200',
};

function LocalityRow({ item }) {
    const median = formatCompactRupees(item.medianAsking);
    const qoq = formatQoqBadge(item.qoqPct);

    return (
        <Link
            href={localityHref(item.slug, item.listingType)}
            className="group flex items-center justify-between gap-4 rounded-2xl border border-slate-200 bg-white px-4 py-3.5 transition-colors hover:border-[#0f4fb5]/40 hover:bg-slate-50"
        >
            <div className="min-w-0">
                <p className="truncate text-sm font-semibold text-slate-900">{item.locality}</p>
                <p className="mt-0.5 text-xs text-slate-500">
                    {describeSample(item.count) || 'Sample size unavailable'}
                </p>
            </div>

            <div className="flex flex-shrink-0 items-center gap-3">
                <div className="text-right">
                    {median ? (
                        <p className="text-sm font-semibold text-slate-900">{median}</p>
                    ) : (
                        <p className="text-sm text-slate-400">—</p>
                    )}
                    {qoq && (
                        <span
                            className={`mt-0.5 inline-block rounded-full border px-2 py-0.5 text-[11px] font-semibold ${QOQ_TONE[qoq.direction]}`}
                        >
                            {qoq.text} QoQ
                        </span>
                    )}
                </div>
                <ArrowRightIcon className="h-4 w-4 flex-shrink-0 text-slate-300 transition-colors group-hover:text-[#0f4fb5]" />
            </div>
        </Link>
    );
}

export default function LocalitiesContent({ localities, sampleFloor, unavailable }) {
    const [listingType, setListingType] = useState('sale');
    const [city, setCity] = useState('all');

    const forType = useMemo(() => {
        const all = Array.isArray(localities) ? localities : [];
        return all.filter((l) => normalizeListingType(l.listingType) === listingType);
    }, [localities, listingType]);

    const cities = useMemo(() => citiesIn(forType), [forType]);

    const visible = useMemo(
        () => (city === 'all' ? forType : forType.filter((l) => l.city === city)),
        [forType, city]
    );

    const grouped = useMemo(() => groupByCity(visible), [visible]);

    // Every row in a quarter carries the same period, so the first one labels
    // the whole page.
    const period = formatPeriod(forType[0]?.period);

    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-14">
                <header className="mb-8">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[#0f4fb5]">
                        Locality data
                    </p>
                    <h1 className="mt-2 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
                        What homes are asking, locality by locality
                    </h1>
                    <p className="mt-3 max-w-2xl text-sm leading-relaxed text-slate-600 sm:text-base">
                        Median asking {listingType === 'rent' ? 'rents' : 'prices'} measured from live
                        DealDirect listings{period ? `, for ${period}` : ''}. Every figure below is
                        what owners are asking today, not what anything sold for.
                    </p>
                </header>

                {/* Filters */}
                <div className="mb-8 space-y-4">
                    <div
                        className="inline-flex rounded-2xl border border-slate-200 bg-white p-1"
                        role="group"
                        aria-label="Listing type"
                    >
                        {['sale', 'rent'].map((t) => (
                            <button
                                key={t}
                                type="button"
                                onClick={() => {
                                    setListingType(t);
                                    setCity('all');
                                }}
                                aria-pressed={listingType === t}
                                className={`rounded-xl px-4 py-2 text-sm font-semibold capitalize transition-colors ${listingType === t
                                    ? 'bg-[#0f4fb5] text-white'
                                    : 'text-slate-600 hover:bg-slate-50'
                                    }`}
                            >
                                {t === 'sale' ? 'For sale' : 'To rent'}
                            </button>
                        ))}
                    </div>

                    {cities.length > 0 && (
                        <div className="flex flex-wrap gap-2">
                            <button
                                type="button"
                                onClick={() => setCity('all')}
                                aria-pressed={city === 'all'}
                                className={`rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${city === 'all'
                                    ? 'border-[#0f4fb5] bg-[#0f4fb5]/10 text-[#0f4fb5]'
                                    : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'
                                    }`}
                            >
                                All cities
                            </button>
                            {cities.map((c) => (
                                <button
                                    key={c}
                                    type="button"
                                    onClick={() => setCity(c)}
                                    aria-pressed={city === c}
                                    className={`rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${city === c
                                        ? 'border-[#0f4fb5] bg-[#0f4fb5]/10 text-[#0f4fb5]'
                                        : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'
                                        }`}
                                >
                                    {c}
                                </button>
                            ))}
                        </div>
                    )}
                </div>

                {/* Results */}
                {grouped.length === 0 ? (
                    <div className="rounded-3xl border border-slate-200 bg-white p-8 text-center">
                        <MapPinIcon className="mx-auto h-8 w-8 text-slate-300" />
                        <h2 className="mt-3 text-lg font-semibold text-slate-900">
                            {unavailable
                                ? 'Locality data is not loading right now'
                                : `Nothing published ${listingTypeLabel(listingType)} yet`}
                        </h2>
                        <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-slate-600">
                            {unavailable
                                ? 'The figures are temporarily unavailable. Try again shortly.'
                                : `A locality appears here once enough listings are live in it${sampleFloor ? ` — at least ${sampleFloor}` : ''}. Below that we withhold the number rather than estimate one.`}
                        </p>
                        <Link
                            href="/properties"
                            className="mt-5 inline-flex items-center gap-2 rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0c3f8f]"
                        >
                            Browse properties
                        </Link>
                    </div>
                ) : (
                    <div className="space-y-8">
                        {grouped.map((group) => (
                            <section key={group.city}>
                                <h2 className="mb-3 flex items-center gap-2 text-lg font-semibold text-slate-900">
                                    <MapPinIcon className="h-5 w-5 text-[#0f4fb5]" />
                                    {group.city}
                                    <span className="text-sm font-normal text-slate-400">
                                        {group.items.length}{' '}
                                        {group.items.length === 1 ? 'locality' : 'localities'}
                                    </span>
                                </h2>
                                <div className="grid gap-2 sm:grid-cols-2">
                                    {group.items.map((item) => (
                                        <LocalityRow
                                            key={`${item.slug}-${item.listingType}`}
                                            item={item}
                                        />
                                    ))}
                                </div>
                            </section>
                        ))}
                    </div>
                )}

                {/* Disclaimer — the page is a measurement, and says so */}
                <footer className="mt-12 rounded-2xl border border-slate-200 bg-white p-5">
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
