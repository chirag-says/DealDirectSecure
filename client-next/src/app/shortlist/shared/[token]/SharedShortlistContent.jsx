'use client';

import Link from 'next/link';
import { BookmarkIcon, ClockIcon, EyeIcon } from '@heroicons/react/24/outline';

import ShortlistCard from '../../../../components/Shortlist/ShortlistCard';
import { formatFullDate } from '../../../../utils/priceIntelligence';

/**
 * Somebody else's shortlist, read-only.
 *
 * No remove control, no save control, no note editing. The only difference
 * between this and the owner's own page is the absence of `onRemove` on the
 * card, which is deliberate: there is one card component and one way to get an
 * edit control on it.
 *
 * @param {{ list: {label?: string, properties?: Array, expiresAt?: string}|null,
 *           unavailable?: boolean }} props
 */
export default function SharedShortlistContent({ list, unavailable }) {
    if (!list || unavailable) {
        return (
            <div className="min-h-screen bg-slate-50/60">
                <div className="mx-auto max-w-xl px-4 py-20 text-center sm:px-6">
                    <BookmarkIcon className="mx-auto h-10 w-10 text-slate-300" />
                    <h1 className="mt-4 text-2xl font-semibold tracking-tight text-slate-900">
                        This shared list is not loading
                    </h1>
                    <p className="mt-3 text-sm leading-relaxed text-slate-600">
                        The link may have expired, or we could not reach it just now. Ask whoever
                        sent it to share it again.
                    </p>
                    <Link
                        href="/properties"
                        className="mt-7 inline-block rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0c3f8f]"
                    >
                        Browse properties
                    </Link>
                </div>
            </div>
        );
    }

    const properties = Array.isArray(list.properties) ? list.properties : [];
    const expires = formatFullDate(list.expiresAt);

    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-14">
                <header className="mb-8">
                    <span className="inline-flex items-center gap-1.5 rounded-full bg-slate-100 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-600">
                        <EyeIcon className="h-3.5 w-3.5" />
                        Shared with you · view only
                    </span>

                    <h1 className="mt-3 text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
                        {list.label || 'A shared shortlist'}
                    </h1>

                    <p className="mt-2 text-sm text-slate-600">
                        {properties.length} {properties.length === 1 ? 'home' : 'homes'}, shared from
                        someone&apos;s DealDirect shortlist. You can open each listing; nothing you
                        do here changes their list.
                    </p>

                    {expires && (
                        <p className="mt-2 flex items-center gap-1.5 text-xs text-slate-500">
                            <ClockIcon className="h-4 w-4" />
                            This link stops working on {expires}
                        </p>
                    )}
                </header>

                {properties.length === 0 ? (
                    <div className="rounded-3xl border border-slate-200 bg-white p-10 text-center">
                        <h2 className="text-lg font-semibold text-slate-900">
                            There is nothing on this list
                        </h2>
                        <p className="mt-2 text-sm text-slate-600">
                            Whoever shared it has not saved any homes yet.
                        </p>
                    </div>
                ) : (
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                        {properties.map((property, i) => (
                            <ShortlistCard
                                key={property?._id || property?.id || i}
                                entry={{ property }}
                            />
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
