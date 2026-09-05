'use client';

import { useState } from 'react';
import Link from 'next/link';
import { ArrowRight } from 'lucide-react';

/**
 * Media houses that carried the press release. The list is the top ~18
 * recognisable names; the full set lives on /press-impressions.
 *
 * `domain` feeds Google's favicon service, which is the only practical way to
 * show this many publication logos without hosting eighteen image assets.
 */
const FEATURED_MEDIA = [
    { name: 'Google News', domain: 'news.google.com' },
    { name: 'Yahoo News', domain: 'yahoo.com' },
    { name: 'News18', domain: 'news18.com' },
    { name: 'Business Standard', domain: 'business-standard.com' },
    { name: 'Tribune India', domain: 'tribuneindia.com' },
    { name: 'ANI', domain: 'aninews.in' },
    { name: 'Lokmat', domain: 'lokmattimes.com' },
    { name: 'Gujarat Samachar', domain: 'gujaratsamachar.news' },
    { name: 'British News Network', domain: 'britishnewsnetwork.com' },
    { name: 'Middle East Times', domain: 'middleeasttimes.news' },
    { name: 'Wall Street Sentinel', domain: 'wallstreetsentinel.news' },
    { name: 'Miami News Herald', domain: 'miaminewsherald.com' },
    { name: 'Washington DC Despatch', domain: 'washingtondcdespatch.com' },
    { name: 'Capitol Hill Reporter', domain: 'capitolhillreporter.com' },
];

const initials = (name) =>
    name.split(/\s+/).slice(0, 2).map((w) => w[0]).join('').toUpperCase();

function MediaChip({ name, domain }) {
    const [failed, setFailed] = useState(false);

    return (
        <div className="flex select-none items-center gap-2.5 whitespace-nowrap rounded-full border border-slate-200 bg-white px-5 py-2.5 shadow-sm">
            {failed ? (
                // Google's favicon service returns a generic globe or a 404 for a
                // handful of these domains. Initials read as intentional; a broken
                // image icon on a trust band does the opposite of its job.
                <span
                    aria-hidden="true"
                    className="flex h-5 w-5 shrink-0 items-center justify-center rounded bg-slate-100 text-[9px] font-bold text-slate-500"
                >
                    {initials(name)}
                </span>
            ) : (
                // eslint-disable-next-line @next/next/no-img-element
                <img
                    src={`https://t2.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://${domain}&size=64`}
                    alt=""
                    width={20}
                    height={20}
                    className="h-5 w-5 shrink-0 rounded-sm object-contain"
                    loading="lazy"
                    onError={() => setFailed(true)}
                />
            )}
            <span className="text-sm font-semibold text-slate-700">{name}</span>
        </div>
    );
}

/** One row of chips, duplicated so the -50% translate loops seamlessly. */
function MarqueeRow({ items, reverse = false, duration }) {
    return (
        <div
            className="press-marquee-track flex w-max gap-4"
            style={{
                animationDuration: `${duration}s`,
                animationDirection: reverse ? 'reverse' : 'normal',
            }}
        >
            {[...items, ...items].map((media, i) => (
                <MediaChip key={`${media.domain}-${i}`} {...media} />
            ))}
        </div>
    );
}

export default function PressMarquee() {
    const half = Math.ceil(FEATURED_MEDIA.length / 2);
    const rowOne = FEATURED_MEDIA.slice(0, half);
    const rowTwo = FEATURED_MEDIA.slice(half);

    return (
        <section
            className="relative overflow-hidden border-t border-slate-100 bg-white py-12 sm:py-16"
            aria-labelledby="press-heading"
        >
            <div className="mx-auto mb-10 max-w-6xl px-6 text-center">
                <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                    Press coverage
                </p>
                <h2
                    id="press-heading"
                    className="mt-3 text-2xl font-extrabold tracking-tight text-slate-900 sm:text-3xl"
                >
                    Featured in <span className="text-red-600 tabular-nums">267+</span> publications
                </h2>
                <p className="mx-auto mt-2 max-w-xl text-sm text-slate-500 sm:text-base">
                    Reaching <span className="font-semibold tabular-nums text-slate-700">782M+</span>{' '}
                    readers across India and the world.
                </p>
            </div>

            {/* Two rows moving in opposite directions. One thin strip under a
                large claim read as filler; a counter-scrolling pair gives the
                section enough mass to carry the number above it. */}
            <div className="relative space-y-4">
                <div className="pointer-events-none absolute inset-y-0 left-0 z-10 w-16 bg-gradient-to-r from-white to-transparent sm:w-32" />
                <div className="pointer-events-none absolute inset-y-0 right-0 z-10 w-16 bg-gradient-to-l from-white to-transparent sm:w-32" />

                <MarqueeRow items={rowOne} duration={40} />
                <MarqueeRow items={rowTwo} reverse duration={48} />
            </div>

            <div className="mt-10 text-center">
                <Link
                    href="/press-impressions"
                    className="inline-flex items-center gap-2 rounded-full bg-slate-900 px-6 py-3 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-slate-900 focus-visible:ring-offset-2"
                >
                    View press impressions
                    <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
            </div>

            <style jsx>{`
                .press-marquee-track {
                    animation-name: marquee-scroll;
                    animation-timing-function: linear;
                    animation-iteration-count: infinite;
                }
                .press-marquee-track:hover {
                    animation-play-state: paused;
                }
                @keyframes marquee-scroll {
                    0% { transform: translateX(0); }
                    100% { transform: translateX(-50%); }
                }
                /* Without this the global reduce-motion rule collapses the
                   animation to 0.01ms, which lands the row at -50% and clips the
                   first half of the chips. Stopping it at 0 keeps them readable. */
                @media (prefers-reduced-motion: reduce) {
                    .press-marquee-track {
                        animation: none;
                        transform: translateX(0);
                    }
                }
            `}</style>
        </section>
    );
}
