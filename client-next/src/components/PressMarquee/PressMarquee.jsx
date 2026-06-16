'use client';

import Link from 'next/link';
import { FaNewspaper, FaArrowRight } from 'react-icons/fa';

/**
 * Top media houses featured in the press release.
 * We hardcode the top ~14 recognizable names for the marquee strip.
 * Domain is used to pull favicon via Google's API.
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

function MediaChip({ name, domain }) {
    return (
        <div className="flex items-center gap-2.5 px-5 py-2.5 bg-white/80 backdrop-blur-sm rounded-full border border-gray-200/60 shadow-sm whitespace-nowrap select-none">
            <img
                src={`https://t2.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://${domain}&size=64`}
                alt={name}
                width={20}
                height={20}
                className="rounded-sm flex-shrink-0"
                loading="lazy"
            />
            <span className="text-sm font-semibold text-gray-700">{name}</span>
        </div>
    );
}

export default function PressMarquee() {
    // Duplicate the list to create seamless infinite scroll
    const items = [...FEATURED_MEDIA, ...FEATURED_MEDIA];

    return (
        <section className="relative py-10 sm:py-14 bg-gradient-to-b from-gray-50 to-white overflow-hidden">
            {/* Header */}
            <div className="max-w-6xl mx-auto px-6 text-center mb-8">
                <h2 className="text-2xl sm:text-3xl font-extrabold text-gray-900 tracking-tight">
                    Featured in <span className="text-red-600">267+</span> Publications
                </h2>
                <p className="text-gray-500 mt-2 text-sm sm:text-base max-w-xl mx-auto">
                    Reaching 782M+ readers across India and the world
                </p>
            </div>

            {/* Marquee */}
            <div className="relative">
                {/* Left fade */}
                <div className="absolute left-0 top-0 bottom-0 w-20 sm:w-32 bg-gradient-to-r from-gray-50 to-transparent z-10 pointer-events-none" />
                {/* Right fade */}
                <div className="absolute right-0 top-0 bottom-0 w-20 sm:w-32 bg-gradient-to-l from-white to-transparent z-10 pointer-events-none" />

                <div className="press-marquee-track flex gap-4">
                    {items.map((media, i) => (
                        <MediaChip key={`${media.domain}-${i}`} {...media} />
                    ))}
                </div>
            </div>

            {/* CTA */}
            <div className="text-center mt-8">
                <Link
                    href="/press-impressions"
                    className="inline-flex items-center gap-2 bg-gray-900 hover:bg-gray-800 text-white font-semibold text-sm px-6 py-3 rounded-full shadow-lg hover:shadow-xl transition-all duration-300 hover:-translate-y-0.5"
                >
                    View Press Impressions <FaArrowRight className="text-xs" />
                </Link>
            </div>

            {/* Marquee CSS animation */}
            <style jsx>{`
                .press-marquee-track {
                    animation: marquee-scroll 35s linear infinite;
                    width: max-content;
                }
                .press-marquee-track:hover {
                    animation-play-state: paused;
                }
                @keyframes marquee-scroll {
                    0% { transform: translateX(0); }
                    100% { transform: translateX(-50%); }
                }
            `}</style>
        </section>
    );
}
