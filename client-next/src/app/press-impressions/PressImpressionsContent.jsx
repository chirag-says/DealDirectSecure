'use client';

import { useState, useMemo } from 'react';
import Link from 'next/link';
import { FaExternalLinkAlt, FaSearch, FaNewspaper, FaGlobe, FaArrowLeft } from 'react-icons/fa';
import pressData from '../../data/pressReleases.json';

/**
 * Extract domain from a URL for favicon lookup
 */
function getDomain(url) {
    try {
        return new URL(url).hostname.replace('www.', '');
    } catch {
        return '';
    }
}

/**
 * Google's v2 favicon API — much better coverage than s2/favicons.
 * Returns proper logos for nearly all sites.
 */
function getFaviconUrl(domain) {
    return `https://t2.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=https://${domain}&size=64`;
}

/**
 * Top-tier publications that get a highlighted badge
 */
const TOP_TIER = new Set([
    'Google', 'Yahoo', 'news18', 'Business Standard',
    'Tribune', 'ANI', 'Lokmat English'
]);

export default function PressImpressionsContent() {
    const [search, setSearch] = useState('');

    const filtered = useMemo(() => {
        if (!search.trim()) return pressData;
        const q = search.toLowerCase();
        return pressData.filter(m =>
            m.name.toLowerCase().includes(q) ||
            m.url.toLowerCase().includes(q)
        );
    }, [search]);

    return (
        <div className="min-h-screen bg-gray-50">
            {/* Hero */}
            <section className="relative bg-gradient-to-br from-gray-900 via-slate-800 to-gray-900 text-white overflow-hidden">
                {/* Subtle pattern overlay */}
                <div className="absolute inset-0 opacity-[0.04]" style={{
                    backgroundImage: 'radial-gradient(circle at 1px 1px, white 1px, transparent 0)',
                    backgroundSize: '32px 32px'
                }} />

                <div className="relative max-w-6xl mx-auto px-6 py-16 sm:py-24 text-center">

                    <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight mb-4">
                        In the <span className="text-red-500">Spotlight</span>
                    </h1>
                    <p className="text-gray-300 text-base sm:text-lg max-w-2xl mx-auto mb-10 leading-relaxed">
                        Our launch story was picked up by <strong className="text-white">267+ newsrooms</strong> across the globe, reaching over <strong className="text-white">782 million</strong> readers — from national desks to international wires.
                    </p>

                    {/* Stats */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 sm:gap-6 max-w-3xl mx-auto mb-10">
                        {[
                            { value: '267+', label: 'Newsrooms' },
                            { value: '782M+', label: 'Readers Reached' },
                            { value: '76%', label: 'India' },
                            { value: '24%', label: 'Global' },
                        ].map(stat => (
                            <div key={stat.label} className="bg-white/5 backdrop-blur border border-white/10 rounded-xl py-4 px-3">
                                <div className="text-2xl sm:text-3xl font-black text-white">{stat.value}</div>
                                <div className="text-[11px] sm:text-xs text-gray-400 mt-1 uppercase tracking-wider">{stat.label}</div>
                            </div>
                        ))}
                    </div>

                    {/* Press release headline */}
                    <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">12 May 2026 · Press Release</p>
                    <p className="text-sm sm:text-base font-medium text-gray-300 italic max-w-xl mx-auto">
                        &ldquo;DealDirect.in Launches Broker-Free Property Marketplace with Reward-Backed Model&rdquo;
                    </p>
                </div>
            </section>

            {/* Search & Grid */}
            <section className="max-w-7xl mx-auto px-4 sm:px-6 py-10 sm:py-16">
                {/* Search */}
                <div className="flex flex-col sm:flex-row items-center justify-end gap-4 mb-8">
                    <div className="relative w-full sm:w-80">
                        <FaSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 text-gray-400 text-sm" />
                        <input
                            type="text"
                            placeholder="Search publications..."
                            value={search}
                            onChange={e => setSearch(e.target.value)}
                            className="w-full pl-10 pr-4 py-2.5 rounded-full border border-gray-200 bg-white text-sm text-gray-800 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-400 shadow-sm transition-all placeholder:text-gray-400"
                        />
                    </div>
                </div>

                {/* Grid */}
                {filtered.length === 0 ? (
                    <div className="text-center py-20">
                        <p className="text-gray-400 text-lg">No publications found for &ldquo;{search}&rdquo;</p>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                        {filtered.map((media, i) => {
                            const domain = getDomain(media.url);
                            const isTop = TOP_TIER.has(media.name);
                            return (
                                <a
                                    key={`${media.name}-${i}`}
                                    href={media.url}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className={`group relative flex items-center gap-3.5 p-4 rounded-xl border bg-white shadow-sm hover:shadow-lg hover:-translate-y-0.5 transition-all duration-300 ${isTop
                                            ? 'border-red-200 bg-red-50/30 hover:border-red-300'
                                            : 'border-gray-100 hover:border-gray-200'
                                        }`}
                                >
                                    {/* Favicon */}
                                    <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${isTop ? 'bg-red-100' : 'bg-gray-100'
                                        }`}>
                                        <img
                                            src={getFaviconUrl(domain)}
                                            alt={media.name}
                                            width={24}
                                            height={24}
                                            className="rounded-sm"
                                            loading="lazy"
                                            onError={(e) => {
                                                if (!e.target.dataset.fallback) {
                                                    e.target.dataset.fallback = '1';
                                                    e.target.src = `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
                                                } else {
                                                    e.target.style.display = 'none';
                                                    e.target.parentElement.innerHTML = `<span style="font-weight:700;font-size:16px;color:#9ca3af">${media.name.charAt(0).toUpperCase()}</span>`;
                                                }
                                            }}
                                        />
                                    </div>

                                    {/* Name & domain */}
                                    <div className="flex-1 min-w-0">
                                        <p className="text-sm font-semibold text-gray-800 truncate group-hover:text-red-600 transition-colors">
                                            {media.name}
                                        </p>
                                        <p className="text-xs text-gray-400 truncate">{domain}</p>
                                    </div>

                                    {/* External link icon */}
                                    <FaExternalLinkAlt className="flex-shrink-0 text-[10px] text-gray-300 group-hover:text-red-500 transition-colors" />

                                    {/* Top badge */}
                                    {isTop && (
                                        <div className="absolute -top-1.5 -right-1.5 bg-red-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full shadow-sm">
                                            TOP
                                        </div>
                                    )}
                                </a>
                            );
                        })}
                    </div>
                )}
            </section>

            {/* Bottom CTA */}
            <section className="bg-white border-t border-gray-100 py-12">
                <div className="max-w-3xl mx-auto px-6 text-center">
                    <h2 className="text-xl sm:text-2xl font-bold text-gray-900 mb-3">
                        Want to learn more about DealDirect?
                    </h2>
                    <p className="text-gray-500 text-sm mb-6">
                        Join thousands of property owners and buyers who are already using DealDirect to transact directly — no brokerage, no middlemen.
                    </p>
                    <div className="flex flex-wrap justify-center gap-3">
                        <Link
                            href="/about"
                            className="inline-flex items-center gap-2 bg-gray-900 hover:bg-gray-800 text-white font-semibold text-sm px-6 py-3 rounded-full shadow-lg hover:shadow-xl transition-all duration-300"
                        >
                            About DealDirect
                        </Link>
                        <Link
                            href="/properties"
                            className="inline-flex items-center gap-2 bg-white hover:bg-gray-50 text-gray-800 font-semibold text-sm px-6 py-3 rounded-full shadow-md border border-gray-200 hover:border-gray-300 transition-all duration-300"
                        >
                            Browse Properties
                        </Link>
                    </div>
                </div>
            </section>
        </div>
    );
}
