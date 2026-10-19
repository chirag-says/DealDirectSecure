'use client';

import React, { useState, useEffect, useMemo } from "react";
import { useRouter, useSearchParams } from 'next/navigation';
import {
    MapPin, Search, X, Building2, Bookmark, BookmarkCheck,
    CalendarDays, Sparkles, Construction, KeyRound, BadgeCheck,
    LayoutGrid, ArrowUpDown, ArrowRight, SlidersHorizontal,
} from "lucide-react";
import Link from 'next/link';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:9000';
const FALLBACK = "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800";

// ── Helpers ───────────────────────────────────────────────────────────────────

const toArray = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val.filter(Boolean);
    if (typeof val === 'string' && val.trim()) return [val.trim()];
    return [];
};

/**
 * Highlights are admin-authored free text and arrive in three shapes: an array,
 * a JSON-encoded array, or one delimited string.
 *
 * The length filter is the important part. Some projects have their entire
 * amenity list pasted in as a single unpunctuated sentence, and the old parser
 * happily rendered all 300 characters of it as one "chip" — which is what made
 * two cards in every row three times taller than the rest. Anything that is not
 * chip-sized is not a highlight; it is a description, and it belongs on the
 * project detail page.
 */
const toHighlights = (val) => {
    let raw = [];
    if (Array.isArray(val)) raw = val;
    else if (typeof val === 'string') {
        try {
            const parsed = JSON.parse(val);
            raw = Array.isArray(parsed) ? parsed : [val];
        } catch { raw = [val]; }
    }
    return raw
        .flatMap((s) => String(s).split(/[,;|\n•]+/))
        .map((s) => s.trim())
        // Must contain a letter: splitting on commas leaves bare number
        // fragments ("150") behind, and a chip reading "150" tells nobody anything.
        .filter((s) => s.length > 2 && s.length <= 26 && /[a-z]/i.test(s));
};

const fmtPrice = (n) => {
    if (!n || n <= 0) return null;
    if (n >= 1e7) return `₹${(n / 1e7).toFixed(2).replace(/\.?0+$/, '')} Cr`;
    if (n >= 1e5) return `₹${(n / 1e5).toFixed(0)} L`;
    return `₹${n.toLocaleString('en-IN')}`;
};

const fmtDate = (d) => {
    if (!d) return null;
    const dt = new Date(d);
    if (isNaN(dt)) return null;
    return dt.toLocaleDateString('en-IN', { month: 'short', year: 'numeric' });
};

/**
 * Status is categorical data, so colour is doing real work here — but never
 * alone. Every badge pairs the colour with a literal icon and the status text,
 * so it survives greyscale printing and colour-blind vision.
 *
 * Icons are chosen for what the status means: a launch, work in progress, keys
 * being handed over, a finished build. The previous set used a flame for "New
 * Launch" and a star for "Completed" — decoration that told the reader nothing.
 */
const STATUS = {
    "New Launch": { icon: Sparkles, pill: "bg-blue-700 text-white", soft: "bg-blue-50 text-blue-800 border-blue-200" },
    "Under Construction": { icon: Construction, pill: "bg-amber-600 text-white", soft: "bg-amber-50 text-amber-800 border-amber-200" },
    "Ready To Move": { icon: KeyRound, pill: "bg-emerald-600 text-white", soft: "bg-emerald-50 text-emerald-800 border-emerald-200" },
    "Completed": { icon: BadgeCheck, pill: "bg-slate-700 text-white", soft: "bg-slate-100 text-slate-700 border-slate-200" },
};
const STATUS_ORDER = ['New Launch', 'Under Construction', 'Ready To Move', 'Completed'];

const INITIAL_FILTERS = { search: "", city: "", status: "" };

// ── Skeleton Card ─────────────────────────────────────────────────────────────
const SkeletonCard = () => (
    <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white">
        <div className="h-52 animate-pulse bg-slate-200" />
        <div className="space-y-3 p-5">
            <div className="h-5 w-3/4 animate-pulse rounded bg-slate-200" />
            <div className="h-4 w-1/2 animate-pulse rounded bg-slate-200" />
            <div className="flex gap-2 pt-1">
                <div className="h-6 w-16 animate-pulse rounded-full bg-slate-200" />
                <div className="h-6 w-16 animate-pulse rounded-full bg-slate-200" />
            </div>
            <div className="mt-3 h-10 w-full animate-pulse rounded bg-slate-200" />
        </div>
    </div>
);

// ── Spec chip ─────────────────────────────────────────────────────────────────
/** One chip style for every factual spec. Variety here was noise, not hierarchy. */
function Chip({ icon: Icon, children }) {
    return (
        <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-slate-50 px-2.5 py-1 text-[11px] font-medium text-slate-700">
            {Icon && <Icon className="h-3 w-3 shrink-0 text-slate-400" />}
            {children}
        </span>
    );
}

// ── Project Card ──────────────────────────────────────────────────────────────
function ProjectCard({ project, isBookmarked, onBookmark }) {
    const images = toArray(project.media?.exteriorImages);
    const [imgSrc, setImgSrc] = useState(images[0] || FALLBACK);
    const [imgErr, setImgErr] = useState(false);

    const builderName = project.builder?.company || project.builder?.name;
    const builderLogo = project.builder?.logoUrl;
    const builderEst = project.builder?.yearEstablished;
    const builderProjs = project.builder?.totalProjectsDelivered;

    const loc = [project.location?.locality, project.location?.city].filter(Boolean).join(', ');
    const status = project.basics?.status || 'New Launch';
    const cfg = STATUS[status] || STATUS['New Launch'];
    const StatusIcon = cfg.icon;

    const highlights = toHighlights(project.basics?.highlights).slice(0, 2);
    const reraNumber = project.basics?.reraNumber;

    const priceMin = fmtPrice(project.priceRange?.min);
    const priceMax = fmtPrice(project.priceRange?.max);
    const priceLabel = priceMin
        ? (priceMax && project.priceRange?.max !== project.priceRange?.min
            ? `${priceMin} – ${priceMax}`
            : priceMin)
        : null;

    const possession = fmtDate(project.overview?.possessionDate);
    const totalUnits = project.overview?.totalUnits;
    const unitCfgCount = project.unitTypeCount || 0;
    const landArea = project.overview?.totalLandArea;
    const projectName = project.basics?.name || 'Builder Project';

    const credibility = [
        builderEst ? `Est. ${builderEst}` : null,
        builderProjs ? `${builderProjs} delivered` : null,
    ].filter(Boolean).join(' · ');

    return (
        <article className="group relative flex flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white transition-shadow duration-200 hover:shadow-lg hover:shadow-slate-200/70">

            {/* Bookmark sits above the link so it never triggers navigation */}
            <button
                type="button"
                onClick={() => onBookmark(project._id)}
                aria-pressed={isBookmarked}
                aria-label={isBookmarked ? `Remove ${projectName} from saved` : `Save ${projectName}`}
                className="absolute right-3 top-3 z-20 flex h-8 w-8 items-center justify-center rounded-full bg-white/95 text-slate-600 shadow-sm ring-1 ring-slate-900/5 transition-colors hover:bg-white hover:text-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"
            >
                {isBookmarked
                    ? <BookmarkCheck className="h-4 w-4 text-blue-700" />
                    : <Bookmark className="h-4 w-4" />}
            </button>

            <Link href={`/projects/${project._id}`} className="flex flex-1 flex-col focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 focus-visible:ring-inset">

                {/* ── Image ─────────────────────────────────────────────── */}
                <div className="relative h-52 overflow-hidden bg-slate-100">
                    <div className="absolute left-3 top-3 z-10 flex flex-wrap items-center gap-1.5">
                        <span className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold shadow-sm ${cfg.pill}`}>
                            <StatusIcon className="h-3 w-3" aria-hidden="true" />
                            {status}
                        </span>
                    </div>

                    {/* eslint-disable-next-line @next/next/no-img-element */}
                    <img
                        src={imgSrc}
                        alt={projectName}
                        className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-[1.04]"
                        onError={() => { if (!imgErr) { setImgErr(true); setImgSrc(FALLBACK); } }}
                        loading="lazy"
                    />
                    <div className="pointer-events-none absolute inset-0 bg-gradient-to-t from-slate-950/75 via-slate-950/5 to-transparent" />

                    {/* Builder strip */}
                    {builderName && (
                        <div className="absolute inset-x-0 bottom-0 z-10 flex items-end justify-between gap-3 px-3.5 pb-3">
                            <span className="flex min-w-0 items-center gap-2 text-[13px] font-semibold text-white">
                                {builderLogo
                                    // eslint-disable-next-line @next/next/no-img-element
                                    ? <img src={builderLogo} alt="" className="h-5 w-5 shrink-0 rounded-full bg-white object-cover" />
                                    : <Building2 className="h-4 w-4 shrink-0 text-white/70" aria-hidden="true" />}
                                <span className="truncate">{builderName}</span>
                            </span>
                            {credibility && (
                                <span className="shrink-0 text-[11px] font-medium text-white/70">{credibility}</span>
                            )}
                        </div>
                    )}
                </div>

                {/* ── Body ──────────────────────────────────────────────── */}
                <div className="flex flex-1 flex-col p-5">
                    <h3 className="line-clamp-1 text-[17px] font-bold tracking-tight text-slate-900 transition-colors group-hover:text-blue-800">
                        {projectName}
                    </h3>
                    <p className="mt-1 flex items-center gap-1.5 text-sm text-slate-500">
                        <MapPin className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden="true" />
                        <span className="line-clamp-1">{loc || 'India'}</span>
                    </p>

                    {/* Specs — one chip style, so the eye reads the row as one group */}
                    <div className="mt-4 flex flex-wrap gap-1.5">
                        {unitCfgCount > 0 && (
                            <Chip icon={LayoutGrid}>{unitCfgCount} Config{unitCfgCount !== 1 ? 's' : ''}</Chip>
                        )}
                        {totalUnits && <Chip>{totalUnits} Units</Chip>}
                        {landArea && <Chip>{landArea}</Chip>}
                        {highlights.map((h, i) => <Chip key={i}>{h}</Chip>)}
                    </div>

                    {/* Trust + timing */}
                    <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 text-xs text-slate-500">
                        {/* The registration number as entered, not a "verified" badge:
                            nothing checks it against a state RERA register. */}
                        {reraNumber && (
                            <span className="inline-flex items-center gap-1.5">
                                RERA <strong className="font-semibold text-slate-700">{reraNumber}</strong>
                            </span>
                        )}
                        {possession && (
                            <span className="inline-flex items-center gap-1.5">
                                <CalendarDays className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
                                Possession <strong className="font-semibold text-slate-700">{possession}</strong>
                            </span>
                        )}
                    </div>

                    {/* Price footer — mt-auto keeps it on the same baseline in every
                        card of a row, which is what makes prices comparable at a glance */}
                    <div className="mt-auto flex items-end justify-between gap-3 border-t border-slate-100 pt-4">
                        <div className="min-w-0">
                            <p className="mb-0.5 text-[10px] font-semibold uppercase tracking-wider text-slate-400">
                                {priceLabel ? 'Starting from' : 'Price'}
                            </p>
                            {priceLabel
                                ? <p className="truncate text-xl font-bold leading-none tracking-tight text-slate-900 tabular-nums">{priceLabel}</p>
                                : <p className="text-sm leading-none text-slate-400">On request</p>}
                        </div>
                        <span className="inline-flex shrink-0 items-center gap-1 pb-0.5 text-[13px] font-semibold text-blue-700">
                            View details
                            <ArrowRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                        </span>
                    </div>
                </div>
            </Link>
        </article>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function BuilderProjectsContent({ initialProjects = [] }) {
    const router = useRouter();
    const searchParams = useSearchParams();

    const [projects, setProjects] = useState(initialProjects);
    const [loading, setLoading] = useState(initialProjects.length === 0);
    const [filters, setFilters] = useState(INITIAL_FILTERS);
    const [sortBy, setSortBy] = useState('newest');
    const [onlyBookmarked, setOnlyBookmarked] = useState(false);
    const [bookmarked, setBookmarked] = useState(() => {
        if (typeof window === 'undefined') return new Set();
        try { return new Set(JSON.parse(localStorage.getItem('dd_proj_bookmarks') || '[]')); }
        catch { return new Set(); }
    });

    const toggleBookmark = (id) => {
        setBookmarked(prev => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            try { localStorage.setItem('dd_proj_bookmarks', JSON.stringify([...next])); } catch { }
            return next;
        });
    };

    const cities = useMemo(() => {
        const s = new Set(projects.map(p => p.location?.city).filter(Boolean));
        return [...s].sort();
    }, [projects]);

    useEffect(() => {
        if (initialProjects.length > 0) { setLoading(false); return; }
        setLoading(true);
        fetch(`${API_BASE}/api/projects?isActive=true&limit=200`)
            .then(r => r.json())
            .then(d => setProjects(d?.data || (Array.isArray(d) ? d : [])))
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    useEffect(() => {
        const updates = {};
        ['city', 'status', 'search'].forEach(k => {
            const v = searchParams.get(k);
            if (v) updates[k] = v;
        });
        if (Object.keys(updates).length) setFilters(f => ({ ...f, ...updates }));
    }, [searchParams]);

    const handleFilter = (key, val) => setFilters(f => ({ ...f, [key]: val }));

    // Derived, not an effect: unbookmarking the last project drops the view back
    // to everything on the same render, instead of flashing an empty grid for a
    // frame and then correcting itself.
    const showingBookmarked = onlyBookmarked && bookmarked.size > 0;
    const hasActiveFilter = Object.values(filters).some(Boolean) || showingBookmarked;

    const displayProjects = useMemo(() => {
        const q = filters.search.toLowerCase().trim();
        let list = projects.filter(p => {
            if (showingBookmarked && !bookmarked.has(p._id)) return false;
            if (filters.city && p.location?.city !== filters.city) return false;
            if (filters.status && p.basics?.status !== filters.status) return false;

            if (q) {
                return [
                    p.basics?.name, p.location?.city, p.location?.locality,
                    p.location?.microMarket, p.builder?.company, p.builder?.name,
                    p.basics?.status, p.basics?.subType, p.basics?.reraNumber,
                ].filter(Boolean).some(f => String(f).toLowerCase().includes(q));
            }
            return true;
        });

        list = [...list];
        if (sortBy === 'price_asc') list.sort((a, b) => (a.priceRange?.min || 0) - (b.priceRange?.min || 0));
        if (sortBy === 'price_desc') list.sort((a, b) => (b.priceRange?.min || 0) - (a.priceRange?.min || 0));
        if (sortBy === 'possession') list.sort((a, b) => {
            const da = a.overview?.possessionDate ? new Date(a.overview.possessionDate) : new Date('2099-01-01');
            const db = b.overview?.possessionDate ? new Date(b.overview.possessionDate) : new Date('2099-01-01');
            return da - db;
        });
        if (sortBy === 'newest') list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        return list;
    }, [projects, filters, sortBy, showingBookmarked, bookmarked]);

    const resetAll = () => { setFilters(INITIAL_FILTERS); setOnlyBookmarked(false); };

    const selectClass = "h-10 cursor-pointer appearance-none rounded-lg border border-slate-300 bg-white pl-9 pr-8 text-sm font-medium text-slate-700 transition-colors hover:border-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-100";

    return (
        <div className="-mt-10 min-h-screen bg-slate-50 text-slate-800 lg:-mt-8">

            {/* ── Filter bar ──────────────────────────────────────────────
                One control height (h-10) across search, selects and chips.
                Mixed heights were the loudest "assembled by hand" tell.

                The negative page margin and the `top-1 lg:-top-2` offset are the
                same pair /properties uses. ClientLayout reserves navbar space
                with pt-16/lg:pt-20 and its overflow-x-hidden makes the wrapper a
                scroll container, so a plain `top-16` here resolves against the
                wrong box and parks the bar on top of the heading. */}
            <div className="sticky top-1 z-30 border-b border-slate-200 bg-white lg:-top-2">
                <div className="mx-auto max-w-7xl space-y-3 px-6 py-4">

                    <div className="flex flex-wrap items-center gap-2.5">
                        <div className="relative min-w-[200px] flex-1 sm:max-w-md">
                            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                            <input
                                type="text"
                                aria-label="Search projects"
                                placeholder="Search project, builder or locality"
                                className="h-10 w-full rounded-lg border border-slate-300 bg-white pl-9 pr-9 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-100"
                                value={filters.search}
                                onChange={e => handleFilter('search', e.target.value)}
                                onKeyDown={e => e.key === 'Escape' && handleFilter('search', '')}
                            />
                            {filters.search && (
                                <button
                                    type="button"
                                    onClick={() => handleFilter('search', '')}
                                    aria-label="Clear search"
                                    className="absolute right-2.5 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700"
                                >
                                    <X className="h-3.5 w-3.5" />
                                </button>
                            )}
                        </div>

                        <div className="relative">
                            <MapPin className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                            <select aria-label="Filter by city" className={selectClass}
                                value={filters.city} onChange={e => handleFilter('city', e.target.value)}>
                                <option value="">All cities</option>
                                {cities.map(c => <option key={c} value={c}>{c}</option>)}
                            </select>
                        </div>

                        <div className="relative ml-auto">
                            <ArrowUpDown className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                            <select aria-label="Sort projects" className={selectClass}
                                value={sortBy} onChange={e => setSortBy(e.target.value)}>
                                <option value="newest">Newest first</option>
                                <option value="price_asc">Price: low to high</option>
                                <option value="price_desc">Price: high to low</option>
                                <option value="possession">Possession: soonest</option>
                            </select>
                        </div>

                        {hasActiveFilter && (
                            <button
                                type="button"
                                onClick={resetAll}
                                className="h-10 whitespace-nowrap rounded-lg px-3 text-sm font-semibold text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900"
                            >
                                Reset
                            </button>
                        )}
                    </div>

                    {/* Quick status chips */}
                    <div className="flex items-center gap-2 overflow-x-auto pb-0.5 scrollbar-hide">
                        <span className="flex shrink-0 items-center gap-1.5 text-xs font-medium text-slate-400">
                            <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
                            Filter
                        </span>
                        <button
                            type="button"
                            onClick={() => handleFilter('status', '')}
                            aria-pressed={!filters.status}
                            className={`shrink-0 rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${!filters.status
                                ? 'border-slate-900 bg-slate-900 text-white'
                                : 'border-slate-200 bg-white text-slate-600 hover:border-slate-400'}`}
                        >
                            All
                        </button>
                        {STATUS_ORDER.map(s => {
                            const Icon = STATUS[s].icon;
                            const active = filters.status === s;
                            return (
                                <button
                                    key={s}
                                    type="button"
                                    onClick={() => handleFilter('status', active ? '' : s)}
                                    aria-pressed={active}
                                    className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${active
                                        ? 'border-slate-900 bg-slate-900 text-white'
                                        : 'border-slate-200 bg-white text-slate-600 hover:border-slate-400'}`}
                                >
                                    <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                                    {s}
                                </button>
                            );
                        })}

                        {bookmarked.size > 0 && (
                            <>
                                <span className="mx-1 h-5 w-px shrink-0 bg-slate-200" aria-hidden="true" />
                                <button
                                    type="button"
                                    onClick={() => setOnlyBookmarked(v => !v)}
                                    aria-pressed={onlyBookmarked}
                                    className={`inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full border px-3.5 py-1.5 text-xs font-semibold transition-colors ${onlyBookmarked
                                        ? 'border-blue-700 bg-blue-700 text-white'
                                        : 'border-slate-200 bg-white text-slate-600 hover:border-slate-400'}`}
                                >
                                    <Bookmark className="h-3.5 w-3.5" aria-hidden="true" />
                                    Saved ({bookmarked.size})
                                </button>
                            </>
                        )}
                    </div>
                </div>
            </div>

            {/* ── Main ────────────────────────────────────────────────────── */}
            {/* pt clears the sticky bar. The negative page margin above shifts
                the bar's flow box up, so content that follows it needs the
                difference back or the heading sits under the chips row. */}
            <main className="mx-auto max-w-7xl px-6 pb-8 pt-14 lg:pt-12">

                <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <h1 className="text-2xl font-bold tracking-tight text-slate-900">
                            {showingBookmarked ? 'Saved projects' : 'Builder Projects'}
                        </h1>
                        <p className="mt-1 text-sm text-slate-500">
                            {loading
                                ? 'Loading projects…'
                                : showingBookmarked
                                    ? `${displayProjects.length} saved on this device`
                                    : `${displayProjects.length} of ${projects.length} project${projects.length !== 1 ? 's' : ''}`}
                        </p>
                    </div>

                    {!loading && (filters.city || filters.search) && (
                        <div className="flex flex-wrap justify-end gap-2 text-[11px]">
                            {['city', 'search'].filter(k => filters[k]).map(k => (
                                <span key={k} className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-slate-700">
                                    <span className="capitalize text-slate-400">{k}</span>
                                    <strong className="font-semibold">{filters[k]}</strong>
                                    <button
                                        type="button"
                                        onClick={() => handleFilter(k, '')}
                                        aria-label={`Clear ${k} filter`}
                                        className="rounded-full p-0.5 hover:bg-slate-100 hover:text-red-600"
                                    >
                                        <X className="h-3 w-3" />
                                    </button>
                                </span>
                            ))}
                        </div>
                    )}
                </div>

                {loading ? (
                    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                        {[1, 2, 3, 4, 5, 6].map(n => <SkeletonCard key={n} />)}
                    </div>
                ) : displayProjects.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-slate-300 bg-white px-6 py-20 text-center">
                        <div className="mx-auto mb-5 flex h-16 w-16 items-center justify-center rounded-full bg-slate-100">
                            {showingBookmarked
                                ? <Bookmark className="h-7 w-7 text-slate-400" />
                                : <Building2 className="h-7 w-7 text-slate-400" />}
                        </div>
                        <h2 className="text-xl font-bold text-slate-900">
                            {showingBookmarked ? 'No saved projects yet' : 'No projects found'}
                        </h2>
                        <p className="mx-auto mt-2 max-w-md text-sm text-slate-500">
                            {showingBookmarked
                                ? 'Tap the bookmark on any project to keep it here. Saved projects live on this device only.'
                                : hasActiveFilter
                                    ? 'No projects match these filters. Try widening them.'
                                    : 'No builder projects are listed yet. Check back soon.'}
                        </p>
                        <div className="mt-6 flex flex-wrap justify-center gap-3">
                            {hasActiveFilter && (
                                <button
                                    type="button"
                                    onClick={resetAll}
                                    className="rounded-lg bg-slate-900 px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-slate-800"
                                >
                                    Clear filters
                                </button>
                            )}
                            <button
                                type="button"
                                onClick={() => router.push('/')}
                                className="rounded-lg border border-slate-300 bg-white px-5 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50"
                            >
                                Back to home
                            </button>
                        </div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3">
                        {displayProjects.map(p => (
                            <ProjectCard
                                key={p._id}
                                project={p}
                                isBookmarked={bookmarked.has(p._id)}
                                onBookmark={toggleBookmark}
                            />
                        ))}
                    </div>
                )}
            </main>
        </div>
    );
}
