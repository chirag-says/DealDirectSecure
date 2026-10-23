'use client';

import React, { useState, useEffect, useMemo } from "react";
import { useRouter, useSearchParams } from 'next/navigation';
import {
    MapPin, Search, X, Building2, Bookmark, ArrowUpDown, SlidersHorizontal,
} from "lucide-react";
import ProjectCard, { ProjectCardSkeleton, PROJECT_STATUS, PROJECT_STATUS_ORDER } from '../../components/Projects/ProjectCard';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:9000';

const INITIAL_FILTERS = { search: "", city: "", status: "" };

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

    // Chips show how many projects each status has, and a status with none
    // is hidden: a chip that can only lead to an empty grid is a dead end.
    const statusCounts = useMemo(() => {
        const counts = {};
        projects.forEach(p => { const st = p.basics?.status; if (st) counts[st] = (counts[st] || 0) + 1; });
        return counts;
    }, [projects]);

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

    const selectClass = "h-10 w-full cursor-pointer appearance-none rounded-lg border border-slate-300 bg-white pl-9 pr-8 text-sm font-medium text-slate-700 transition-colors hover:border-slate-400 focus:border-blue-600 focus:outline-none focus:ring-2 focus:ring-blue-100";

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
                        <div className="relative basis-full sm:min-w-[200px] sm:max-w-md sm:flex-1 sm:basis-auto">
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

                        <div className="relative flex-1 sm:flex-none">
                            <MapPin className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
                            <select aria-label="Filter by city" className={selectClass}
                                value={filters.city} onChange={e => handleFilter('city', e.target.value)}>
                                <option value="">All cities</option>
                                {cities.map(c => <option key={c} value={c}>{c}</option>)}
                            </select>
                        </div>

                        <div className="relative flex-1 sm:ml-auto sm:flex-none">
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
                            All <span className={`tabular-nums ${!filters.status ? 'text-white/70' : 'text-slate-400'}`}>{projects.length}</span>
                        </button>
                        {PROJECT_STATUS_ORDER.filter(s => statusCounts[s] || filters.status === s).map(s => {
                            const Icon = PROJECT_STATUS[s].icon;
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
                                    <span className={`tabular-nums ${active ? 'text-white/70' : 'text-slate-400'}`}>{statusCounts[s] || 0}</span>
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
                        {!showingBookmarked && (
                            <p className="mt-1 max-w-xl text-sm text-slate-600">
                                New construction, straight from developers. Enquiring is free, and DealDirect never asks for a booking amount.
                            </p>
                        )}
                        <p className="mt-2 text-xs font-medium text-slate-400">
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
                    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                        {[1, 2, 3, 4, 5, 6, 7, 8].map(n => <ProjectCardSkeleton key={n} />)}
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
                    <div className="grid grid-cols-1 gap-6 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
                        {displayProjects.map(p => (
                            <ProjectCard
                                key={p._id}
                                project={p}
                                sizes="(min-width: 1280px) 300px, (min-width: 1024px) 33vw, (min-width: 640px) 50vw, 100vw"
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
