'use client';

import React, { useState, useEffect, useMemo } from "react";
import { useRouter, useSearchParams } from 'next/navigation';
import {
    FaMapMarkerAlt, FaSearch, FaTimes,
    FaBuilding, FaUsers, FaBookmark, FaRegBookmark,
    FaCalendarAlt, FaCheckCircle, FaFire, FaStar,
} from "react-icons/fa";
import { Home, Sparkles, CheckCircle, ArrowUpDown, BadgeCheck } from "lucide-react";
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

const toHighlights = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val.filter(Boolean);
    if (typeof val === 'string') {
        try { const p = JSON.parse(val); if (Array.isArray(p)) return p; } catch {}
        return val.split(/[,;|\n]/).map(s => s.trim()).filter(Boolean);
    }
    return [];
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

const STATUS_STYLES = {
    "New Launch":         { bar: "bg-indigo-600 text-white", ring: "ring-2 ring-indigo-400 ring-offset-2", dot: "bg-indigo-500" },
    "Under Construction": { bar: "bg-amber-500 text-white",  ring: "",                                     dot: "bg-amber-400" },
    "Ready To Move":      { bar: "bg-emerald-500 text-white",ring: "ring-2 ring-emerald-400 ring-offset-2",dot: "bg-emerald-500" },
    "Completed":          { bar: "bg-slate-500 text-white",  ring: "",                                     dot: "bg-slate-400" },
};

const INITIAL_FILTERS = { search: "", city: "", status: "" };

// ── Skeleton Card ─────────────────────────────────────────────────────────────
const SkeletonCard = () => (
    <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden animate-pulse">
        <div className="h-56 bg-slate-200" />
        <div className="p-5 space-y-3">
            <div className="h-5 bg-slate-200 rounded w-3/4" />
            <div className="h-4 bg-slate-200 rounded w-1/2" />
            <div className="flex gap-2 pt-1">
                <div className="h-6 bg-slate-200 rounded-full w-16" />
                <div className="h-6 bg-slate-200 rounded-full w-16" />
                <div className="h-6 bg-slate-200 rounded-full w-16" />
            </div>
            <div className="h-10 bg-slate-200 rounded w-full mt-3" />
        </div>
    </div>
);

// ── Project Card ──────────────────────────────────────────────────────────────
function ProjectCard({ project, isBookmarked, onBookmark }) {
    const images = toArray(project.media?.exteriorImages);
    const [imgSrc, setImgSrc] = useState(images[0] || FALLBACK);
    const [imgErr, setImgErr] = useState(false);

    const builderName  = project.builder?.company || project.builder?.name;
    const builderLogo  = project.builder?.logoUrl;
    const builderEst   = project.builder?.yearEstablished;
    const builderProjs = project.builder?.totalProjectsDelivered;

    const loc          = [project.location?.locality, project.location?.city].filter(Boolean).join(', ');
    const status       = project.basics?.status || 'New Launch';
    const styles       = STATUS_STYLES[status] || STATUS_STYLES["New Launch"];
    const isNewLaunch  = status === 'New Launch';
    const isReady      = status === 'Ready To Move';

    const hasActiveCampaign = (project.activeCampaignCount || 0) > 0;
    const highlights        = toHighlights(project.basics?.highlights).slice(0, 2);
    const reraNumber        = project.basics?.reraNumber;

    const priceMin  = fmtPrice(project.priceRange?.min);
    const priceMax  = fmtPrice(project.priceRange?.max);
    const priceLabel = priceMin
        ? (priceMax && project.priceRange?.max !== project.priceRange?.min
            ? `${priceMin} – ${priceMax}`
            : priceMin)
        : null;

    const possession  = fmtDate(project.overview?.possessionDate);
    const totalUnits  = project.overview?.totalUnits;
    const unitCfgCount = project.unitTypeCount || 0;
    const landArea    = project.overview?.totalLandArea;

    return (
        <div className={`group relative bg-white rounded-2xl border shadow-sm hover:shadow-2xl hover:-translate-y-1 transition-all duration-300 overflow-hidden flex flex-col ${styles.ring} ${isNewLaunch ? 'border-indigo-200' : 'border-slate-100'}`}>

            {/* ── Bookmark button ─────────────────────────── */}
            <button
                onClick={e => { e.preventDefault(); onBookmark(project._id); }}
                className="absolute top-3 right-3 z-20 w-8 h-8 rounded-full bg-black/30 backdrop-blur-sm flex items-center justify-center hover:bg-black/60 transition-colors"
                aria-label="Bookmark project"
            >
                {isBookmarked
                    ? <FaBookmark className="text-yellow-300 text-sm" />
                    : <FaRegBookmark className="text-white text-sm" />}
            </button>

            {/* ── Image ───────────────────────────────────── */}
            <Link href={`/projects/${project._id}`} className="flex-1 flex flex-col">
                <div className="relative h-56 overflow-hidden bg-slate-100">

                    {/* Status badge top-left */}
                    <div className="absolute top-3 left-3 z-10 flex items-center gap-1.5">
                        <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full shadow flex items-center gap-1 ${styles.bar}`}>
                            {isNewLaunch && <FaFire className="text-[10px]" />}
                            {isReady && <FaStar className="text-[10px]" />}
                            {status}
                        </span>
                        {hasActiveCampaign && (
                            <span className="bg-orange-500 text-white text-[11px] font-bold px-2.5 py-1 rounded-full flex items-center gap-1 shadow">
                                <FaUsers className="text-[9px]" /> Group Buy
                            </span>
                        )}
                    </div>

                    {/* Subtype top-right (left space for bookmark) */}
                    <span className="absolute top-3 right-12 z-10 bg-white/90 backdrop-blur text-slate-700 text-[11px] font-bold px-2.5 py-1 rounded-full shadow">
                        {project.basics?.subType || project.basics?.category || 'Residential'}
                    </span>

                    <img
                        src={imgSrc}
                        alt={project.basics?.name || 'Builder Project'}
                        className="w-full h-full object-cover group-hover:scale-110 transition-transform duration-700"
                        onError={() => { if (!imgErr) { setImgErr(true); setImgSrc(FALLBACK); } }}
                        loading="lazy"
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/65 via-black/10 to-transparent" />

                    {/* Builder strip at bottom of image */}
                    {builderName && (
                        <div className="absolute bottom-0 left-0 right-0 z-10 px-3 py-2.5 flex items-center justify-between">
                            <span className="inline-flex items-center gap-1.5 bg-black/55 backdrop-blur-sm text-white text-xs font-semibold px-2.5 py-1.5 rounded-lg max-w-[70%] truncate">
                                {builderLogo
                                    ? <img src={builderLogo} alt="" className="w-4 h-4 rounded-full object-cover flex-shrink-0" />
                                    : <FaBuilding className="text-[9px] flex-shrink-0 text-indigo-300" />}
                                {builderName}
                            </span>
                            {/* Builder credibility */}
                            {(builderEst || builderProjs) && (
                                <span className="text-white/70 text-[10px] font-medium">
                                    {builderEst ? `Est. ${builderEst}` : ''}
                                    {builderEst && builderProjs ? ' · ' : ''}
                                    {builderProjs ? `${builderProjs} delivered` : ''}
                                </span>
                            )}
                        </div>
                    )}

                    {/* Possession urgency ribbon for Ready To Move */}
                    {isReady && (
                        <div className="absolute top-0 left-0 right-0 z-10 bg-emerald-500/90 text-white text-center text-[11px] font-bold py-1 tracking-wider flex items-center justify-center gap-1.5">
                            <FaCheckCircle size={11} /> READY TO MOVE IN
                        </div>
                    )}
                </div>

                {/* ── Card Body ───────────────────────────────────────────── */}
                <div className="p-5 flex-1 flex flex-col">
                    <h3 className="text-lg font-bold line-clamp-1 mb-1 text-slate-900 group-hover:text-indigo-700 transition-colors">
                        {project.basics?.name || 'Builder Project'}
                    </h3>
                    <p className="text-slate-500 text-sm flex items-center gap-1 mb-3 line-clamp-1">
                        <FaMapMarkerAlt className="text-red-500 flex-shrink-0" size={11} />
                        {loc || 'India'}
                    </p>

                    {/* ── Config / unit chips ────────────────────────────── */}
                    <div className="flex flex-wrap gap-1.5 mb-3">
                        {unitCfgCount > 0 && (
                            <span className="bg-indigo-50 text-indigo-700 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border border-indigo-100 flex items-center gap-1">
                                <Home size={9} /> {unitCfgCount} Config{unitCfgCount !== 1 ? 's' : ''}
                            </span>
                        )}
                        {totalUnits && (
                            <span className="bg-slate-50 text-slate-600 text-[11px] font-medium px-2.5 py-0.5 rounded-full border border-slate-200">
                                {totalUnits} Units
                            </span>
                        )}
                        {landArea && (
                            <span className="bg-slate-50 text-slate-600 text-[11px] font-medium px-2.5 py-0.5 rounded-full border border-slate-200">
                                {landArea}
                            </span>
                        )}
                        {highlights.map((h, i) => (
                            <span key={i} className="bg-amber-50 text-amber-700 text-[11px] font-medium px-2.5 py-0.5 rounded-full border border-amber-100">
                                {h}
                            </span>
                        ))}
                        {reraNumber && (
                            <span className="bg-emerald-50 text-emerald-700 text-[11px] font-semibold px-2.5 py-0.5 rounded-full border border-emerald-100 flex items-center gap-0.5">
                                <CheckCircle size={9} /> RERA Verified
                            </span>
                        )}
                    </div>

                    {/* ── Possession date ────────────────────────────────── */}
                    {possession && !isReady && (
                        <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-3">
                            <FaCalendarAlt className="text-indigo-400" size={11} />
                            <span>Possession: <strong className="text-slate-700">{possession}</strong></span>
                        </div>
                    )}

                    {/* ── Price row ──────────────────────────────────────── */}
                    <div className="mt-auto border-t border-slate-100 pt-4 flex items-center justify-between gap-2">
                        <div>
                            {priceLabel ? (
                                <>
                                    <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wide mb-0.5">Starting from</p>
                                    <p className="text-xl font-extrabold text-indigo-700 tracking-tight leading-none">{priceLabel}</p>
                                </>
                            ) : (
                                <div>
                                    <p className="text-[10px] text-slate-400 font-medium uppercase tracking-wide mb-0.5">Price</p>
                                    <p className="text-sm text-slate-400 italic">On Request</p>
                                </div>
                            )}
                        </div>
                        <span className="text-xs text-indigo-600 font-semibold group-hover:translate-x-1 transition-transform flex items-center gap-0.5">
                            View Details →
                        </span>
                    </div>
                </div>
            </Link>
        </div>
    );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function BuilderProjectsContent({ initialProjects = [] }) {
    const router = useRouter();
    const searchParams = useSearchParams();

    const [projects, setProjects]     = useState(initialProjects);
    const [loading, setLoading]       = useState(initialProjects.length === 0);
    const [filters, setFilters]       = useState(INITIAL_FILTERS);
    const [sortBy, setSortBy]         = useState('newest');
    const [bookmarked, setBookmarked] = useState(() => {
        if (typeof window === 'undefined') return new Set();
        try { return new Set(JSON.parse(localStorage.getItem('dd_proj_bookmarks') || '[]')); }
        catch { return new Set(); }
    });

    // Persist bookmarks
    const toggleBookmark = (id) => {
        setBookmarked(prev => {
            const next = new Set(prev);
            next.has(id) ? next.delete(id) : next.add(id);
            try { localStorage.setItem('dd_proj_bookmarks', JSON.stringify([...next])); } catch {}
            return next;
        });
    };

    // Derived city list
    const cities = useMemo(() => {
        const s = new Set(projects.map(p => p.location?.city).filter(Boolean));
        return [...s].sort();
    }, [projects]);

    // Fetch if no SSR data
    useEffect(() => {
        if (initialProjects.length > 0) { setLoading(false); return; }
        setLoading(true);
        fetch(`${API_BASE}/api/projects?isActive=true&limit=200`)
            .then(r => r.json())
            .then(d => setProjects(d?.data || (Array.isArray(d) ? d : [])))
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    // Sync URL params
    useEffect(() => {
        const updates = {};
        ['city', 'status', 'search'].forEach(k => {
            const v = searchParams.get(k);
            if (v) updates[k] = v;
        });
        if (Object.keys(updates).length) setFilters(f => ({ ...f, ...updates }));
    }, [searchParams]);

    const handleFilter = (key, val) => setFilters(f => ({ ...f, [key]: val }));
    const hasActiveFilter = Object.values(filters).some(Boolean);

    // ── Filter + Sort ─────────────────────────────────────────────────────────
    const displayProjects = useMemo(() => {
        const q = filters.search.toLowerCase().trim();
        let list = projects.filter(p => {
            if (filters.city     && p.location?.city    !== filters.city)     return false;
            if (filters.status   && p.basics?.status    !== filters.status)   return false;

            if (q) {
                return [
                    p.basics?.name, p.location?.city, p.location?.locality,
                    p.location?.microMarket, p.builder?.company, p.builder?.name,
                    p.basics?.status, p.basics?.subType, p.basics?.reraNumber,
                ].filter(Boolean).some(f => String(f).toLowerCase().includes(q));
            }
            return true;
        });

        // Sort
        list = [...list];
        if (sortBy === 'price_asc')  list.sort((a, b) => (a.priceRange?.min || 0) - (b.priceRange?.min || 0));
        if (sortBy === 'price_desc') list.sort((a, b) => (b.priceRange?.min || 0) - (a.priceRange?.min || 0));
        if (sortBy === 'possession') list.sort((a, b) => {
            const da = a.overview?.possessionDate ? new Date(a.overview.possessionDate) : new Date('2099-01-01');
            const db = b.overview?.possessionDate ? new Date(b.overview.possessionDate) : new Date('2099-01-01');
            return da - db;
        });
        if (sortBy === 'newest') list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        return list;
    }, [projects, filters, sortBy]);

    const STATUS_QUICK = ['New Launch', 'Under Construction', 'Ready To Move', 'Completed'];

    return (
        <div className="min-h-screen bg-slate-50 font-sans text-slate-800 -mt-10 lg:-mt-8">

            {/* ── Sticky Filter Bar ─────────────────────────────────────────── */}
            <div className="sticky top-1 lg:-top-2 z-30 bg-white shadow-md border-b border-slate-200 py-4 mb-0 px-6 transition-all">
                <div className="max-w-7xl mx-auto space-y-3">

                    {/* Row 1: Search + dropdowns + sort */}
                    <div className="flex flex-wrap items-center gap-2 lg:gap-3">

                        {/* Search */}
                        <div className="relative flex-1 min-w-[180px] max-w-md flex gap-2">
                            <div className="relative flex-1">
                                <FaSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 z-10 text-xs" />
                                <input
                                    type="text"
                                    placeholder="Search project, builder, locality..."
                                    className="w-full pl-9 pr-3 py-2.5 bg-slate-50 border border-slate-200 focus:bg-white focus:border-indigo-500 rounded-xl outline-none transition-all text-sm"
                                    value={filters.search}
                                    onChange={e => handleFilter('search', e.target.value)}
                                    onKeyDown={e => e.key === 'Escape' && handleFilter('search', '')}
                                />
                                {filters.search && (
                                    <button onClick={() => handleFilter('search', '')} className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-red-500">
                                        <FaTimes size={10} />
                                    </button>
                                )}
                            </div>
                            <button
                                onClick={() => handleFilter('search', filters.search)}
                                className="px-4 py-2.5 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-colors font-medium text-sm shadow-sm flex items-center gap-2 whitespace-nowrap"
                            >
                                <FaSearch className="text-xs" />
                                <span className="hidden sm:inline">Search</span>
                            </button>
                        </div>

                        {/* City */}
                        <div className="relative">
                            <select className="appearance-none bg-white border border-slate-200 py-2.5 pl-3 pr-8 rounded-xl text-sm font-medium hover:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-100 cursor-pointer shadow-sm transition-all"
                                value={filters.city} onChange={e => handleFilter('city', e.target.value)}>
                                <option value="">All Cities</option>
                                {cities.map(c => <option key={c} value={c}>{c}</option>)}
                            </select>
                            <FaMapMarkerAlt className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none text-xs" />
                        </div>

                        {/* Sort */}
                        <div className="relative ml-auto">
                            <ArrowUpDown className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 pointer-events-none" size={12} />
                            <select className="appearance-none bg-white border border-slate-200 py-2.5 pl-8 pr-8 rounded-xl text-sm font-medium hover:border-indigo-400 focus:outline-none focus:ring-2 focus:ring-indigo-100 cursor-pointer shadow-sm transition-all"
                                value={sortBy} onChange={e => setSortBy(e.target.value)}>
                                <option value="newest">Newest First</option>
                                <option value="price_asc">Price: Low → High</option>
                                <option value="price_desc">Price: High → Low</option>
                                <option value="possession">Possession: Soonest</option>
                            </select>
                        </div>

                        {/* Reset */}
                        {hasActiveFilter && (
                            <button onClick={() => setFilters(INITIAL_FILTERS)}
                                className="text-indigo-600 text-sm font-semibold hover:underline px-2 py-2 hover:bg-indigo-50 rounded-lg transition-colors whitespace-nowrap">
                                Reset
                            </button>
                        )}
                    </div>

                    {/* Row 2: Quick status chips */}
                    <div className="flex items-center gap-2 overflow-x-auto pb-0.5 scrollbar-hide">
                        <span className="text-xs text-slate-400 font-medium whitespace-nowrap flex-shrink-0">Quick Filter:</span>
                        <button
                            onClick={() => handleFilter('status', '')}
                            className={`flex-shrink-0 px-3.5 py-1.5 rounded-full text-xs font-semibold border transition-all ${!filters.status ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm' : 'bg-white text-slate-600 border-slate-200 hover:border-indigo-400'}`}
                        >
                            All
                        </button>
                        {STATUS_QUICK.map(s => (
                            <button key={s}
                                onClick={() => handleFilter('status', filters.status === s ? '' : s)}
                                className={`flex-shrink-0 flex items-center gap-1 px-3.5 py-1.5 rounded-full text-xs font-semibold border transition-all whitespace-nowrap ${filters.status === s ? 'bg-indigo-600 text-white border-indigo-600 shadow-sm' : 'bg-white text-slate-600 border-slate-200 hover:border-indigo-400'}`}
                            >
                                {s === 'New Launch' && <FaFire className="text-[10px]" />}
                                {s === 'Ready To Move' && <FaCheckCircle className="text-[10px]" />}
                                {s === 'Under Construction' && <FaBuilding className="text-[10px]" />}
                                {s === 'Completed' && <FaStar className="text-[10px]" />}
                                {s}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* ── Main Content ──────────────────────────────────────────────── */}
            <main className="max-w-7xl mx-auto px-6 py-8">

                {/* Header row */}
                <div className="mb-6 flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
                    <div>
                        <h1 className="text-2xl font-bold text-slate-900">Builder Projects</h1>
                        <p className="text-slate-500 text-sm mt-1">
                            {loading
                                ? 'Finding the best projects for you...'
                                : `Showing ${displayProjects.length} of ${projects.length} project${projects.length !== 1 ? 's' : ''}`}
                        </p>
                    </div>

                    {/* Active filter pills */}
                    {!loading && hasActiveFilter && (
                        <div className="flex flex-wrap justify-end gap-2 text-[11px]">
                            {['city', 'search'].filter(k => filters[k]).map(k => (
                                <span key={k} className="px-2.5 py-1 rounded-full bg-indigo-50 border border-indigo-200 text-indigo-700 flex items-center gap-1">
                                    <strong className="capitalize">{k}</strong>: {filters[k]}
                                    <button onClick={() => handleFilter(k, '')} className="ml-0.5 hover:text-red-500"><FaTimes size={8} /></button>
                                </span>
                            ))}
                        </div>
                    )}
                </div>

                {/* Bookmarks strip */}
                {bookmarked.size > 0 && !loading && (
                    <div className="mb-6 flex items-center gap-2 bg-yellow-50 border border-yellow-200 rounded-xl px-4 py-2.5">
                        <FaBookmark className="text-yellow-500 flex-shrink-0" size={12} />
                        <span className="text-sm text-yellow-800 font-medium">
                            {bookmarked.size} project{bookmarked.size !== 1 ? 's' : ''} bookmarked
                        </span>
                        <button
                            onClick={() => handleFilter('search', '')}
                            className="ml-auto text-xs text-yellow-700 font-semibold hover:underline"
                        >
                            Show bookmarked
                        </button>
                    </div>
                )}

                {/* Grid / States */}
                {loading ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
                        {[1, 2, 3, 4, 5, 6].map(n => <SkeletonCard key={n} />)}
                    </div>
                ) : displayProjects.length === 0 ? (
                    <div className="text-center py-24 bg-white rounded-3xl border border-dashed border-slate-300">
                        <div className="bg-slate-50 w-24 h-24 rounded-full flex items-center justify-center mx-auto mb-6">
                            <FaBuilding className="text-4xl text-slate-400" />
                        </div>
                        <h3 className="text-2xl font-bold text-slate-700 mb-2">No Projects Found</h3>
                        <p className="text-slate-500 max-w-md mx-auto mb-6">
                            {hasActiveFilter
                                ? 'No projects match your current filters. Try adjusting them.'
                                : 'No builder projects are available yet. Check back soon.'}
                        </p>
                        <div className="flex flex-wrap gap-3 justify-center">
                            {hasActiveFilter && (
                                <button onClick={() => setFilters(INITIAL_FILTERS)}
                                    className="bg-slate-900 text-white px-6 py-3 rounded-full text-sm font-semibold hover:bg-indigo-600 transition-colors">
                                    Clear All Filters
                                </button>
                            )}
                            <button onClick={() => router.push('/')}
                                className="bg-slate-100 text-slate-700 px-6 py-3 rounded-full text-sm font-semibold hover:bg-slate-200 transition-colors">
                                Back to Home
                            </button>
                        </div>
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">
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

