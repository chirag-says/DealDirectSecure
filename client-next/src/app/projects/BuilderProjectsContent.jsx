'use client';

import React, { useState, useEffect, useMemo } from "react";
import { useSearchParams } from 'next/navigation';
import Image from 'next/image';
import Link from 'next/link';
import {
    FaMapMarkerAlt, FaSearch, FaTimes, FaChevronDown,
    FaUsers, FaArrowRight, FaBuilding
} from "react-icons/fa";
import { Building2, Sparkles, Home, CheckCircle, MapPin } from "lucide-react";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:9000';
const FALLBACK = "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800";

const STATUS_BADGE = {
    "New Launch": "bg-indigo-600 text-white",
    "Under Construction": "bg-amber-500 text-white",
    "Ready To Move": "bg-emerald-500 text-white",
    "Completed": "bg-slate-500 text-white",
};

const SkeletonCard = () => (
    <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden animate-pulse">
        <div className="h-56 bg-slate-200" />
        <div className="p-5 space-y-3">
            <div className="h-5 bg-slate-200 rounded w-3/4" />
            <div className="h-4 bg-slate-200 rounded w-1/2" />
            <div className="h-10 bg-slate-200 rounded w-full mt-4" />
        </div>
    </div>
);

// Normalize highlights from backend (may be string, JSON string, or array)
const toHighlights = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val.filter(Boolean);
    if (typeof val === 'string') {
        try { const p = JSON.parse(val); if (Array.isArray(p)) return p; } catch {}
        return val.split(/[,;|\n]/).map(s => s.trim()).filter(Boolean);
    }
    return [];
};

// Normalize media fields (single string URL or array)
const toArray = (val) => {
    if (!val) return [];
    if (Array.isArray(val)) return val.filter(Boolean);
    if (typeof val === 'string' && val.trim()) return [val.trim()];
    return [];
};

// ─── Project Card (new schema) ─────────────────────────────────────────────────
function ProjectCard({ project }) {
    const images = toArray(project.media?.exteriorImages);
    const [imgSrc, setImgSrc] = useState(images[0] || FALLBACK);
    const [imgError, setImgError] = useState(false);
    const builderName = project.builder?.company || project.builder?.name;
    const loc = [project.location?.locality, project.location?.city].filter(Boolean).join(", ");
    const status = project.basics?.status || "New Launch";
    const hasActiveCampaign = (project.activeCampaignCount || 0) > 0;
    const highlights = toHighlights(project.basics?.highlights);

    const handleImgError = () => {
        if (!imgError) { setImgError(true); setImgSrc(FALLBACK); }
    };

    return (
        <Link href={`/projects/${project._id}`}
            className="group relative bg-white rounded-2xl shadow-sm hover:shadow-xl border border-slate-100 hover:border-indigo-200 transition-all duration-300 overflow-hidden hover:-translate-y-1 block">

            {/* Image */}
            <div className="relative h-52 overflow-hidden bg-slate-100">
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                    src={imgSrc}
                    alt={project.basics?.name || "Builder Project"}
                    className="absolute inset-0 w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
                    onError={handleImgError}
                    loading="lazy"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />

                {/* Status badge */}
                <div className="absolute top-3 left-3 flex items-center gap-2">
                    <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full shadow ${STATUS_BADGE[status] || "bg-indigo-600 text-white"}`}>
                        {status}
                    </span>
                    {hasActiveCampaign && (
                        <span className="bg-amber-500 text-white text-[11px] font-bold px-2.5 py-1 rounded-full flex items-center gap-1 shadow">
                            <FaUsers className="text-[10px]" /> Group Buy
                        </span>
                    )}
                </div>

                {/* Category */}
                <span className="absolute top-3 right-3 bg-white/90 backdrop-blur text-slate-700 text-[11px] font-bold px-2.5 py-1 rounded-full shadow">
                    {project.basics?.subType || project.basics?.category || "Residential"}
                </span>

                {/* Builder name */}
                {builderName && (
                    <div className="absolute bottom-3 left-3 right-3">
                        <span className="bg-black/50 backdrop-blur text-white text-[11px] font-semibold px-2 py-1 rounded-lg flex items-center gap-1 w-fit">
                            <FaBuilding className="text-[9px]" /> {builderName}
                        </span>
                    </div>
                )}
            </div>

            {/* Content */}
            <div className="p-4">
                <h3 className="text-base font-bold text-slate-900 mb-1 line-clamp-1 group-hover:text-indigo-700 transition-colors">
                    {project.basics?.name}
                </h3>

                <p className="text-sm text-slate-500 flex items-center gap-1 mb-3">
                    <MapPin size={13} className="text-red-500 flex-shrink-0" />
                    <span className="truncate">{loc || "India"}</span>
                </p>

                {/* Highlights */}
                <div className="flex flex-wrap gap-1.5 mb-3">
                    {highlights.slice(0, 2).map((h, i) => (
                        <span key={i} className="bg-indigo-50 text-indigo-700 text-[11px] font-medium px-2 py-0.5 rounded-md">{h}</span>
                    ))}
                    {project.basics?.reraNumber && (
                        <span className="bg-green-50 text-green-700 text-[11px] font-medium px-2 py-0.5 rounded-md flex items-center gap-0.5">
                            <CheckCircle size={9} /> RERA
                        </span>
                    )}
                </div>

                {/* Stats */}
                <div className="flex items-center justify-between pt-3 border-t border-slate-100">
                    <div className="text-xs text-slate-500 space-y-0.5">
                        {project.overview?.totalUnits && (
                            <p className="flex items-center gap-1"><Home size={11} className="text-indigo-400" /> {project.overview.totalUnits} units</p>
                        )}
                        {project.overview?.possessionDate && (
                            <p className="text-slate-400">Possession: {new Date(project.overview.possessionDate).toLocaleDateString("en-IN", { month: "short", year: "numeric" })}</p>
                        )}
                    </div>
                    <span className="text-xs text-indigo-600 font-semibold flex items-center gap-1 group-hover:gap-2 transition-all">
                        View <FaArrowRight className="text-[10px]" />
                    </span>
                </div>
            </div>
        </Link>
    );
}

// ─── Main Component ─────────────────────────────────────────────────────────────
const CITIES = ["Mumbai", "Bangalore", "Delhi NCR", "Pune", "Hyderabad", "Chennai", "Kolkata", "Ahmedabad"];

export default function BuilderProjectsContent({ initialProjects = [] }) {
    const searchParams = useSearchParams();

    const [projects, setProjects] = useState(initialProjects);
    const [loading, setLoading] = useState(initialProjects.length === 0);
    const [search, setSearch] = useState("");
    const [cityFilter, setCityFilter] = useState("");
    const [statusFilter, setStatusFilter] = useState("");
    const [categoryFilter, setCategoryFilter] = useState("");

    // Read city from URL
    useEffect(() => {
        const city = searchParams.get("city");
        if (city) setCityFilter(city);
    }, [searchParams]);

    // Client-side fallback fetch if SSR returned nothing
    useEffect(() => {
        if (initialProjects.length > 0) { setLoading(false); return; }
        const doFetch = async () => {
            try {
                const res = await fetch(`${API_BASE}/api/projects?isActive=true&limit=100`, {
                    headers: { 'Accept': 'application/json' },
                });
                const json = await res.json();
                setProjects(json.data || []);
            } catch (e) {
                console.error("Failed to fetch projects", e);
            } finally {
                setLoading(false);
            }
        };
        doFetch();
    }, []);

    const filtered = useMemo(() => {
        return projects.filter((p) => {
            if (search) {
                const q = search.toLowerCase();
                const hay = [
                    p.basics?.name, p.location?.city, p.location?.locality,
                    p.location?.microMarket, p.basics?.subType,
                    p.builder?.name, p.builder?.company,
                ].filter(Boolean).join(" ").toLowerCase();
                if (!hay.includes(q)) return false;
            }
            if (cityFilter) {
                const c = (p.location?.city || "").toLowerCase();
                if (!c.includes(cityFilter.toLowerCase())) return false;
            }
            if (statusFilter) {
                if (p.basics?.status !== statusFilter) return false;
            }
            if (categoryFilter) {
                if (p.basics?.category !== categoryFilter) return false;
            }
            return true;
        });
    }, [projects, search, cityFilter, statusFilter, categoryFilter]);

    const clearFilters = () => {
        setSearch(""); setCityFilter(""); setStatusFilter(""); setCategoryFilter("");
    };
    const hasFilters = search || cityFilter || statusFilter || categoryFilter;
    const activeCampaignCount = projects.filter(p => (p.activeCampaignCount || 0) > 0).length;

    return (
        <div className="min-h-screen bg-slate-50/50">

            {/* ── Hero Header ────────────────────────────────────────────────── */}
            <div className="bg-gradient-to-br from-indigo-900 via-indigo-800 to-indigo-700 text-white pt-24 pb-12 px-6 relative overflow-hidden">
                <div className="absolute inset-0 opacity-10" style={{
                    backgroundImage: 'radial-gradient(circle at 1px 1px, white 1px, transparent 0)',
                    backgroundSize: '32px 32px'
                }} />
                <div className="max-w-6xl mx-auto relative z-10">
                    <div className="flex items-center gap-2 text-indigo-300 text-sm font-medium mb-3">
                        <Link href="/" className="hover:text-white transition-colors">Home</Link>
                        <span>/</span>
                        <span className="text-white">Builder Projects</span>
                    </div>
                    <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight mb-2 flex items-center gap-3">
                        <Sparkles className="text-amber-400" size={32} />
                        Builder Projects
                    </h1>
                    <p className="text-indigo-200 text-base max-w-xl">
                        Verified developer projects across India's top cities. Buy directly — no middlemen, no brokerage.
                    </p>
                    <div className="flex gap-6 mt-6 text-sm">
                        <div><span className="text-2xl font-bold text-white">{projects.length}</span><span className="text-indigo-300 ml-1.5">Projects</span></div>
                        <div>
                            <span className="text-2xl font-bold text-white">
                                {new Set(projects.map(p => p.location?.city).filter(Boolean)).size}
                            </span>
                            <span className="text-indigo-300 ml-1.5">Cities</span>
                        </div>
                        <div>
                            <span className="text-2xl font-bold text-amber-400">{activeCampaignCount}</span>
                            <span className="text-indigo-300 ml-1.5">Group Buy Active</span>
                        </div>
                    </div>
                </div>
            </div>

            {/* ── Filter Bar ─────────────────────────────────────────────────── */}
            <div className="sticky top-0 z-30 bg-white border-b border-slate-200 shadow-sm">
                <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3 flex flex-wrap items-center gap-3">

                    {/* Search */}
                    <div className="relative flex-1 min-w-[200px]">
                        <FaSearch className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm" />
                        <input
                            type="text"
                            placeholder="Search by project, city, builder..."
                            value={search}
                            onChange={e => setSearch(e.target.value)}
                            className="w-full pl-10 pr-4 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/30 focus:border-indigo-400 transition"
                        />
                    </div>

                    {/* City */}
                    <div className="relative">
                        <select value={cityFilter} onChange={e => setCityFilter(e.target.value)}
                            className="appearance-none pl-3 pr-8 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/30 cursor-pointer font-medium text-slate-700">
                            <option value="">All Cities</option>
                            {CITIES.map(c => <option key={c} value={c}>{c}</option>)}
                        </select>
                        <FaChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs pointer-events-none" />
                    </div>

                    {/* Status */}
                    <div className="relative">
                        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
                            className="appearance-none pl-3 pr-8 py-2.5 text-sm bg-slate-50 border border-slate-200 rounded-xl focus:outline-none focus:ring-2 focus:ring-indigo-500/30 cursor-pointer font-medium text-slate-700">
                            <option value="">All Status</option>
                            {["New Launch", "Under Construction", "Ready To Move", "Completed"].map(s => (
                                <option key={s} value={s}>{s}</option>
                            ))}
                        </select>
                        <FaChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-xs pointer-events-none" />
                    </div>

                    {/* Category */}
                    <div className="flex items-center gap-2">
                        {["Residential", "Commercial"].map(cat => (
                            <button key={cat} onClick={() => setCategoryFilter(prev => prev === cat ? "" : cat)}
                                className={`px-3 py-2 text-xs font-bold rounded-xl border transition-all ${categoryFilter === cat
                                    ? "bg-indigo-600 text-white border-indigo-600"
                                    : "bg-white text-slate-600 border-slate-200 hover:border-indigo-300"}`}>
                                {cat}
                            </button>
                        ))}
                    </div>

                    {hasFilters && (
                        <button onClick={clearFilters}
                            className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-rose-600 hover:bg-rose-50 rounded-xl border border-rose-200 transition-all">
                            <FaTimes /> Clear
                        </button>
                    )}

                    <p className="ml-auto text-sm text-slate-500 font-medium hidden sm:block">
                        {loading ? "Loading..." : `${filtered.length} project${filtered.length !== 1 ? "s" : ""}`}
                    </p>
                </div>
            </div>

            {/* ── Grid ───────────────────────────────────────────────────────── */}
            <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8">
                {loading ? (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                        {[...Array(6)].map((_, i) => <SkeletonCard key={i} />)}
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-24 text-slate-400">
                        <Building2 size={56} className="mb-4 text-slate-200" />
                        <p className="text-xl font-bold text-slate-600 mb-1">No projects found</p>
                        <p className="text-sm mb-6">
                            {hasFilters ? "Try clearing your filters." : "No builder projects published yet. Check back soon."}
                        </p>
                        {hasFilters && (
                            <button onClick={clearFilters}
                                className="px-5 py-2 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition">
                                Clear Filters
                            </button>
                        )}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
                        {filtered.map(p => <ProjectCard key={p._id} project={p} />)}
                    </div>
                )}
            </div>
        </div>
    );
}
