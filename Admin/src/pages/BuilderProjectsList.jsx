import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { builderApi, projectApi } from "../api/adminApi";
import { toast } from "react-toastify";
import {
  Building2, ChevronLeft, Plus, Search, Loader2, Home, Phone, Mail
} from "lucide-react";

const badge = (status) => {
  const map = {
    "New Launch": "bg-blue-100 text-blue-700",
    "Under Construction": "bg-yellow-100 text-yellow-700",
    "Ready To Move": "bg-green-100 text-green-700",
    "Completed": "bg-gray-100 text-gray-700",
  };
  return `px-2 py-0.5 rounded-full text-xs font-medium ${map[status] || "bg-gray-100 text-gray-600"}`;
};

const FALLBACK_IMG = "https://images.unsplash.com/photo-1516132431682-12f5a65a3962?auto=format&fit=crop&w=800&q=80";
const FALLBACK_IMG_ON_ERROR = "https://images.unsplash.com/photo-1560518883-ce09059eeffa?auto=format&fit=crop&w=800&q=80";

export default function BuilderProjectsList() {
  const { builderId } = useParams();
  const navigate = useNavigate();
  const [builder, setBuilder] = useState(null);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [search, setSearch] = useState("");

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      setLoading(true);
      setLoadError(false);
      try {
        const [builderRes, projectsRes] = await Promise.all([
          builderApi.getById(builderId),
          projectApi.getByBuilder(builderId),
        ]);
        if (cancelled) return;
        setBuilder(builderRes?.data || builderRes || null);
        setProjects(Array.isArray(projectsRes) ? projectsRes : (projectsRes?.data || []));
      } catch (err) {
        if (cancelled) return;
        if (err.response?.status !== 401) toast.error("Failed to load builder or projects");
        setLoadError(true);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    if (builderId) load();
    return () => { cancelled = true; };
  }, [builderId]);

  if (loading) {
    return (
      <div className="min-h-screen flex flex-col justify-center items-center bg-gray-50/50">
        <Loader2 className="w-10 h-10 animate-spin text-indigo-600 mb-4" />
        <p className="text-gray-500 font-medium">Loading projects...</p>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto">
        <button onClick={() => navigate("/builder-management")} className="text-sm text-blue-600 hover:underline mb-4 flex items-center gap-1">
          <ChevronLeft className="w-4 h-4" /> Back to Builders
        </button>
        <div className="flex flex-col items-center justify-center p-16 bg-white border border-gray-200 border-dashed rounded-2xl shadow-sm">
          <Building2 className="w-16 h-16 text-gray-300 mb-4" />
          <h3 className="text-xl font-semibold text-gray-700">Couldn't load this builder</h3>
          <p className="text-gray-500 mt-2 text-center max-w-md">There was an error loading the builder's details. Please try again.</p>
        </div>
      </div>
    );
  }

  if (!builder) {
    return (
      <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto">
        <button onClick={() => navigate("/builder-management")} className="text-sm text-blue-600 hover:underline mb-4 flex items-center gap-1">
          <ChevronLeft className="w-4 h-4" /> Back to Builders
        </button>
        <div className="flex flex-col items-center justify-center p-16 bg-white border border-gray-200 border-dashed rounded-2xl shadow-sm">
          <Building2 className="w-16 h-16 text-gray-300 mb-4" />
          <h3 className="text-xl font-semibold text-gray-700">Builder not found</h3>
          <p className="text-gray-500 mt-2 text-center max-w-md">This builder may have been removed or doesn't exist.</p>
        </div>
      </div>
    );
  }

  const locLine = [builder.address?.city, builder.address?.state].filter(Boolean).join(", ");
  const projectCount = projects.length;
  const searchRaw = search.toLowerCase().trim();
  const filtered = searchRaw
    ? projects.filter(p => {
        const name = (p.basics?.name || "").toLowerCase();
        const locality = (p.location?.locality || "").toLowerCase();
        const city = (p.location?.city || "").toLowerCase();
        return name.includes(searchRaw) || locality.includes(searchRaw) || city.includes(searchRaw);
      })
    : projects;

  return (
    <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto space-y-6">
      {/* Back link */}
      <button onClick={() => navigate("/builder-management")} className="text-sm text-blue-600 hover:underline flex items-center gap-1">
        <ChevronLeft className="w-4 h-4" /> Back to Builders
      </button>

      {/* Header strip */}
      <div className="bg-white px-6 py-5 rounded-2xl border border-gray-200 shadow-sm">
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center flex-shrink-0 overflow-hidden">
              {builder.logoUrl ? (
                <img src={builder.logoUrl} alt={builder.company || builder.name} className="w-full h-full object-cover" />
              ) : (
                <span className="text-indigo-700 font-bold text-lg">{(builder.company || builder.name || "?").charAt(0).toUpperCase()}</span>
              )}
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gray-900">{builder.name}</h1>
              {builder.company && <p className="text-sm text-gray-500">{builder.company}</p>}
            </div>
          </div>
          <button
            onClick={() => navigate(`/create-project?builderId=${builderId}`)}
            className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm"
          >
            <Plus className="w-4 h-4" /> Add Project
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-x-4 gap-y-1.5 mt-4 text-sm text-gray-500">
          {locLine && <span>{locLine}</span>}
          {builder.phone && (
            <span className="flex items-center gap-1.5">
              <Phone className="w-3.5 h-3.5 text-gray-400" /> {builder.phone}
            </span>
          )}
          {builder.email && (
            <span className="flex items-center gap-1.5">
              <Mail className="w-3.5 h-3.5 text-gray-400" /> {builder.email}
            </span>
          )}
        </div>

        <div className="mt-3">
          <span className="bg-gray-100 text-gray-600 px-2.5 py-0.5 rounded-full text-xs font-semibold">
            {projectCount} {projectCount === 1 ? "Project" : "Projects"}
          </span>
        </div>
      </div>

      {/* Search bar */}
      <div className="flex gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
        <div className="relative flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by name, locality or city..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none placeholder-gray-400"
          />
        </div>
      </div>

      {/* Projects grid */}
      {projectCount === 0 ? (
        <div className="flex flex-col items-center justify-center p-16 bg-white border border-gray-200 border-dashed rounded-2xl shadow-sm">
          <Building2 className="w-16 h-16 text-gray-300 mb-4" />
          <h3 className="text-xl font-semibold text-gray-700">No projects yet for this builder</h3>
          <p className="text-gray-500 mt-2 text-center max-w-md">Create the first project to start tracking unit types, campaigns, and inventory.</p>
          <button
            onClick={() => navigate(`/create-project?builderId=${builderId}`)}
            className="mt-5 flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm"
          >
            <Plus className="w-4 h-4" /> Create the first project
          </button>
        </div>
      ) : filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-12 bg-white border border-gray-200 border-dashed rounded-2xl shadow-sm">
          <Search className="w-12 h-12 text-gray-300 mb-3" />
          <p className="text-gray-600 font-medium">No projects match your search</p>
          <p className="text-gray-400 text-sm mt-1">Try a different name, locality, or city.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
          {filtered.map(p => {
            const heroImg = p.media?.exteriorImages?.[0] || FALLBACK_IMG;
            const projName = p.basics?.name || "Untitled project";
            const projLoc = [p.location?.locality, p.location?.city].filter(Boolean).join(", ");
            return (
              <div
                key={p._id}
                onClick={() => navigate(`/project/${p._id}`)}
                className="group bg-white rounded-2xl overflow-hidden border border-gray-200 shadow-sm hover:shadow-xl hover:border-gray-300 transition-all duration-300 flex flex-col cursor-pointer"
              >
                <div className="relative aspect-[4/3] bg-gray-100 overflow-hidden">
                  <img
                    src={heroImg}
                    className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
                    alt={projName}
                    onError={(e) => { e.target.src = FALLBACK_IMG_ON_ERROR; }}
                  />
                  {p.basics?.status && (
                    <div className="absolute top-3 right-3 z-10">
                      <span className={badge(p.basics.status)}>{p.basics.status}</span>
                    </div>
                  )}
                </div>
                <div className="p-5 flex flex-col flex-grow">
                  <h3 className="text-base font-bold text-gray-900 leading-tight mb-2 line-clamp-2 group-hover:text-indigo-700 transition-colors">
                    {projName}
                  </h3>
                  {projLoc && (
                    <div className="flex items-center gap-1.5 text-gray-500 text-sm bg-gray-50 w-fit px-2 py-1 rounded-md">
                      <Home className="w-3.5 h-3.5 flex-shrink-0" />
                      <span className="truncate max-w-[180px]">{projLoc}</span>
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
