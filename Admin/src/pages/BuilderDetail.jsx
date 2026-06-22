import React, { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { builderApi, projectApi } from "../api/adminApi";
import { toast } from "react-toastify";
import {
  Building2, ChevronLeft, Plus, Phone, Mail, MapPin,
  FileText, Loader2, Ban, CheckCircle, Pencil, X,
  Home, Search, RefreshCw, AlertCircle, StickyNote,
  User, Briefcase, Hash, CreditCard
} from "lucide-react";

// ── Small badge helper ────────────────────────────────────────────────────────
const ProjectStatusBadge = ({ status }) => {
  const map = {
    "New Launch": "bg-blue-100 text-blue-700",
    "Under Construction": "bg-yellow-100 text-yellow-700",
    "Ready To Move": "bg-green-100 text-green-700",
    "Completed": "bg-gray-100 text-gray-700",
  };
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${map[status] || "bg-gray-100 text-gray-600"}`}>
      {status}
    </span>
  );
};

const FALLBACK_IMG = "https://images.unsplash.com/photo-1516132431682-12f5a65a3962?auto=format&fit=crop&w=800&q=80";

// ── Inline edit modal (re-uses the same fields as BuilderManagement's modal) ──
function BuilderEditModal({ builder, onClose, onSaved }) {
  const [form, setForm] = useState({
    name: builder?.name || "",
    company: builder?.company || "",
    phone: builder?.phone || "",
    alternatePhone: builder?.alternatePhone || "",
    email: builder?.email || "",
    reraNumber: builder?.reraNumber || "",
    gstNumber: builder?.gstNumber || "",
    city: builder?.address?.city || "",
    state: builder?.address?.state || "",
    notes: builder?.notes || "",
    description: builder?.description || "",
    yearEstablished: builder?.yearEstablished || "",
    totalProjectsDelivered: builder?.totalProjectsDelivered || "",
    totalSqFtDelivered: builder?.totalSqFtDelivered || "",
    websiteUrl: builder?.websiteUrl || "",
  });
  const [submitting, setSubmitting] = useState(false);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.name.trim()) return toast.error("Name is required");
    if (!form.phone.trim()) return toast.error("Phone is required");
    setSubmitting(true);
    try {
      await builderApi.update(builder._id, {
        name: form.name.trim(),
        company: form.company.trim() || undefined,
        phone: form.phone.trim(),
        alternatePhone: form.alternatePhone.trim() || undefined,
        email: form.email.trim() || undefined,
        reraNumber: form.reraNumber.trim() || undefined,
        gstNumber: form.gstNumber.trim() || undefined,
        address: { city: form.city.trim(), state: form.state.trim() },
        notes: form.notes.trim() || undefined,
        description: form.description.trim() || undefined,
        yearEstablished: form.yearEstablished || undefined,
        totalProjectsDelivered: form.totalProjectsDelivered || undefined,
        totalSqFtDelivered: form.totalSqFtDelivered || undefined,
        websiteUrl: form.websiteUrl.trim() || undefined,
      });
      toast.success("Builder updated!");
      onSaved();
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to save builder");
    } finally {
      setSubmitting(false);
    }
  };

  const inp = "w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50";
  const lbl = "block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5";

  return (
    <div className="fixed inset-0 bg-gray-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
      <div className="bg-white w-full max-w-lg rounded-2xl shadow-2xl border border-gray-200 overflow-hidden">
        <div className="p-6 border-b border-gray-100 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl">
              <Building2 className="w-5 h-5" />
            </div>
            <h2 className="text-lg font-bold text-gray-900">Edit Builder</h2>
          </div>
          <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4 max-h-[72vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-4">
            <div className="col-span-2">
              <label className={lbl}>Contact Name *</label>
              <input value={form.name} onChange={e => set("name", e.target.value)} required placeholder="e.g. Rajesh Mehta" className={inp} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Company / Firm</label>
              <input value={form.company} onChange={e => set("company", e.target.value)} placeholder="e.g. Prestige Group" className={inp} />
            </div>
            <div>
              <label className={lbl}>Phone *</label>
              <input value={form.phone} onChange={e => set("phone", e.target.value)} required placeholder="+91 98765 43210" className={inp} />
            </div>
            <div>
              <label className={lbl}>Alternate Phone</label>
              <input value={form.alternatePhone} onChange={e => set("alternatePhone", e.target.value)} placeholder="Optional" className={inp} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Email</label>
              <input type="email" value={form.email} onChange={e => set("email", e.target.value)} placeholder="Optional" className={inp} />
            </div>
            <div>
              <label className={lbl}>RERA Number</label>
              <input value={form.reraNumber} onChange={e => set("reraNumber", e.target.value)} placeholder="Optional" className={inp} />
            </div>
            <div>
              <label className={lbl}>GST Number</label>
              <input value={form.gstNumber} onChange={e => set("gstNumber", e.target.value)} placeholder="Optional" className={inp} />
            </div>
            <div>
              <label className={lbl}>City</label>
              <input value={form.city} onChange={e => set("city", e.target.value)} placeholder="e.g. Pune" className={inp} />
            </div>
            <div>
              <label className={lbl}>State</label>
              <input value={form.state} onChange={e => set("state", e.target.value)} placeholder="e.g. Maharashtra" className={inp} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Company Description</label>
              <textarea value={form.description} onChange={e => set("description", e.target.value)} rows={2}
                placeholder="Brief description of the company"
                className={`${inp} resize-none`} />
            </div>
            <div>
              <label className={lbl}>Year Established</label>
              <input type="number" min="1900" max="2030" value={form.yearEstablished} onChange={e => set("yearEstablished", e.target.value)} placeholder="e.g. 2005" className={inp} />
            </div>
            <div>
              <label className={lbl}>Projects Delivered</label>
              <input type="number" min="0" value={form.totalProjectsDelivered} onChange={e => set("totalProjectsDelivered", e.target.value)} placeholder="e.g. 25" className={inp} />
            </div>
            <div>
              <label className={lbl}>Total Sq.Ft Delivered</label>
              <input value={form.totalSqFtDelivered} onChange={e => set("totalSqFtDelivered", e.target.value)} placeholder="e.g. 10M sq.ft" className={inp} />
            </div>
            <div>
              <label className={lbl}>Website</label>
              <input value={form.websiteUrl} onChange={e => set("websiteUrl", e.target.value)} placeholder="https://" className={inp} />
            </div>
            <div className="col-span-2">
              <label className={lbl}>Internal Notes</label>
              <textarea value={form.notes} onChange={e => set("notes", e.target.value)} rows={2}
                placeholder="Admin-only notes"
                className={`${inp} resize-none`} />
            </div>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="button" onClick={onClose}
              className="flex-1 px-4 py-2.5 border border-gray-200 text-gray-700 rounded-xl text-sm font-semibold hover:bg-gray-50 transition-colors">
              Cancel
            </button>
            <button type="submit" disabled={submitting}
              className="flex-1 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-60">
              {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Pencil className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function BuilderDetail() {
  const { builderId } = useParams();
  const navigate = useNavigate();

  const [builder, setBuilder] = useState(null);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [activeTab, setActiveTab] = useState("projects");
  const [search, setSearch] = useState("");
  const [showEditModal, setShowEditModal] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(false);
    try {
      const [builderRes, projectsRes] = await Promise.all([
        builderApi.getById(builderId),
        projectApi.getByBuilder(builderId),
      ]);
      setBuilder(builderRes?.data || builderRes || null);
      setProjects(Array.isArray(projectsRes) ? projectsRes : (projectsRes?.data || []));
    } catch (err) {
      if (err.response?.status !== 401) toast.error("Failed to load builder");
      setLoadError(true);
    } finally {
      setLoading(false);
    }
  }, [builderId]);

  useEffect(() => { if (builderId) load(); }, [builderId, load]);

  const handleDeactivate = async () => {
    if (!window.confirm(`Deactivate "${builder.name}"?`)) return;
    setActionLoading(true);
    try {
      await builderApi.delete(builder._id);
      toast.success("Builder deactivated");
      load();
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to deactivate");
    } finally {
      setActionLoading(false);
    }
  };

  const handleReactivate = async () => {
    setActionLoading(true);
    try {
      await builderApi.update(builder._id, { isActive: true });
      toast.success("Builder reactivated");
      load();
    } catch (err) {
      toast.error("Failed to reactivate");
    } finally {
      setActionLoading(false);
    }
  };

  const searchLower = search.toLowerCase().trim();
  const filteredProjects = searchLower
    ? projects.filter(p => {
        const name = (p.basics?.name || "").toLowerCase();
        const locality = (p.location?.locality || "").toLowerCase();
        const city = (p.location?.city || "").toLowerCase();
        return name.includes(searchLower) || locality.includes(searchLower) || city.includes(searchLower);
      })
    : projects;

  // ── Loading / Error / Not Found states ──────────────────────────────────────
  if (loading) {
    return (
      <div className="min-h-screen flex flex-col justify-center items-center bg-gray-50/50 gap-3">
        <Loader2 className="w-10 h-10 animate-spin text-indigo-600" />
        <p className="text-gray-500 font-medium">Loading builder...</p>
      </div>
    );
  }

  if (loadError || !builder) {
    return (
      <div className="p-8 min-h-screen bg-gray-50/30">
        <button onClick={() => navigate("/builder-management")}
          className="text-sm text-blue-600 hover:underline mb-6 flex items-center gap-1">
          <ChevronLeft className="w-4 h-4" /> Back to Builders
        </button>
        <div className="flex flex-col items-center justify-center p-16 bg-white border border-dashed border-gray-200 rounded-2xl shadow-sm">
          <AlertCircle className="w-16 h-16 text-gray-300 mb-4" />
          <h3 className="text-xl font-semibold text-gray-700">
            {loadError ? "Couldn't load this builder" : "Builder not found"}
          </h3>
          <p className="text-gray-500 mt-2 text-center max-w-md">
            {loadError ? "There was an error. Please try again." : "This builder may have been removed."}
          </p>
          <button onClick={load}
            className="mt-5 flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all">
            <RefreshCw className="w-4 h-4" /> Retry
          </button>
        </div>
      </div>
    );
  }

  const locLine = [builder.address?.city, builder.address?.state].filter(Boolean).join(", ");
  const TABS = [
    { id: "projects", label: "Projects", icon: <Building2 className="w-4 h-4" /> },
    { id: "profile", label: "Profile", icon: <User className="w-4 h-4" /> },
    { id: "notes", label: "Notes", icon: <StickyNote className="w-4 h-4" /> },
  ];

  return (
    <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto space-y-6">

      {/* Back link */}
      <button onClick={() => navigate("/builder-management")}
        className="text-sm text-blue-600 hover:underline flex items-center gap-1">
        <ChevronLeft className="w-4 h-4" /> Back to Builders
      </button>

      {/* ── Header Card ─────────────────────────────────────────────────────── */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
        {/* Top gradient bar */}
        <div className="h-2 bg-gradient-to-r from-indigo-500 to-purple-600" />
        <div className="p-6">
          <div className="flex flex-col sm:flex-row justify-between items-start gap-5">
            {/* Logo + identity */}
            <div className="flex items-center gap-4">
              <div className="w-16 h-16 rounded-2xl bg-indigo-50 flex items-center justify-center flex-shrink-0 overflow-hidden border border-indigo-100 shadow-sm">
                {builder.logoUrl ? (
                  <img src={builder.logoUrl} alt={builder.company || builder.name} className="w-full h-full object-cover" />
                ) : (
                  <span className="text-indigo-700 font-bold text-2xl">
                    {(builder.company || builder.name).charAt(0).toUpperCase()}
                  </span>
                )}
              </div>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">{builder.name}</h1>
                {builder.company && <p className="text-sm text-gray-500 mt-0.5">{builder.company}</p>}
                <div className="flex flex-wrap items-center gap-3 mt-2 text-sm text-gray-500">
                  {locLine && (
                    <span className="flex items-center gap-1.5">
                      <MapPin className="w-3.5 h-3.5 text-gray-400" /> {locLine}
                    </span>
                  )}
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
              </div>
            </div>

            {/* Status + CTAs */}
            <div className="flex flex-wrap items-center gap-2 sm:flex-col sm:items-end">
              <span className={`px-3 py-1 rounded-full text-xs font-bold border ${
                builder.isActive
                  ? "bg-emerald-50 text-emerald-700 border-emerald-200"
                  : "bg-gray-100 text-gray-500 border-gray-200"
              }`}>
                {builder.isActive ? "● Active" : "○ Inactive"}
              </span>
              <div className="flex items-center gap-2">
                <button onClick={() => navigate(`/create-project?builderId=${builderId}`)}
                  className="flex items-center gap-1.5 px-3 py-2 bg-indigo-600 text-white rounded-xl text-xs font-semibold hover:bg-indigo-700 transition-all shadow-sm">
                  <Plus className="w-3.5 h-3.5" /> Add Project
                </button>
                <button onClick={() => setShowEditModal(true)}
                  className="flex items-center gap-1.5 px-3 py-2 border border-gray-200 text-gray-700 rounded-xl text-xs font-semibold hover:bg-gray-50 transition-all">
                  <Pencil className="w-3.5 h-3.5" /> Edit
                </button>
                {builder.isActive ? (
                  <button onClick={handleDeactivate} disabled={actionLoading}
                    className="flex items-center gap-1.5 px-3 py-2 border border-rose-200 text-rose-600 rounded-xl text-xs font-semibold hover:bg-rose-50 transition-all disabled:opacity-50">
                    <Ban className="w-3.5 h-3.5" /> Deactivate
                  </button>
                ) : (
                  <button onClick={handleReactivate} disabled={actionLoading}
                    className="flex items-center gap-1.5 px-3 py-2 border border-emerald-200 text-emerald-600 rounded-xl text-xs font-semibold hover:bg-emerald-50 transition-all disabled:opacity-50">
                    <CheckCircle className="w-3.5 h-3.5" /> Reactivate
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Stats strip */}
          <div className="mt-5 pt-4 border-t border-gray-100 grid grid-cols-2 sm:grid-cols-3 gap-4">
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">{projects.length}</p>
              <p className="text-xs text-gray-500 mt-0.5">{projects.length === 1 ? "Project" : "Projects"}</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">
                {projects.reduce((sum, p) => sum + (p.overview?.totalUnits || 0), 0) || "—"}
              </p>
              <p className="text-xs text-gray-500 mt-0.5">Total Units</p>
            </div>
            <div className="text-center">
              <p className="text-2xl font-bold text-gray-900">
                {projects.filter(p => p.basics?.status === "Ready To Move" || p.basics?.status === "Completed").length}
              </p>
              <p className="text-xs text-gray-500 mt-0.5">Completed / RTM</p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Tab Bar ─────────────────────────────────────────────────────────── */}
      <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
        <div className="flex border-b border-gray-100">
          {TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-5 py-3.5 text-sm font-semibold transition-all border-b-2 -mb-px ${
                activeTab === tab.id
                  ? "border-indigo-600 text-indigo-700 bg-indigo-50/40"
                  : "border-transparent text-gray-500 hover:text-gray-800 hover:bg-gray-50"
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.id === "projects" && (
                <span className="ml-1 px-1.5 py-0.5 rounded-full text-xs bg-indigo-100 text-indigo-700 font-bold">
                  {projects.length}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* ── Tab: Projects ──────────────────────────────────────────────────── */}
        {activeTab === "projects" && (
          <div className="p-6 space-y-4">
            {/* Search bar */}
            <div className="flex gap-3 items-center">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search by name, locality or city..."
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="w-full pl-11 pr-4 py-2.5 bg-gray-50 border border-gray-200 rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none placeholder-gray-400"
                />
              </div>
              <button
                onClick={() => navigate(`/create-project?builderId=${builderId}`)}
                className="flex items-center gap-1.5 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm whitespace-nowrap">
                <Plus className="w-4 h-4" /> New Project
              </button>
            </div>

            {/* Projects grid */}
            {projects.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-20 border border-dashed border-gray-200 rounded-2xl">
                <Building2 className="w-14 h-14 text-gray-200 mb-4" />
                <h3 className="text-lg font-semibold text-gray-700">No projects yet</h3>
                <p className="text-gray-500 mt-1 text-sm text-center max-w-sm">
                  Create the first project to start tracking unit types, campaigns, and inventory.
                </p>
                <button
                  onClick={() => navigate(`/create-project?builderId=${builderId}`)}
                  className="mt-5 flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all">
                  <Plus className="w-4 h-4" /> Create First Project
                </button>
              </div>
            ) : filteredProjects.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 border border-dashed border-gray-200 rounded-2xl">
                <Search className="w-10 h-10 text-gray-300 mb-3" />
                <p className="text-gray-600 font-medium">No projects match your search</p>
                <p className="text-gray-400 text-sm mt-1">Try a different name, locality, or city.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5">
                {filteredProjects.map(p => {
                  const heroImg = p.media?.exteriorImages?.[0] || FALLBACK_IMG;
                  const projName = p.basics?.name || "Untitled project";
                  const projLoc = [p.location?.locality, p.location?.city].filter(Boolean).join(", ");
                  return (
                    <div
                      key={p._id}
                      onClick={() => navigate(`/project/${p._id}`)}
                      className="group bg-white rounded-2xl overflow-hidden border border-gray-200 shadow-sm hover:shadow-xl hover:border-indigo-200 transition-all duration-300 flex flex-col cursor-pointer"
                    >
                      <div className="relative aspect-[4/3] bg-gray-100 overflow-hidden">
                        <img
                          src={heroImg}
                          className="w-full h-full object-cover transition-transform duration-500 group-hover:scale-105"
                          alt={projName}
                          onError={e => { e.target.src = FALLBACK_IMG; }}
                        />
                        {p.basics?.status && (
                          <div className="absolute top-3 right-3">
                            <ProjectStatusBadge status={p.basics.status} />
                          </div>
                        )}
                      </div>
                      <div className="p-4 flex flex-col flex-grow">
                        <h3 className="text-sm font-bold text-gray-900 leading-tight mb-1.5 line-clamp-2 group-hover:text-indigo-700 transition-colors">
                          {projName}
                        </h3>
                        {projLoc && (
                          <div className="flex items-center gap-1.5 text-gray-500 text-xs">
                            <Home className="w-3.5 h-3.5 flex-shrink-0" />
                            <span className="truncate">{projLoc}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ── Tab: Profile ───────────────────────────────────────────────────── */}
        {activeTab === "profile" && (
          <div className="p-6">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {[
                { icon: <User className="w-4 h-4 text-indigo-400" />, label: "Contact Name", value: builder.name },
                { icon: <Briefcase className="w-4 h-4 text-indigo-400" />, label: "Company", value: builder.company || "—" },
                { icon: <Phone className="w-4 h-4 text-indigo-400" />, label: "Primary Phone", value: builder.phone },
                { icon: <Phone className="w-4 h-4 text-gray-300" />, label: "Alternate Phone", value: builder.alternatePhone || "—" },
                { icon: <Mail className="w-4 h-4 text-indigo-400" />, label: "Email", value: builder.email || "—" },
                { icon: <MapPin className="w-4 h-4 text-indigo-400" />, label: "Location", value: locLine || "—" },
                { icon: <Hash className="w-4 h-4 text-indigo-400" />, label: "RERA Number", value: builder.reraNumber || "Not provided" },
                { icon: <CreditCard className="w-4 h-4 text-indigo-400" />, label: "GST Number", value: builder.gstNumber || "Not provided" },
                { icon: <Building2 className="w-4 h-4 text-indigo-400" />, label: "Year Established", value: builder.yearEstablished || "—" },
                { icon: <Building2 className="w-4 h-4 text-indigo-400" />, label: "Projects Delivered", value: builder.totalProjectsDelivered || "—" },
                { icon: <Building2 className="w-4 h-4 text-indigo-400" />, label: "Sq.Ft Delivered", value: builder.totalSqFtDelivered || "—" },
                { icon: <FileText className="w-4 h-4 text-indigo-400" />, label: "Website", value: builder.websiteUrl || "—" },
                { icon: <FileText className="w-4 h-4 text-indigo-400" />, label: "Added", value: builder.createdAt ? new Date(builder.createdAt).toLocaleDateString("en-IN", { day: "numeric", month: "long", year: "numeric" }) : "—" },
              ].map(({ icon, label, value }) => (
                <div key={label} className="flex items-start gap-3 p-4 bg-gray-50 rounded-xl border border-gray-100">
                  <div className="p-1.5 bg-white rounded-lg border border-gray-100 shadow-sm mt-0.5 flex-shrink-0">
                    {icon}
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs text-gray-400 font-medium uppercase tracking-wide">{label}</p>
                    <p className="text-sm font-semibold text-gray-800 mt-0.5 break-words">{value}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Tab: Notes ─────────────────────────────────────────────────────── */}
        {activeTab === "notes" && (
          <div className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-gray-700">Internal Admin Notes</h3>
              <button onClick={() => setShowEditModal(true)}
                className="flex items-center gap-1.5 text-xs text-indigo-600 hover:underline">
                <Pencil className="w-3.5 h-3.5" /> Edit
              </button>
            </div>
            {builder.notes ? (
              <div className="bg-amber-50 border border-amber-200 rounded-xl p-5 text-sm text-gray-700 whitespace-pre-wrap leading-relaxed">
                {builder.notes}
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center py-16 border border-dashed border-gray-200 rounded-2xl">
                <StickyNote className="w-10 h-10 text-gray-200 mb-3" />
                <p className="text-gray-500 text-sm">No internal notes yet.</p>
                <button onClick={() => setShowEditModal(true)}
                  className="mt-3 text-xs text-indigo-600 hover:underline">
                  Add a note via Edit
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Edit modal */}
      {showEditModal && (
        <BuilderEditModal
          builder={builder}
          onClose={() => setShowEditModal(false)}
          onSaved={load}
        />
      )}
    </div>
  );
}

