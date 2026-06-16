import React, { useState, useEffect } from "react";
import { groupBuyApi, propertyManagementApi } from "../api/adminApi";
import { toast } from "react-toastify";
import {
    Users, Plus, RefreshCw, Loader2, Search,
    ChevronDown, X, Calendar, IndianRupee,
    Building2, Clock, CheckCircle2, XCircle,
    AlertCircle, Lock, TrendingUp
} from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────────

const formatDate = (d) => {
    if (!d) return "N/A";
    return new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
};

const daysLeft = (deadline) => {
    if (!deadline) return null;
    const diff = new Date(deadline) - new Date();
    return Math.max(0, Math.ceil(diff / (1000 * 60 * 60 * 24)));
};

const STATUS_META = {
    forming:      { label: "Forming",      color: "bg-blue-50 text-blue-700 border border-blue-200" },
    locked:       { label: "Locked",       color: "bg-indigo-50 text-indigo-700 border border-indigo-200" },
    negotiating:  { label: "Negotiating",  color: "bg-amber-50 text-amber-700 border border-amber-200" },
    terms_shared: { label: "Terms Shared", color: "bg-purple-50 text-purple-700 border border-purple-200" },
    closed:       { label: "Closed",       color: "bg-emerald-50 text-emerald-700 border border-emerald-200" },
    expired:      { label: "Expired",      color: "bg-rose-50 text-rose-700 border border-rose-200" },
    cancelled:    { label: "Cancelled",    color: "bg-gray-100 text-gray-600 border border-gray-200" },
};

// ─── Create Group Modal ──────────────────────────────────────────────────────

function CreateGroupModal({ onClose, onCreated }) {
    const [properties, setProperties] = useState([]);
    const [loadingProps, setLoadingProps] = useState(true);
    const [submitting, setSubmitting] = useState(false);
    const [form, setForm] = useState({
        propertyId: "",
        tokenAmount: "",
        deadlineDays: "30",
        minGroupSize: "3",
        maxDiscount: "",
        closureThreshold: "75",
        perks: "",
        adminNotes: "",
    });

    useEffect(() => {
        propertyManagementApi.getAll({ status: "approved", limit: 200 })
            .then(d => setProperties(d.data || d.properties || []))
            .catch(() => toast.error("Could not load properties"))
            .finally(() => setLoadingProps(false));
    }, []);

    const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!form.propertyId) return toast.error("Select a property");
        if (!form.tokenAmount || Number(form.tokenAmount) < 25000)
            return toast.error("Token amount must be at least ₹25,000");

        setSubmitting(true);
        try {
            const payload = {
                propertyId: form.propertyId,
                tokenAmount: Number(form.tokenAmount),
                deadlineDays: Number(form.deadlineDays),
                minGroupSize: Number(form.minGroupSize),
                maxDiscount: form.maxDiscount ? Number(form.maxDiscount) : undefined,
                closureThreshold: Number(form.closureThreshold),
                perks: form.perks.split(",").map(p => p.trim()).filter(Boolean),
                adminNotes: form.adminNotes,
            };
            await groupBuyApi.createProject(payload);
            toast.success("Group Buy project created!");
            onCreated();
            onClose();
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to create project");
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-gray-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="bg-white w-full max-w-lg rounded-2xl shadow-2xl border border-gray-200 overflow-hidden">
                {/* Header */}
                <div className="p-6 border-b border-gray-100 flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl">
                            <Users className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-gray-900">Create Group Buy Project</h2>
                            <p className="text-xs text-gray-500">Enable group buying for a property</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                {/* Form */}
                <form onSubmit={handleSubmit} className="p-6 space-y-4 max-h-[70vh] overflow-y-auto">
                    {/* Property */}
                    <div>
                        <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Property *</label>
                        {loadingProps ? (
                            <div className="flex items-center gap-2 text-gray-500 text-sm"><Loader2 className="w-4 h-4 animate-spin" /> Loading...</div>
                        ) : (
                            <select
                                value={form.propertyId}
                                onChange={e => set("propertyId", e.target.value)}
                                required
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                            >
                                <option value="">Select a property...</option>
                                {properties.map(p => (
                                    <option key={p._id} value={p._id}>
                                        {p.title} — {p.address?.city || p.city || ""}
                                    </option>
                                ))}
                            </select>
                        )}
                    </div>

                    {/* Token Amount */}
                    <div>
                        <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Token Amount (₹) *</label>
                        <input
                            type="number"
                            value={form.tokenAmount}
                            onChange={e => set("tokenAmount", e.target.value)}
                            placeholder="e.g. 50000"
                            min="25000"
                            max="500000"
                            required
                            className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                        />
                        <p className="text-xs text-gray-400 mt-1">Range: ₹25,000 – ₹5,00,000</p>
                    </div>

                    {/* Deadline + Min Size */}
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Deadline (days)</label>
                            <select
                                value={form.deadlineDays}
                                onChange={e => set("deadlineDays", e.target.value)}
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                            >
                                <option value="30">30 days</option>
                                <option value="45">45 days</option>
                                <option value="60">60 days</option>
                                <option value="75">75 days</option>
                                <option value="90">90 days</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Min Group Size</label>
                            <input
                                type="number"
                                value={form.minGroupSize}
                                onChange={e => set("minGroupSize", e.target.value)}
                                min="3"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                            />
                        </div>
                    </div>

                    {/* Max Discount + Closure Threshold */}
                    <div className="grid grid-cols-2 gap-4">
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Max Discount (%)</label>
                            <input
                                type="number"
                                value={form.maxDiscount}
                                onChange={e => set("maxDiscount", e.target.value)}
                                placeholder="e.g. 15"
                                min="1" max="30"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                            />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Closure Threshold (%)</label>
                            <input
                                type="number"
                                value={form.closureThreshold}
                                onChange={e => set("closureThreshold", e.target.value)}
                                min="51" max="100"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                            />
                        </div>
                    </div>

                    {/* Perks */}
                    <div>
                        <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Perks (comma-separated)</label>
                        <input
                            type="text"
                            value={form.perks}
                            onChange={e => set("perks", e.target.value)}
                            placeholder="Free parking, Floor upgrade, Zero maintenance Year 1"
                            className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50"
                        />
                    </div>

                    {/* Admin Notes */}
                    <div>
                        <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Admin Notes (internal)</label>
                        <textarea
                            value={form.adminNotes}
                            onChange={e => set("adminNotes", e.target.value)}
                            rows={2}
                            placeholder="Internal notes — not visible to buyers"
                            className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50 resize-none"
                        />
                    </div>

                    {/* Actions */}
                    <div className="flex gap-3 pt-2">
                        <button type="button" onClick={onClose}
                            className="flex-1 px-4 py-2.5 border border-gray-200 text-gray-700 rounded-xl text-sm font-semibold hover:bg-gray-50 transition-colors">
                            Cancel
                        </button>
                        <button type="submit" disabled={submitting}
                            className="flex-1 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-60">
                            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                            Create Project
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function GroupBuyManagement() {
    const [projects, setProjects] = useState([]);
    const [loading, setLoading] = useState(true);
    const [statusFilter, setStatusFilter] = useState("forming");
    const [search, setSearch] = useState("");
    const [showCreate, setShowCreate] = useState(false);

    const stats = {
        forming:     projects.filter(p => p.status === "forming").length,
        locked:      projects.filter(p => p.status === "locked").length,
        negotiating: projects.filter(p => p.status === "negotiating").length,
        closed:      projects.filter(p => p.status === "closed").length,
    };

    const fetchProjects = async () => {
        try {
            setLoading(true);
            const data = await groupBuyApi.getProjects({ status: statusFilter || undefined, limit: 50 });
            setProjects(data.data || []);
        } catch (err) {
            if (err.response?.status !== 401) toast.error("Failed to load group buy projects");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => { fetchProjects(); }, [statusFilter]);

    const filtered = projects.filter(p => {
        if (!search) return true;
        const q = search.toLowerCase();
        return (
            p.propertySnapshot?.title?.toLowerCase().includes(q) ||
            p.propertySnapshot?.city?.toLowerCase().includes(q)
        );
    });

    return (
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 w-full max-w-full mx-auto space-y-8">

            {/* Header */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
                        <Users className="w-8 h-8 text-indigo-600" />
                        Group Buy Management
                    </h1>
                    <p className="text-sm text-gray-500 mt-1 sm:ml-10">
                        Create and manage group buying consortiums.
                    </p>
                </div>
                <button
                    onClick={() => setShowCreate(true)}
                    className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm"
                >
                    <Plus className="w-4 h-4" /> New Group Buy
                </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                {[
                    { label: "Forming",     value: stats.forming,     color: "text-blue-600",   bg: "bg-blue-50",    icon: <Clock className="w-5 h-5" /> },
                    { label: "Locked",      value: stats.locked,      color: "text-indigo-600", bg: "bg-indigo-50",  icon: <Lock className="w-5 h-5" /> },
                    { label: "Negotiating", value: stats.negotiating, color: "text-amber-600",  bg: "bg-amber-50",   icon: <TrendingUp className="w-5 h-5" /> },
                    { label: "Closed",      value: stats.closed,      color: "text-emerald-600",bg: "bg-emerald-50", icon: <CheckCircle2 className="w-5 h-5" /> },
                ].map(s => (
                    <button
                        key={s.label}
                        onClick={() => setStatusFilter(s.label.toLowerCase())}
                        className={`bg-white rounded-2xl p-4 shadow-sm border border-gray-200 text-left hover:border-indigo-200 transition-all ${statusFilter === s.label.toLowerCase() ? "ring-2 ring-indigo-500/30" : ""}`}
                    >
                        <div className={`inline-flex p-2 rounded-xl ${s.bg} ${s.color} mb-3`}>{s.icon}</div>
                        <p className="text-2xl font-bold text-gray-900">{s.value}</p>
                        <p className="text-xs font-medium text-gray-500 mt-0.5">{s.label}</p>
                    </button>
                ))}
            </div>

            {/* Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
                <div className="relative w-full sm:flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                        type="text"
                        placeholder="Search by property or city..."
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                        className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none placeholder-gray-400"
                    />
                </div>
                <select
                    value={statusFilter}
                    onChange={e => setStatusFilter(e.target.value)}
                    className="w-full sm:w-44 py-2.5 px-4 bg-gray-50/50 border-none rounded-xl text-sm text-gray-700 focus:ring-2 focus:ring-indigo-500/20 outline-none font-medium cursor-pointer"
                >
                    <option value="">All Statuses</option>
                    {Object.entries(STATUS_META).map(([v, m]) => (
                        <option key={v} value={v}>{m.label}</option>
                    ))}
                </select>
                <button onClick={fetchProjects} disabled={loading}
                    className="p-2.5 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-all shadow-sm flex items-center gap-2">
                    <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
                </button>
            </div>

            {/* Table */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden min-h-[400px] flex flex-col">
                {loading ? (
                    <div className="flex-1 flex justify-center items-center">
                        <Loader2 className="w-10 h-10 animate-spin text-indigo-600" />
                    </div>
                ) : filtered.length === 0 ? (
                    <div className="flex-1 flex flex-col justify-center items-center text-gray-400 py-24">
                        <Users className="w-16 h-16 mb-4 text-gray-200" />
                        <p className="text-lg font-semibold text-gray-600">No group buy projects found</p>
                        <p className="text-sm mt-1">Create your first one using the button above.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto flex-1">
                        <table className="min-w-full text-sm divide-y divide-gray-100">
                            <thead className="bg-gray-50/80">
                                <tr>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Property</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Members</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Token</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Deadline</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="py-4 px-6 text-right text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Created</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100/80 bg-white">
                                {filtered.map(project => {
                                    const meta = STATUS_META[project.status] || STATUS_META.forming;
                                    const days = daysLeft(project.formingDeadline);
                                    return (
                                        <tr key={project._id} className="hover:bg-gray-50/50 transition-all">
                                            {/* Property */}
                                            <td className="py-4 px-6">
                                                <div className="flex items-center gap-3">
                                                    <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center flex-shrink-0">
                                                        {project.propertySnapshot?.image ? (
                                                            <img src={project.propertySnapshot.image} alt="" className="w-full h-full object-cover rounded-xl" />
                                                        ) : (
                                                            <Building2 className="w-5 h-5 text-indigo-400" />
                                                        )}
                                                    </div>
                                                    <div>
                                                        <p className="font-bold text-gray-900 truncate max-w-[180px]">
                                                            {project.propertySnapshot?.title || "Untitled"}
                                                        </p>
                                                        <p className="text-xs text-gray-500">
                                                            {project.propertySnapshot?.city} · {project.propertySnapshot?.bhk}
                                                        </p>
                                                    </div>
                                                </div>
                                            </td>
                                            {/* Members */}
                                            <td className="py-4 px-6 hidden md:table-cell">
                                                <div className="flex items-center gap-1.5">
                                                    <Users className="w-4 h-4 text-gray-400" />
                                                    <span className="font-bold text-gray-900">{project.memberCount}</span>
                                                    <span className="text-gray-400 text-xs">/ min {project.config?.minGroupSize}</span>
                                                </div>
                                                {/* Fill progress */}
                                                <div className="mt-1.5 w-24 bg-gray-100 rounded-full h-1.5">
                                                    <div
                                                        className="h-1.5 rounded-full bg-indigo-500 transition-all"
                                                        style={{ width: `${Math.min(100, (project.memberCount / project.config?.minGroupSize) * 100)}%` }}
                                                    />
                                                </div>
                                            </td>
                                            {/* Token */}
                                            <td className="py-4 px-6 hidden md:table-cell">
                                                <div className="flex items-center gap-1 font-semibold text-gray-800">
                                                    <IndianRupee className="w-3.5 h-3.5" />
                                                    {project.config?.tokenAmount?.toLocaleString("en-IN")}
                                                </div>
                                            </td>
                                            {/* Deadline */}
                                            <td className="py-4 px-6 hidden md:table-cell">
                                                {project.status === "forming" && days !== null ? (
                                                    <span className={`text-xs font-semibold ${days <= 7 ? "text-rose-600" : days <= 14 ? "text-amber-600" : "text-gray-600"}`}>
                                                        {days === 0 ? "Expires today" : `${days}d left`}
                                                    </span>
                                                ) : (
                                                    <span className="text-xs text-gray-400">{formatDate(project.formingDeadline)}</span>
                                                )}
                                            </td>
                                            {/* Status */}
                                            <td className="py-4 px-6">
                                                <span className={`px-2.5 py-1 rounded-lg text-xs font-bold ${meta.color}`}>
                                                    {meta.label}
                                                </span>
                                            </td>
                                            {/* Created */}
                                            <td className="py-4 px-6 text-right hidden md:table-cell text-xs text-gray-500">
                                                {formatDate(project.createdAt)}
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Create Modal */}
            {showCreate && (
                <CreateGroupModal
                    onClose={() => setShowCreate(false)}
                    onCreated={fetchProjects}
                />
            )}
        </div>
    );
}
