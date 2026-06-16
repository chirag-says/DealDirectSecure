import React, { useState, useEffect, useRef } from "react";
import { builderApi } from "../api/adminApi";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import {
    Building2, Plus, Search, RefreshCw, Loader2,
    X, Phone, Mail, Home, Pencil, Ban, CheckCircle, PlusCircle, ChevronRight
} from "lucide-react";

const formatDate = (d) => {
    if (!d) return "N/A";
    return new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" });
};

// ── Builder Form Modal ────────────────────────────────────────────────────────
function BuilderModal({ builder, onClose, onSaved }) {
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
    });
    const [logoFile, setLogoFile] = useState(null);
    const [logoPreview, setLogoPreview] = useState(builder?.logoUrl || null);
    const [submitting, setSubmitting] = useState(false);
    const logoInputRef = useRef(null);

    const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

    const handleLogoChange = (e) => {
        const file = e.target.files?.[0];
        if (file) {
            setLogoFile(file);
            setLogoPreview(URL.createObjectURL(file));
        }
    };

    const removeLogo = () => {
        setLogoFile(null);
        setLogoPreview(null);
        if (logoInputRef.current) logoInputRef.current.value = "";
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!form.name.trim()) return toast.error("Name is required");
        if (!form.phone.trim()) return toast.error("Phone is required");
        setSubmitting(true);
        try {
            // Use FormData if logo is being uploaded, otherwise plain JSON
            if (logoFile) {
                const fd = new FormData();
                fd.append("name", form.name.trim());
                if (form.company.trim()) fd.append("company", form.company.trim());
                fd.append("phone", form.phone.trim());
                if (form.alternatePhone.trim()) fd.append("alternatePhone", form.alternatePhone.trim());
                if (form.email.trim()) fd.append("email", form.email.trim());
                if (form.reraNumber.trim()) fd.append("reraNumber", form.reraNumber.trim());
                if (form.gstNumber.trim()) fd.append("gstNumber", form.gstNumber.trim());
                fd.append("address", JSON.stringify({ city: form.city.trim(), state: form.state.trim() }));
                if (form.notes.trim()) fd.append("notes", form.notes.trim());
                fd.append("logo", logoFile);

                if (builder) {
                    await builderApi.update(builder._id, fd);
                    toast.success("Builder updated!");
                } else {
                    await builderApi.create(fd);
                    toast.success("Builder created!");
                }
            } else {
                const payload = {
                    name: form.name.trim(),
                    company: form.company.trim() || undefined,
                    phone: form.phone.trim(),
                    alternatePhone: form.alternatePhone.trim() || undefined,
                    email: form.email.trim() || undefined,
                    reraNumber: form.reraNumber.trim() || undefined,
                    gstNumber: form.gstNumber.trim() || undefined,
                    address: { city: form.city.trim(), state: form.state.trim() },
                    notes: form.notes.trim() || undefined,
                };
                if (builder) {
                    await builderApi.update(builder._id, payload);
                    toast.success("Builder updated!");
                } else {
                    await builderApi.create(payload);
                    toast.success("Builder created!");
                }
            }
            onSaved();
            onClose();
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to save builder");
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-gray-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
            <div className="bg-white w-full max-w-lg rounded-2xl shadow-2xl border border-gray-200 overflow-hidden">
                <div className="p-6 border-b border-gray-100 flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl">
                            <Building2 className="w-5 h-5" />
                        </div>
                        <div>
                            <h2 className="text-lg font-bold text-gray-900">{builder ? "Edit Builder" : "Add Builder"}</h2>
                            <p className="text-xs text-gray-500">Contact card — no login required</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors">
                        <X className="w-5 h-5" />
                    </button>
                </div>

                <form onSubmit={handleSubmit} className="p-6 space-y-4 max-h-[72vh] overflow-y-auto">
                    {/* ── Company Logo Upload ── */}
                    <div className="flex items-center gap-4">
                        <div className="relative group">
                            <button type="button" onClick={() => logoInputRef.current?.click()}
                                className="w-20 h-20 rounded-full border-2 border-dashed border-gray-300 flex items-center justify-center overflow-hidden bg-gray-50 hover:border-indigo-400 hover:bg-indigo-50/50 transition-all cursor-pointer">
                                {logoPreview ? (
                                    <img src={logoPreview} alt="Logo" className="w-full h-full object-cover rounded-full" />
                                ) : (
                                    <div className="text-center">
                                        <PlusCircle className="w-6 h-6 text-gray-400 mx-auto" />
                                        <span className="text-[9px] text-gray-400 mt-0.5 block">Logo</span>
                                    </div>
                                )}
                            </button>
                            {logoPreview && (
                                <button type="button" onClick={removeLogo}
                                    className="absolute -top-1 -right-1 w-5 h-5 rounded-full bg-red-500 text-white flex items-center justify-center text-xs shadow hover:bg-red-600 opacity-0 group-hover:opacity-100 transition-opacity">
                                    ×
                                </button>
                            )}
                            <input ref={logoInputRef} type="file" accept="image/*" className="hidden" onChange={handleLogoChange} />
                        </div>
                        <div>
                            <p className="text-sm font-semibold text-gray-700">Company Logo</p>
                            <p className="text-xs text-gray-400">Click to upload (JPG, PNG, WebP)</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                        <div className="col-span-2">
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Contact Name *</label>
                            <input value={form.name} onChange={e => set("name", e.target.value)} required placeholder="e.g. Rajesh Mehta"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Company / Firm</label>
                            <input value={form.company} onChange={e => set("company", e.target.value)} placeholder="e.g. Prestige Group"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Phone *</label>
                            <input value={form.phone} onChange={e => set("phone", e.target.value)} required placeholder="+91 98765 43210"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Alternate Phone</label>
                            <input value={form.alternatePhone} onChange={e => set("alternatePhone", e.target.value)} placeholder="Optional"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Email</label>
                            <input type="email" value={form.email} onChange={e => set("email", e.target.value)} placeholder="Optional"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">RERA Number</label>
                            <input value={form.reraNumber} onChange={e => set("reraNumber", e.target.value)} placeholder="Optional"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">GST Number</label>
                            <input value={form.gstNumber} onChange={e => set("gstNumber", e.target.value)} placeholder="Optional"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">City</label>
                            <input value={form.city} onChange={e => set("city", e.target.value)} placeholder="e.g. Pune"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div>
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">State</label>
                            <input value={form.state} onChange={e => set("state", e.target.value)} placeholder="e.g. Maharashtra"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50" />
                        </div>
                        <div className="col-span-2">
                            <label className="block text-xs font-bold text-gray-500 uppercase tracking-wider mb-1.5">Internal Notes</label>
                            <textarea value={form.notes} onChange={e => set("notes", e.target.value)} rows={2}
                                placeholder="Admin-only notes about this builder"
                                className="w-full px-3 py-2.5 border border-gray-200 rounded-xl text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/20 bg-gray-50 resize-none" />
                        </div>
                    </div>

                    <div className="flex gap-3 pt-2">
                        <button type="button" onClick={onClose}
                            className="flex-1 px-4 py-2.5 border border-gray-200 text-gray-700 rounded-xl text-sm font-semibold hover:bg-gray-50 transition-colors">
                            Cancel
                        </button>
                        <button type="submit" disabled={submitting}
                            className="flex-1 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-colors flex items-center justify-center gap-2 disabled:opacity-60">
                            {submitting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Plus className="w-4 h-4" />}
                            {builder ? "Save Changes" : "Add Builder"}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function BuilderManagement() {
    const navigate = useNavigate();
    const [builders, setBuilders] = useState([]);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [showModal, setShowModal] = useState(false);
    const [editTarget, setEditTarget] = useState(null);
    const [selectedBuilder, setSelectedBuilder] = useState(null);

    const fetchBuilders = async (q = search) => {
        try {
            setLoading(true);
            const data = await builderApi.getAll({ search: q, limit: 50 });
            setBuilders(data.data || []);
        } catch (err) {
            if (err.response?.status !== 401) toast.error("Failed to load builders");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const t = setTimeout(() => fetchBuilders(search), 400);
        return () => clearTimeout(t);
    }, [search]);

    const handleDeactivate = async (builder) => {
        if (!window.confirm(`Deactivate "${builder.name}"? This will prevent new Group Buy projects for their properties.`)) return;
        try {
            await builderApi.delete(builder._id);
            toast.success("Builder deactivated");
            fetchBuilders();
            if (selectedBuilder?._id === builder._id) setSelectedBuilder(null);
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to deactivate");
        }
    };

    const handleReactivate = async (builder) => {
        try {
            await builderApi.update(builder._id, { isActive: true });
            toast.success("Builder reactivated");
            fetchBuilders();
        } catch (err) {
            toast.error("Failed to reactivate");
        }
    };

    const openEdit = (builder) => {
        setEditTarget(builder);
        setShowModal(true);
    };

    const openCreate = () => {
        setEditTarget(null);
        setShowModal(true);
    };

    return (
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 w-full max-w-full mx-auto space-y-8">

            {/* Header */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
                        <Building2 className="w-8 h-8 text-indigo-600" />
                        Builder Management
                    </h1>
                    <p className="text-sm text-gray-500 mt-1 sm:ml-10">
                        Builders have no login — admin posts properties on their behalf.
                    </p>
                </div>
                <button onClick={openCreate}
                    className="flex items-center gap-2 px-4 py-2.5 bg-indigo-600 text-white rounded-xl text-sm font-semibold hover:bg-indigo-700 transition-all shadow-sm">
                    <Plus className="w-4 h-4" /> Add Builder
                </button>
            </div>

            {/* Filter Bar */}
            <div className="flex gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
                <div className="relative flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input type="text" placeholder="Search by name, company or phone..."
                        value={search} onChange={e => setSearch(e.target.value)}
                        className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none placeholder-gray-400" />
                </div>
                <button onClick={() => fetchBuilders()} disabled={loading}
                    className="p-2.5 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-all shadow-sm">
                    <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
                </button>
            </div>

            {/* Table */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden min-h-[400px] flex flex-col">
                {loading ? (
                    <div className="flex-1 flex justify-center items-center">
                        <Loader2 className="w-10 h-10 animate-spin text-indigo-600" />
                    </div>
                ) : builders.length === 0 ? (
                    <div className="flex-1 flex flex-col justify-center items-center text-gray-400 py-24">
                        <Building2 className="w-16 h-16 mb-4 text-gray-200" />
                        <p className="text-lg font-semibold text-gray-600">No builders yet</p>
                        <p className="text-sm mt-1">Add your first builder to enable Group Buy projects.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto flex-1">
                        <table className="min-w-full text-sm divide-y divide-gray-100">
                            <thead className="bg-gray-50/80">
                                <tr>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Builder</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Contact</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell">Location</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden lg:table-cell">Properties</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider">Status</th>
                                    <th className="py-4 px-6 text-right text-xs font-bold text-gray-500 uppercase tracking-wider">Actions</th>
                                    <th className="py-4 px-2 w-px hidden md:table-cell"></th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100/80 bg-white">
                                {builders.map(b => (
                                    <tr key={b._id} className="hover:bg-gray-50/50 transition-all group cursor-pointer"
                                        onClick={() => navigate(`/builder/${b._id}/projects`)}
                                        onKeyDown={(e) => {
                                            if (e.key === "Enter" || e.key === " ") {
                                                e.preventDefault();
                                                navigate(`/builder/${b._id}/projects`);
                                            }
                                        }}
                                        role="link"
                                        tabIndex={0}>
                                        <td className="py-4 px-6">
                                            <div className="flex items-center gap-3">
                                                <div className="w-10 h-10 rounded-xl bg-indigo-50 flex items-center justify-center flex-shrink-0 overflow-hidden">
                                                    {b.logoUrl ? (
                                                        <img src={b.logoUrl} alt={b.company || b.name} className="w-full h-full object-cover" />
                                                    ) : (
                                                        <span className="text-indigo-700 font-bold text-lg">{(b.company || b.name).charAt(0).toUpperCase()}</span>
                                                    )}
                                                </div>
                                                <div>
                                                    <p className="font-bold text-gray-900 group-hover:text-indigo-600 transition-colors">{b.name}</p>
                                                    {b.company && <p className="text-xs text-gray-500">{b.company}</p>}
                                                </div>
                                            </div>
                                        </td>
                                        <td className="py-4 px-6 hidden md:table-cell">
                                            <div className="space-y-1">
                                                <div className="flex items-center gap-1.5 text-gray-600 text-xs">
                                                    <Phone className="w-3.5 h-3.5 text-gray-400" />
                                                    {b.phone}
                                                </div>
                                                {b.email && (
                                                    <div className="flex items-center gap-1.5 text-gray-600 text-xs">
                                                        <Mail className="w-3.5 h-3.5 text-gray-400" />
                                                        {b.email}
                                                    </div>
                                                )}
                                            </div>
                                        </td>
                                        <td className="py-4 px-6 text-sm text-gray-600 hidden md:table-cell">
                                            {[b.address?.city, b.address?.state].filter(Boolean).join(", ") || "—"}
                                        </td>
                                        <td className="py-4 px-6 hidden lg:table-cell">
                                            <div className="flex items-center gap-1.5">
                                                <Home className="w-4 h-4 text-gray-400" />
                                                <span className="font-bold text-gray-900">{b.propertyCount || 0}</span>
                                                <span className="text-gray-400 text-xs">propert{b.propertyCount === 1 ? "y" : "ies"}</span>
                                            </div>
                                        </td>
                                        <td className="py-4 px-6">
                                            <span className={`px-2.5 py-1 rounded-lg text-xs font-bold ${b.isActive ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : "bg-gray-100 text-gray-500 border border-gray-200"}`}>
                                                {b.isActive ? "Active" : "Inactive"}
                                            </span>
                                        </td>
                                        <td className="py-4 px-6 text-right">
                                            <div className="flex justify-end gap-2">
                                                <button onClick={(e) => { e.stopPropagation(); navigate(`/admin-add-property?builderId=${b._id}`); }}
                                                    className="p-2 text-gray-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors" title="Add Legacy Property">
                                                    <PlusCircle className="w-4 h-4" />
                                                </button>
                                                <button onClick={(e) => { e.stopPropagation(); navigate(`/create-project?builderId=${b._id}`); }}
                                                    className="p-2 text-gray-400 hover:text-blue-600 hover:bg-blue-50 rounded-lg transition-colors" title="Add New Project">
                                                    <Building2 className="w-4 h-4" />
                                                </button>
                                                <button onClick={(e) => { e.stopPropagation(); openEdit(b); }}
                                                    className="p-2 text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors" title="Edit">
                                                    <Pencil className="w-4 h-4" />
                                                </button>
                                                {b.isActive ? (
                                                    <button onClick={(e) => { e.stopPropagation(); handleDeactivate(b); }}
                                                        className="p-2 text-gray-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors" title="Deactivate">
                                                        <Ban className="w-4 h-4" />
                                                    </button>
                                                ) : (
                                                    <button onClick={(e) => { e.stopPropagation(); handleReactivate(b); }}
                                                        className="p-2 text-gray-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors" title="Reactivate">
                                                        <CheckCircle className="w-4 h-4" />
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                        <td className="py-4 px-2 hidden md:table-cell">
                                            <ChevronRight className="w-4 h-4 text-gray-300 group-hover:text-indigo-500 group-hover:translate-x-1 transition-all" />
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {showModal && (
                <BuilderModal
                    builder={editTarget}
                    onClose={() => setShowModal(false)}
                    onSaved={fetchBuilders}
                />
            )}
        </div>
    );
}
