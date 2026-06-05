import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import {
    Trash,
    CheckCircle,
    XCircle,
    MapPin,
    Search,
    Filter,
    Calendar,
    X,
    RefreshCw,
    Home as HomeIcon,
    AlertTriangle,
    Image as ImageIcon,
    Loader2
} from "lucide-react";
import { toast } from "react-toastify";
import adminApi from "../api/adminApi";

const API_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:9000";

const AllProperty = () => {
    const [properties, setProperties] = useState([]);
    const [loading, setLoading] = useState(true);

    // --- Filter States ---
    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");
    const [startDate, setStartDate] = useState("");
    const [endDate, setEndDate] = useState("");

    // --- Modal State ---
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [selectedPropertyId, setSelectedPropertyId] = useState(null);
    const [rejectionReason, setRejectionReason] = useState("");

    const location = useLocation();

    // Helper: Extract data safely
    const extractList = (resData) => {
        if (!resData) return [];
        if (Array.isArray(resData)) return resData;
        if (Array.isArray(resData.data)) return resData.data;
        return [];
    };

    // Helper: Resolve Image
    const resolveImage = (img) => {
        if (!img) return null;
        const s = String(img).toLowerCase();
        if (s.startsWith("data:") || s.startsWith("http")) return img;
        if (img.startsWith("/uploads")) return `${API_URL}${img}`;
        return `${API_URL}/uploads/${img}`;
    };

    // --- Fetch Properties using adminApi (cookie-based auth) ---
    const fetchProperties = async (overrideSearch) => {
        setLoading(true);
        try {
            // Build Params
            const params = {
                search: overrideSearch !== undefined ? overrideSearch : searchTerm,
                status: statusFilter,
                startDate: startDate || undefined,
                endDate: endDate || undefined
            };

            const res = await adminApi.get(`/api/properties/admin/all`, { params });
            setProperties(extractList(res.data));
        } catch (err) {
            console.error(err);
            toast.error("Failed to fetch properties");
        }
        setLoading(false);
    };

    // Auto-fetch ONLY on filter changes (Dropdowns/Dates)
    // We EXCLUDE searchTerm here so it doesn't search on every keystroke
    useEffect(() => {
        fetchProperties();
    }, [statusFilter, startDate, endDate]);

    // Initial load from URL query (?search=...)
    useEffect(() => {
        const params = new URLSearchParams(location.search);
        const initialSearch = params.get("search");
        if (initialSearch) {
            setSearchTerm(initialSearch);
            fetchProperties(initialSearch);
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [location.search]);

    // Handle Enter Key in Search Input
    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            fetchProperties();
        }
    };

    const clearFilters = () => {
        setSearchTerm("");
        setStatusFilter("all");
        setStartDate("");
        setEndDate("");
        setTimeout(() => window.location.reload(), 100);
    };

    // --- Actions (Approve, Reject, Delete) using adminApi ---
    const handleDelete = async (id) => {
        if (!window.confirm("Permanently delete this property?")) return;
        try {
            await adminApi.delete(`/api/properties/delete/${id}`);
            toast.success("Property deleted");
            setProperties(prev => prev.filter(p => p._id !== id));
        } catch (err) {
            toast.error("Deletion failed");
        }
    };

    const handleApprove = async (id) => {
        try {
            await adminApi.put(`/api/properties/approve/${id}`, {});
            toast.success("Property Listed successfully");
            fetchProperties();
        } catch (err) { toast.error("Failed to approve property"); }
    };

    const openRejectModal = (id) => {
        setSelectedPropertyId(id);
        setRejectionReason("");
        setIsModalOpen(true);
    };

    const submitRejection = async () => {
        if (!rejectionReason.trim()) return toast.error("Rejection reason is required");
        try {
            await adminApi.put(`/api/properties/disapprove/${selectedPropertyId}`,
                { rejectionReason }
            );
            toast.success("Property Rejected");
            setIsModalOpen(false);
            fetchProperties();
        } catch (err) { toast.error("Failed to reject property"); }
    };

    if (loading && properties.length === 0) {
        return (
            <div className="min-h-screen flex flex-col justify-center items-center bg-gray-50/50">
                <Loader2 className="w-10 h-10 animate-spin text-indigo-600 mb-4" />
                <p className="text-gray-500 font-medium">Loading Property Data...</p>
            </div>
        );
    }

    return (
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 w-full max-w-full mx-auto flex flex-col gap-8">
            
             {/* HEADER */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
                    <HomeIcon className="w-8 h-8 text-indigo-600" />
                    Property Manager
                </h1>
                <p className="text-sm text-gray-500 mt-1 sm:ml-10">
                    Review and manage submitted properties.
                </p>
                </div>
                
                <div className="hidden sm:flex items-center justify-center px-4 py-2 bg-indigo-50 border border-indigo-100 rounded-xl">
                    <span className="text-sm font-bold text-indigo-700">
                        {properties.length} <span className="font-normal text-indigo-500 uppercase tracking-wider text-xs">Total</span>
                    </span>
                </div>
            </div>

            {/* --- FILTER BAR --- */}
            <div className="flex flex-col xl:flex-row gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
                
                {/* Search */}
                <div className="relative w-full xl:flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                        type="text"
                        placeholder="Search Title, City, or State... (Press Enter)"
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        onKeyDown={handleKeyDown}
                        className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all placeholder-gray-400"
                    />
                </div>

                <div className="h-8 w-px bg-gray-200 hidden xl:block"></div>

                {/* Status Filter */}
                <div className="w-full xl:w-48 relative">
                    <select
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                        className="w-full py-2.5 px-4 bg-gray-50/50 border-none rounded-xl text-sm text-gray-700 focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all font-medium cursor-pointer appearance-none"
                    >
                        <option value="all">All Status</option>
                        <option value="listed">Listed Verified</option>
                        <option value="rejected">Rejected / Pending</option>
                    </select>
                </div>

                <div className="h-8 w-px bg-gray-200 hidden xl:block"></div>

                {/* Actions */}
                <div className="flex w-full xl:w-auto items-center gap-2">
                    <button 
                        onClick={fetchProperties} 
                        className="flex-1 xl:flex-none px-5 py-2.5 bg-indigo-600 text-white font-semibold rounded-xl text-sm hover:bg-indigo-700 hover:shadow shadow-sm transition-all"
                    >
                        Search
                    </button>
                    <button 
                        onClick={clearFilters} 
                        className="p-2.5 bg-white border border-gray-200 text-gray-600 hover:text-gray-900 hover:bg-gray-50 rounded-xl transition-all shadow-sm flex items-center justify-center"
                        title="Reset Filters"
                    >
                        <RefreshCw className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* --- GRID --- */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {!loading && properties.length === 0 && (
                     <div className="col-span-full py-24 flex flex-col items-center justify-center text-gray-500">
                     <HomeIcon className="w-12 h-12 text-gray-300 mb-3" />
                     <p className="text-lg font-medium text-gray-600">No properties found</p>
                     <p className="text-sm mt-1">Adjust your search or filter criteria.</p>
                 </div>
                )}

                {!loading && properties.map((item) => {
                    const imgUrl = resolveImage(item.images?.[0]);
                    return (
                    <div key={item._id} className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden relative group hover:shadow-md transition-shadow flex flex-col">
                        {/* Status Badge */}
                        <div className="absolute top-4 right-4 z-10">
                             <span className={`inline-flex items-center px-2.5 py-1 rounded-md text-xs font-bold shadow-sm uppercase tracking-wider ${item.isApproved ? "bg-emerald-500 text-white" : "bg-white text-gray-600 shadow-xl border border-gray-200"}`}>
                                 {item.isApproved ? "LISTED" : "REJECTED"}
                             </span>
                        </div>

                        {/* Image */}
                        <div className="w-full aspect-[4/3] relative bg-gray-100 overflow-hidden">
                            {imgUrl ? (
                                <img src={imgUrl} className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500" alt={item.title} />
                            ) : (
                                <div className="w-full h-full flex items-center justify-center">
                                    <ImageIcon className="w-10 h-10 text-gray-300" />
                                </div>
                            )}
                            <div className="absolute inset-0 bg-gradient-to-t from-gray-900/60 to-transparent pointer-events-none" />
                        </div>

                        <div className="p-5 flex-1 flex flex-col">
                            {/* Meta info */}
                             <div className="flex justify-between text-xs text-gray-500 font-medium mb-2">
                                <span className="flex items-center gap-1.5"><MapPin className="w-3 h-3 text-indigo-500" /> {item.address?.city || item.city || "N/A"}</span>
                                <span className="flex items-center gap-1.5"><Calendar className="w-3 h-3 text-gray-400" /> {new Date(item.createdAt).toLocaleDateString()}</span>
                            </div>

                            {/* Title */}
                            <h3 className="text-lg font-bold text-gray-900 leading-tight mb-2 line-clamp-2" title={item.title}>{item.title}</h3>

                             {/* Price & owner (optional extra info if present) */}
                             <div className="flex-1">
                                {!item.isApproved && item.rejectionReason && (
                                    <div className="bg-rose-50 border border-rose-100 p-3 rounded-xl text-xs text-rose-700 mt-3 font-medium">
                                        <div className="flex items-start gap-2">
                                            <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5 text-rose-500" />
                                            <p><span className="font-bold">Rejected:</span> {item.rejectionReason}</p>
                                        </div>
                                    </div>
                                )}
                             </div>

                             {/* Actions */}
                            <div className="pt-4 mt-4 border-t border-gray-100 flex items-center gap-3">
                                {item.isApproved ? (
                                    <button 
                                        onClick={() => openRejectModal(item._id)} 
                                        className="flex-1 bg-white border border-gray-200 text-gray-700 hover:text-rose-600 hover:border-rose-300 hover:bg-rose-50 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-sm flex justify-center items-center gap-2"
                                    >
                                        <XCircle className="w-4 h-4" /> Reject Listing
                                    </button>
                                ) : (
                                    <button 
                                        onClick={() => handleApprove(item._id)} 
                                        className="flex-1 bg-emerald-50 border border-emerald-200 text-emerald-700 hover:bg-emerald-100 py-2.5 rounded-xl text-sm font-semibold transition-all shadow-sm flex justify-center items-center gap-2"
                                    >
                                        <CheckCircle className="w-4 h-4" /> Approve Listing
                                    </button>
                                )}
                                <button 
                                    onClick={() => handleDelete(item._id)} 
                                    className="p-2.5 bg-white border border-transparent text-gray-400 hover:text-rose-600 hover:bg-rose-50 rounded-xl transition-colors shadow-sm"
                                    title="Delete Property Completely"
                                >
                                    <Trash className="w-5 h-5" />
                                </button>
                            </div>
                        </div>
                    </div>
                )})}
            </div>

            {/* Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/60 backdrop-blur-sm p-4">
                     <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 overflow-hidden transform transition-all">
                        <div className="px-6 py-5 border-b border-gray-100 flex justify-between items-center bg-white">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-rose-100 text-rose-600 rounded-full">
                                    <XCircle className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="text-lg font-bold text-gray-900">Reject Property</h3>
                                </div>
                            </div>
                        </div>
                        <div className="p-6 bg-gray-50/50">
                            <label className="block text-sm font-semibold text-gray-700 mb-2">
                                Please provide a reason for rejection: <span className="text-rose-500">*</span>
                            </label>
                            <textarea 
                                className="w-full p-4 border border-gray-200 rounded-xl focus:ring-4 focus:ring-rose-500/10 focus:border-rose-500 text-sm outline-none transition-all shadow-sm resize-none" 
                                placeholder="E.g., Incomplete information, fake listing..." 
                                value={rejectionReason} 
                                onChange={(e) => setRejectionReason(e.target.value)} 
                                rows={4}
                            />
                        </div>
                        <div className="px-6 py-5 border-t border-gray-100 flex justify-end gap-3 bg-white">
                            <button 
                                onClick={() => setIsModalOpen(false)} 
                                className="px-5 py-2.5 bg-white border border-gray-200 text-gray-700 font-semibold rounded-xl text-sm hover:bg-gray-50 transition-colors shadow-sm"
                            >
                                Cancel
                            </button>
                            <button 
                                onClick={submitRejection} 
                                className="px-5 py-2.5 bg-rose-600 text-white font-semibold rounded-xl text-sm hover:bg-rose-700 transition-all shadow-sm flex items-center gap-2"
                            >
                                Reject Property
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AllProperty;