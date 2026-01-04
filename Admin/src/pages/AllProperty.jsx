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
    AlertTriangle
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
        if (!img) return "https://images.unsplash.com/photo-1560518883-cf3726f1454c?fit=crop&w=600&q=80";
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



            // Using adminApi - cookies are sent automatically
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
        if (!window.confirm("Permanently delete?")) return;
        try {
            await adminApi.delete(`/api/properties/delete/${id}`);
            toast.success("Deleted");
            setProperties(prev => prev.filter(p => p._id !== id));
        } catch (err) {
            toast.error("Deletion failed");
        }
    };

    const handleApprove = async (id) => {
        try {
            await adminApi.put(`/api/properties/approve/${id}`, {});
            toast.success("Property Listed");
            fetchProperties();
        } catch (err) { toast.error("Failed"); }
    };

    const openRejectModal = (id) => {
        setSelectedPropertyId(id);
        setRejectionReason("");
        setIsModalOpen(true);
    };

    const submitRejection = async () => {
        if (!rejectionReason.trim()) return toast.error("Reason required");
        try {
            await adminApi.put(`/api/properties/disapprove/${selectedPropertyId}`,
                { rejectionReason }
            );
            toast.success("Rejected");
            setIsModalOpen(false);
            fetchProperties();
        } catch (err) { toast.error("Failed"); }
    };

    return (
        <div className="p-2 sm:p-4 bg-gray-50 min-h-screen relative">
            <div className="flex flex-col mb-6 gap-4">
                <h2 className="text-3xl font-extrabold text-gray-900 flex items-center gap-2">
                    <HomeIcon className="w-8 h-8 text-indigo-600" /> Admin Property Manager
                </h2>

                {/* --- SEARCH BAR --- */}
                <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200 grid grid-cols-1 md:grid-cols-12 gap-4 items-end">

                    {/* Search Input */}
                    <div className="md:col-span-4">
                        <label className="block text-xs font-bold text-gray-500 mb-1">SEARCH</label>
                        <div className="relative">
                            <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                            <input
                                type="text"
                                placeholder="Search Title, City, or State..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                onKeyDown={handleKeyDown} // ✅ Press Enter to Search
                                className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm"
                            />
                        </div>
                    </div>

                    {/* Status Filter */}
                    <div className="md:col-span-2">
                        <label className="block text-xs font-bold text-gray-500 mb-1">STATUS</label>
                        <div className="relative">
                            <Filter className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                            <select
                                value={statusFilter}
                                onChange={(e) => setStatusFilter(e.target.value)}
                                className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm bg-white"
                            >
                                <option value="all">All Properties</option>
                                <option value="listed">Listed</option>
                                <option value="rejected">Rejected</option>
                            </select>
                        </div>
                    </div>

                    {/* Dates */}
                    <div className="md:col-span-2">
                        <label className="block text-xs font-bold text-gray-500 mb-1">FROM</label>
                        <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} className="w-full px-3 py-2 border rounded-lg text-sm text-gray-600" />
                    </div>
                    <div className="md:col-span-2">
                        <label className="block text-xs font-bold text-gray-500 mb-1">TO</label>
                        <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} className="w-full px-3 py-2 border rounded-lg text-sm text-gray-600" />
                    </div>

                    {/* Buttons */}
                    <div className="md:col-span-2 flex gap-2">
                        <button onClick={fetchProperties} className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2 rounded-lg font-semibold text-sm transition">
                            Search
                        </button>
                        <button onClick={clearFilters} className="px-3 bg-gray-100 hover:bg-gray-200 text-gray-600 rounded-lg transition">
                            <RefreshCw className="w-4 h-4" />
                        </button>
                    </div>
                </div>
            </div>

            {/* --- GRID --- */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                {loading && <div className="col-span-full text-center py-10">Loading...</div>}
                {!loading && properties.length === 0 && <div className="col-span-full text-center py-20 text-gray-500 bg-white rounded-xl border border-dashed">No properties match your filters.</div>}

                {!loading && properties.map((item) => (
                    <div key={item._id} className="bg-white rounded-xl shadow-lg border border-gray-200 overflow-hidden relative group">
                        <div className={`absolute top-3 right-3 px-3 py-1 text-xs font-bold text-white rounded-full ${item.isApproved ? "bg-green-600" : "bg-red-500"} z-10 shadow-sm`}>
                            {item.isApproved ? "LISTED" : "REJECTED"}
                        </div>
                        <img src={resolveImage(item.images?.[0])} className="w-full h-48 object-cover" alt={item.title} />
                        <div className="p-5 space-y-3">
                            <h3 className="text-lg font-bold text-gray-900 truncate">{item.title}</h3>
                            <div className="flex justify-between text-sm text-gray-600">
                                <span className="flex items-center gap-1"><MapPin className="w-3 h-3" /> {item.address?.city || item.city}</span>
                                <span className="flex items-center gap-1"><Calendar className="w-3 h-3" /> {new Date(item.createdAt).toLocaleDateString()}</span>
                            </div>

                            {!item.isApproved && item.rejectionReason && (
                                <div className="bg-red-50 border border-red-100 p-3 rounded-lg text-xs text-red-700 mt-2">
                                    <span className="font-bold block mb-1">Reason:</span> {item.rejectionReason}
                                </div>
                            )}

                            <div className="pt-3 border-t flex gap-2 mt-2">
                                {item.isApproved ? (
                                    <button onClick={() => openRejectModal(item._id)} className="flex-1 bg-yellow-50 text-yellow-700 hover:bg-yellow-100 py-2 rounded-lg text-xs font-bold flex justify-center items-center gap-2">
                                        <XCircle className="w-4 h-4" /> REJECT
                                    </button>
                                ) : (
                                    <button onClick={() => handleApprove(item._id)} className="flex-1 bg-green-50 text-green-700 hover:bg-green-100 py-2 rounded-lg text-xs font-bold flex justify-center items-center gap-2">
                                        <CheckCircle className="w-4 h-4" /> LIST
                                    </button>
                                )}
                                <button onClick={() => handleDelete(item._id)} className="px-3 bg-red-50 text-red-600 hover:bg-red-100 rounded-lg">
                                    <Trash className="w-4 h-4" />
                                </button>
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Modal */}
            {isModalOpen && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50 p-4">
                    <div className="bg-white rounded-2xl shadow-xl w-full max-w-md overflow-hidden">
                        <div className="bg-red-50 px-6 py-4 flex justify-between items-center border-b border-red-100">
                            <h3 className="text-lg font-bold text-red-800">Reject Property</h3>
                            <button onClick={() => setIsModalOpen(false)}><X className="w-6 h-6 text-gray-500" /></button>
                        </div>
                        <div className="p-6">
                            <textarea className="w-full border border-gray-300 rounded-lg p-3 h-32" placeholder="Reason..." value={rejectionReason} onChange={(e) => setRejectionReason(e.target.value)} />
                        </div>
                        <div className="bg-gray-50 px-6 py-4 flex justify-end gap-3">
                            <button onClick={() => setIsModalOpen(false)} className="px-4 py-2 bg-white border border-gray-300 rounded-lg text-sm">Cancel</button>
                            <button onClick={submitRejection} className="px-4 py-2 bg-red-600 text-white rounded-lg text-sm font-bold">Confirm</button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
};

export default AllProperty;