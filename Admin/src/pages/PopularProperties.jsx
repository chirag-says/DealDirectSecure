import React, { useEffect, useState } from "react";
import {
    MapPin,
    Search,
    Filter,
    Calendar,
    RefreshCw,
    Star,
    Home as HomeIcon,
    Eye
} from "lucide-react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";

const API_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:9000";

const PopularProperties = () => {
    const [properties, setProperties] = useState([]);
    const [loading, setLoading] = useState(true);

    // --- Filter States ---
    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("all"); // 'popular', 'not-popular', 'all'

    // Auth handled by adminApi via cookies

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

    // --- Fetch Properties ---
    const fetchProperties = async () => {
        setLoading(true);
        try {
            const params = {
                search: searchTerm,
            };

            // Using adminApi - cookies sent automatically
            const res = await adminApi.get(`/api/properties/admin/all`, {
                params: params
            });

            let list = extractList(res.data);

            // Only show Approved properties for popular selection, usually
            list = list.filter(p => p.isApproved);

            // Filter by status if needed
            if (statusFilter === 'popular') {
                list = list.filter(p => p.isPopular);
            } else if (statusFilter === 'not-popular') {
                list = list.filter(p => !p.isPopular);
            }

            setProperties(list);
        } catch (err) {
            console.error(err);
            toast.error("Failed to fetch properties");
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchProperties();
    }, [statusFilter]);

    // Handle Enter Key in Search Input
    const handleKeyDown = (e) => {
        if (e.key === 'Enter') {
            fetchProperties();
        }
    };

    const togglePopular = async (property) => {
        try {
            const newStatus = !property.isPopular;
            // Using adminApi - cookies sent automatically
            await adminApi.put(`/api/properties/popular/${property._id}`,
                { isPopular: newStatus }
            );

            toast.success(newStatus ? "Added to Popular Properties" : "Removed from Popular Properties");

            // Update local state
            setProperties(prev => prev.map(p =>
                p._id === property._id ? { ...p, isPopular: newStatus } : p
            ));
        } catch (err) {
            console.error(err);
            toast.error("Failed to update status");
        }
    };

    return (
        <div className="p-4 bg-gray-50 min-h-screen relative">
            <div className="flex flex-col mb-6 gap-4">
                <h2 className="text-3xl font-extrabold text-gray-900 flex items-center gap-2">
                    <Star className="w-8 h-8 text-yellow-500 fill-yellow-500" /> Popular Properties Manager
                </h2>
                <p className="text-gray-500 text-sm">Select properties to display in the "Popular Properties" section of the home page.</p>

                {/* --- SEARCH BAR --- */}
                <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200 grid grid-cols-1 md:grid-cols-12 gap-4 items-end">

                    {/* Search Input */}
                    <div className="md:col-span-6">
                        <label className="block text-xs font-bold text-gray-500 mb-1">SEARCH</label>
                        <div className="relative">
                            <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                            <input
                                type="text"
                                placeholder="Search Title, City..."
                                value={searchTerm}
                                onChange={(e) => setSearchTerm(e.target.value)}
                                onKeyDown={handleKeyDown}
                                className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm"
                            />
                        </div>
                    </div>

                    {/* Status Filter */}
                    <div className="md:col-span-3">
                        <label className="block text-xs font-bold text-gray-500 mb-1">FILTER</label>
                        <div className="relative">
                            <Filter className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                            <select
                                value={statusFilter}
                                onChange={(e) => setStatusFilter(e.target.value)}
                                className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm bg-white"
                            >
                                <option value="all">All Properties</option>
                                <option value="popular">Popular Only</option>
                                <option value="not-popular">Not Popular</option>
                            </select>
                        </div>
                    </div>

                    {/* Buttons */}
                    <div className="md:col-span-3 flex gap-2">
                        <button onClick={fetchProperties} className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2 rounded-lg font-semibold text-sm transition">
                            Search
                        </button>
                    </div>
                </div>
            </div>

            {/* --- GRID --- */}
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
                {loading && <div className="col-span-full text-center py-10">Loading...</div>}
                {!loading && properties.length === 0 && <div className="col-span-full text-center py-20 text-gray-500">No properties found.</div>}

                {!loading && properties.map((item) => (
                    <div key={item._id} className={`bg-white rounded-xl shadow border transition-all duration-200 ${item.isPopular ? 'border-yellow-400 ring-2 ring-yellow-100 shadow-md transform scale-[1.01]' : 'border-gray-200'}`}>
                        <div className="relative">
                            <div className={`absolute top-3 right-3 px-3 py-1 text-xs font-bold text-white rounded-full ${item.isPopular ? "bg-yellow-500" : "bg-gray-400"} z-10 shadow-sm flex items-center gap-1`}>
                                <Star className={`w-3 h-3 ${item.isPopular ? 'fill-white' : ''}`} />
                                {item.isPopular ? "POPULAR" : "STANDARD"}
                            </div>
                            <img src={resolveImage(item.images?.[0])} className="w-full h-48 object-cover rounded-t-xl" alt={item.title} />
                        </div>

                        <div className="p-4 space-y-3">
                            <h3 className="text-lg font-bold text-gray-900 truncate">{item.title}</h3>
                            <div className="flex justify-between text-sm text-gray-600">
                                <span className="flex items-center gap-1"><MapPin className="w-3 h-3" /> {item.address?.city || item.city}</span>
                                <span className="flex items-center gap-1"><Calendar className="w-3 h-3" /> {new Date(item.createdAt).toLocaleDateString()}</span>
                            </div>

                            <button
                                onClick={() => togglePopular(item)}
                                className={`w-full py-2.5 rounded-lg text-sm font-bold flex justify-center items-center gap-2 transition-colors ${item.isPopular
                                    ? "bg-red-50 text-red-600 hover:bg-red-100"
                                    : "bg-yellow-50 text-yellow-700 hover:bg-yellow-100"
                                    }`}
                            >
                                <Star className={`w-4 h-4 ${item.isPopular ? 'fill-red-600' : ''}`} />
                                {item.isPopular ? "Remove from Popular" : "Mark as Popular"}
                            </button>

                            <a
                                href={`http://localhost:5173/properties/${item._id}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="w-full py-2.5 rounded-lg text-sm font-bold flex justify-center items-center gap-2 bg-blue-50 text-blue-600 hover:bg-blue-100 transition-colors"
                            >
                                <Eye className="w-4 h-4" /> View Details
                            </a>
                        </div>
                    </div>
                ))}
            </div>
        </div>
    );
};

export default PopularProperties;