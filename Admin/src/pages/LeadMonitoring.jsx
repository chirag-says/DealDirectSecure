import React, { useState, useEffect, useRef } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
    Mail,
    PhoneCall,
    MessageSquare,
    Filter,
    User,
    X,
    Sparkles,
    Loader2,
    RefreshCw,
    ChevronDown,
    Search,
    Calendar,
    RotateCcw,
} from "lucide-react";

const API_URL = import.meta.env.VITE_API_BASE_URL;

// Helper function to safely format date
const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
        return new Date(dateString).toLocaleDateString("en-GB", {
            day: "numeric",
            month: "short",
            year: "numeric",
        });
    } catch {
        return "Invalid Date";
    }
};

export default function LeadMonitoring() {
    const [selectedLead, setSelectedLead] = useState(null);
    const [expandedLead, setExpandedLead] = useState(null);
    const [leads, setLeads] = useState([]);
    const [loading, setLoading] = useState(true);

    // Stats
    const [stats, setStats] = useState({
        total: 0,
        new: 0,
        contacted: 0,
        interested: 0,
        negotiating: 0,
        converted: 0,
        lost: 0,
    });

    // Filters State
    const [statusFilter, setStatusFilter] = useState("all");
    const [search, setSearch] = useState("");
    const [startDate, setStartDate] = useState("");
    const [endDate, setEndDate] = useState("");

    const [showFilter, setShowFilter] = useState(false);
    const [updatingStatus, setUpdatingStatus] = useState(null);

    // Auth handled by adminApi via cookies

    // Ref for the status filter dropdown for outside click dismissal (best practice)
    const filterRef = useRef(null);

    // Fetch leads from backend
    const fetchLeads = async () => {
        try {
            setLoading(true);
            // Using adminApi - cookies sent automatically
            const { data } = await adminApi.get(`/api/admin/leads`, {
                params: {
                    status: statusFilter,
                    search: search,
                    startDate: startDate,
                    endDate: endDate
                },
            });

            if (data.success) {
                setLeads(data.data || []);
                // Update stats, providing defaults if API response is missing some keys
                setStats({
                    total: data.stats?.total || 0,
                    new: data.stats?.new || 0,
                    contacted: data.stats?.contacted || 0,
                    interested: data.stats?.interested || 0,
                    negotiating: data.stats?.negotiating || 0,
                    converted: data.stats?.converted || 0,
                    lost: data.stats?.lost || 0,
                });
            }
        } catch (error) {
            console.error("Failed to fetch leads:", error);
            // 401 errors are handled by adminApi interceptor
            if (error.response?.status !== 401) {
                toast.error("Failed to fetch leads");
            }
        } finally {
            setLoading(false);
        }
    };

    // Fetch when filters change (debounced)
    useEffect(() => {
        const timer = setTimeout(() => {
            fetchLeads();
        }, 500);
        return () => clearTimeout(timer);
    }, [statusFilter, startDate, endDate, search]);

    // Handle outside click for Status Filter Dropdown
    useEffect(() => {
        function handleClickOutside(event) {
            if (filterRef.current && !filterRef.current.contains(event.target)) {
                setShowFilter(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => document.removeEventListener("mousedown", handleClickOutside);
    }, [filterRef]);


    // Update lead status
    const updateLeadStatus = async (leadId, newStatus) => {
        try {
            setUpdatingStatus(leadId);
            const { data } = await adminApi.put(
                `/api/admin/leads/${leadId}`,
                { status: newStatus }
            );

            if (data.success) {
                toast.success("Lead status updated");
                fetchLeads(); // Refresh leads
            }
        } catch (error) {
            toast.error("Failed to update status");
        } finally {
            setUpdatingStatus(null);
        }
    };

    // Reset Filters Function
    const handleResetFilters = () => {
        setSearch("");
        setStatusFilter("all");
        setStartDate("");
        setEndDate("");
    };

    // ✅ NEW: Handler for stat box clicks
    const handleStatFilter = (status) => {
        // Clear search and date filters to ensure the stat filter is dominant
        setSearch("");
        setStartDate("");
        setEndDate("");
        // Apply the status filter
        setStatusFilter(status);
        // The useEffect hook handles the fetch call with the new filter
    };

    const statusColors = {
        new: "bg-blue-100 text-blue-700 border-blue-300",
        contacted: "bg-green-100 text-green-700 border-green-300",
        interested: "bg-purple-100 text-purple-700 border-purple-300",
        negotiating: "bg-orange-100 text-orange-700 border-orange-300",
        converted: "bg-emerald-100 text-emerald-700 border-emerald-300",
        lost: "bg-red-100 text-red-700 border-red-300",
    };

    const statusOptions = [
        { value: "all", label: "All Leads" },
        { value: "new", label: "New" },
        { value: "contacted", label: "Contacted" },
        { value: "interested", label: "Interested" },
        { value: "negotiating", label: "Negotiating" },
        { value: "converted", label: "Converted" },
        { value: "lost", label: "Lost" },
    ];

    return (
        <div className=" sm:p-4 min-h-screen">

            {/* --- Page Header & Filters --- */}
            <div className="flex flex-col xl:flex-row justify-between items-start xl:items-center mb-8 gap-6">

                {/* Title */}
                <h1 className="text-3xl sm:text-3xl font-black text-gray-900 flex items-center gap-3 tracking-tight">
                    <Sparkles className="text-purple-600 drop-shadow" />
                    Lead Monitoring
                </h1>

                {/* Controls Toolbar */}
                <div className="w-full xl:w-auto flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3">

                    {/* 1. Stats BUTTONS (Visible on all screens now) */}
                    {/* ✅ MODIFIED: Added onClick handlers and changed div to button-like structure */}
                    <div className="flex items-center gap-2 mr-2">
                        <button
                            onClick={() => handleStatFilter('new')}
                            className={`px-4 py-2 rounded-xl text-sm font-bold shadow-md transition-all hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-blue-500/50 ${statusFilter === 'new' ? 'bg-blue-300 text-blue-800' : 'bg-blue-100 text-blue-700'}`}
                        >
                            New: {stats.new}
                        </button>
                        <button
                            onClick={() => handleStatFilter('converted')}
                            className={`px-4 py-2 rounded-xl text-sm font-bold shadow-md transition-all hover:shadow-lg focus:outline-none focus:ring-2 focus:ring-emerald-500/50 ${statusFilter === 'converted' ? 'bg-emerald-300 text-emerald-800' : 'bg-emerald-100 text-emerald-700'}`}
                        >
                            Conv: {stats.converted}
                        </button>
                    </div>

                    {/* 2. Search Input */}
                    <div className="relative flex-grow sm:flex-grow-0">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
                        <input
                            type="text"
                            placeholder="Search..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            className="w-full sm:w-40 pl-9 pr-4 py-3 bg-white/80 backdrop-blur-xl rounded-2xl shadow border-none outline-none focus:ring-2 focus:ring-purple-500/50 text-sm transition-all"
                        />
                    </div>

                    {/* 3. Date Range Filter */}
                    <div className="flex items-center gap-1 bg-white/80 backdrop-blur-xl p-1 rounded-2xl shadow">
                        <div className="relative">
                            <input
                                type="date"
                                value={startDate}
                                onChange={(e) => setStartDate(e.target.value)}
                                className="pl-3 pr-1 py-2 bg-transparent border-none text-xs sm:text-sm text-gray-600 focus:ring-0 outline-none w-28 sm:w-32 cursor-pointer"
                            />
                        </div>
                        <span className="text-gray-300">-</span>
                        <div className="relative">
                            <input
                                type="date"
                                value={endDate}
                                onChange={(e) => setEndDate(e.target.value)}
                                className="pl-1 pr-3 py-2 bg-transparent border-none text-xs sm:text-sm text-gray-600 focus:ring-0 outline-none w-28 sm:w-32 cursor-pointer"
                            />
                        </div>
                    </div>

                    {/* 4. Reset Button (Only visible if filters active) */}
                    {(search || startDate || endDate || statusFilter !== 'all') && (
                        <button
                            onClick={handleResetFilters}
                            className="p-3 bg-red-50 text-red-500 rounded-xl hover:bg-red-100 transition-all shadow"
                            title="Reset Filters"
                        >
                            <RotateCcw size={20} />
                        </button>
                    )}

                    {/* 5. Refresh Button */}
                    <button
                        onClick={fetchLeads}
                        className="p-3 bg-purple-50 text-purple-500 rounded-xl hover:bg-purple-100 transition-all shadow"
                        title="Refresh Leads"
                        disabled={loading}
                    >
                        <RefreshCw size={20} className={loading ? 'animate-spin' : ''} />
                    </button>

                    {/* 6. Status Filter Dropdown */}
                    <div className="relative" ref={filterRef}>
                        <button
                            onClick={() => setShowFilter(!showFilter)}
                            className="w-full sm:w-auto flex items-center justify-center gap-2 px-5 py-3 bg-white/80 backdrop-blur-xl rounded-2xl shadow hover:shadow-xl transition-all"
                        >
                            <Filter className="text-gray-700" size={20} />
                            <span className="font-medium text-gray-800 whitespace-nowrap">
                                {statusOptions.find((s) => s.value === statusFilter)?.label}
                            </span>
                            <ChevronDown size={16} />
                        </button>

                        {showFilter && (
                            <div className="absolute right-0 mt-2 w-full sm:w-48 bg-white rounded-xl shadow-xl border border-gray-100 py-2 z-50">
                                {statusOptions.map((option) => (
                                    <button
                                        key={option.value}
                                        onClick={() => {
                                            setStatusFilter(option.value);
                                            setShowFilter(false);
                                        }}
                                        className={`w-full px-4 py-2 text-left hover:bg-gray-50 ${statusFilter === option.value
                                                ? "bg-purple-50 text-purple-700 font-medium"
                                                : "text-gray-700"
                                            }`}
                                    >
                                        {option.label}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>

                </div>
            </div>

            {/* Card */}
            <div className="bg-white/70 backdrop-blur-xl rounded shadow-2xl overflow-hidden border border-white/40 min-h-[600px] flex flex-col">
                {loading ? (
                    <div className="flex-1 flex justify-center items-center py-20">
                        <Loader2 className="w-10 h-10 animate-spin text-purple-600" />
                    </div>
                ) : leads.length === 0 ? (
                    <div className="flex-1 flex flex-col justify-center items-center py-20 text-gray-500">
                        <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                        <p className="text-xl font-medium">No leads found</p>
                        <p className="text-sm mt-2">Try adjusting your date or status filters</p>
                        <button
                            onClick={handleResetFilters}
                            className="mt-4 text-purple-600 hover:underline text-sm"
                        >
                            Clear all filters
                        </button>
                    </div>
                ) : (
                    <div className="overflow-x-auto flex-1">
                        <table className="w-full">
                            <thead className="bg-gradient-to-r from-purple-200 via-blue-200 to-pink-200">
                                <tr className="text-gray-800">
                                    <th className="py-4 px-6 text-left font-semibold whitespace-nowrap">Buyer</th>
                                    <th className="py-4 px-6 text-left font-semibold hidden md:table-cell whitespace-nowrap">Property</th>
                                    <th className="py-4 px-6 text-left font-semibold hidden md:table-cell whitespace-nowrap">Owner</th>
                                    <th className="py-4 px-6 text-left font-semibold hidden md:table-cell whitespace-nowrap">Date</th>
                                    <th className="py-4 px-6 text-left font-semibold hidden md:table-cell whitespace-nowrap">Status</th>
                                    <th className="py-4 px-6 text-center font-semibold hidden md:table-cell whitespace-nowrap">Actions</th>
                                </tr>
                            </thead>

                            <tbody>
                                {leads.map((lead) => (
                                    <tr
                                        key={lead._id}
                                        className="hover:bg-gradient-to-r hover:from-purple-50 hover:to-blue-50 transition-all border-b last:border-none"
                                    >
                                        {/* Buyer */}
                                        <td className="py-4 px-6 bg-transparent block md:table-cell w-full md:w-auto">
                                            <div className="flex flex-col gap-2">
                                                {/* Main Row Content */}
                                                <div className="flex items-center justify-between w-full">
                                                    <div className="flex items-center gap-3 overflow-hidden">
                                                        <div className="w-11 h-11 rounded-full bg-gradient-to-br from-purple-300 to-blue-300 flex items-center justify-center shadow-inner overflow-hidden flex-shrink-0">
                                                            {lead.user?.profileImage ? (
                                                                <img
                                                                    src={lead.user.profileImage}
                                                                    alt={lead.user?.name}
                                                                    className="w-full h-full object-cover"
                                                                />
                                                            ) : (
                                                                <User size={19} className="text-gray-800" />
                                                            )}
                                                        </div>
                                                        <div className="flex flex-col overflow-hidden">
                                                            <p className="font-medium text-gray-900 truncate max-w-[140px] sm:max-w-none">
                                                                {lead.user?.name || lead.userSnapshot?.name || "Unknown"}
                                                            </p>
                                                            <p className="text-sm text-gray-500 whitespace-nowrap hidden md:block">
                                                                {lead.user?.email || lead.userSnapshot?.email || ""}
                                                            </p>
                                                        </div>
                                                        {lead.status === "new" && (
                                                            <span className="ml-2 text-xs bg-red-600 text-white px-2 py-0.5 rounded-full animate-pulse flex-shrink-0">
                                                                NEW
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Mobile Toggle Button */}
                                                    <button
                                                        onClick={() => setExpandedLead(expandedLead === lead._id ? null : lead._id)}
                                                        className="md:hidden p-2 text-gray-400 hover:text-purple-600 transition-colors"
                                                    >
                                                        <ChevronDown
                                                            size={20}
                                                            className={`transition-transform duration-200 ${expandedLead === lead._id ? "rotate-180" : ""}`}
                                                        />
                                                    </button>
                                                </div>

                                                {/* Mobile Expanded Details */}
                                                {expandedLead === lead._id && (
                                                    <div className="md:hidden bg-indigo-50/50 rounded-lg p-3 text-sm space-y-3 mt-2 border border-indigo-100 animate-in fade-in slide-in-from-top-1">
                                                        <div className="grid grid-cols-[auto,1fr] gap-2">
                                                            <span className="text-gray-500 font-medium">Email:</span>
                                                            <span className="text-gray-800 break-all">{lead.user?.email || "N/A"}</span>

                                                            <span className="text-gray-500 font-medium">Property:</span>
                                                            <span className="text-gray-800">{lead.property?.title || "N/A"}</span>

                                                            <span className="text-gray-500 font-medium">Location:</span>
                                                            <span className="text-gray-800">{lead.property?.address?.city || "N/A"}</span>

                                                            <span className="text-gray-500 font-medium">Owner:</span>
                                                            <span className="text-gray-800">
                                                                {lead.propertyOwner?.name || "N/A"}
                                                                {lead.propertyOwner?.phone ? ` (${lead.propertyOwner.phone})` : ""}
                                                            </span>

                                                            <span className="text-gray-500 font-medium">Date:</span>
                                                            <span className="text-gray-800">{formatDate(lead.createdAt)}</span>
                                                        </div>

                                                        {/* Mobile Actions & Status */}
                                                        <div className="flex flex-col gap-2 pt-2 border-t border-indigo-200">
                                                            <div className="flex items-center justify-between">
                                                                <span className="text-gray-500 font-medium">Status:</span>
                                                                <select
                                                                    value={lead.status}
                                                                    onChange={(e) => updateLeadStatus(lead._id, e.target.value)}
                                                                    disabled={updatingStatus === lead._id}
                                                                    className={`px-2 py-1 border rounded-lg text-xs font-medium cursor-pointer focus:outline-none focus:ring-2 focus:ring-purple-500 ${statusColors[lead.status] || "bg-gray-100"}`}
                                                                >
                                                                    <option value="new">New</option>
                                                                    <option value="contacted">Contacted</option>
                                                                    <option value="interested">Interested</option>
                                                                    <option value="negotiating">Negotiating</option>
                                                                    <option value="converted">Converted</option>
                                                                    <option value="lost">Lost</option>
                                                                </select>
                                                            </div>
                                                            <div className="flex justify-end gap-3 mt-1">
                                                                <button onClick={() => setSelectedLead(lead)} className="text-blue-600 p-1" title="View Details">
                                                                    <MessageSquare size={20} />
                                                                </button>
                                                                {lead.user?.phone && (
                                                                    <a href={`tel:${lead.user.phone}`} className="text-green-600 p-1" title="Call Buyer">
                                                                        <PhoneCall size={20} />
                                                                    </a>
                                                                )}
                                                                {lead.user?.email && (
                                                                    <a href={`mailto:${lead.user.email}`} className="text-gray-700 p-1" title="Email Buyer">
                                                                        <Mail size={20} />
                                                                    </a>
                                                                )}
                                                            </div>
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        </td>

                                        {/* Property */}
                                        <td className="py-4 px-6 hidden md:table-cell whitespace-nowrap">
                                            <div>
                                                <p className="text-gray-900 font-medium whitespace-nowrap">
                                                    {lead.property?.title || lead.propertySnapshot?.title || "N/A"}
                                                </p>
                                                <p className="text-sm text-gray-500 whitespace-nowrap">
                                                    {lead.property?.address?.city || lead.propertySnapshot?.city || ""}
                                                </p>
                                            </div>
                                        </td>

                                        {/* Owner */}
                                        <td className="py-4 px-6 hidden md:table-cell whitespace-nowrap">
                                            <div>
                                                <p className="text-gray-900">
                                                    {lead.propertyOwner?.name || "N/A"}
                                                </p>
                                                <p className="text-sm text-gray-500">
                                                    {lead.propertyOwner?.phone || ""}
                                                </p>
                                            </div>
                                        </td>

                                        {/* Date */}
                                        <td className="py-4 px-6 text-gray-700 hidden md:table-cell whitespace-nowrap">
                                            {formatDate(lead.createdAt)}
                                        </td>

                                        {/* Status */}
                                        <td className="py-4 px-6 whitespace-nowrap hidden md:table-cell">
                                            <select
                                                value={lead.status}
                                                onChange={(e) => updateLeadStatus(lead._id, e.target.value)}
                                                disabled={updatingStatus === lead._id}
                                                className={`px-2 py-1 border rounded-lg text-xs md:text-sm font-medium cursor-pointer focus:outline-none focus:ring-2 focus:ring-purple-500 ${statusColors[lead.status] || "bg-gray-100"
                                                    }`}
                                            >
                                                <option value="new">New</option>
                                                <option value="contacted">Contacted</option>
                                                <option value="interested">Interested</option>
                                                <option value="negotiating">Negotiating</option>
                                                <option value="converted">Converted</option>
                                                <option value="lost">Lost</option>
                                            </select>
                                        </td>

                                        {/* Actions */}
                                        <td className="py-4 px-6 text-center whitespace-nowrap hidden md:table-cell">
                                            <div className="flex justify-center gap-3 md:gap-5">
                                                <button
                                                    onClick={() => setSelectedLead(lead)}
                                                    className="text-blue-600 hover:scale-125 transition-transform"
                                                    title="View Details"
                                                >
                                                    <MessageSquare size={20} />
                                                </button>

                                                {lead.user?.phone && (
                                                    <a
                                                        href={`tel:${lead.user.phone}`}
                                                        className="text-green-600 hover:scale-125 transition-transform"
                                                        title="Call Buyer"
                                                    >
                                                        <PhoneCall size={20} />
                                                    </a>
                                                )}

                                                {lead.user?.email && (
                                                    <a
                                                        href={`mailto:${lead.user.email}`}
                                                        className="text-gray-700 hover:scale-125 transition-transform"
                                                        title="Email Buyer"
                                                    >
                                                        <Mail size={20} />
                                                    </a>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Lead Details Modal - Unchanged */}
            {selectedLead && (
                <div className="fixed inset-0 bg-black/50 backdrop-blur flex items-center justify-center p-4 z-50 animate-fadeIn">
                    <div className="bg-white w-full max-w-lg rounded-3xl shadow-2xl overflow-hidden border border-gray-200">
                        {/* Header */}
                        <div className="p-5 bg-gradient-to-r from-purple-600 to-blue-600 text-white flex justify-between items-center">
                            <h2 className="text-xl font-bold">Lead Details</h2>
                            <button
                                onClick={() => setSelectedLead(null)}
                                className="hover:scale-125 transition"
                            >
                                <X size={28} />
                            </button>
                        </div>

                        {/* Lead Info */}
                        <div className="p-6 space-y-4 max-h-[60vh] overflow-y-auto">
                            {/* Buyer Info */}
                            <div className="bg-gray-50 rounded-xl p-4">
                                <h3 className="font-semibold text-gray-800 mb-3">Buyer Information</h3>
                                <div className="space-y-2 text-sm">
                                    <p>
                                        <span className="text-gray-500">Name:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.user?.name || selectedLead.userSnapshot?.name || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Email:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.user?.email || selectedLead.userSnapshot?.email || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Phone:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.user?.phone || selectedLead.userSnapshot?.phone || "N/A"}
                                        </span>
                                    </p>
                                </div>
                            </div>

                            {/* Property Info */}
                            <div className="bg-gray-50 rounded-xl p-4">
                                <h3 className="font-semibold text-gray-800 mb-3">Property Information</h3>
                                <div className="space-y-2 text-sm">
                                    <p>
                                        <span className="text-gray-500">Title:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.property?.title || selectedLead.propertySnapshot?.title || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Location:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.property?.address?.city || selectedLead.propertySnapshot?.city || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Price:</span>{" "}
                                        <span className="font-medium">
                                            ₹{selectedLead.property?.price || selectedLead.propertySnapshot?.price || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Type:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.property?.listingType || selectedLead.propertySnapshot?.listingType || "N/A"}
                                        </span>
                                    </p>
                                </div>
                            </div>

                            {/* Owner Info */}
                            <div className="bg-gray-50 rounded-xl p-4">
                                <h3 className="font-semibold text-gray-800 mb-3">Property Owner</h3>
                                <div className="space-y-2 text-sm">
                                    <p>
                                        <span className="text-gray-500">Name:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.propertyOwner?.name || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Email:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.propertyOwner?.email || "N/A"}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Phone:</span>{" "}
                                        <span className="font-medium">
                                            {selectedLead.propertyOwner?.phone || "N/A"}
                                        </span>
                                    </p>
                                </div>
                            </div>

                            {/* Lead Status & Notes */}
                            <div className="bg-gray-50 rounded-xl p-4">
                                <h3 className="font-semibold text-gray-800 mb-3">Lead Status</h3>
                                <div className="space-y-2 text-sm">
                                    <p>
                                        <span className="text-gray-500">Status:</span>{" "}
                                        <span
                                            className={`px-3 py-1 rounded-full text-xs font-medium ${statusColors[selectedLead.status] || "bg-gray-100"
                                                }`}
                                        >
                                            {selectedLead.status}
                                        </span>
                                    </p>
                                    <p>
                                        <span className="text-gray-500">Created:</span>{" "}
                                        <span className="font-medium">
                                            {formatDate(selectedLead.createdAt)}
                                        </span>
                                    </p>
                                    {selectedLead.notes && (
                                        <p>
                                            <span className="text-gray-500">Notes:</span>{" "}
                                            <span className="font-medium">{selectedLead.notes}</span>
                                        </p>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Close */}
                        <div className="p-6 border-t">
                            <button
                                onClick={() => setSelectedLead(null)}
                                className="w-full py-3 bg-gray-900 text-white rounded-xl hover:bg-gray-700 transition-all shadow-md"
                            >
                                Close
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}