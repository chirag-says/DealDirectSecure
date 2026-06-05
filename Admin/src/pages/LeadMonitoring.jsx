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
    Activity
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

    const [showFilter, setShowFilter] = useState(false);
    const [updatingStatus, setUpdatingStatus] = useState(null);

    // Ref for the status filter dropdown for outside click dismissal
    const filterRef = useRef(null);

    // Fetch leads from backend
    const fetchLeads = async () => {
        try {
            setLoading(true);
            const { data } = await adminApi.get(`/api/admin/leads`, {
                params: {
                    status: statusFilter,
                    search: search
                },
            });

            if (data.success) {
                setLeads(data.data || []);
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
            if (error.response?.status !== 401) {
                toast.error("Failed to fetch leads");
            }
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        const timer = setTimeout(() => {
            fetchLeads();
        }, 500);
        return () => clearTimeout(timer);
    }, [statusFilter, search]);

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
                fetchLeads();
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
    };

    // Handler for stat box clicks
    const handleStatFilter = (status) => {
        setSearch("");
        setStatusFilter(status);
    };

    const statusColors = {
        new: "bg-blue-50 text-blue-700 border border-blue-200",
        contacted: "bg-indigo-50 text-indigo-700 border border-indigo-200",
        interested: "bg-purple-50 text-purple-700 border border-purple-200",
        negotiating: "bg-amber-50 text-amber-700 border border-amber-200",
        converted: "bg-emerald-50 text-emerald-700 border border-emerald-200",
        lost: "bg-rose-50 text-rose-700 border border-rose-200",
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
        <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 w-full max-w-full mx-auto space-y-8">

            {/* --- Page Header --- */}
            <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                    <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
                        <Activity className="w-8 h-8 text-indigo-600" />
                        Lead Monitoring
                    </h1>
                    <p className="text-sm text-gray-500 mt-1 sm:ml-10">
                        Track, manage, and engage with potential buyers.
                    </p>
                </div>
                
                <div className="flex gap-2">
                    <button
                        onClick={() => handleStatFilter('new')}
                        className={`px-4 py-2 rounded-xl text-sm font-bold border transition-all shadow-sm ${statusFilter === 'new' ? 'bg-indigo-50 border-indigo-200 text-indigo-700' : 'bg-white border-gray-200 text-gray-600 hover:bg-gray-50'}`}
                    >
                        New Leads <span className="ml-1.5 px-2 py-0.5 bg-indigo-100 rounded-full text-indigo-800 text-xs">{stats.new}</span>
                    </button>
                    <button
                        onClick={() => handleStatFilter('converted')}
                        className={`px-4 py-2 rounded-xl text-sm font-bold border transition-all shadow-sm ${statusFilter === 'converted' ? 'bg-emerald-50 border-emerald-200 text-emerald-700' : 'bg-white border-gray-200 text-gray-600 hover:bg-gray-50'}`}
                    >
                        Converted <span className="ml-1.5 px-2 py-0.5 bg-emerald-100 rounded-full text-emerald-800 text-xs">{stats.converted}</span>
                    </button>
                </div>
            </div>

             {/* FILTER BAR */}
             <div className="flex flex-col sm:flex-row gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
                
                {/* Search */}
                <div className="relative w-full sm:flex-1">
                    <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
                    <input
                        type="text"
                        placeholder="Search leads by name, email or property..."
                        value={search}
                        onChange={(e) => setSearch(e.target.value)}
                        className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all placeholder-gray-400"
                    />
                </div>

                <div className="h-8 w-px bg-gray-200 hidden sm:block"></div>

                {/* Status Filter */}
                <div className="relative w-full sm:w-48" ref={filterRef}>
                    <button
                        onClick={() => setShowFilter(!showFilter)}
                        className="w-full py-2.5 px-4 bg-gray-50/50 border-none rounded-xl text-sm text-gray-700 focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all font-medium cursor-pointer flex items-center justify-between"
                    >
                        <span className="flex items-center gap-2">
                             <Filter className="w-4 h-4 text-gray-400" />
                             {statusOptions.find((s) => s.value === statusFilter)?.label}
                        </span>
                        <ChevronDown className="w-4 h-4 text-gray-400" />
                    </button>

                    {showFilter && (
                        <div className="absolute right-0 mt-2 w-full bg-white rounded-xl shadow-xl border border-gray-100 py-2 z-50">
                            {statusOptions.map((option) => (
                                <button
                                    key={option.value}
                                    onClick={() => {
                                        setStatusFilter(option.value);
                                        setShowFilter(false);
                                    }}
                                    className={`w-full px-4 py-2 text-left text-sm hover:bg-gray-50 transition-colors ${statusFilter === option.value ? "bg-indigo-50/50 text-indigo-700 font-bold" : "text-gray-700 font-medium"}`}
                                >
                                    {option.label}
                                </button>
                            ))}
                        </div>
                    )}
                </div>

                <div className="h-8 w-px bg-gray-200 hidden sm:block"></div>

                {/* Actions */}
                <div className="flex w-full sm:w-auto items-center gap-2">
                     {(search || statusFilter !== 'all') && (
                        <button 
                            onClick={handleResetFilters} 
                            className="flex-1 sm:flex-none p-2.5 bg-rose-50 border border-rose-100 text-rose-600 hover:bg-rose-100 rounded-xl transition-all shadow-sm flex justify-center items-center"
                            title="Reset Filters"
                        >
                            <RotateCcw className="w-4 h-4" />
                        </button>
                    )}
                    <button 
                        onClick={fetchLeads} 
                        disabled={loading}
                        className="flex-1 sm:flex-none p-2.5 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-all shadow-sm flex justify-center items-center gap-2"
                        title="Refresh Leads"
                    >
                        <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                    </button>
                </div>
            </div>

            {/* TABLE */}
            <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden min-h-[500px] flex flex-col">
                {loading ? (
                    <div className="flex-1 flex justify-center items-center">
                        <Loader2 className="w-10 h-10 animate-spin text-indigo-600" />
                    </div>
                ) : leads.length === 0 ? (
                    <div className="flex-1 flex flex-col justify-center items-center text-gray-500 py-24">
                        <MessageSquare className="w-16 h-16 mx-auto mb-4 text-gray-300" />
                        <p className="text-xl font-medium text-gray-600">No leads found</p>
                        <p className="text-sm mt-2">Try adjusting your date or status filters.</p>
                        {(search || startDate || endDate || statusFilter !== 'all') && (
                             <button onClick={handleResetFilters} className="mt-4 text-indigo-600 hover:text-indigo-700 font-semibold text-sm">Clear all filters</button>
                        )}
                    </div>
                ) : (
                    <div className="overflow-x-auto flex-1">
                        <table className="min-w-full text-sm divide-y divide-gray-100">
                            <thead className="bg-gray-50/80">
                                <tr>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">Buyer</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">Property</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">Owner</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">Date</th>
                                    <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">Status</th>
                                    <th className="py-4 px-6 text-right text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">Actions</th>
                                </tr>
                            </thead>

                            <tbody className="divide-y divide-gray-100/80 bg-white">
                                {leads.map((lead) => (
                                    <tr
                                        key={lead._id}
                                        className="hover:bg-gray-50/50 transition-all group"
                                    >
                                        {/* Buyer */}
                                        <td className="py-4 px-6 block md:table-cell w-full md:w-auto">
                                            <div className="flex flex-col gap-2">
                                                {/* Main Row Content */}
                                                <div className="flex items-center justify-between w-full">
                                                    <div className="flex items-center gap-3 overflow-hidden">
                                                        <div className="w-10 h-10 rounded-full bg-indigo-50 border border-indigo-100 flex items-center justify-center text-indigo-700 flex-shrink-0 font-bold overflow-hidden">
                                                            {lead.user?.profileImage ? (
                                                                <img
                                                                    src={lead.user.profileImage}
                                                                    alt=""
                                                                    className="w-full h-full object-cover"
                                                                />
                                                            ) : (
                                                                (lead.user?.name || lead.userSnapshot?.name || "U").charAt(0).toUpperCase()
                                                            )}
                                                        </div>
                                                        <div className="flex flex-col overflow-hidden">
                                                            <p className="font-bold text-gray-900 group-hover:text-indigo-600 transition-colors truncate max-w-[140px] sm:max-w-none">
                                                                {lead.user?.name || lead.userSnapshot?.name || "Unknown"}
                                                            </p>
                                                            <p className="text-xs text-gray-500 font-medium whitespace-nowrap hidden md:block">
                                                                {lead.user?.email || lead.userSnapshot?.email || ""}
                                                            </p>
                                                        </div>
                                                        {lead.status === "new" && (
                                                            <span className="ml-2 text-[10px] font-bold tracking-wider uppercase bg-amber-100 text-amber-800 border border-amber-200 px-2 py-0.5 rounded-md flex-shrink-0">
                                                                NEW
                                                            </span>
                                                        )}
                                                    </div>

                                                    {/* Mobile Toggle Button */}
                                                    <button
                                                        onClick={() => setExpandedLead(expandedLead === lead._id ? null : lead._id)}
                                                        className="md:hidden p-2 text-gray-400 hover:text-indigo-600 transition-colors bg-gray-50 rounded-lg border border-gray-100"
                                                    >
                                                        <ChevronDown
                                                            className={`w-4 h-4 transition-transform duration-200 ${expandedLead === lead._id ? "rotate-180" : ""}`}
                                                        />
                                                    </button>
                                                </div>

                                                {/* Mobile Expanded Details */}
                                                {expandedLead === lead._id && (
                                                    <div className="md:hidden bg-gray-50 rounded-xl p-4 text-sm space-y-3 mt-2 border border-gray-100 animate-in fade-in slide-in-from-top-1">
                                                        <div className="grid grid-cols-[auto,1fr] gap-x-3 gap-y-2">
                                                            <span className="text-gray-500 font-medium text-xs uppercase tracking-wider">Email</span>
                                                            <span className="text-gray-900 font-medium truncate">{lead.user?.email || "N/A"}</span>

                                                            <span className="text-gray-500 font-medium text-xs uppercase tracking-wider">Property</span>
                                                            <span className="text-gray-900 font-medium line-clamp-1">{lead.property?.title || "N/A"}</span>

                                                            <span className="text-gray-500 font-medium text-xs uppercase tracking-wider">Owner</span>
                                                            <span className="text-gray-900 font-medium">
                                                                {lead.propertyOwner?.name || "N/A"}
                                                            </span>

                                                            <span className="text-gray-500 font-medium text-xs uppercase tracking-wider">Date</span>
                                                            <span className="text-gray-900 font-medium">{formatDate(lead.createdAt)}</span>
                                                        </div>

                                                        {/* Mobile Actions & Status */}
                                                        <div className="flex flex-col gap-3 pt-3 border-t border-gray-200 mt-2">
                                                            <div className="flex items-center justify-between">
                                                                <span className="text-gray-500 font-medium text-xs uppercase tracking-wider">Status</span>
                                                                <select
                                                                    value={lead.status}
                                                                    onChange={(e) => updateLeadStatus(lead._id, e.target.value)}
                                                                    disabled={updatingStatus === lead._id}
                                                                    className={`px-3 py-1.5 border rounded-lg text-xs font-bold uppercase tracking-wider cursor-pointer outline-none ${statusColors[lead.status] || "bg-gray-50 text-gray-700"}`}
                                                                >
                                                                    <option value="new">New</option>
                                                                    <option value="contacted">Contacted</option>
                                                                    <option value="interested">Interested</option>
                                                                    <option value="negotiating">Negotiating</option>
                                                                    <option value="converted">Converted</option>
                                                                    <option value="lost">Lost</option>
                                                                </select>
                                                            </div>
                                                            <div className="flex justify-end gap-2">
                                                                <button onClick={() => setSelectedLead(lead)} className="p-2 bg-indigo-50 text-indigo-600 rounded-lg hover:bg-indigo-100" title="View Details">
                                                                    <MessageSquare className="w-4 h-4" />
                                                                </button>
                                                                {lead.user?.phone && (
                                                                    <a href={`tel:${lead.user.phone}`} className="p-2 bg-emerald-50 text-emerald-600 rounded-lg hover:bg-emerald-100" title="Call Buyer">
                                                                        <PhoneCall className="w-4 h-4" />
                                                                    </a>
                                                                )}
                                                                {lead.user?.email && (
                                                                    <a href={`mailto:${lead.user.email}`} className="p-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200" title="Email Buyer">
                                                                        <Mail className="w-4 h-4" />
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
                                                <p className="text-gray-900 font-semibold truncate max-w-[200px]" title={lead.property?.title || lead.propertySnapshot?.title}>
                                                    {lead.property?.title || lead.propertySnapshot?.title || "N/A"}
                                                </p>
                                                <p className="text-xs text-gray-500 font-medium mt-0.5">
                                                    {lead.property?.address?.city || lead.propertySnapshot?.city || ""}
                                                </p>
                                            </div>
                                        </td>

                                        {/* Owner */}
                                        <td className="py-4 px-6 hidden md:table-cell whitespace-nowrap">
                                            <div>
                                                <p className="text-gray-900 font-semibold">
                                                    {lead.propertyOwner?.name || "N/A"}
                                                </p>
                                                <p className="text-xs text-gray-500 font-medium">
                                                    {lead.propertyOwner?.phone || ""}
                                                </p>
                                            </div>
                                        </td>

                                        {/* Date */}
                                        <td className="py-4 px-6 text-gray-600 font-medium hidden md:table-cell whitespace-nowrap">
                                            {formatDate(lead.createdAt)}
                                        </td>

                                        {/* Status */}
                                        <td className="py-4 px-6 whitespace-nowrap hidden md:table-cell align-middle">
                                            <select
                                                value={lead.status}
                                                onChange={(e) => updateLeadStatus(lead._id, e.target.value)}
                                                disabled={updatingStatus === lead._id}
                                                className={`px-3 py-1.5 rounded-lg text-xs font-bold uppercase tracking-wider cursor-pointer focus:outline-none focus:ring-2 focus:ring-indigo-500/20 ${statusColors[lead.status] || "bg-gray-50 text-gray-600 border border-gray-200"
                                                    }`}
                                            >
                                                <option value="new">NEW</option>
                                                <option value="contacted">CONTACTED</option>
                                                <option value="interested">INTERESTED</option>
                                                <option value="negotiating">NEGOTIATING</option>
                                                <option value="converted">CONVERTED</option>
                                                <option value="lost">LOST</option>
                                            </select>
                                        </td>

                                        {/* Actions */}
                                        <td className="py-4 px-6 text-right whitespace-nowrap hidden md:table-cell align-middle">
                                            <div className="flex justify-end gap-2 items-center">
                                                <button
                                                    onClick={() => setSelectedLead(lead)}
                                                    className="inline-flex items-center justify-center px-3 py-1.5 bg-white border border-gray-200 text-gray-600 hover:text-indigo-700 hover:border-indigo-300 hover:bg-indigo-50 rounded-lg text-xs font-bold transition-all shadow-sm"
                                                    title="View Details"
                                                >
                                                    <span className="px-2">Details</span>
                                                </button>

                                                {lead.user?.phone && (
                                                    <a
                                                        href={`tel:${lead.user.phone}`}
                                                        className="inline-flex items-center justify-center p-1.5 border border-transparent text-gray-400 hover:text-emerald-600 hover:bg-emerald-50 rounded-lg transition-colors"
                                                        title="Call Buyer"
                                                    >
                                                        <PhoneCall className="w-5 h-5" />
                                                    </a>
                                                )}

                                                {lead.user?.email && (
                                                    <a
                                                        href={`mailto:${lead.user.email}`}
                                                        className="inline-flex items-center justify-center p-1.5 border border-transparent text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 rounded-lg transition-colors"
                                                        title="Email Buyer"
                                                    >
                                                        <Mail className="w-5 h-5" />
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

            {/* Lead Details Modal */}
            {selectedLead && (
                <div className="fixed inset-0 bg-gray-900/60 backdrop-blur-sm flex items-center justify-center p-4 z-50">
                    <div className="bg-white w-full max-w-lg rounded-2xl shadow-2xl overflow-hidden border border-gray-200 transform transition-all">
                        {/* Header */}
                        <div className="p-6 bg-white border-b border-gray-100 flex justify-between items-center">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-indigo-50 text-indigo-600 rounded-xl">
                                    <MessageSquare className="w-5 h-5" />
                                </div>
                                <div>
                                    <h2 className="text-lg font-bold text-gray-900">Lead Details</h2>
                                </div>
                            </div>
                            <button
                                onClick={() => setSelectedLead(null)}
                                className="p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        {/* Lead Info */}
                        <div className="p-6 space-y-6 max-h-[60vh] overflow-y-auto bg-gray-50/50">
                            {/* Buyer Info */}
                            <div>
                                <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Buyer Information</h3>
                                <div className="bg-white border border-gray-200 rounded-xl p-4 text-sm font-medium space-y-2.5">
                                    <div className="flex justify-between border-b border-gray-100 pb-2">
                                        <span className="text-gray-500">Name</span>
                                        <span className="text-gray-900">{selectedLead.user?.name || selectedLead.userSnapshot?.name || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between border-b border-gray-100 pb-2">
                                        <span className="text-gray-500">Email</span>
                                        <span className="text-gray-900">{selectedLead.user?.email || selectedLead.userSnapshot?.email || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-500">Phone</span>
                                        <span className="text-gray-900">{selectedLead.user?.phone || selectedLead.userSnapshot?.phone || "N/A"}</span>
                                    </div>
                                </div>
                            </div>

                            {/* Property Info */}
                            <div>
                                <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Property Inquiry</h3>
                                <div className="bg-white border border-gray-200 rounded-xl p-4 text-sm font-medium space-y-2.5">
                                    <div className="flex flex-col border-b border-gray-100 pb-3 mb-1">
                                        <span className="text-gray-500 mb-1">Title</span>
                                        <span className="text-gray-900">{selectedLead.property?.title || selectedLead.propertySnapshot?.title || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-500">Location</span>
                                        <span className="text-gray-900">{selectedLead.property?.address?.city || selectedLead.propertySnapshot?.city || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-500">Price</span>
                                        <span className="text-gray-900">₹{selectedLead.property?.price || selectedLead.propertySnapshot?.price || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-500">Type</span>
                                        <span className="text-gray-900 capitalize">{selectedLead.property?.listingType || selectedLead.propertySnapshot?.listingType || "N/A"}</span>
                                    </div>
                                </div>
                            </div>

                            {/* Owner Info */}
                            <div>
                                 <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Property Owner</h3>
                                <div className="bg-white border border-gray-200 rounded-xl p-4 text-sm font-medium space-y-2.5">
                                    <div className="flex justify-between border-b border-gray-100 pb-2">
                                        <span className="text-gray-500">Name</span>
                                        <span className="text-gray-900">{selectedLead.propertyOwner?.name || "N/A"}</span>
                                    </div>
                                    <div className="flex justify-between">
                                        <span className="text-gray-500">Contact</span>
                                        <span className="text-gray-900">{selectedLead.propertyOwner?.phone || selectedLead.propertyOwner?.email || "N/A"}</span>
                                    </div>
                                </div>
                            </div>

                            {/* Lead Status & Notes */}
                            <div>
                                <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Lead Status & Details</h3>
                                <div className="bg-white border border-gray-200 rounded-xl p-4 text-sm font-medium space-y-3">
                                    <div className="flex justify-between items-center border-b border-gray-100 pb-3">
                                        <span className="text-gray-500">Current Status</span>
                                        <span className={`px-2.5 py-1 rounded-md text-xs font-bold uppercase tracking-wider ${statusColors[selectedLead.status] || "bg-gray-100"}`}>
                                            {selectedLead.status}
                                        </span>
                                    </div>
                                    <div className="flex justify-between items-center">
                                        <span className="text-gray-500">Inquiry Date</span>
                                        <span className="text-gray-900">{formatDate(selectedLead.createdAt)}</span>
                                    </div>
                                    {selectedLead.notes && (
                                        <div className="mt-3 bg-gray-50 p-3 rounded-lg border border-gray-100">
                                            <span className="text-gray-500 block mb-1">Notes</span>
                                            <span className="text-gray-900 leading-relaxed font-normal text-sm">{selectedLead.notes}</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Close */}
                        <div className="px-6 py-5 border-t border-gray-100 bg-white flex justify-end">
                            <button
                                onClick={() => setSelectedLead(null)}
                                className="px-5 py-2.5 bg-white border border-gray-200 text-gray-700 font-semibold rounded-xl text-sm hover:bg-gray-50 transition-colors shadow-sm"
                            >
                                Close Details
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}