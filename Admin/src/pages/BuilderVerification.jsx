import React, { useMemo, useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
    Loader2,
    Mail,
    Phone,
    Home,
    Search,
    Users,
    RefreshCw,
    XCircle,
    User,
    CheckCircle,
    FileSpreadsheet, // ✅ Added Icon
    FileText         // ✅ Added Icon
} from "lucide-react";

// Assuming VITE_API_BASE_URL is correctly set in your environment
const API_URL = import.meta.env.VITE_API_BASE_URL;

// Helper function to safely format date
const formatDate = (dateString) => {
    if (!dateString) return "N/A";
    try {
        return new Date(dateString).toLocaleDateString();
    } catch {
        return "Invalid Date";
    }
};

// --- Status Badge Component ---
const StatusBadge = ({ isBlocked }) => {
    let styles, label;
    if (isBlocked) {
        styles = "bg-red-100 text-red-700 ring-red-300";
        label = "Blocked";
    } else {
        styles = "bg-emerald-100 text-emerald-700 ring-emerald-300";
        label = "Active";
    }
    return (
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ring-1 ${styles}`}>
            {label}
        </span>
    );
};

// --- Main Component: BuilderVerification ---

export default function BuilderVerification() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [downloading, setDownloading] = useState(false); // ✅ State for export loading

    const [searchQuery, setSearchQuery] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");

    // Block reason modal state
    const [blockModalOpen, setBlockModalOpen] = useState(false);
    const [blockReason, setBlockReason] = useState("");
    const [ownerToBlock, setOwnerToBlock] = useState(null);
    const [blockLoading, setBlockLoading] = useState(false);

    // Selected owner drawer state
    const [selectedOwner, setSelectedOwner] = useState(null);
    const [drawerOpen, setDrawerOpen] = useState(false);

    // Auth handled by adminApi via cookies

    /* -----------------------------------------------
      🔥 FETCH OWNERS
    ------------------------------------------------- */
    const fetchOwners = async () => {
        try {
            setLoading(true);
            // Using adminApi - cookies sent automatically
            const { data } = await adminApi.get(`/api/users/list?role=owner`);
            setUsers(data.users.map((u) => ({
                ...u,
                joinedAt: formatDate(u.createdAt),
            })));
            setLoading(false);
            toast.success(`Owner list synchronized!`);
        } catch (error) {
            setLoading(false);
            toast.error("Failed to fetch owners.");
        }
    };

    useEffect(() => {
        fetchOwners();
    }, []);

    /* -----------------------------------------------
      ✅ HANDLE DOWNLOAD (CSV / PDF)
    ------------------------------------------------- */
    const handleDownload = async (type) => {
        setDownloading(true);

        try {
            // Pointing to the NEW Owner-specific routes
            const endpoint = type === 'csv' ? '/api/users/export-owners-csv' : '/api/users/export-owners-pdf';
            const filename = type === 'csv' ? 'owners_list.csv' : 'owners_list.pdf';

            const response = await adminApi.get(endpoint, {
                responseType: 'blob', // Important for file download
            });

            // Create blob link to trigger download
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', filename);
            document.body.appendChild(link);
            link.click();
            link.remove();
            window.URL.revokeObjectURL(url);

            toast.success(`${type.toUpperCase()} downloaded successfully!`);
        } catch (error) {
            console.error("Download Error:", error);
            toast.error(`Failed to download ${type.toUpperCase()}.`);
        } finally {
            setDownloading(false);
        }
    };

    /* -----------------------------------------------
      BLOCK / UNBLOCK LOGIC (omitted for brevity, unchanged)
    ------------------------------------------------- */
    const handleBlockClick = (owner) => {
        if (!owner?.id) {
            toast.error("Owner ID is missing. Cannot perform action.");
            return;
        }
        if (owner.isBlocked) {
            confirmBlock(owner.id, null);
        } else {
            setOwnerToBlock(owner);
            setBlockReason("");
            setBlockModalOpen(true);
        }
    };

    const confirmBlock = async (ownerId, reason) => {
        setBlockLoading(true);
        try {
            const { data } = await adminApi.put(`/api/users/block/${ownerId}`, { reason });
            toast.success(data.message);
            // API returns { message, user: { isBlocked, blockReason, ... } }
            const newIsBlocked = data.user?.isBlocked ?? data.isBlocked;
            const newBlockReason = data.user?.blockReason || data.blockReason || "";
            setUsers(prevUsers => prevUsers.map(u => u.id === ownerId ? { ...u, isBlocked: newIsBlocked, blockReason: newBlockReason } : u));
            if (selectedOwner?.id === ownerId) {
                setSelectedOwner(prev => ({ ...prev, isBlocked: newIsBlocked, blockReason: newBlockReason }));
            }
            setBlockModalOpen(false);
            setOwnerToBlock(null);
            setBlockReason("");
        } catch (err) {
            toast.error(err.response?.data?.message || "Action failed. Check console for details.");
        } finally {
            setBlockLoading(false);
        }
    };

    const handleConfirmBlock = () => {
        if (!blockReason.trim()) return toast.error("Please provide a reason for blocking this owner.");
        if (ownerToBlock) confirmBlock(ownerToBlock.id, blockReason.trim());
    };

    /* -----------------------------------------------
      FILTERING + SEARCH (omitted for brevity, unchanged)
    ------------------------------------------------- */
    const filteredOwners = useMemo(() => {
        return users.filter(user => {
            if (statusFilter === "active" && user.isBlocked) return false;
            if (statusFilter === "blocked" && !user.isBlocked) return false;
            if (searchQuery) {
                const query = searchQuery.toLowerCase();
                const textToSearch = `${user.name} ${user.email} ${user.phone} ${user.role}`.toLowerCase();
                return textToSearch.includes(query);
            }
            return true;
        });
    }, [users, searchQuery, statusFilter]);

    const openDrawer = (owner) => {
        setSelectedOwner(owner);
        setDrawerOpen(true);
    };

    if (loading) {
        return (
            <div className="p-8 bg-gray-50 min-h-screen flex justify-center items-center">
                <div className="flex items-center text-purple-600">
                    <Loader2 className="w-8 h-8 animate-spin" />
                    <span className="ml-4 text-xl font-medium">Loading Property Owner Data...</span>
                </div>
            </div>
        );
    }

    return (
        <div className="p-2 sm:p-2 min-h-screen">
            <div className="max-w-7xl mx-auto">

                {/* Header */}
                <div className="mb-6 sm:mb-8 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                    <div>
                        <h2 className="text-2xl sm:text-4xl font-extrabold text-gray-900 tracking-tight flex items-center gap-2">
                            <Home className="w-8 h-8 text-pink-600" />
                            <span>Property Owner Panel</span>
                        </h2>
                        <p className="text-gray-500 mt-1">Manage registered property owners.</p>
                    </div>

                    {/* ✅ EXPORT BUTTONS */}
                    <div className="flex gap-2 w-full sm:w-auto">
                        <button
                            onClick={() => handleDownload('csv')}
                            disabled={downloading}
                            className="flex-1 sm:flex-none justify-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center text-sm font-medium shadow-sm disabled:opacity-50"
                        >
                            {downloading ? <Loader2 className="animate-spin mr-2 h-4 w-4" /> : <FileSpreadsheet className="mr-2 h-4 w-4" />}
                            Export CSV
                        </button>
                        <button
                            onClick={() => handleDownload('pdf')}
                            disabled={downloading}
                            className="flex-1 sm:flex-none justify-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 flex items-center text-sm font-medium shadow-sm disabled:opacity-50"
                        >
                            {downloading ? <Loader2 className="animate-spin mr-2 h-4 w-4" /> : <FileText className="mr-2 h-4 w-4" />}
                            Export PDF
                        </button>
                    </div>
                </div>

                {/* Filters and Search (omitted for brevity, unchanged) */}
                <div className="bg-white p-4 sm:p-5 rounded-xl shadow-lg border border-gray-200 mb-6 flex flex-col md:flex-row gap-3 sm:gap-4 items-center">
                    {/* Search Input */}
                    <div className="relative w-full md:w-5/12">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Search by name, email, or phone..."
                            value={searchQuery}
                            onChange={(e) => setSearchQuery(e.target.value)}
                            className="w-full pl-10 pr-4 py-2 sm:py-2.5 border border-gray-300 rounded-lg focus:ring-purple-500 focus:border-purple-500 transition-shadow text-sm"
                        />
                    </div>
                    {/* Mobile Row for Filter & Sync */}
                    <div className="w-full md:w-auto flex flex-row gap-2 flex-1 md:contents">
                        {/* Status Filter */}
                        <select
                            value={statusFilter}
                            onChange={(e) => setStatusFilter(e.target.value)}
                            className="w-1/2 md:w-3/12 py-2 sm:py-2.5 px-3 border border-gray-300 rounded-lg bg-white focus:ring-purple-500 focus:border-purple-500 text-sm"
                        >
                            <option value="all">All Statuses</option>
                            <option value="active">Active</option>
                            <option value="blocked">Blocked</option>
                        </select>
                        <button
                            onClick={fetchOwners}
                            className="w-1/2 md:w-2/12 py-2 sm:py-2.5 px-3 bg-gray-700 text-white rounded-lg hover:bg-gray-800 transition-colors flex items-center justify-center gap-2 font-medium text-sm whitespace-nowrap"
                        >
                            <RefreshCw className="w-4 h-4" /> Sync
                        </button>
                    </div>
                    <span className="text-xs sm:text-sm font-semibold text-gray-600 w-full md:w-2/12 md:text-right text-center md:text-right">
                        Total: {filteredOwners.length} / {users.length}
                    </span>
                </div>

                {/* --- Owners Table Card --- */}
                <div className="bg-white rounded-xl shadow-2xl overflow-hidden border-2 border-pink-500/10">

                    {/* Table Header Section - Multi-Color Gradient */}
                    <div className="bg-gradient-to-r from-blue-600 via-purple-600 to-pink-600 py-4 px-6">
                        <h3 className="text-xl font-bold text-white flex items-center gap-2">
                            <Users className="w-6 h-6" /> Property Owners
                        </h3>
                    </div>

                    {/* Table Content */}
                    <table className="min-w-full text-sm divide-y divide-purple-100">
                        <thead className="bg-pink-50">
                            <tr>
                                <th className="py-4 px-6 text-left font-bold text-pink-800 whitespace-nowrap">OWNER NAME</th>
                                <th className="py-4 px-6 text-left font-bold text-pink-800 hidden md:table-cell whitespace-nowrap">EMAIL</th>
                                <th className="py-4 px-6 text-left font-bold text-pink-800 hidden md:table-cell whitespace-nowrap">PHONE</th>
                                <th className="py-4 px-6 text-left font-bold text-pink-800 hidden md:table-cell whitespace-nowrap">STATUS</th>
                                <th className="py-4 px-6 text-center font-bold text-pink-800 whitespace-nowrap">ACTIONS</th>
                            </tr>
                        </thead>

                        <tbody className="divide-y divide-gray-100">
                            {filteredOwners.length > 0 ? (
                                filteredOwners.map((u) => (
                                    <tr
                                        key={u.id}
                                        className="transition-all hover:bg-pink-50"
                                    >
                                        {/* Owner Name */}
                                        <td className="py-4 px-6">
                                            <div className="flex items-center gap-3">
                                                <div className="w-8 h-8 rounded-full bg-red-500/10 flex items-center justify-center ring-2 ring-red-500/30 flex-shrink-0">
                                                    <User className="w-4 h-4 text-red-600" />
                                                </div>
                                                <div className="flex flex-col">
                                                    <span className="font-semibold text-gray-900 truncate max-w-[120px] sm:max-w-none block">
                                                        {u.name}
                                                    </span>
                                                    {/* Mobile-only secondary info */}
                                                    <div className="md:hidden flex flex-col text-xs text-gray-500 mt-0.5 space-y-0.5">
                                                        <span>{u.phone || 'N/A'}</span>
                                                        <span className={u.isBlocked ? 'text-red-500 font-medium' : 'text-green-500 font-medium'}>
                                                            {u.isBlocked ? 'Blocked' : 'Active'}
                                                        </span>
                                                    </div>
                                                </div>
                                            </div>
                                        </td>

                                        {/* Email */}
                                        <td className="py-4 px-6 text-sm text-gray-600 hidden md:table-cell whitespace-nowrap">
                                            <div className="flex items-center gap-2">
                                                <Mail className="w-4 h-4 text-fuchsia-500" />
                                                <span className="text-xs">{u.email}</span>
                                            </div>
                                        </td>

                                        {/* Phone */}
                                        <td className="py-4 px-6 text-sm text-gray-600 hidden md:table-cell whitespace-nowrap">
                                            <div className="flex items-center gap-2">
                                                <Phone className="w-4 h-4 text-orange-500" />
                                                <span className="text-xs">{u.phone || 'N/A'}</span>
                                            </div>
                                        </td>

                                        {/* Status */}
                                        <td className="py-4 px-6 hidden md:table-cell whitespace-nowrap">
                                            <StatusBadge isBlocked={u.isBlocked} />
                                        </td>

                                        {/* Actions: Block/Unblock */}
                                        <td className="py-4 px-6 text-center whitespace-nowrap">
                                            <div className="flex justify-center gap-2">
                                                {/* View Button */}
                                                <button
                                                    onClick={() => openDrawer(u)}
                                                    className="px-3 py-1.5 bg-white shadow-sm border border-gray-300 text-gray-700 rounded-md hover:bg-gray-100 text-xs font-medium transition-colors whitespace-nowrap"
                                                >
                                                    View
                                                </button>

                                                {/* Block Button (Active Owner -> Block, styled Red) */}
                                                {!u.isBlocked && (
                                                    <button
                                                        onClick={() => handleBlockClick(u)}
                                                        className="w-24 flex items-center justify-center gap-1 py-1.5 rounded-xl text-white text-xs font-bold transition-all shadow-md bg-red-600 hover:bg-red-700 shadow-red-400/50 hover:shadow-lg whitespace-nowrap"
                                                    >
                                                        <XCircle className="w-4 h-4" /> Block
                                                    </button>
                                                )}

                                                {/* Unblock Button (Blocked Owner -> Unblock, styled Green) */}
                                                {u.isBlocked && (
                                                    <button
                                                        onClick={() => handleBlockClick(u)}
                                                        className="w-24 flex items-center justify-center gap-1 py-1.5 rounded-xl text-white text-xs font-bold transition-all shadow-md bg-emerald-600 hover:bg-emerald-700 shadow-emerald-400/50 hover:shadow-lg whitespace-nowrap"
                                                    >
                                                        <CheckCircle className="w-4 h-4" /> Unblock
                                                    </button>
                                                )}
                                            </div>
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="5" className="py-12 text-center text-gray-500 text-lg italic">
                                        <XCircle className="w-6 h-6 text-red-400 inline-block mr-2" />
                                        No property owners match the current filter criteria.
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* BLOCK REASON MODAL (unchanged) */}
            {blockModalOpen && ownerToBlock && (
                <div className="fixed inset-0 flex items-center justify-center z-50 bg-black/50">
                    <div className="bg-white rounded-lg shadow-xl w-full max-w-md mx-4 overflow-hidden">
                        <div className="bg-red-600 px-6 py-4">
                            <h3 className="text-lg font-semibold text-white">Block Owner</h3>
                        </div>
                        <div className="p-6">
                            <p className="text-gray-700 mb-4">
                                You are about to block <strong>{ownerToBlock.name}</strong> ({ownerToBlock.email}).
                            </p>
                            <p className="text-sm text-gray-600 mb-3">
                                Please provide a reason for blocking this owner. This will be shown to the owner when they try to login.
                            </p>
                            <textarea
                                value={blockReason}
                                onChange={(e) => setBlockReason(e.target.value)}
                                placeholder="Enter reason for blocking (e.g., Violation of terms of service, Fraudulent property listings, etc.)"
                                className="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 resize-none"
                                rows={4}
                            />
                        </div>
                        <div className="bg-gray-50 px-6 py-4 flex justify-end gap-3">
                            <button
                                onClick={() => {
                                    setBlockModalOpen(false);
                                    setOwnerToBlock(null);
                                    setBlockReason("");
                                }}
                                className="px-4 py-2 text-gray-700 bg-white border border-gray-300 rounded-lg hover:bg-gray-50 font-medium"
                                disabled={blockLoading}
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleConfirmBlock}
                                className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 font-medium flex items-center gap-2"
                                disabled={blockLoading}
                            >
                                {blockLoading && <Loader2 className="w-4 h-4 animate-spin" />}
                                Block Owner
                            </button>
                        </div>
                    </div>
                </div>
            )}

            {/* OWNER DETAILS DRAWER (unchanged) */}
            {drawerOpen && selectedOwner && (
                <div className="fixed inset-0 flex z-50">
                    <div
                        className="flex-1 bg-black/50 transition-opacity duration-300"
                        onClick={() => setDrawerOpen(false)}
                    />

                    <div className="w-full max-w-lg bg-white shadow-2xl p-6 overflow-y-auto transform translate-x-0 transition-transform duration-300">
                        <div className="flex justify-between items-start mb-4">
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900">{selectedOwner.name}</h2>
                                <p className="text-purple-600 font-medium">{selectedOwner.email}</p>
                            </div>
                            <button onClick={() => setDrawerOpen(false)} className="text-gray-500 hover:text-gray-700 text-2xl font-bold">
                                &times;
                            </button>
                        </div>

                        <div className="flex gap-3 mb-6">
                            <button
                                onClick={() => handleBlockClick(selectedOwner)}
                                className={`px-4 py-2 text-white rounded-md text-sm font-semibold transition-colors ${selectedOwner.isBlocked
                                    ? "bg-green-600 hover:bg-green-700"
                                    : "bg-red-600 hover:bg-red-700"
                                    }`}
                            >
                                {selectedOwner.isBlocked ? "Unblock Owner" : "Block Owner"}
                            </button>
                        </div>

                        {/* Owner Details */}
                        <div className="space-y-4 text-gray-700">
                            <div className="p-3 bg-purple-50 rounded-lg">
                                <p className="font-semibold text-gray-900">Role: <span className="text-purple-700 capitalize">{selectedOwner.role}</span></p>
                                <p className="font-semibold text-gray-900">Status:
                                    <span className={`ml-2 font-bold ${!selectedOwner.isBlocked ? 'text-green-600' : 'text-red-600'}`}>
                                        {selectedOwner.isBlocked ? 'Blocked' : 'Active'}
                                    </span>
                                </p>
                                {selectedOwner.isBlocked && selectedOwner.blockReason && (
                                    <div className="mt-2 p-2 bg-red-100 border border-red-200 rounded">
                                        <p className="text-sm text-red-800"><strong>Block Reason:</strong> {selectedOwner.blockReason}</p>
                                    </div>
                                )}
                                <p className="text-sm text-gray-600"><strong>Joined Date:</strong> {selectedOwner.joinedAt}</p>
                            </div>

                            <p><strong>Phone:</strong> {selectedOwner.phone || "N/A"}</p>
                            <p><strong>Alternate Phone:</strong> {selectedOwner.alternatePhone || "N/A"}</p>

                            <p><strong>Gender:</strong> {selectedOwner.gender || "N/A"}</p>
                            <p><strong>Date of Birth:</strong>
                                {selectedOwner.dateOfBirth
                                    ? formatDate(selectedOwner.dateOfBirth)
                                    : "N/A"}
                            </p>

                            <p><strong>Bio:</strong> {selectedOwner.bio || "N/A"}</p>

                            <div>
                                <h4 className="font-semibold text-gray-900 mt-4 mb-2">Address Details:</h4>
                                {selectedOwner.address ? (
                                    <div className="bg-gray-100 p-3 rounded text-sm space-y-1">
                                        <p><strong>Line 1:</strong> {selectedOwner.address.line1 || 'N/A'}</p>
                                        <p><strong>Line 2:</strong> {selectedOwner.address.line2 || 'N/A'}</p>
                                        <p><strong>City/Town:</strong> {selectedOwner.address.city || 'N/A'}</p>
                                        <p><strong>State:</strong> {selectedOwner.address.state || 'N/A'}</p>
                                        <p><strong>Pincode:</strong> <span className="font-bold text-purple-700">{selectedOwner.address.pincode || 'N/A'}</span></p>
                                    </div>
                                ) : (
                                    <p className="text-red-500">No address information available.</p>
                                )}
                            </div>

                            <div>
                                <h4 className="font-semibold text-gray-900 mt-4 mb-2">Preferences:</h4>
                                <ul className="ml-4 list-disc list-inside bg-gray-50 p-3 rounded-lg text-sm">
                                    <li>Email Notifications: <span className="font-medium">{selectedOwner?.preferences?.emailNotifications ? "Yes" : "No"}</span></li>
                                    <li>SMS Notifications: <span className="font-medium">{selectedOwner?.preferences?.smsNotifications ? "Yes" : "No"}</span></li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}