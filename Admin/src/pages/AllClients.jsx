import React, { useMemo, useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import { Search, RefreshCw, FileText, FileSpreadsheet, Loader2, X, XCircle, CheckCircle, Users, Mail, Phone } from "lucide-react";

// Helper function to safely format date
const formatDate = (date) =>
  date ? new Date(date).toLocaleDateString("en-GB") : "N/A";

// --- Status Badge Component (Shared Design) ---
const StatusBadge = ({ isBlocked }) => {
    let styles, label;
    if (isBlocked) {
        styles = "bg-rose-50 text-rose-600 border border-rose-200";
        label = "Blocked";
    } else {
        styles = "bg-emerald-50 text-emerald-600 border border-emerald-200";
        label = "Active";
    }
    return (
        <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold shadow-sm tracking-wide ${styles}`}>
            {isBlocked ? <XCircle className="w-3.5 h-3.5 mr-1.5" /> : <CheckCircle className="w-3.5 h-3.5 mr-1.5" />}
            {label}
        </span>
    );
};

export default function AllClients() {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  const [downloading, setDownloading] = useState(false);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("All");

  const [selectedUser, setSelectedUser] = useState(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  const [blockModalOpen, setBlockModalOpen] = useState(false);
  const [blockReason, setBlockReason] = useState("");
  const [userToBlock, setUserToBlock] = useState(null);
  const [blockLoading, setBlockLoading] = useState(false);

  // Auth handled by adminApi via cookies

  const fetchUsers = async () => {
    try {
        setLoading(true);
        const { data } = await adminApi.get(`/api/users/list?role=user`);

        setUsers(
            data.users.map((u) => ({
                id: u.id,
                name: u.name,
                email: u.email,
                phone: u.phone,
                status: u.isBlocked ? "Blocked" : "Active",
                blockReason: u.blockReason,
                joinedAt: formatDate(u.createdAt),

                profile: {
                    gender: u.gender,
                    alternatePhone: u.alternatePhone,
                    address: u.address,
                    dateOfBirth: formatDate(u.dateOfBirth),
                    preferences: u.preferences,
                    bio: u.bio,
                },
            }))
        );
        setLoading(false);
    } catch {
        setLoading(false);
        toast.error("Failed to load users");
    }
  };

  useEffect(() => {
    fetchUsers();
  }, []);

  const handleDownload = async (type) => {
    setDownloading(true);
    try {
        const endpoint = type === "csv" ? "/api/users/export-csv" : "/api/users/export-pdf";
        const fileName = type === "csv" ? "clients_list.csv" : "clients_list.pdf";

        const res = await adminApi.get(endpoint, {
            responseType: "blob",
        });

        const url = window.URL.createObjectURL(new Blob([res.data]));
        const link = document.createElement("a");
        link.href = url;
        link.setAttribute("download", fileName);
        link.click();
        
        toast.success(`${type.toUpperCase()} downloaded successfully.`);
    } catch {
        toast.error(`Failed to export ${type.toUpperCase()}`);
    } finally {
        setDownloading(false);
    }
  };

  const confirmBlock = async (userId, reason) => {
    setBlockLoading(true);
    try {
        await adminApi.put(`/api/users/block/${userId}`, { reason });
        fetchUsers();
        toast.success("User status updated successfully");
        setBlockModalOpen(false);
        setUserToBlock(null);
        setBlockReason("");
    } catch {
        toast.error("Failed to block user");
    } finally {
        setBlockLoading(false);
    }
  };

  const filtered = useMemo(() => {
    return users.filter((u) => {
        let q = search.toLowerCase();
        if (q && !`${u.name} ${u.email} ${u.phone}`.toLowerCase().includes(q))
            return false;
        if (statusFilter !== "All" && u.status !== statusFilter) return false;
        return true;
    });
  }, [users, search, statusFilter]);

  if (loading) {
    return (
        <div className="min-h-screen flex flex-col justify-center items-center bg-gray-50/50">
            <Loader2 className="w-10 h-10 animate-spin text-indigo-600 mb-4" />
            <p className="text-gray-500 font-medium">Loading Client Data...</p>
        </div>
    );
  }

  return (
    <div className="p-4 sm:p-8 min-h-screen bg-gray-50/30 max-w-7xl mx-auto space-y-8">
      
      {/* HEADER */}
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-gray-900 flex items-center gap-2">
            <Users className="w-8 h-8 text-indigo-600" />
            Client Management
          </h1>
          <p className="text-sm text-gray-500 mt-1 ml-10">
            View, manage, and export registered customers.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-2 w-full sm:w-auto">
          {/* EXPORT CSV */}
          <button
            onClick={() => handleDownload("csv")}
            disabled={downloading}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-700 hover:text-emerald-700 hover:border-emerald-300 rounded-xl shadow-sm transition-all text-sm font-semibold disabled:opacity-50"
          >
            {downloading ? <Loader2 className="animate-spin w-4 h-4" /> : <FileSpreadsheet className="w-4 h-4" />}
            Export CSV
          </button>

          {/* EXPORT PDF */}
          <button
            onClick={() => handleDownload("pdf")}
            disabled={downloading}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-white border border-gray-200 text-gray-700 hover:text-rose-700 hover:border-rose-300 rounded-xl shadow-sm transition-all text-sm font-semibold disabled:opacity-50"
          >
            {downloading ? <Loader2 className="animate-spin w-4 h-4" /> : <FileText className="w-4 h-4" />}
            Export PDF
          </button>

          {/* REFRESH */}
          <button
            onClick={fetchUsers}
            className="flex-1 sm:flex-none flex items-center justify-center gap-2 px-4 py-2 bg-indigo-600 border border-indigo-600 text-white hover:bg-indigo-700 hover:border-indigo-700 rounded-xl shadow-sm transition-all text-sm font-semibold disabled:opacity-50"
          >
            <RefreshCw className="w-4 h-4" />
            Sync Data
          </button>
        </div>
      </div>

      {/* FILTER BAR */}
      <div className="flex flex-col sm:flex-row gap-4 items-center bg-white p-3 rounded-2xl border border-gray-200 shadow-sm">
        <div className="relative w-full sm:flex-1">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-400" />
          <input
            type="text"
            placeholder="Search by name, email, or phone..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-11 pr-4 py-2.5 bg-gray-50/50 border-none rounded-xl text-sm focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all placeholder-gray-400"
          />
        </div>

        <div className="h-8 w-px bg-gray-200 hidden sm:block"></div>

        <div className="w-full sm:w-auto flex items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="w-full sm:w-40 py-2.5 px-4 bg-gray-50/50 border-none rounded-xl text-sm text-gray-700 focus:ring-2 focus:ring-indigo-500/20 outline-none transition-all font-medium cursor-pointer"
          >
            <option value="All">All Statuses</option>
            <option value="Active">Active</option>
            <option value="Blocked">Blocked</option>
          </select>
        </div>

        <div className="hidden sm:flex items-center justify-center px-4 py-1.5 bg-indigo-50 rounded-lg shrink-0">
            <span className="text-sm font-bold text-indigo-700">
                {filtered.length} <span className="font-normal text-indigo-500 text-xs uppercase tracking-wider">Results</span>
            </span>
        </div>
      </div>

      {/* TABLE */}
      <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden">
        <div className="overflow-x-auto">
            <table className="min-w-full text-sm divide-y divide-gray-100">
              <thead className="bg-gray-50/80">
                <tr>
                  <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                    Client Details
                  </th>
                  <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden lg:table-cell whitespace-nowrap">
                    Contact Info
                  </th>
                  <th className="py-4 px-6 text-left text-xs font-bold text-gray-500 uppercase tracking-wider hidden md:table-cell whitespace-nowrap">
                    Activity Status
                  </th>
                  <th className="py-4 px-6 text-right text-xs font-bold text-gray-500 uppercase tracking-wider whitespace-nowrap">
                    Actions
                  </th>
                </tr>
              </thead>

              <tbody className="divide-y divide-gray-100/80 bg-white">
                {filtered.length > 0 ? (
                  filtered.map((u) => (
                    <tr
                      key={u.id}
                      className="transition-all hover:bg-gray-50/50 group"
                    >
                      {/* Client Details */}
                      <td className="py-4 px-6">
                          <div className="flex items-center gap-4">
                              <div className="w-10 h-10 rounded-full bg-indigo-50 flex items-center justify-center text-indigo-700 flex-shrink-0 font-bold tracking-wider ring-1 ring-indigo-100">
                                  {u.name.charAt(0).toUpperCase()}
                              </div>
                              <div className="flex flex-col">
                                  <span className="font-bold text-gray-900 group-hover:text-indigo-600 transition-colors">
                                      {u.name}
                                  </span>
                                  {/* Mobile-only secondary info */}
                                  <div className="lg:hidden flex flex-col text-xs text-gray-500 mt-1 space-y-1">
                                      <span className="flex items-center gap-1"><Mail className="w-3 h-3" /> {u.email}</span>
                                      <span className="flex items-center gap-1"><Phone className="w-3 h-3" /> {u.phone || 'N/A'}</span>
                                      <span className="md:hidden mt-2">
                                          <StatusBadge isBlocked={u.status === "Blocked"} />
                                      </span>
                                  </div>
                              </div>
                          </div>
                      </td>

                      {/* Contact Info (Desktop) */}
                      <td className="py-4 px-6 hidden lg:table-cell whitespace-nowrap">
                          <div className="flex flex-col space-y-1.5 text-gray-600 font-medium">
                              <div className="flex items-center gap-2">
                                  <Mail className="w-3.5 h-3.5 text-gray-400" />
                                  <a href={`mailto:${u.email}`} className="hover:text-indigo-600 transition-colors">{u.email}</a>
                              </div>
                              <div className="flex items-center gap-2">
                                  <Phone className="w-3.5 h-3.5 text-gray-400" />
                                  <a href={`tel:${u.phone}`} className="hover:text-indigo-600 transition-colors">{u.phone || "N/A"}</a>
                              </div>
                          </div>
                      </td>

                      {/* Activity Status */}
                      <td className="py-4 px-6 hidden md:table-cell whitespace-nowrap align-middle">
                        <StatusBadge isBlocked={u.status === "Blocked"} />
                      </td>

                      {/* Actions */}
                      <td className="py-4 px-6 text-right whitespace-nowrap">
                        <div className="flex justify-end gap-2 items-center">
                          <button
                            onClick={() => {
                              setSelectedUser(u);
                              setDrawerOpen(true);
                            }}
                            className="inline-flex items-center justify-center px-3 py-1.5 bg-white border border-gray-200 text-gray-600 hover:text-indigo-700 hover:border-indigo-300 hover:bg-indigo-50 rounded-lg text-xs font-bold transition-all shadow-sm"
                            title="View Client Details"
                          >
                            <span className="px-2">View Profile</span>
                          </button>
                          
                          {u.status === "Active" ? (
                              <button
                                  onClick={() => {
                                      setBlockModalOpen(true);
                                      setUserToBlock(u);
                                  }}
                                  className="inline-flex items-center justify-center p-1.5 border border-transparent text-gray-400 hover:text-rose-600 hover:bg-rose-50 rounded-lg transition-colors"
                                  title="Block Client"
                              >
                                  <XCircle className="w-5 h-5" />
                              </button>
                          ) : (
                              <button
                                  onClick={() => confirmBlock(u.id, null)}
                                  className="inline-flex items-center justify-center p-1.5 border border-transparent text-emerald-600 bg-emerald-50 hover:bg-emerald-100 rounded-lg transition-colors shadow-sm"
                                  title="Unblock Client"
                              >
                                  <CheckCircle className="w-5 h-5" />
                              </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" className="py-16 text-center">
                        <div className="flex flex-col items-center justify-center text-gray-500">
                            <Users className="w-12 h-12 text-gray-300 mb-3" />
                            <p className="text-lg font-medium text-gray-600">No clients found</p>
                            <p className="text-sm mt-1">Adjust your search or filter criteria.</p>
                        </div>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
        </div>
      </div>

      {/* BLOCK REASON MODAL */}
      {blockModalOpen && userToBlock && (
        <div className="fixed inset-0 flex items-center justify-center z-50 bg-gray-900/60 backdrop-blur-sm p-4">
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 overflow-hidden transform transition-all">
                <div className="px-6 py-5 border-b border-gray-100 flex justify-between items-center">
                    <div className="flex items-center gap-3">
                        <div className="p-2 bg-rose-100 text-rose-600 rounded-full">
                            <XCircle className="w-5 h-5" />
                        </div>
                        <div>
                            <h3 className="text-lg font-bold text-gray-900">Block Client</h3>
                            <p className="text-xs text-gray-500 font-medium mt-0.5">Please provide a reason</p>
                        </div>
                    </div>
                </div>
                <div className="p-6 bg-gray-50/50">
                    <p className="text-sm text-gray-700 font-medium mb-4">
                        Blocking <span className="font-bold text-gray-900">{userToBlock.name}</span> will prevent them from logging in and accessing client features.
                    </p>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                        Reason for blocking <span className="text-rose-500">*</span>
                    </label>
                    <textarea
                        value={blockReason}
                        onChange={(e) => setBlockReason(e.target.value)}
                        placeholder="E.g., Inappropriate behavior, spam..."
                        className="w-full p-4 border border-gray-200 rounded-xl focus:ring-4 focus:ring-rose-500/10 focus:border-rose-500 text-sm outline-none transition-all shadow-sm resize-none"
                        rows={4}
                        maxLength={300}
                    />
                    <p className="text-xs text-gray-400 mt-2 text-right">{blockReason.length}/300</p>
                </div>
                <div className="px-6 py-5 border-t border-gray-100 flex justify-end gap-3 bg-white">
                    <button
                        onClick={() => {
                            setBlockModalOpen(false);
                            setUserToBlock(null);
                            setBlockReason("");
                        }}
                        className="px-5 py-2.5 bg-white border border-gray-200 text-gray-700 font-semibold rounded-xl text-sm hover:bg-gray-50 transition-colors shadow-sm"
                        disabled={blockLoading}
                    >
                        Cancel
                    </button>
                    <button
                        onClick={() => {
                            if (!blockReason.trim()) return toast.error("Reason required");
                            confirmBlock(userToBlock.id, blockReason.trim());
                        }}
                        className="px-5 py-2.5 bg-rose-600 text-white font-semibold rounded-xl text-sm hover:bg-rose-700 transition-all shadow-sm flex items-center gap-2 disabled:opacity-50"
                        disabled={blockLoading || !blockReason.trim()}
                    >
                        {blockLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <XCircle className="w-4 h-4" />}
                        Block Client
                    </button>
                </div>
            </div>
        </div>
      )}

      {/* DRAWER */}
      {drawerOpen && selectedUser && (
        <div className="fixed inset-0 flex z-50">
          <div
            className="flex-1 bg-gray-900/60 backdrop-blur-sm transition-opacity duration-300"
            onClick={() => setDrawerOpen(false)}
          />

          <div className="w-full max-w-md bg-white shadow-2xl overflow-y-auto transform transition-transform duration-300 ml-auto border-l border-gray-200">
            <div className="p-6 sticky top-0 bg-white/95 backdrop-blur z-10 border-b border-gray-100 flex justify-between items-center">
                <div>
                    <h2 className="text-xl font-bold text-gray-900">{selectedUser.name}</h2>
                    <p className="text-sm text-indigo-600 font-medium">Client Profile</p>
                </div>
                <button onClick={() => setDrawerOpen(false)} className="p-2 text-gray-400 hover:text-gray-700 hover:bg-gray-100 rounded-full transition-colors">
                    <XCircle className="w-6 h-6" />
                </button>
            </div>

            <div className="p-6 space-y-8">
                {/* Fast Actions */}
                <div className="flex gap-3">
                    {selectedUser.status === "Active" ? (
                        <button
                            onClick={() => {
                                setDrawerOpen(false);
                                setBlockModalOpen(true);
                                setUserToBlock(selectedUser);
                            }}
                            className="flex-1 py-2.5 rounded-xl text-sm font-bold border transition-all shadow-sm flex justify-center items-center gap-2 bg-white text-rose-600 border-gray-200 hover:bg-rose-50 hover:border-rose-200"
                        >
                            <XCircle className="w-4 h-4"/> Block Client
                        </button>
                    ) : (
                        <button
                            onClick={() => {
                                confirmBlock(selectedUser.id, null);
                                setDrawerOpen(false);
                            }}
                            className="flex-1 py-2.5 rounded-xl text-sm font-bold border transition-all shadow-sm flex justify-center items-center gap-2 bg-emerald-50 text-emerald-700 border-emerald-200 hover:bg-emerald-100"
                        >
                            <CheckCircle className="w-4 h-4"/> Unblock Client
                        </button>
                    )}
                </div>

                {/* Core Details */}
                <div className="space-y-4">
                    <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wider">Account Information</h3>
                    <div className="p-4 bg-gray-50 rounded-xl border border-gray-100 space-y-3 text-sm">
                        <div className="flex justify-between border-b border-gray-200 pb-2">
                            <span className="text-gray-500">Status</span>
                            <StatusBadge isBlocked={selectedUser.status === "Blocked"} />
                        </div>
                        <div className="flex justify-between pb-1">
                            <span className="text-gray-500">Joined</span>
                            <span className="font-semibold text-gray-900">{selectedUser.joinedAt}</span>
                        </div>
                    </div>
                    {selectedUser.status === "Blocked" && selectedUser.blockReason && (
                        <div className="p-3 bg-rose-50 border border-rose-100 rounded-xl mt-2">
                            <p className="text-xs text-rose-800 font-medium"><span className="font-bold">Reason:</span> {selectedUser.blockReason}</p>
                        </div>
                    )}
                </div>

                {/* Contact Details */}
                <div className="space-y-4">
                    <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wider">Contact & Personal</h3>
                    <div className="space-y-3 text-sm">
                        <div className="flex items-center gap-3 text-gray-700">
                            <Mail className="w-4 h-4 text-gray-400" /> {selectedUser.email}
                        </div>
                        <div className="flex items-center gap-3 text-gray-700">
                            <Phone className="w-4 h-4 text-gray-400" /> {selectedUser.phone || "N/A"}
                        </div>
                        <p className="text-gray-600 pl-7"><span className="text-gray-400 pr-1">Alt:</span> {selectedUser.profile.alternatePhone || "N/A"}</p>
                        <p className="text-gray-600 pl-7"><span className="text-gray-400 pr-1">DOB:</span> {selectedUser.profile.dateOfBirth}</p>
                        <p className="text-gray-600 pl-7"><span className="text-gray-400 pr-1">Gender:</span> <span className="capitalize">{selectedUser.profile.gender || "N/A"}</span></p>
                    </div>
                </div>

                 {/* Address */}
                 <div className="space-y-4">
                    <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wider">Location / Address</h3>
                    {selectedUser.profile.address?.city || selectedUser.profile.address?.state ? (
                        <div className="bg-gray-50 border border-gray-100 p-4 rounded-xl text-sm text-gray-700 space-y-1.5 font-medium">
                            <p>{selectedUser.profile.address.city ? selectedUser.profile.address.city + ", " : ""}{selectedUser.profile.address.state || ""}</p>
                        </div>
                    ) : (
                        <p className="text-sm text-gray-400 italic">No address provided.</p>
                    )}
                </div>

                {/* Bio */}
                <div className="space-y-4">
                    <h3 className="text-sm font-bold text-gray-900 uppercase tracking-wider">Bio</h3>
                    <div className="bg-gray-50 border border-gray-100 p-4 rounded-xl text-sm text-gray-700">
                        {selectedUser.profile.bio ? selectedUser.profile.bio : <span className="text-gray-400 italic">No bio added.</span>}
                    </div>
                </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
