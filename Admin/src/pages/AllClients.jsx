import React, { useMemo, useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import { Search, RefreshCw, FileText, FileSpreadsheet, Loader2, X } from "lucide-react";

const API_URL = import.meta.env.VITE_API_BASE_URL;

const formatDate = (date) =>
  date ? new Date(date).toLocaleDateString("en-GB") : "N/A";

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
      // Using adminApi - cookies sent automatically
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
      const endpoint =
        type === "csv" ? "/api/users/export-csv" : "/api/users/export-pdf";
      const fileName =
        type === "csv" ? "clients_list.csv" : "clients_list.pdf";

      const res = await adminApi.get(endpoint, {
        responseType: "blob",
      });

      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", fileName);
      link.click();
    } catch {
      toast.error("Export failed");
    }
    setDownloading(false);
  };

  const confirmBlock = async (userId, reason) => {
    setBlockLoading(true);
    try {
      await adminApi.put(
        `/api/users/block/${userId}`,
        { reason }
      );
      fetchUsers();
      toast.success("Updated");
      setBlockModalOpen(false);
    } catch {
      toast.error("Failed to block user");
    }
    setBlockLoading(false);
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

  return (
    <div className="sm:p-4 bg-gray-50 min-h-screen">
      <div className="max-w-7xl mx-auto">

        {/* HEADER */}
        <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center mb-6 gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-gray-900">
              Client Management
            </h1>
            <p className="text-gray-500 text-sm">
              View & manage registered customers
            </p>
          </div>

          <div className="flex flex-wrap gap-2 w-full sm:w-auto">
            {/* EXPORT CSV */}
            <button
              onClick={() => handleDownload("csv")}
              className="flex-1 sm:flex-none px-4 py-2 bg-green-600 text-white rounded-lg flex items-center justify-center hover:bg-green-700 shadow-sm"
            >
              {downloading ? (
                <Loader2 className="animate-spin mr-2 h-4 w-4" />
              ) : (
                <FileSpreadsheet className="mr-2 h-4 w-4" />
              )}
              CSV
            </button>

            {/* EXPORT PDF */}
            <button
              onClick={() => handleDownload("pdf")}
              className="flex-1 sm:flex-none px-4 py-2 bg-red-600 text-white rounded-lg flex items-center justify-center hover:bg-red-700 shadow-sm"
            >
              {downloading ? (
                <Loader2 className="animate-spin mr-2 h-4 w-4" />
              ) : (
                <FileText className="mr-2 h-4 w-4" />
              )}
              PDF
            </button>

            {/* REFRESH */}
            <button
              onClick={fetchUsers}
              className="flex-1 sm:flex-none px-4 py-2 bg-white border rounded-lg flex items-center justify-center hover:bg-gray-100 text-gray-700"
            >
              <RefreshCw className={`${loading ? "animate-spin" : ""} mr-2 h-4 w-4`} />
              Refresh
            </button>
          </div>
        </div>

        {/* FILTER BAR */}
        <div className="bg-white p-4 rounded-xl shadow-sm border flex flex-col md:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-2 text-gray-400 h-5 w-5" />
            <input
              placeholder="Search user by name, email or phone"
              className="pl-10 pr-3 py-2 border rounded-lg w-full text-sm focus:ring-2 focus:ring-indigo-500"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="border px-3 py-2 rounded-lg text-sm"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="All">All Statuses</option>
            <option value="Active">Active Users</option>
            <option value="Blocked">Blocked Users</option>
          </select>
        </div>

        {/* TABLE */}
        <div className="bg-white shadow rounded-lg mt-4 overflow-x-auto">
          {loading ? (
            <div className="p-6 text-center">
              <Loader2 className="animate-spin text-indigo-600" size={28} />
            </div>
          ) : (
            <table className="w-full min-w-[700px]">
              <thead className="bg-indigo-50 border-b border-indigo-200">
                <tr>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                    User
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                    Email
                  </th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-gray-700">
                    Phone
                  </th>
                  <th className="px-4 py-3 text-center text-sm font-semibold text-gray-700">
                    Status
                  </th>
                  <th className="px-4 py-3 text-right text-sm font-semibold text-gray-700">
                    Actions
                  </th>
                </tr>
              </thead>

              <tbody>
                {filtered.map((u) => (
                  <tr
                    key={u.id}
                    className="border-b hover:bg-gray-50 transition"
                  >
                    <td className="px-4 py-3 font-medium">{u.name}</td>
                    <td className="px-4 py-3 text-gray-600">{u.email}</td>
                    <td className="px-4 py-3 text-gray-600">{u.phone || "N/A"}</td>
                    <td className="px-4 py-3 text-center">
                      <span
                        className={`px-3 py-1 text-xs rounded-full font-medium ${u.status === "Active"
                            ? "bg-green-100 text-green-700"
                            : "bg-red-100 text-red-700"
                          }`}
                      >
                        {u.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex justify-end gap-2">
                        <button
                          onClick={() => {
                            setSelectedUser(u);
                            setDrawerOpen(true);
                          }}
                          className="px-3 py-1 text-sm border rounded hover:bg-gray-100"
                        >
                          View
                        </button>
                        <button
                          onClick={() => {
                            if (u.status === "Blocked") {
                              confirmBlock(u.id, null);
                            } else {
                              setBlockModalOpen(true);
                              setUserToBlock(u);
                            }
                          }}
                          className={`px-3 py-1 text-sm rounded text-white ${u.status === "Active"
                              ? "bg-red-600 hover:bg-red-700"
                              : "bg-green-600 hover:bg-green-700"
                            }`}
                        >
                          {u.status === "Active" ? "Block" : "Unblock"}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {!loading && filtered.length === 0 && (
            <p className="p-6 text-center text-gray-500">No users found.</p>
          )}
        </div>
      </div>

      {/* DRAWER */}
      {drawerOpen && selectedUser && (
        <div className="fixed inset-0 flex z-50">
          <div className="flex-1 bg-black/50" onClick={() => setDrawerOpen(false)} />
          <div className="w-full max-w-lg bg-white p-6 overflow-y-auto shadow-xl">
            <div className="flex justify-between items-center">
              <h2 className="text-2xl font-bold">{selectedUser.name}</h2>
              <button
                onClick={() => setDrawerOpen(false)}
                className="p-1 hover:bg-gray-200 rounded"
              >
                <X />
              </button>
            </div>

            <hr className="my-4" />

            <p><strong>Email:</strong> {selectedUser.email}</p>
            <p><strong>Phone:</strong> {selectedUser.phone || "N/A"}</p>
            <p><strong>Status:</strong> {selectedUser.status}</p>
            <p><strong>Joined:</strong> {selectedUser.joinedAt}</p>

            <h3 className="mt-4 font-semibold text-lg">Profile Details</h3>
            <div className="mt-2 space-y-1">
              <p><strong>Gender:</strong> {selectedUser.profile.gender || "N/A"}</p>
              <p><strong>DOB:</strong> {selectedUser.profile.dateOfBirth}</p>
              <p><strong>Alternate Phone:</strong> {selectedUser.profile.alternatePhone || "N/A"}</p>

              <p>
                <strong>Location:</strong>{" "}
                {selectedUser.profile.address?.city || "N/A"},{" "}
                {selectedUser.profile.address?.state || "N/A"}
              </p>
              <p><strong>Bio:</strong> {selectedUser.profile.bio || "No bio added"}</p>
            </div>
          </div>
        </div>
      )}

      {/* BLOCK MODAL */}
      {blockModalOpen && userToBlock && (
        <div className="fixed inset-0 flex justify-center items-center bg-black/50 z-50">
          <div className="bg-white rounded-xl p-6 w-full max-w-md shadow-lg">
            <h3 className="text-lg font-bold mb-3">Block User</h3>

            <textarea
              className="w-full border p-2 rounded h-24 text-sm"
              placeholder="Enter reason..."
              value={blockReason}
              onChange={(e) => setBlockReason(e.target.value)}
            />

            <div className="flex justify-end gap-2 mt-4">
              <button
                className="px-4 py-2 border rounded hover:bg-gray-100"
                onClick={() => setBlockModalOpen(false)}
              >
                Cancel
              </button>

              <button
                className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700"
                onClick={() => {
                  if (!blockReason.trim())
                    return toast.error("Reason required");
                  confirmBlock(userToBlock.id, blockReason.trim());
                }}
              >
                {blockLoading ? "Processing..." : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
