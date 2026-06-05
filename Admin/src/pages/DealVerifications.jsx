import React, { useState, useEffect, useCallback } from "react";
import { dealVerificationsApi } from "../api/adminApi";
import {
  FileText,
  CheckCircle,
  XCircle,
  Clock,
  Eye,
  User,
  Home,
  ExternalLink,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  AlertCircle,
  Award,
} from "lucide-react";

const statusConfig = {
  pending: { bg: "bg-amber-100", text: "text-amber-700", icon: Clock, label: "Pending" },
  approved: { bg: "bg-green-100", text: "text-green-700", icon: CheckCircle, label: "Approved" },
  rejected: { bg: "bg-red-100", text: "text-red-700", icon: XCircle, label: "Rejected" },
};

const StatusBadge = ({ status }) => {
  const config = statusConfig[status] || statusConfig.pending;
  const Icon = config.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${config.bg} ${config.text}`}>
      <Icon className="w-3.5 h-3.5" />
      {config.label}
    </span>
  );
};

export default function DealVerifications() {
  const [verifications, setVerifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("pending");
  const [pagination, setPagination] = useState({ page: 1, totalPages: 1, total: 0 });
  const [actionLoading, setActionLoading] = useState(null);
  const [selectedVerification, setSelectedVerification] = useState(null);
  const [rejectNotes, setRejectNotes] = useState("");
  const [showRejectModal, setShowRejectModal] = useState(false);
  const [showDocModal, setShowDocModal] = useState(null);

  const fetchVerifications = useCallback(async (page = 1) => {
    setLoading(true);
    try {
      const data = await dealVerificationsApi.getAll({
        status: statusFilter || undefined,
        page,
        limit: 15,
      });
      if (data.success) {
        setVerifications(data.verifications || []);
        setPagination(data.pagination || { page: 1, totalPages: 1, total: 0 });
      }
    } catch (err) {
      console.error("Failed to load verifications:", err);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchVerifications(1);
  }, [fetchVerifications]);

  const handleApprove = async (id) => {
    if (!window.confirm("Are you sure you want to approve this deal? Both parties will be notified to claim their rewards.")) return;
    setActionLoading(id);
    try {
      const res = await dealVerificationsApi.approve(id);
      if (res.success) {
        alert("✅ Deal approved! Both parties have been notified to claim their rewards.");
        fetchVerifications(pagination.page);
      }
    } catch (err) {
      alert("Failed to approve: " + (err.response?.data?.message || err.message));
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async () => {
    if (!rejectNotes.trim()) {
      alert("Please provide rejection notes.");
      return;
    }
    setActionLoading(selectedVerification);
    try {
      const res = await dealVerificationsApi.reject(selectedVerification, rejectNotes.trim());
      if (res.success) {
        alert("Deal verification rejected. Property reactivated.");
        setShowRejectModal(false);
        setRejectNotes("");
        setSelectedVerification(null);
        fetchVerifications(pagination.page);
      }
    } catch (err) {
      alert("Failed to reject: " + (err.response?.data?.message || err.message));
    } finally {
      setActionLoading(null);
    }
  };

  const openRejectModal = (id) => {
    setSelectedVerification(id);
    setRejectNotes("");
    setShowRejectModal(true);
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Award className="w-7 h-7 text-blue-600" />
            Deal Verifications
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Review and verify property sale/rental closures. Approving notifies both parties to claim rewards.
          </p>
        </div>
        <button
          onClick={() => fetchVerifications(pagination.page)}
          className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm font-medium text-gray-700 hover:bg-gray-50 transition"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 mb-6 bg-white rounded-xl p-1 border border-gray-200 w-fit">
        {["pending", "approved", "rejected", ""].map((status) => (
          <button
            key={status}
            onClick={() => setStatusFilter(status)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
              statusFilter === status
                ? "bg-blue-600 text-white shadow-sm"
                : "text-gray-600 hover:bg-gray-100"
            }`}
          >
            {status ? status.charAt(0).toUpperCase() + status.slice(1) : "All"}
          </button>
        ))}
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div className="bg-white rounded-xl border border-gray-200 p-4 flex items-center gap-3">
          <div className="p-3 rounded-xl bg-amber-100">
            <Clock className="w-5 h-5 text-amber-600" />
          </div>
          <div>
            <p className="text-xl font-bold text-gray-900">{pagination.total}</p>
            <p className="text-xs text-gray-500">{statusFilter || "Total"} verifications</p>
          </div>
        </div>
      </div>

      {/* Table */}
      {loading ? (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
          <RefreshCw className="w-8 h-8 text-gray-400 animate-spin mx-auto mb-3" />
          <p className="text-gray-500">Loading verifications...</p>
        </div>
      ) : verifications.length === 0 ? (
        <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
          <AlertCircle className="w-12 h-12 text-gray-300 mx-auto mb-3" />
          <p className="text-gray-500 font-medium">No {statusFilter || ""} verifications found</p>
        </div>
      ) : (
        <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px]">
              <thead>
                <tr className="bg-gray-50 border-b border-gray-200">
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Property</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Owner</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Buyer</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Type</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Status</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Documents</th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-500 uppercase">Date</th>
                  <th className="px-4 py-3 text-center text-xs font-semibold text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {verifications.map((v) => (
                  <tr key={v._id} className="hover:bg-gray-50 transition">
                    {/* Property */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Home className="w-4 h-4 text-gray-400 flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-gray-900 truncate max-w-[200px]">
                            {v.property?.title || "N/A"}
                          </p>
                          <p className="text-xs text-gray-500">
                            {v.property?.city || v.property?.address?.city || ""}
                          </p>
                        </div>
                      </div>
                    </td>

                    {/* Owner */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-blue-400 flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-gray-800 truncate">{v.owner?.name || "N/A"}</p>
                          <p className="text-xs text-gray-500 truncate">{v.owner?.email || ""}</p>
                        </div>
                      </div>
                    </td>

                    {/* Buyer */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <User className="w-4 h-4 text-green-400 flex-shrink-0" />
                        <div className="min-w-0">
                          <p className="text-sm font-medium text-gray-800 truncate">{v.buyer?.name || "N/A"}</p>
                          <p className="text-xs text-gray-500 truncate">{v.buyer?.email || ""}</p>
                        </div>
                      </div>
                    </td>

                    {/* Closing Type */}
                    <td className="px-4 py-3">
                      <span className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                        v.closingType === "sold"
                          ? "bg-blue-100 text-blue-700"
                          : "bg-purple-100 text-purple-700"
                      }`}>
                        {v.closingType?.charAt(0).toUpperCase() + v.closingType?.slice(1)}
                      </span>
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <StatusBadge status={v.status} />
                    </td>

                    {/* Documents */}
                    <td className="px-4 py-3">
                      <button
                        onClick={() => setShowDocModal(v)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-100 text-gray-700 rounded-lg text-xs font-medium hover:bg-gray-200 transition"
                      >
                        <FileText className="w-3.5 h-3.5" />
                        {v.documentUrls?.length || 0} file(s)
                      </button>
                    </td>

                    {/* Date */}
                    <td className="px-4 py-3 text-sm text-gray-500 whitespace-nowrap">
                      {new Date(v.createdAt).toLocaleDateString("en-IN", {
                        day: "numeric",
                        month: "short",
                        year: "numeric",
                      })}
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      {v.status === "pending" ? (
                        <div className="flex items-center justify-center gap-2">
                          <button
                            onClick={() => handleApprove(v._id)}
                            disabled={actionLoading === v._id}
                            className="flex items-center gap-1 px-3 py-1.5 bg-green-600 text-white rounded-lg text-xs font-medium hover:bg-green-700 transition disabled:opacity-50"
                          >
                            <CheckCircle className="w-3.5 h-3.5" />
                            {actionLoading === v._id ? "..." : "Approve"}
                          </button>
                          <button
                            onClick={() => openRejectModal(v._id)}
                            disabled={actionLoading === v._id}
                            className="flex items-center gap-1 px-3 py-1.5 bg-red-600 text-white rounded-lg text-xs font-medium hover:bg-red-700 transition disabled:opacity-50"
                          >
                            <XCircle className="w-3.5 h-3.5" />
                            Reject
                          </button>
                        </div>
                      ) : (
                        <div className="text-center">
                          {v.status === "approved" && (
                            <p className="text-xs text-green-600 font-medium">
                              ✅ Approved — Rewards pending claim
                            </p>
                          )}
                          {v.adminNotes && (
                            <p className="text-xs text-gray-500 mt-1 truncate max-w-[200px]" title={v.adminNotes}>
                              {v.adminNotes}
                            </p>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {pagination.totalPages > 1 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200">
              <p className="text-sm text-gray-500">
                Page {pagination.page} of {pagination.totalPages} ({pagination.total} total)
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => fetchVerifications(pagination.page - 1)}
                  disabled={pagination.page <= 1}
                  className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronLeft className="w-4 h-4" />
                </button>
                <button
                  onClick={() => fetchVerifications(pagination.page + 1)}
                  disabled={pagination.page >= pagination.totalPages}
                  className="p-2 rounded-lg border border-gray-200 hover:bg-gray-50 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Reject Modal */}
      {showRejectModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6">
            <h3 className="text-lg font-bold text-gray-900 mb-2">Reject Verification</h3>
            <p className="text-sm text-gray-500 mb-4">
              Please provide a reason. The owner will be notified and the property will be reactivated.
            </p>
            <textarea
              value={rejectNotes}
              onChange={(e) => setRejectNotes(e.target.value)}
              placeholder="Enter rejection reason..."
              rows={4}
              className="w-full p-3 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-red-500 focus:border-transparent resize-none"
            />
            <div className="flex justify-end gap-3 mt-4">
              <button
                onClick={() => { setShowRejectModal(false); setSelectedVerification(null); }}
                className="px-4 py-2 text-sm font-medium text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleReject}
                disabled={actionLoading}
                className="px-4 py-2 text-sm font-medium text-white bg-red-600 rounded-lg hover:bg-red-700 transition disabled:opacity-50"
              >
                {actionLoading ? "Rejecting..." : "Reject Deal"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Document Viewer Modal */}
      {showDocModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-xl max-w-2xl w-full p-6 max-h-[80vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-gray-900">Proof Documents</h3>
              <button
                onClick={() => setShowDocModal(null)}
                className="p-2 rounded-lg hover:bg-gray-100 transition"
              >
                <XCircle className="w-5 h-5 text-gray-500" />
              </button>
            </div>
            <div className="space-y-4">
              {showDocModal.documentUrls?.map((url, idx) => {
                const isPdf = url.toLowerCase().includes(".pdf") || url.toLowerCase().includes("/raw/");
                return (
                  <div key={idx} className="border border-gray-200 rounded-lg overflow-hidden">
                    <div className="flex items-center justify-between px-3 py-2 bg-gray-50 border-b border-gray-200">
                      <span className="text-sm font-medium text-gray-700">
                        Document {idx + 1} {isPdf ? "(PDF)" : "(Image)"}
                      </span>
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 font-medium"
                      >
                        <ExternalLink className="w-4 h-4" />
                        Open in new tab
                      </a>
                    </div>
                    {!isPdf && (
                      <img
                        src={url}
                        alt={`Document ${idx + 1}`}
                        className="max-h-[500px] object-contain w-full bg-gray-50"
                      />
                    )}
                    {isPdf && (
                      <iframe
                        src={`https://docs.google.com/viewer?url=${encodeURIComponent(url)}&embedded=true`}
                        title={`Document ${idx + 1}`}
                        className="w-full bg-white"
                        style={{ height: "500px" }}
                        frameBorder="0"
                      />
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
