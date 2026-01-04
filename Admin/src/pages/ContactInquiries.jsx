import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
  Mail,
  Search,
  Filter,
  Eye,
  Trash2,
  CheckCircle,
  Clock,
  AlertCircle,
  MessageSquare,
  User,
  Phone,
  Calendar,
  X,
  Send,
  ChevronLeft,
  ChevronRight,
  RefreshCw,
  MailOpen,
  Tag,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:9000";

const ContactInquiries = () => {
  const [inquiries, setInquiries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState({});
  const [unreadCount, setUnreadCount] = useState(0);
  const [pagination, setPagination] = useState({
    page: 1,
    pages: 1,
    total: 0,
    limit: 20,
  });

  // Filters
  const [filters, setFilters] = useState({
    status: "",
    priority: "",
    category: "",
    search: "",
  });

  // Selected inquiry for detail view
  const [selectedInquiry, setSelectedInquiry] = useState(null);
  const [showDetailModal, setShowDetailModal] = useState(false);
  const [adminResponse, setAdminResponse] = useState("");
  const [adminNotes, setAdminNotes] = useState("");
  const [updating, setUpdating] = useState(false);

  // Fetch inquiries
  const fetchInquiries = async (page = 1) => {
    try {
      setLoading(true);
      const params = new URLSearchParams({
        page,
        limit: pagination.limit,
        ...(filters.status && { status: filters.status }),
        ...(filters.priority && { priority: filters.priority }),
        ...(filters.category && { category: filters.category }),
        ...(filters.search && { search: filters.search }),
      });

      // Using adminApi - cookies sent automatically
      const response = await adminApi.get(`/api/contact/admin/all?${params}`);

      if (response.data.success) {
        setInquiries(response.data.inquiries);
        setPagination(response.data.pagination);
        setStats(response.data.stats);
        setUnreadCount(response.data.unreadCount);
      }
    } catch (error) {
      console.error("Fetch inquiries error:", error);
      toast.error("Failed to fetch inquiries");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInquiries();
  }, [filters.status, filters.priority, filters.category]);

  // Search with debounce
  useEffect(() => {
    const timer = setTimeout(() => {
      if (filters.search !== undefined) {
        fetchInquiries(1);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [filters.search]);

  // View inquiry details
  const handleViewInquiry = async (inquiry) => {
    try {
      // Using adminApi - cookies sent automatically
      const response = await adminApi.get(`/api/contact/admin/${inquiry._id}`);

      if (response.data.success) {
        setSelectedInquiry(response.data.inquiry);
        setAdminResponse(response.data.inquiry.adminResponse || "");
        setAdminNotes(response.data.inquiry.adminNotes || "");
        setShowDetailModal(true);
        // Update local state to mark as read
        setInquiries((prev) =>
          prev.map((i) => (i._id === inquiry._id ? { ...i, isRead: true } : i))
        );
        setUnreadCount((prev) => Math.max(0, prev - 1));
      }
    } catch (error) {
      console.error("View inquiry error:", error);
      toast.error("Failed to load inquiry details");
    }
  };

  // Update inquiry
  const handleUpdateInquiry = async (updates) => {
    try {
      setUpdating(true);
      // Using adminApi - cookies sent automatically
      const response = await adminApi.put(
        `/api/contact/admin/${selectedInquiry._id}`,
        updates
      );

      if (response.data.success) {
        toast.success("Inquiry updated successfully");
        setSelectedInquiry(response.data.inquiry);
        fetchInquiries(pagination.page);
      }
    } catch (error) {
      console.error("Update inquiry error:", error);
      toast.error("Failed to update inquiry");
    } finally {
      setUpdating(false);
    }
  };

  // Delete inquiry
  const handleDeleteInquiry = async (id) => {
    if (!window.confirm("Are you sure you want to delete this inquiry?")) return;

    try {
      // Using adminApi - cookies sent automatically
      await adminApi.delete(`/api/contact/admin/${id}`);
      toast.success("Inquiry deleted");
      fetchInquiries(pagination.page);
      setShowDetailModal(false);
    } catch (error) {
      console.error("Delete inquiry error:", error);
      toast.error("Failed to delete inquiry");
    }
  };

  // Mark all as read
  const handleMarkAllRead = async () => {
    try {
      // Using adminApi - cookies sent automatically
      await adminApi.patch(`/api/contact/admin/mark-all-read`, {});
      toast.success("All marked as read");
      fetchInquiries(pagination.page);
    } catch (error) {
      console.error("Mark all read error:", error);
      toast.error("Failed to mark all as read");
    }
  };

  // Status badge colors
  const getStatusBadge = (status) => {
    const styles = {
      pending: "bg-yellow-100 text-yellow-700",
      "in-progress": "bg-blue-100 text-blue-700",
      resolved: "bg-green-100 text-green-700",
      closed: "bg-gray-100 text-gray-700",
    };
    return styles[status] || styles.pending;
  };

  // Priority badge colors
  const getPriorityBadge = (priority) => {
    const styles = {
      low: "bg-gray-100 text-gray-600",
      medium: "bg-blue-100 text-blue-600",
      high: "bg-orange-100 text-orange-600",
      urgent: "bg-red-100 text-red-600",
    };
    return styles[priority] || styles.medium;
  };

  // Category badge colors
  const getCategoryBadge = (category) => {
    const styles = {
      general: "bg-slate-100 text-slate-600",
      property: "bg-purple-100 text-purple-600",
      partnership: "bg-indigo-100 text-indigo-600",
      support: "bg-cyan-100 text-cyan-600",
      feedback: "bg-green-100 text-green-600",
      complaint: "bg-red-100 text-red-600",
      other: "bg-gray-100 text-gray-600",
    };
    return styles[category] || styles.general;
  };

  return (
    <div className="sm:p-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Mail className="h-7 w-7 text-blue-600" />
            Contact Inquiries
            {unreadCount > 0 && (
              <span className="ml-2 px-2.5 py-0.5 bg-red-500 text-white text-sm font-medium rounded-full">
                {unreadCount} new
              </span>
            )}
          </h1>
          <p className="text-gray-500 mt-1">Manage customer inquiries from the contact page</p>
        </div>
        <div className="flex gap-2 mt-4 md:mt-0">
          <button
            onClick={handleMarkAllRead}
            className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors"
          >
            <MailOpen className="h-4 w-4" />
            Mark All Read
          </button>
          <button
            onClick={() => fetchInquiries(pagination.page)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-yellow-100 rounded-lg">
              <Clock className="h-5 w-5 text-yellow-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-yellow-700">{stats.pending || 0}</p>
              <p className="text-sm text-yellow-600">Pending</p>
            </div>
          </div>
        </div>
        <div className="bg-blue-50 border border-blue-200 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-blue-100 rounded-lg">
              <AlertCircle className="h-5 w-5 text-blue-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-blue-700">{stats["in-progress"] || 0}</p>
              <p className="text-sm text-blue-600">In Progress</p>
            </div>
          </div>
        </div>
        <div className="bg-green-50 border border-green-200 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-green-100 rounded-lg">
              <CheckCircle className="h-5 w-5 text-green-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-green-700">{stats.resolved || 0}</p>
              <p className="text-sm text-green-600">Resolved</p>
            </div>
          </div>
        </div>
        <div className="bg-gray-50 border border-gray-200 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-gray-100 rounded-lg">
              <MessageSquare className="h-5 w-5 text-gray-600" />
            </div>
            <div>
              <p className="text-2xl font-bold text-gray-700">{pagination.total || 0}</p>
              <p className="text-sm text-gray-600">Total</p>
            </div>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 p-4 mb-6">
        <div className="flex flex-col md:flex-row gap-4">
          {/* Search */}
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-5 w-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search by name, email, subject..."
              value={filters.search}
              onChange={(e) => setFilters({ ...filters, search: e.target.value })}
              className="w-full pl-10 pr-4 py-2.5 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          {/* Status Filter */}
          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="px-4 py-2.5 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Status</option>
            <option value="pending">Pending</option>
            <option value="in-progress">In Progress</option>
            <option value="resolved">Resolved</option>
            <option value="closed">Closed</option>
          </select>

          {/* Priority Filter */}
          <select
            value={filters.priority}
            onChange={(e) => setFilters({ ...filters, priority: e.target.value })}
            className="px-4 py-2.5 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Priority</option>
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="urgent">Urgent</option>
          </select>

          {/* Category Filter */}
          <select
            value={filters.category}
            onChange={(e) => setFilters({ ...filters, category: e.target.value })}
            className="px-4 py-2.5 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value="">All Categories</option>
            <option value="general">General</option>
            <option value="property">Property</option>
            <option value="partnership">Partnership</option>
            <option value="support">Support</option>
            <option value="feedback">Feedback</option>
            <option value="complaint">Complaint</option>
            <option value="other">Other</option>
          </select>
        </div>
      </div>

      {/* Inquiries Table */}
      <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <div className="animate-spin rounded-full h-10 w-10 border-4 border-blue-500 border-t-transparent"></div>
          </div>
        ) : inquiries.length === 0 ? (
          <div className="text-center py-20">
            <Mail className="h-12 w-12 text-gray-300 mx-auto mb-4" />
            <p className="text-gray-500">No inquiries found</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-gray-50 border-b border-gray-200">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Sender
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Subject
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Category
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Status
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Priority
                  </th>
                  <th className="px-4 py-3 text-left text-xs font-semibold text-gray-600 uppercase">
                    Date
                  </th>
                  <th className="px-4 py-3 text-center text-xs font-semibold text-gray-600 uppercase">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {inquiries.map((inquiry) => (
                  <tr
                    key={inquiry._id}
                    className={`hover:bg-gray-50 transition-colors ${!inquiry.isRead ? "bg-blue-50/50" : ""
                      }`}
                  >
                    <td className="px-4 py-4">
                      <div className="flex items-center gap-3">
                        <div className="h-10 w-10 rounded-full bg-gradient-to-br from-blue-500 to-indigo-600 flex items-center justify-center text-white font-semibold">
                          {inquiry.userSnapshot?.name?.charAt(0)?.toUpperCase() || "U"}
                        </div>
                        <div>
                          <p className="font-medium text-gray-900 flex items-center gap-2">
                            {inquiry.userSnapshot?.name}
                            {!inquiry.isRead && (
                              <span className="h-2 w-2 bg-blue-500 rounded-full"></span>
                            )}
                          </p>
                          <p className="text-sm text-gray-500">{inquiry.userSnapshot?.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-4">
                      <p className="font-medium text-gray-900 truncate max-w-xs">{inquiry.subject}</p>
                      <p className="text-sm text-gray-500 truncate max-w-xs">{inquiry.message}</p>
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getCategoryBadge(
                          inquiry.category
                        )}`}
                      >
                        {inquiry.category}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getStatusBadge(
                          inquiry.status
                        )}`}
                      >
                        {inquiry.status}
                      </span>
                    </td>
                    <td className="px-4 py-4">
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getPriorityBadge(
                          inquiry.priority
                        )}`}
                      >
                        {inquiry.priority}
                      </span>
                    </td>
                    <td className="px-4 py-4 text-sm text-gray-500">
                      {new Date(inquiry.createdAt).toLocaleDateString("en-IN", {
                        day: "numeric",
                        month: "short",
                        year: "numeric",
                      })}
                    </td>
                    <td className="px-4 py-4">
                      <div className="flex items-center justify-center gap-2">
                        <button
                          onClick={() => handleViewInquiry(inquiry)}
                          className="p-2 text-blue-600 hover:bg-blue-50 rounded-lg transition-colors"
                          title="View Details"
                        >
                          <Eye className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => handleDeleteInquiry(inquiry._id)}
                          className="p-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {pagination.pages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 bg-gray-50">
            <p className="text-sm text-gray-600">
              Showing {(pagination.page - 1) * pagination.limit + 1} to{" "}
              {Math.min(pagination.page * pagination.limit, pagination.total)} of {pagination.total}{" "}
              inquiries
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => fetchInquiries(pagination.page - 1)}
                disabled={pagination.page <= 1}
                className="p-2 border border-gray-200 rounded-lg hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="h-4 w-4" />
              </button>
              <span className="px-3 py-1 bg-blue-600 text-white rounded-lg text-sm font-medium">
                {pagination.page}
              </span>
              <button
                onClick={() => fetchInquiries(pagination.page + 1)}
                disabled={pagination.page >= pagination.pages}
                className="p-2 border border-gray-200 rounded-lg hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Detail Modal */}
      {showDetailModal && selectedInquiry && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            {/* Modal Header */}
            <div className="sticky top-0 bg-white border-b border-gray-200 px-6 py-4 flex items-center justify-between">
              <h2 className="text-xl font-bold text-gray-900">Inquiry Details</h2>
              <button
                onClick={() => setShowDetailModal(false)}
                className="p-2 hover:bg-gray-100 rounded-lg transition-colors"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            {/* Modal Content */}
            <div className="p-6 space-y-6">
              {/* Sender Info */}
              <div className="bg-gray-50 rounded-xl p-4">
                <h3 className="font-semibold text-gray-900 mb-3 flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Sender Information
                </h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-sm text-gray-500">Name</p>
                    <p className="font-medium">{selectedInquiry.userSnapshot?.name}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Email</p>
                    <p className="font-medium">{selectedInquiry.userSnapshot?.email}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Phone</p>
                    <p className="font-medium">{selectedInquiry.userSnapshot?.phone || "N/A"}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-500">Submitted</p>
                    <p className="font-medium">
                      {new Date(selectedInquiry.createdAt).toLocaleString("en-IN")}
                    </p>
                  </div>
                </div>
              </div>

              {/* Inquiry Details */}
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <span
                    className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getCategoryBadge(
                      selectedInquiry.category
                    )}`}
                  >
                    {selectedInquiry.category}
                  </span>
                  <span
                    className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getStatusBadge(
                      selectedInquiry.status
                    )}`}
                  >
                    {selectedInquiry.status}
                  </span>
                  <span
                    className={`px-2.5 py-1 rounded-full text-xs font-medium capitalize ${getPriorityBadge(
                      selectedInquiry.priority
                    )}`}
                  >
                    {selectedInquiry.priority}
                  </span>
                </div>
                <h3 className="font-semibold text-gray-900 text-lg">{selectedInquiry.subject}</h3>
                <div className="mt-3 p-4 bg-gray-50 rounded-xl">
                  <p className="text-gray-700 whitespace-pre-wrap">{selectedInquiry.message}</p>
                </div>
              </div>

              {/* Update Status & Priority */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-700 mb-1 block">Status</label>
                  <select
                    value={selectedInquiry.status}
                    onChange={(e) =>
                      handleUpdateInquiry({ status: e.target.value })
                    }
                    disabled={updating}
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="pending">Pending</option>
                    <option value="in-progress">In Progress</option>
                    <option value="resolved">Resolved</option>
                    <option value="closed">Closed</option>
                  </select>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700 mb-1 block">Priority</label>
                  <select
                    value={selectedInquiry.priority}
                    onChange={(e) =>
                      handleUpdateInquiry({ priority: e.target.value })
                    }
                    disabled={updating}
                    className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="urgent">Urgent</option>
                  </select>
                </div>
              </div>

              {/* Admin Notes */}
              <div>
                <label className="text-sm font-medium text-gray-700 mb-1 block">
                  Internal Notes (not visible to user)
                </label>
                <textarea
                  value={adminNotes}
                  onChange={(e) => setAdminNotes(e.target.value)}
                  placeholder="Add internal notes..."
                  rows={3}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
                <button
                  onClick={() => handleUpdateInquiry({ adminNotes })}
                  disabled={updating}
                  className="mt-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition-colors text-sm disabled:opacity-50"
                >
                  Save Notes
                </button>
              </div>

              {/* Admin Response */}
              <div>
                <label className="text-sm font-medium text-gray-700 mb-1 block">
                  Response to User
                </label>
                <textarea
                  value={adminResponse}
                  onChange={(e) => setAdminResponse(e.target.value)}
                  placeholder="Write your response..."
                  rows={4}
                  className="w-full px-3 py-2 border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
                <button
                  onClick={() => handleUpdateInquiry({ adminResponse, status: "resolved" })}
                  disabled={updating || !adminResponse.trim()}
                  className="mt-2 flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm disabled:opacity-50"
                >
                  <Send className="h-4 w-4" />
                  Send Response & Mark Resolved
                </button>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="sticky bottom-0 bg-gray-50 border-t border-gray-200 px-6 py-4 flex justify-between">
              <button
                onClick={() => handleDeleteInquiry(selectedInquiry._id)}
                className="flex items-center gap-2 px-4 py-2 text-red-600 hover:bg-red-50 rounded-lg transition-colors"
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </button>
              <button
                onClick={() => setShowDetailModal(false)}
                className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ContactInquiries;
