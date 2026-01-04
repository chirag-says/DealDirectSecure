import { Link } from "react-router-dom";
import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import { Flag } from "lucide-react";

// Use the correct environment variable for Admin panel
const API_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:9000";

const ReportedMessages = () => {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);
    const [page, setPage] = useState(1);
    const [limit] = useState(10);
    const [totalPages, setTotalPages] = useState(1);
    const [statusFilter, setStatusFilter] = useState("all");

    const fetchReports = async () => {
        try {
            setLoading(true);

            console.log("Fetching reports using adminApi");

            // Using adminApi - cookies sent automatically
            const res = await adminApi.get(`/api/admin/reports`, {
                params: {
                    page,
                    limit,
                    status: statusFilter,
                },
            });

            if (res.data.success) {
                setReports(res.data.data);
                setTotalPages(res.data.pagination.pages);
            }
        } catch (error) {
            console.error("Error fetching reports:", error);
            toast.error(error.response?.data?.message || "Failed to fetch reports");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchReports();
    }, [page, statusFilter]);

    const handleStatusUpdate = async (reportId, newStatus) => {
        try {
            // Using adminApi - cookies sent automatically
            await adminApi.put(`/api/admin/reports/${reportId}`,
                { status: newStatus }
            );
            toast.success("Status updated successfully");
            fetchReports();
        } catch (error) {
            console.error("Error updating status:", error);
            toast.error("Failed to update status");
        }
    };

    const getStatusColor = (status) => {
        switch (status) {
            case "pending": return "text-yellow-800 bg-yellow-100";
            case "reviewed": return "text-blue-800 bg-blue-100";
            case "resolved": return "text-green-800 bg-green-100";
            case "dismissed": return "text-gray-800 bg-gray-100";
            default: return "text-gray-800 bg-gray-100";
        }
    };

    return (
        <div className="sm:p-6">
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-xl sm:text-2xl font-bold text-gray-800 flex items-center gap-2">
                    <Flag className="w-6 h-6 text-red-600" />
                    Reported Messages
                </h1>

                <select
                    value={statusFilter}
                    onChange={(e) => setStatusFilter(e.target.value)}
                    className="border border-gray-300 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                    <option value="all">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="reviewed">Reviewed</option>
                    <option value="resolved">Resolved</option>
                    <option value="dismissed">Dismissed</option>
                </select>
            </div>

            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm text-left">
                        <thead className="bg-gray-50 text-gray-600 font-medium border-b border-gray-200">
                            <tr>
                                <th className="px-6 py-4">Status</th>
                                <th className="px-6 py-4">Reported By</th>
                                <th className="px-6 py-4">Reason</th>
                                <th className="px-6 py-4">Message Content</th>
                                <th className="px-6 py-4">Sender</th>
                                <th className="px-6 py-4">Date</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                            {loading ? (
                                <tr>
                                    <td colSpan="6" className="px-6 py-8 text-center text-gray-500">
                                        Loading reports...
                                    </td>
                                </tr>
                            ) : reports.length === 0 ? (
                                <tr>
                                    <td colSpan="6" className="px-6 py-8 text-center text-gray-500">
                                        No reports found.
                                    </td>
                                </tr>
                            ) : (
                                reports.map((report) => (
                                    <tr key={report._id} className="hover:bg-gray-50 transition-colors">
                                        <td className="px-6 py-4">
                                            <select
                                                value={report.status}
                                                onChange={(e) => handleStatusUpdate(report._id, e.target.value)}
                                                className={`text-xs px-2 py-1 rounded-full border-none focus:ring-1 focus:ring-offset-1 focus:ring-blue-500 cursor-pointer ${getStatusColor(report.status)}`}
                                            >
                                                <option value="pending">Pending</option>
                                                <option value="reviewed">Reviewed</option>
                                                <option value="resolved">Resolved</option>
                                                <option value="dismissed">Dismissed</option>
                                            </select>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="font-medium text-gray-900">{report.reportedBy?.name || "Unknown"}</div>
                                            <div className="text-xs text-gray-500">{report.reportedBy?.email}</div>
                                        </td>
                                        <td className="px-6 py-4 text-gray-600 font-medium">
                                            {report.reason}
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="max-w-xs text-xs text-gray-600 bg-gray-50 p-2 rounded border border-gray-100">
                                                {report.message?.text || "Message content not available"}
                                            </div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <div className="text-gray-600 font-medium">
                                                {report.message?.sender?.name || "Unknown"}
                                            </div>
                                            {report.message?.sender?._id && (
                                                <Link
                                                    to={
                                                        report.message.sender.role === 'owner'
                                                            ? `/all-owners?search=${report.message.sender.email}`
                                                            : `/all-clients?search=${report.message.sender.email}`
                                                    }
                                                    className="text-xs text-blue-600 hover:underline mt-1 block"
                                                >
                                                    Manage User
                                                </Link>
                                            )}
                                        </td>
                                        <td className="px-6 py-4 text-gray-500 whitespace-nowrap">
                                            {new Date(report.createdAt).toLocaleDateString()}
                                        </td>
                                    </tr>
                                ))
                            )}
                        </tbody>
                    </table>
                </div>

                {/* Pagination */}
                {totalPages > 1 && (
                    <div className="px-6 py-4 border-t border-gray-200 flex items-center justify-between">
                        <button
                            onClick={() => setPage(Math.max(1, page - 1))}
                            disabled={page === 1}
                            className="px-3 py-1 text-sm bg-white border border-gray-300 rounded hover:bg-gray-50 disabled:opacity-50"
                        >
                            Previous
                        </button>
                        <span className="text-sm text-gray-600">
                            Page {page} of {totalPages}
                        </span>
                        <button
                            onClick={() => setPage(Math.min(totalPages, page + 1))}
                            disabled={page === totalPages}
                            className="px-3 py-1 text-sm bg-white border border-gray-300 rounded hover:bg-gray-50 disabled:opacity-50"
                        >
                            Next
                        </button>
                    </div>
                )}
            </div>
        </div>
    );
};

export default ReportedMessages;
