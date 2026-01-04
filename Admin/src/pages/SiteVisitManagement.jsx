import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import {
  CalendarDays,
  User,
  MapPin,
  Info,
  CircleCheck,
  XCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  RefreshCw,
  Calendar,
} from "lucide-react";

const API_URL = import.meta.env.VITE_API_BASE_URL;

// Helper function to safely format date
const formatDate = (dateString) => {
  if (!dateString) return "N/A";
  try {
    return new Date(dateString).toLocaleDateString("en-GB");
  } catch {
    return "Invalid Date";
  }
};

export default function SiteVisitManagement() {
  const [leads, setLeads] = useState([]);
  const [loading, setLoading] = useState(true);
  // Auth handled by adminApi via cookies

  // Fetch leads that are interested or negotiating (potential site visits)
  const fetchPotentialVisits = async () => {
    try {
      setLoading(true);
      // Using adminApi - cookies sent automatically
      const { data } = await adminApi.get(`/api/admin/leads`);

      if (data.success) {
        // Filter leads that are in interested or negotiating status (potential visits)
        const potentialVisits = (data.data || []).filter(
          (lead) => lead.status === "interested" || lead.status === "negotiating"
        );
        setLeads(potentialVisits);
      }
    } catch (error) {
      console.error("Failed to fetch leads:", error);
      // 401 errors are handled by adminApi interceptor
      if (error.response?.status !== 401) {
        toast.error("Failed to fetch potential site visits");
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPotentialVisits();
  }, []);

  const updateLeadStatus = async (leadId, newStatus) => {
    try {
      // Using adminApi - cookies sent automatically
      const { data } = await adminApi.put(
        `/api/admin/leads/${leadId}`,
        { status: newStatus }
      );

      if (data.success) {
        toast.success(`Lead marked as ${newStatus}`);
        fetchPotentialVisits(); // Refresh the list
      }
    } catch (error) {
      toast.error("Failed to update status");
    }
  };

  const statusColors = {
    interested: "bg-purple-100 text-purple-800",
    negotiating: "bg-orange-100 text-orange-800",
    converted: "bg-green-100 text-green-800",
    lost: "bg-red-100 text-red-700",
  };

  return (
    <div className="p-6 bg-gray-100 min-h-screen">
      {/* Header */}
      <div className="mb-6 flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">
            Site Visit Management
          </h1>
          <p className="text-gray-600 mt-1">
            Track interested leads and manage potential site visits
          </p>
        </div>
        <button
          onClick={fetchPotentialVisits}
          disabled={loading}
          className="p-3 bg-white rounded-xl shadow hover:shadow-lg transition-all"
        >
          <RefreshCw className={`w-5 h-5 text-gray-700 ${loading ? 'animate-spin' : ''}`} />
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex justify-center items-center py-20">
          <Loader2 className="w-10 h-10 animate-spin text-blue-600" />
        </div>
      ) : leads.length === 0 ? (
        <div className="text-center py-20 bg-white rounded-xl shadow">
          <Calendar className="w-16 h-16 mx-auto mb-4 text-gray-300" />
          <p className="text-xl font-medium text-gray-700">No potential site visits</p>
          <p className="text-sm text-gray-500 mt-2">
            Leads marked as "Interested" or "Negotiating" will appear here for site visit scheduling
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {leads.map((lead) => (
            <div
              key={lead._id}
              className="bg-white rounded-xl shadow-md p-5 border border-gray-200 hover:shadow-lg transition"
            >
              {/* Top Section */}
              <div className="flex justify-between items-center mb-3">
                <span
                  className={`px-3 py-1 rounded-full text-sm font-medium ${statusColors[lead.status]}`}
                >
                  {lead.status.charAt(0).toUpperCase() + lead.status.slice(1)}
                </span>

                <div className="flex items-center text-gray-600">
                  <CalendarDays size={18} className="mr-1" /> {formatDate(lead.createdAt)}
                </div>
              </div>

              {/* Buyer & Property Info */}
              <div className="space-y-2">
                <div className="flex gap-2 items-center">
                  <User size={18} className="text-gray-700" />
                  <div>
                    <span className="font-medium">
                      {lead.user?.name || lead.userSnapshot?.name || "Unknown Buyer"}
                    </span>
                    {lead.user?.phone && (
                      <span className="text-sm text-gray-500 ml-2">({lead.user.phone})</span>
                    )}
                  </div>
                </div>

                <div className="flex gap-2 items-center">
                  <MapPin size={18} className="text-gray-700" />
                  <span>
                    {lead.property?.title || lead.propertySnapshot?.title || "N/A"} - {" "}
                    {lead.property?.address?.city || lead.propertySnapshot?.city || ""}
                  </span>
                </div>

                {lead.propertyOwner && (
                  <div className="text-sm text-gray-500">
                    Owner: {lead.propertyOwner.name} ({lead.propertyOwner.phone || lead.propertyOwner.email})
                  </div>
                )}
              </div>

              {/* Actions */}
              <div className="mt-4 flex flex-wrap gap-3">
                {lead.status === "interested" && (
                  <button
                    onClick={() => updateLeadStatus(lead._id, "negotiating")}
                    className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 flex items-center gap-2"
                  >
                    <CircleCheck size={18} /> Start Negotiation
                  </button>
                )}

                {lead.status === "negotiating" && (
                  <button
                    onClick={() => updateLeadStatus(lead._id, "converted")}
                    className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 flex items-center gap-2"
                  >
                    <CheckCircle2 size={18} /> Mark Converted
                  </button>
                )}

                <button
                  onClick={() => updateLeadStatus(lead._id, "lost")}
                  className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 flex items-center gap-2"
                >
                  <XCircle size={18} /> Mark Lost
                </button>

                {lead.user?.email && (
                  <a
                    href={`mailto:${lead.user.email}?subject=Site Visit for ${lead.property?.title || "Property"}`}
                    className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 flex items-center gap-2"
                  >
                    <Info size={18} /> Contact
                  </a>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
