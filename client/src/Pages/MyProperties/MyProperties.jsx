import React, { useState, useEffect, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import axios from "axios";
import { toast } from "react-toastify";
import {
  Home,
  Building2,
  Eye,
  Heart,
  Phone,
  MessageSquare,
  TrendingUp,
  Calendar,
  MapPin,
  IndianRupee,
  Edit3,
  Trash2,
  Plus,
  MoreVertical,
  Filter,
  Search,
  ChevronDown,
  ExternalLink,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle,
  BarChart3,
  Users,
  Layers,
  RefreshCw,
  Mail,
  User,
  ChevronRight,
  TrendingDown,
  Target,
  UserCheck,
  UserX,
  MessageCircle,
  PhoneCall,
  FileText, // Imported for Export button
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  AreaChart,
  Area,
} from "recharts";

const API_BASE = import.meta.env.VITE_API_BASE;

// ... [Keep StatusBadge, LeadStatusBadge, StatsCard, PropertyCard, LeadCard, and COLORS exactly as they were] ...
// (I am omitting the sub-components here for brevity, assume they are present as in your original code)

const resolveImageSrc = (img) => {
  if (!img) return "https://images.unsplash.com/photo-1560518883-ce09059eeffa?w=400";
  const s = String(img).trim();
  const lower = s.toLowerCase();
  if (lower.startsWith("data:") || lower.startsWith("http")) return s;
  if (s.startsWith("/uploads")) return `${API_BASE}${s}`;
  return `${API_BASE}/uploads/${s}`;
};

// Status badge component
const StatusBadge = ({ status }) => {
  const statusConfig = {
    active: { bg: "bg-green-100", text: "text-green-700", icon: CheckCircle, label: "Active" },
    pending: { bg: "bg-amber-100", text: "text-amber-700", icon: Clock, label: "Pending" },
    sold: { bg: "bg-blue-100", text: "text-blue-700", icon: CheckCircle, label: "Sold" },
    rented: { bg: "bg-purple-100", text: "text-purple-700", icon: CheckCircle, label: "Rented" },
    inactive: { bg: "bg-gray-100", text: "text-gray-700", icon: XCircle, label: "Inactive" },
  };

  const config = statusConfig[status] || statusConfig.pending;
  const Icon = config.icon;

  return (
    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium ${config.bg} ${config.text}`}>
      <Icon className="w-3.5 h-3.5" />
      {config.label}
    </span>
  );
};

// Lead Status Badge
const LeadStatusBadge = ({ status }) => {
  const statusConfig = {
    new: { bg: "bg-blue-100", text: "text-blue-700", label: "New" },
    contacted: { bg: "bg-yellow-100", text: "text-yellow-700", label: "Contacted" },
    interested: { bg: "bg-purple-100", text: "text-purple-700", label: "Interested" },
    negotiating: { bg: "bg-orange-100", text: "text-orange-700", label: "Negotiating" },
    converted: { bg: "bg-green-100", text: "text-green-700", label: "Converted" },
    lost: { bg: "bg-red-100", text: "text-red-700", label: "Lost" },
  };

  const config = statusConfig[status] || statusConfig.new;

  return (
    <span className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium ${config.bg} ${config.text}`}>
      {config.label}
    </span>
  );
};

// Stats Card component
const StatsCard = ({ icon: Icon, label, value, trend, color, subLabel }) => (
  <div className="bg-white rounded-xl border border-gray-200 p-5 hover:shadow-md transition-shadow">
    <div className="flex items-center justify-between">
      <div className={`p-3 rounded-xl ${color}`}>
        <Icon className="w-6 h-6 text-white" />
      </div>
      {trend !== undefined && (
        <span className={`text-xs font-medium flex items-center gap-1 ${trend >= 0 ? "text-green-600" : "text-red-600"}`}>
          {trend >= 0 ? <TrendingUp className="w-3.5 h-3.5" /> : <TrendingDown className="w-3.5 h-3.5" />}
          {Math.abs(trend)}%
        </span>
      )}
    </div>
    <p className="mt-4 text-2xl font-bold text-gray-900">{value}</p>
    <p className="text-sm text-gray-500">{label}</p>
    {subLabel && <p className="text-xs text-gray-400 mt-1">{subLabel}</p>}
  </div>
);

// Property Card component
const PropertyCard = ({ property, onEdit, onDelete, onViewDetails, onViewLeads }) => {
  const [showMenu, setShowMenu] = useState(false);

  const formatPrice = (price) => {
    if (!price) return "Price on Request";
    if (price >= 10000000) return `₹${(price / 10000000).toFixed(2)} Cr`;
    if (price >= 100000) return `₹${(price / 100000).toFixed(2)} Lac`;
    return `₹${price.toLocaleString()}`;
  };

  const getMainImage = () => {
    if (property.categorizedImages) {
      if (property.categorizedImages.residential) {
        const residentialCategories = ['exterior', 'livingRoom', 'bedroom', 'hall', 'balcony', 'kitchen'];
        for (const cat of residentialCategories) {
          if (property.categorizedImages.residential[cat]?.length > 0) {
            return resolveImageSrc(property.categorizedImages.residential[cat][0]);
          }
        }
      }
      if (property.categorizedImages.commercial) {
        const commercialCategories = ['facade', 'reception', 'workArea', 'cabin', 'shopFloor'];
        for (const cat of commercialCategories) {
          if (property.categorizedImages.commercial[cat]?.length > 0) {
            return resolveImageSrc(property.categorizedImages.commercial[cat][0]);
          }
        }
      }
    }
    if (property.images?.length > 0) {
      return resolveImageSrc(property.images[0]);
    }
    return resolveImageSrc(null);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-white rounded-xl border border-gray-200 overflow-hidden hover:shadow-lg transition-all group"
    >
      {/* Image Section */}
      <div className="relative h-48 overflow-hidden">
        <img
          src={getMainImage()}
          alt={property.title}
          loading="lazy"
          onError={(e) => {
            e.target.onerror = null;
            e.target.src = resolveImageSrc(null);
          }}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
        />
        <div className="absolute top-3 left-3">
          <StatusBadge status={property.status || "active"} />
        </div>
        <div className="absolute top-3 right-3">
          <div className="relative">
            <button
              onClick={() => setShowMenu(!showMenu)}
              className="p-2 bg-white/90 backdrop-blur rounded-lg hover:bg-white transition shadow-sm"
            >
              <MoreVertical className="w-4 h-4 text-gray-700" />
            </button>
            <AnimatePresence>
              {showMenu && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95 }}
                  className="absolute right-0 mt-2 w-44 bg-white rounded-lg shadow-xl border border-gray-100 py-1 z-10"
                >
                  <button
                    onClick={() => { onViewDetails(property); setShowMenu(false); }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2"
                  >
                    <ExternalLink className="w-4 h-4" /> View Details
                  </button>
                  <button
                    onClick={() => { onViewLeads(property); setShowMenu(false); }}
                    className="w-full px-4 py-2 text-left text-sm text-blue-600 hover:bg-blue-50 flex items-center gap-2"
                  >
                    <Users className="w-4 h-4" /> View Leads
                  </button>
                  <button
                    onClick={() => { onEdit(property); setShowMenu(false); }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 flex items-center gap-2"
                  >
                    <Edit3 className="w-4 h-4" /> Edit Property
                  </button>
                  <button
                    onClick={() => { onDelete(property); setShowMenu(false); }}
                    className="w-full px-4 py-2 text-left text-sm text-red-600 hover:bg-red-50 flex items-center gap-2"
                  >
                    <Trash2 className="w-4 h-4" /> Delete
                  </button>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
        <div className="absolute bottom-3 left-3 right-3 flex justify-between">
          <span className="px-2.5 py-1 bg-black/70 backdrop-blur text-white text-xs font-medium rounded-lg">
            {property.listingType || "Rent"}
          </span>
          <span className="px-2.5 py-1 bg-white/90 backdrop-blur text-gray-800 text-xs font-medium rounded-lg">
            {typeof property.propertyType === 'object' ? property.propertyType?.name : property.propertyType || property.propertyTypeName || "Property"}
          </span>
        </div>
      </div>

      {/* Content Section */}
      <div className="p-4">
        <h3 className="font-semibold text-gray-900 text-lg line-clamp-1 mb-1">
          {property.title}
        </h3>
        <p className="text-sm text-gray-500 flex items-center gap-1 mb-3">
          <MapPin className="w-3.5 h-3.5" />
          {property.locality || property.address?.locality || property.address?.area || "N/A"}, {property.city || property.address?.city || "N/A"}
        </p>

        <div className="flex items-center justify-between mb-4">
          <div>
            <p className="text-xl font-bold text-gray-900">{formatPrice(property.price || property.expectedPrice)}</p>
            {property.listingType === "Rent" && (
              <p className="text-xs text-gray-500">per month</p>
            )}
          </div>
          <div className="text-right">
            {(property.builtUpArea || property.area?.builtUpSqft) && (
              <p className="text-sm font-medium text-gray-700">{property.builtUpArea || property.area?.builtUpSqft} sq.ft</p>
            )}
            {property.bhk && (
              <p className="text-xs text-gray-500">{property.bhk}</p>
            )}
          </div>
        </div>

        {/* Stats Row */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-100">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5 text-gray-500">
              <Eye className="w-4 h-4" />
              <span className="text-sm font-medium">{property.views || 0}</span>
            </div>
            <div className="flex items-center gap-1.5 text-gray-500">
              <Heart className="w-4 h-4" />
              <span className="text-sm font-medium">{property.likes || 0}</span>
            </div>
            <div className="flex items-center gap-1.5 text-blue-600">
              <Users className="w-4 h-4" />
              <span className="text-sm font-medium">{property.interestedUsers?.length || 0}</span>
            </div>
          </div>
          <p className="text-xs text-gray-400">
            {new Date(property.createdAt).toLocaleDateString("en-IN", { day: "numeric", month: "short" })}
          </p>
        </div>
      </div>
    </motion.div>
  );
};

// Lead Card Component
const LeadCard = ({ lead, onUpdateStatus, onContact }) => {
  const [showActions, setShowActions] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, x: -20 }}
      animate={{ opacity: 1, x: 0 }}
      className="bg-white rounded-xl border border-gray-200 p-4 hover:shadow-md transition-all"
    >
      <div className="flex items-start gap-4">
        {/* User Avatar */}
        <div className="flex-shrink-0">
          {lead.userSnapshot?.profileImage ? (
            <img
              src={lead.userSnapshot.profileImage}
              alt={lead.userSnapshot.name}
              className="w-12 h-12 rounded-full object-cover border-2 border-gray-200"
            />
          ) : (
            <div className="w-12 h-12 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold text-lg">
              {lead.userSnapshot?.name?.charAt(0)?.toUpperCase() || "U"}
            </div>
          )}
        </div>

        {/* Lead Info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between">
            <div>
              <h4 className="font-semibold text-gray-900">{lead.userSnapshot?.name || "Unknown User"}</h4>
              <p className="text-sm text-gray-500 flex items-center gap-1">
                <Mail className="w-3.5 h-3.5" />
                {lead.userSnapshot?.email}
              </p>
              {lead.userSnapshot?.phone && (
                <p className="text-sm text-gray-500 flex items-center gap-1">
                  <Phone className="w-3.5 h-3.5" />
                  {lead.userSnapshot.phone}
                </p>
              )}
            </div>
            <div className="flex items-center gap-2">
              <LeadStatusBadge status={lead.status} />
              {!lead.isViewed && (
                <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse" title="New lead"></span>
              )}
            </div>
          </div>

          {/* Property Info */}
          <div className="mt-3 p-2 bg-gray-50 rounded-lg">
            <p className="text-sm font-medium text-gray-700 line-clamp-1">
              {lead.propertySnapshot?.title || "Property"}
            </p>
            <p className="text-xs text-gray-500">
              {lead.propertySnapshot?.locality}, {lead.propertySnapshot?.city} • ₹{(lead.propertySnapshot?.price || 0).toLocaleString()}
            </p>
          </div>

          {/* Timestamp */}
          <p className="text-xs text-gray-400 mt-2">
            Interested on {new Date(lead.createdAt).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" })}
          </p>
        </div>
      </div>

      {/* Action Buttons */}
      <div className="mt-4 flex items-center gap-2 flex-wrap">
        <a
          href={`tel:${lead.userSnapshot?.phone}`}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-green-100 text-green-700 rounded-lg text-sm font-medium hover:bg-green-200 transition"
        >
          <PhoneCall className="w-4 h-4" /> Call
        </a>
        <a
          href={`mailto:${lead.userSnapshot?.email}`}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-100 text-blue-700 rounded-lg text-sm font-medium hover:bg-blue-200 transition"
        >
          <Mail className="w-4 h-4" /> Email
        </a>
        <a
          href={`https://wa.me/${lead.userSnapshot?.phone?.replace(/\D/g, '')}`}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-100 text-emerald-700 rounded-lg text-sm font-medium hover:bg-emerald-200 transition"
        >
          <MessageCircle className="w-4 h-4" /> WhatsApp
        </a>
        <div className="relative ml-auto">
          <button
            onClick={() => setShowActions(!showActions)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-100 text-gray-700 rounded-lg text-sm font-medium hover:bg-gray-200 transition"
          >
            Update Status <ChevronDown className="w-4 h-4" />
          </button>
          <AnimatePresence>
            {showActions && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="absolute right-0 bottom-full mb-2 w-40 bg-white rounded-lg shadow-xl border border-gray-100 py-1 z-20"
              >
                {["contacted", "interested", "negotiating", "converted", "lost"].map((status) => (
                  <button
                    key={status}
                    onClick={() => { onUpdateStatus(lead._id, status); setShowActions(false); }}
                    className="w-full px-4 py-2 text-left text-sm text-gray-700 hover:bg-gray-50 capitalize"
                  >
                    {status}
                  </button>
                ))}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.div>
  );
};

// Chart Colors
const COLORS = ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];

export default function MyProperties() {
  const navigate = useNavigate();
  const [user, setUser] = useState(null);
  const [properties, setProperties] = useState([]);
  const [leads, setLeads] = useState([]);
  const [leadAnalytics, setLeadAnalytics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState("properties"); // 'properties', 'leads', 'analytics'
  const [filter, setFilter] = useState("all");
  const [leadFilter, setLeadFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState("newest");
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [propertyToDelete, setPropertyToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [selectedPropertyForLeads, setSelectedPropertyForLeads] = useState(null);

  // === NEW STATE for Date Filter & Export ===
  const [startDateFilter, setStartDateFilter] = useState("");
  const [endDateFilter, setEndDateFilter] = useState("");
  const [isExporting, setIsExporting] = useState(false);
  const [todayLeadsCount, setTodayLeadsCount] = useState(0);

  // Auth check
  useEffect(() => {
    const storedUser = localStorage.getItem("user");
    const token = localStorage.getItem("token");

    if (!storedUser || !token) {
      toast.error("Please login to view your properties");
      navigate("/login");
      return;
    }

    const parsedUser = JSON.parse(storedUser);
    setUser(parsedUser);

    if (parsedUser.role !== "owner" && parsedUser.role !== "agent") {
      toast.error("Only property owners can access this page");
      navigate("/");
      return;
    }

    fetchData();
  }, [navigate]);

  // Memoized fetchData function to handle date filters
  const fetchData = useCallback(async (isRefresh = false, startFilter = startDateFilter, endFilter = endDateFilter) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      const token = localStorage.getItem("token");

      // Fetch properties first
      const propertiesRes = await axios.get(`${API_BASE}/api/properties/my-properties`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (propertiesRes.data.success) {
        setProperties(propertiesRes.data.data || []);
      }

      // Build Lead Query Params
      const leadParams = new URLSearchParams();
      if (startFilter) leadParams.append('startDate', startFilter);
      if (endFilter) leadParams.append('endDate', endFilter);

      // Try to fetch leads and analytics
      try {
        const [leadsRes, analyticsRes] = await Promise.all([
          axios.get(`${API_BASE}/api/leads?${leadParams.toString()}`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
          axios.get(`${API_BASE}/api/leads/analytics`, {
            headers: { Authorization: `Bearer ${token}` },
          })
        ]);

        if (leadsRes.data.success) {
          setLeads(leadsRes.data.data || []);
          // Update today's lead count if available in stats
          if (leadsRes.data.stats && leadsRes.data.stats.today !== undefined) {
             setTodayLeadsCount(leadsRes.data.stats.today);
          }
        }

        if (analyticsRes.data.success) {
          setLeadAnalytics(analyticsRes.data.data);
        }
      } catch (leadErr) {
        console.error("Error fetching leads data:", leadErr.message);
        setLeads([]);
        setLeadAnalytics(null);
        setTodayLeadsCount(0);
      }

      setLastUpdated(new Date());
    } catch (err) {
      console.error("Error fetching data:", err);
      toast.error("Failed to load data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [startDateFilter, endDateFilter]); 

  // Initial Fetch (Component Mount)
  useEffect(() => {
    fetchData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // Only run once on mount

  // === DATE FILTER LOGIC ===
  const handleApplyDateFilter = () => {
    if (!startDateFilter || !endDateFilter) {
      toast.error("Please select both start and end dates.");
      return;
    }

    const start = new Date(startDateFilter);
    const end = new Date(endDateFilter);
    
    if (start > end) {
      toast.error("Start date cannot be after end date.");
      return;
    }

    // Calculate the difference in days
    const diffTime = Math.abs(end.getTime() - start.getTime());
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24)); // Difference in days
    
    // 7-day restriction check (allow 0-7 days inclusive)
    if (diffDays > 7) {
      toast.error(
        <div className="flex flex-col">
          <p>You can only view up to <strong>7 days</strong> of leads at once.</p>
          <p className="mt-2 text-sm">For historical data exceeding 7 days, please use the <strong>Export 3-Month Data</strong> button or contact <strong>dealdirect@gmail.com</strong>.</p>
        </div>
      );
      return;
    }

    // Trigger fetchData with the new dates
    fetchData(false, startDateFilter, endDateFilter);
  };
  
  const handleClearDateFilter = () => {
      setStartDateFilter("");
      setEndDateFilter("");
      // Fetch data without filters
      fetchData(false, "", ""); 
  };

  
  // === CORRECTED EXPORT FUNCTION ===
  const handleExportLeads = async () => {
    setIsExporting(true);
    try {
        const token = localStorage.getItem("token");
        
        const response = await axios.get(`${API_BASE}/api/leads/export`, {
            headers: { Authorization: `Bearer ${token}` },
            responseType: 'blob', // Critical: tells axios to handle binary data
        });

        // Check if the response is actually JSON error (edge case where server sends JSON despite blob request)
        if (response.data.type === 'application/json') {
             const errorData = JSON.parse(await response.data.text());
             throw new Error(errorData.message || "Export failed");
        }

        // Create a download link for the blob
        const url = window.URL.createObjectURL(new Blob([response.data]));
        const link = document.createElement('a');
        link.href = url;
        
        // Name the file
        const dateStr = new Date().toISOString().split('T')[0];
        link.setAttribute('download', `MyLeads_History_${dateStr}.xlsx`);
        
        document.body.appendChild(link);
        link.click();
        
        // Cleanup
        link.parentNode.removeChild(link);
        window.URL.revokeObjectURL(url);

        toast.success("Historical data exported successfully!");

    } catch (err) {
        console.error("Export error:", err);
        // Better error message extraction for blob responses
        let errorMsg = "Failed to export data.";
        if (err.response && err.response.data instanceof Blob) {
             try {
                const blobText = await err.response.data.text();
                const errorObj = JSON.parse(blobText);
                errorMsg = errorObj.message || errorMsg;
             } catch (e) { /* ignore json parse error */ }
        } else if (err.message) {
            errorMsg = err.message;
        }
        toast.error(errorMsg);
    } finally {
        setIsExporting(false);
    }
  };

  // ... rest of your component logic and JSX

  const handleRefresh = () => {
    fetchData(true);
  };

  // Calculate stats
  const stats = {
    total: properties.length,
    active: properties.filter((p) => p.status === "active" || !p.status).length,
    todayLeads: todayLeadsCount, // Updated
    totalViews: properties.reduce((sum, p) => sum + (p.views || 0), 0),
    totalLeads: leadAnalytics?.totalLeads || leads.length,
    newLeads: leadAnalytics?.newLeadsThisWeek || leads.filter(l => l.status === "new").length,
    conversionRate: leadAnalytics?.conversionRate || 0,
  };

  // Prepare chart data (unchanged)
  const leadStatusData = leadAnalytics?.statusStats 
    ? Object.entries(leadAnalytics.statusStats)
        .filter(([name, value]) => value > 0)
        .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value }))
    : [];

  const dailyLeadsData = leadAnalytics?.dailyLeads?.map(d => ({
    date: new Date(d._id).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' }),
    leads: d.count
  })) || [];

  const propertyLeadsData = leadAnalytics?.leadsByProperty?.map(p => ({
    name: p.propertyTitle?.substring(0, 20) + (p.propertyTitle?.length > 20 ? '...' : '') || 'Property',
    leads: p.count
  })) || [];

  // Filter properties
  const filteredProperties = properties
    .filter((p) => {
      if (filter === "all") return true;
      return (p.status || "active") === filter;
    })
    .filter((p) => {
      if (!searchQuery) return true;
      const query = searchQuery.toLowerCase();
      const locality = p.locality || p.address?.locality || p.address?.area || "";
      const city = p.city || p.address?.city || "";
      return (
        p.title?.toLowerCase().includes(query) ||
        locality.toLowerCase().includes(query) ||
        city.toLowerCase().includes(query)
      );
    })
    .sort((a, b) => {
      switch (sortBy) {
        case "newest": return new Date(b.createdAt) - new Date(a.createdAt);
        case "oldest": return new Date(a.createdAt) - new Date(b.createdAt);
        case "price-high": return (b.expectedPrice || b.price || 0) - (a.expectedPrice || a.price || 0);
        case "price-low": return (a.expectedPrice || a.price || 0) - (b.expectedPrice || b.price || 0);
        case "views": return (b.views || 0) - (a.views || 0);
        case "leads": return (b.interestedUsers?.length || 0) - (a.interestedUsers?.length || 0);
        default: return 0;
      }
    });

  // Filter leads
  const filteredLeads = leads
    .filter((l) => {
      if (leadFilter === "all") return true;
      return l.status === leadFilter;
    })
    .filter((l) => {
      if (selectedPropertyForLeads) {
        return l.property?._id === selectedPropertyForLeads._id || l.property === selectedPropertyForLeads._id;
      }
      return true;
    });

  const handleEdit = (property) => {
    navigate(`/edit-property/${property._id}`);
  };

  const handleDelete = (property) => {
    setPropertyToDelete(property);
    setShowDeleteModal(true);
  };

  const confirmDelete = async () => {
    if (!propertyToDelete) return;
    setDeleting(true);
    try {
      const token = localStorage.getItem("token");
      await axios.delete(`${API_BASE}/api/properties/${propertyToDelete._id}`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      toast.success("Property deleted successfully");
      setProperties(properties.filter((p) => p._id !== propertyToDelete._id));
      setShowDeleteModal(false);
      setPropertyToDelete(null);
    } catch (err) {
      toast.error("Failed to delete property");
    } finally {
      setDeleting(false);
    }
  };

  const handleViewDetails = (property) => {
    navigate(`/properties/${property._id}`);
  };

  const handleViewLeads = (property) => {
    setSelectedPropertyForLeads(property);
    setActiveTab("leads");
  };

  const handleUpdateLeadStatus = async (leadId, status) => {
    try {
      const token = localStorage.getItem("token");
      await axios.put(
        `${API_BASE}/api/leads/${leadId}/status`,
        { status },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      toast.success(`Lead status updated to ${status}`);
      // Refresh leads to update UI
      fetchData(false, startDateFilter, endDateFilter);
    } catch (err) {
      toast.error("Failed to update lead status");
    }
  };

  const [showPlans, setShowPlans] = useState(false);

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 pt-24 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 text-blue-600 animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Loading your dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 pt-20">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900">My Dashboard</h1>
              <p className="text-gray-500 mt-1">Manage properties, track leads & analytics</p>
              {lastUpdated && (
                <p className="text-xs text-gray-400 mt-1">
                  Last updated: {lastUpdated.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' })}
                </p>
              )}
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="inline-flex items-center gap-2 bg-gray-100 text-gray-700 px-4 py-2.5 rounded-xl font-medium hover:bg-gray-200 transition border border-gray-200 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                {refreshing ? 'Refreshing...' : 'Refresh'}
              </button>
              <Link
                to="/add-property"
                className="inline-flex items-center gap-2 bg-blue-600 text-white px-5 py-2.5 rounded-xl font-semibold hover:bg-blue-700 transition shadow-md"
              >
                <Plus className="w-5 h-5" />
                Add Property
              </Link>
            </div>
          </div>

          {/* Tabs */}
          <div className="flex gap-1 mt-6 bg-gray-100 p-1 rounded-xl w-full md:w-fit overflow-x-auto">
            {[
              { key: "properties", label: "Properties", icon: Home },
              { key: "leads", label: "Leads", icon: Users, badge: stats.newLeads },
              { key: "analytics", label: "Analytics", icon: BarChart3 },
            ].map((tab) => (
              <button
                key={tab.key}
                onClick={() => { setActiveTab(tab.key); setSelectedPropertyForLeads(null); }}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition ${
                  activeTab === tab.key
                    ? "bg-white text-blue-600 shadow-sm"
                    : "text-gray-600 hover:text-gray-900"
                }`}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
                {tab.badge > 0 && (
                  <span className="bg-red-500 text-white text-xs px-1.5 py-0.5 rounded-full">{tab.badge}</span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8">
          <StatsCard icon={Layers} label="Total Properties" value={stats.total} color="bg-blue-600" />
          <StatsCard icon={CheckCircle} label="Active Listings" value={stats.active} color="bg-green-600" />
          {/* New "Today's Leads" Card */}
          <StatsCard icon={Calendar} label="Today's Leads" value={stats.todayLeads} color="bg-indigo-600" />
          <StatsCard icon={Eye} label="Total Views" value={stats.totalViews} color="bg-purple-600" />
          <StatsCard icon={Users} label="Total Leads" value={stats.totalLeads} color="bg-pink-600" />
          <StatsCard icon={Target} label="Conversion Rate" value={`${stats.conversionRate}%`} color="bg-teal-600" />
        </div>

        {/* Properties Tab */}
        {activeTab === "properties" && (
          <>
            {/* Filters */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6">
              <div className="flex flex-col md:flex-row gap-4">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search by title, locality, or city..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full pl-10 pr-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                  />
                </div>
                <div className="flex items-center gap-2 overflow-x-auto pb-1">
                  {[
                    { key: "all", label: "All" },
                    { key: "active", label: "Active" },
                    { key: "pending", label: "Pending" },
                    { key: "sold", label: "Sold" },
                    { key: "rented", label: "Rented" },
                  ].map((tab) => (
                    <button
                      key={tab.key}
                      onClick={() => setFilter(tab.key)}
                      className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition ${
                        filter === tab.key
                          ? "bg-blue-600 text-white"
                          : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                      }`}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
                <select
                  value={sortBy}
                  onChange={(e) => setSortBy(e.target.value)}
                  className="px-4 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 focus:ring-2 focus:ring-blue-500 outline-none"
                >
                  <option value="newest">Newest First</option>
                  <option value="oldest">Oldest First</option>
                  <option value="price-high">Price: High to Low</option>
                  <option value="price-low">Price: Low to High</option>
                  <option value="views">Most Viewed</option>
                  <option value="leads">Most Leads</option>
                </select>
              </div>
            </div>

            {/* Properties Grid */}
            {filteredProperties.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filteredProperties.map((property) => (
                  <PropertyCard
                    key={property._id}
                    property={property}
                    onEdit={handleEdit}
                    onDelete={handleDelete}
                    onViewDetails={handleViewDetails}
                    onViewLeads={handleViewLeads}
                  />
                ))}
              </div>
            ) : (
              <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
                <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Home className="w-10 h-10 text-gray-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                  {searchQuery || filter !== "all" ? "No properties found" : "No properties yet"}
                </h3>
                <p className="text-gray-500 mb-6">
                  {searchQuery || filter !== "all"
                    ? "Try adjusting your search or filter criteria"
                    : "Start by listing your first property"}
                </p>
                {!searchQuery && filter === "all" && (
                  <Link
                    to="/add-property"
                    className="inline-flex items-center gap-2 bg-blue-600 text-white px-6 py-3 rounded-xl font-semibold hover:bg-blue-700 transition"
                  >
                    <Plus className="w-5 h-5" />
                    List Your First Property
                  </Link>
                )}
              </div>
            )}
          </>
        )}

        {/* Leads Tab (Updated) */}
        {activeTab === "leads" && (
          <>
            {/* Lead Filters and Date Range */}
            <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6">
              <div className="flex flex-col gap-6">
                
                {/* Date Filter & Export Row */}
                <div className="flex flex-col lg:flex-row gap-4 items-end justify-between border-b border-gray-100 pb-4">
                    <div className="flex gap-3 flex-1 flex-wrap">
                        <div className="flex flex-col">
                            <label className="text-xs font-medium text-gray-500 mb-1">From Date (Max 7 days)</label>
                            <input
                                type="date"
                                value={startDateFilter}
                                onChange={(e) => setStartDateFilter(e.target.value)}
                                className="px-4 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 focus:ring-2 focus:ring-blue-500 outline-none"
                            />
                        </div>
                        <div className="flex flex-col">
                            <label className="text-xs font-medium text-gray-500 mb-1">To Date</label>
                            <input
                                type="date"
                                value={endDateFilter}
                                onChange={(e) => setEndDateFilter(e.target.value)}
                                className="px-4 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 focus:ring-2 focus:ring-blue-500 outline-none"
                            />
                        </div>
                        <div className="flex items-end gap-2">
                            <button
                                onClick={handleApplyDateFilter}
                                className="inline-flex items-center gap-2 bg-blue-600 text-white px-4 py-2.5 rounded-lg text-sm font-medium hover:bg-blue-700 transition"
                                disabled={!startDateFilter || !endDateFilter}
                            >
                                <Filter className="w-4 h-4" /> Apply Filter
                            </button>
                            {(startDateFilter || endDateFilter) && (
                                <button
                                    onClick={handleClearDateFilter}
                                    className="p-2.5 text-gray-500 bg-gray-100 rounded-lg hover:bg-gray-200 transition"
                                    title="Clear Date Filter"
                                >
                                    <X className="w-5 h-5" />
                                </button>
                            )}
                        </div>
                    </div>

                    <div className="w-full lg:w-auto text-right">
                        <button
                            onClick={handleExportLeads}
                            disabled={isExporting}
                            className="w-full lg:w-auto inline-flex items-center justify-center gap-2 bg-emerald-600 text-white px-5 py-2.5 rounded-xl font-semibold hover:bg-emerald-700 transition disabled:opacity-50"
                        >
                            <FileText className={`w-5 h-5 ${isExporting ? 'animate-bounce' : ''}`} />
                            {isExporting ? 'Generating Excel...' : 'Export 3-Month Data (Excel)'}
                        </button>
                        <p className="text-xs text-gray-500 mt-1">
                            Max 3 months of historical data.
                        </p>
                    </div>
                </div>

                {/* Status and Property Filters */}
                <div className="flex flex-col md:flex-row gap-4 items-start md:items-center">
                  {selectedPropertyForLeads && (
                    <div className="flex items-center gap-2 bg-blue-50 px-3 py-2 rounded-lg">
                      <span className="text-sm text-blue-700">Showing leads for:</span>
                      <span className="font-medium text-blue-900">{selectedPropertyForLeads.title}</span>
                      <button
                        onClick={() => setSelectedPropertyForLeads(null)}
                        className="ml-2 text-blue-500 hover:text-blue-700"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  )}
                  <div className="flex items-center gap-2 overflow-x-auto pb-1 flex-1">
                    {[
                      { key: "all", label: "All Leads" },
                      { key: "new", label: "New" },
                      { key: "contacted", label: "Contacted" },
                      { key: "interested", label: "Interested" },
                      { key: "negotiating", label: "Negotiating" },
                      { key: "converted", label: "Converted" },
                      { key: "lost", label: "Lost" },
                    ].map((tab) => (
                      <button
                        key={tab.key}
                        onClick={() => setLeadFilter(tab.key)}
                        className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition ${
                          leadFilter === tab.key
                            ? "bg-blue-600 text-white"
                            : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                        }`}
                      >
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Leads List */}
            {filteredLeads.length > 0 ? (
              <div className="space-y-4">
                {filteredLeads.map((lead) => (
                  <LeadCard
                    key={lead._id}
                    lead={lead}
                    onUpdateStatus={handleUpdateLeadStatus}
                  />
                ))}
              </div>
            ) : (
              <div className="bg-white rounded-xl border border-gray-200 p-12 text-center">
                <div className="w-20 h-20 bg-gray-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Users className="w-10 h-10 text-gray-400" />
                </div>
                <h3 className="text-xl font-semibold text-gray-900 mb-2">
                    {startDateFilter && endDateFilter ? "No leads found for this date range" : "No leads yet"}
                </h3>
                <p className="text-gray-500">
                  When users express interest in your properties, they'll appear here.
                </p>
              </div>
            )}
          </>
        )}

        {/* Analytics Tab (unchanged) */}
        {activeTab === "analytics" && (
          <div className="space-y-6">
            {/* Charts Row 1 */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Leads Over Time */}
              <div className="bg-white rounded-xl border border-gray-200 p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Leads Over Time</h3>
                {dailyLeadsData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <AreaChart data={dailyLeadsData}>
                      <defs>
                        <linearGradient id="colorLeads" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3}/>
                          <stop offset="95%" stopColor="#3B82F6" stopOpacity={0}/>
                        </linearGradient>
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                      <XAxis dataKey="date" tick={{ fontSize: 12 }} stroke="#9CA3AF" />
                      <YAxis tick={{ fontSize: 12 }} stroke="#9CA3AF" />
                      <Tooltip 
                        contentStyle={{ borderRadius: '8px', border: '1px solid #E5E7EB' }}
                      />
                      <Area 
                        type="monotone" 
                        dataKey="leads" 
                        stroke="#3B82F6" 
                        fillOpacity={1} 
                        fill="url(#colorLeads)" 
                        strokeWidth={2}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[250px] flex items-center justify-center text-gray-400">
                    No data available yet
                  </div>
                )}
              </div>

              {/* Lead Status Distribution */}
              <div className="bg-white rounded-xl border border-gray-200 p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Lead Status Distribution</h3>
                {leadStatusData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <PieChart>
                      <Pie
                        data={leadStatusData}
                        cx="50%"
                        cy="50%"
                        innerRadius={60}
                        outerRadius={100}
                        paddingAngle={2}
                        dataKey="value"
                      >
                        {leadStatusData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[250px] flex items-center justify-center text-gray-400">
                    No data available yet
                  </div>
                )}
              </div>
            </div>

            {/* Charts Row 2 */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Leads by Property */}
              <div className="bg-white rounded-xl border border-gray-200 p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Top Properties by Leads</h3>
                {propertyLeadsData.length > 0 ? (
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart data={propertyLeadsData} layout="vertical">
                      <CartesianGrid strokeDasharray="3 3" stroke="#E5E7EB" />
                      <XAxis type="number" tick={{ fontSize: 12 }} stroke="#9CA3AF" />
                      <YAxis type="category" dataKey="name" tick={{ fontSize: 11 }} stroke="#9CA3AF" width={120} />
                      <Tooltip 
                        contentStyle={{ borderRadius: '8px', border: '1px solid #E5E7EB' }}
                      />
                      <Bar dataKey="leads" fill="#3B82F6" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                ) : (
                  <div className="h-[250px] flex items-center justify-center text-gray-400">
                    No data available yet
                  </div>
                )}
              </div>

              {/* Quick Stats */}
              <div className="bg-white rounded-xl border border-gray-200 p-6">
                <h3 className="font-semibold text-gray-900 mb-4">Performance Metrics</h3>
                <div className="space-y-4">
                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-blue-100 rounded-lg">
                        <Users className="w-5 h-5 text-blue-600" />
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Total Leads</p>
                        <p className="text-xl font-bold text-gray-900">{leadAnalytics?.totalLeads || 0}</p>
                      </div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>

                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-green-100 rounded-lg">
                        <UserCheck className="w-5 h-5 text-green-600" />
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Converted</p>
                        <p className="text-xl font-bold text-gray-900">{leadAnalytics?.convertedLeads || 0}</p>
                      </div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>

                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-purple-100 rounded-lg">
                        <Target className="w-5 h-5 text-purple-600" />
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Conversion Rate</p>
                        <p className="text-xl font-bold text-gray-900">{leadAnalytics?.conversionRate || 0}%</p>
                      </div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>

                  <div className="flex items-center justify-between p-4 bg-gray-50 rounded-xl">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-orange-100 rounded-lg">
                        <AlertCircle className="w-5 h-5 text-orange-600" />
                      </div>
                      <div>
                        <p className="text-sm text-gray-500">Unread Leads</p>
                        <p className="text-xl font-bold text-gray-900">{leadAnalytics?.unreadLeads || 0}</p>
                      </div>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-400" />
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Delete Confirmation Modal */}
      <AnimatePresence>
        {showDeleteModal && (
          <>
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setShowDeleteModal(false)}
              className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
            />
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95 }}
              className="fixed inset-0 z-50 flex items-center justify-center p-4"
            >
              <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md p-6">
                <div className="w-14 h-14 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
                  <Trash2 className="w-7 h-7 text-red-600" />
                </div>
                <h3 className="text-xl font-bold text-gray-900 text-center mb-2">
                  Delete Property?
                </h3>
                <p className="text-gray-500 text-center mb-6">
                  Are you sure you want to delete "{propertyToDelete?.title}"? This action cannot be undone.
                </p>
                <div className="flex gap-3">
                  <button
                    onClick={() => setShowDeleteModal(false)}
                    className="flex-1 px-4 py-2.5 border border-gray-300 text-gray-700 rounded-xl font-medium hover:bg-gray-50 transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={confirmDelete}
                    disabled={deleting}
                    className="flex-1 px-4 py-2.5 bg-red-600 text-white rounded-xl font-medium hover:bg-red-700 transition disabled:opacity-50 flex items-center justify-center gap-2"
                  >
                    {deleting ? (
                      <>
                        <RefreshCw className="w-4 h-4 animate-spin" />
                        Deleting...
                      </>
                    ) : (
                      "Delete"
                    )}
                  </button>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
      {/* Owner Upgrade Floating Button */}
{user?.role === "owner" && properties.length >= 1 && (
  <div className="fixed bottom-24 right-6 z-40">
    <button
      onClick={() => setShowPlans(true)}
      className="group flex items-center gap-3 bg-gradient-to-r from-blue-600 via-indigo-600 to-violet-600 text-white px-6 py-3.5 rounded-full shadow-lg hover:shadow-2xl transition-all duration-300 hover:scale-[1.03] active:scale-[0.98] relative overflow-hidden"
    >
      <span className="absolute inset-0 bg-white/10 opacity-0 group-hover:opacity-100 transition-opacity" />
      <span className="text-sm font-semibold relative z-10">
        Want to list more than 1 property?
      </span>
      <span className="bg-white/20 border border-white/30 rounded-full px-3 py-1 text-xs font-bold relative z-10">
        View Plans
      </span>
    </button>
  </div>
)}

{/* Owner Plans Modal */}
<AnimatePresence>
  {showPlans && (
    <>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/70 backdrop-blur-md z-50"
        onClick={() => setShowPlans(false)}
      />

      <motion.div
        initial={{ opacity: 0, y: 60, scale: 0.95 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: 60, scale: 0.95 }}
        transition={{ type: "spring", stiffness: 180, damping: 18 }}
        className="fixed bottom-6 md:bottom-10 right-4 md:right-10 z-50 w-[94%] max-w-md"
      >
        <div className="bg-white/90 backdrop-blur-xl rounded-3xl shadow-2xl border border-gray-200 overflow-hidden">

          {/* Header */}
          <div className="px-6 py-5 flex items-start justify-between gap-3 border-b border-gray-100">
            <div>
              <p className="text-xs font-bold text-indigo-600 uppercase tracking-[0.18em]">
                Owner Upgrade
              </p>
              <h3 className="text-xl font-extrabold text-gray-900 mt-1">
                Unlock More Listings
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                Choose your plan & grow your property reach.
              </p>
            </div>

            <button
              onClick={() => setShowPlans(false)}
              className="p-2 rounded-full hover:bg-gray-100 text-gray-500 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Plans */}
          <div className="px-6 py-5 grid gap-4">

            {/* Starter */}
            <div className="flex items-center justify-between rounded-2xl border border-gray-200 bg-gray-50 px-5 py-4 hover:shadow-sm transition">
              <div>
                <p className="text-xs font-bold text-gray-500 uppercase tracking-[0.16em]">
                  Free
                </p>
                <p className="text-base font-semibold text-gray-900">
                  Starter Owner
                </p>
                <p className="text-xs text-gray-500 mt-1">
                  1 active property • Basic visibility
                </p>
              </div>
              <p className="text-base font-bold text-emerald-600">
                ₹0/mo
              </p>
            </div>

            {/* Growth - Featured */}
            <div className="relative flex items-center justify-between rounded-2xl border-2 border-indigo-500 bg-indigo-50 px-5 py-4 shadow-md hover:shadow-lg transition">
              <span className="absolute -top-3 left-4 bg-indigo-600 text-white text-[10px] font-bold px-3 py-1 rounded-full shadow">
                MOST POPULAR
              </span>

              <div>
                <p className="text-xs font-bold text-indigo-600 uppercase tracking-[0.16em]">
                  Growth
                </p>
                <p className="text-base font-semibold text-gray-900">
                  Growth Plan
                </p>
                <p className="text-xs text-gray-600 mt-1">
                  Up to 3 listings • Priority placement • Lead insights
                </p>
              </div>
              <Link
                to="/pricing"
                className="text-xs font-bold text-indigo-700 border border-indigo-300 rounded-full px-3 py-1 hover:bg-indigo-600 hover:text-white transition"
              >
                View Plans
              </Link>
            </div>

            {/* Premium */}
            <div className="flex items-center justify-between rounded-2xl border border-amber-300 bg-amber-50 px-5 py-4 hover:shadow-md transition">
              <div>
                <p className="text-xs font-bold text-amber-600 uppercase tracking-[0.16em]">
                  Premium
                </p>
                <p className="text-base font-semibold text-gray-900">
                  Builder / Portfolio
                </p>
                <p className="text-xs text-gray-600 mt-1">
                  Featured badge • High limits • Dedicated support
                </p>
              </div>
              <p className="text-xs font-bold text-amber-800 text-right">
                Talk to<br />Sales Team
              </p>
            </div>
          </div>

          {/* Footer */}
          <div className="px-6 py-4 border-t border-gray-100 flex items-center justify-between gap-3 text-xs text-gray-500 bg-gray-50">
            <p>Online payments coming soon.</p>

            <button
              onClick={() => {
                navigator.clipboard.writeText("dealdirect@gmail.com");
                toast.success("Support email copied");
              }}
              className="text-indigo-600 font-bold hover:underline whitespace-nowrap"
            >
              Copy Support Email
            </button>
          </div>
        </div>
      </motion.div>
    </>
  )}
</AnimatePresence>

    </div>
  );
}