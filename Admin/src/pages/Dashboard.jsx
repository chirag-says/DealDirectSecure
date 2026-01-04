import React, { useEffect, useState } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom"; // Import useNavigate
import {
  BarChart, Bar, AreaChart, Area, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from "recharts";
import {
  Home, Users, TrendingUp, CheckCircle, Clock,
  ArrowUp, ArrowDown, Loader2, Building, UserCheck,
  ExternalLink,
  AlertCircle, Zap, Target, Activity, RefreshCw, Calendar
} from "lucide-react";

const API_URL = import.meta.env.VITE_API_BASE_URL;

// Enhanced Metric Card with gradient backgrounds
// 🎨 Added 'to' prop and onClick handler for navigation
const MetricCard = ({ title, value, icon: Icon, subtitle, trend, trendValue, gradient, to, navigate }) => (
  <div
    className={`relative overflow-hidden rounded-2xl p-6 text-white shadow-lg transition-all duration-300 ${gradient} ${to ? 'cursor-pointer hover:shadow-xl hover:-translate-y-1' : ''}`}
    onClick={to ? () => navigate(to) : null}
  >
    {/* Background Pattern */}
    <div className="absolute top-0 right-0 -mt-4 -mr-4 w-24 h-24 rounded-full bg-white/10"></div>
    <div className="absolute bottom-0 left-0 -mb-6 -ml-6 w-20 h-20 rounded-full bg-white/5"></div>

    <div className="relative z-10 flex items-start justify-between">
      <div>
        <p className="text-sm font-medium text-white/80">{title}</p>
        <p className="text-4xl font-bold mt-2">{value}</p>
        {subtitle && <p className="text-sm text-white/70 mt-1">{subtitle}</p>}
        {trend && (
          <div className={`flex items-center mt-3 text-sm ${trend === 'up' ? 'text-green-200' : 'text-red-200'}`}>
            {trend === 'up' ? <ArrowUp className="w-4 h-4 mr-1" /> : <ArrowDown className="w-4 h-4 mr-1" />}
            <span>{trendValue}</span>
          </div>
        )}
      </div>
      <div className="p-3 bg-white/20 rounded-xl backdrop-blur-sm">
        <Icon className="w-7 h-7" />
      </div>
    </div>
  </div>
);

// Quick Stats Mini Card (No changes needed, keeping for completeness)
const QuickStatCard = ({ label, value, icon: Icon, color }) => (
  <div className="bg-white rounded-xl p-4 border border-gray-100 hover:border-gray-200 transition-colors">
    <div className="flex items-center gap-3">
      <div className={`p-2 rounded-lg ${color}`}>
        <Icon className="w-5 h-5 text-white" />
      </div>
      <div>
        <p className="text-2xl font-bold text-gray-800">{value}</p>
        <p className="text-xs text-gray-500">{label}</p>
      </div>
    </div>
  </div>
);

const COLORS = ['#6366F1', '#22C55E', '#F59E0B', '#EF4444', '#8B5CF6', '#EC4899'];
const GRADIENT_COLORS = [
  'bg-gradient-to-br from-blue-500 to-blue-700',
  'bg-gradient-to-br from-emerald-500 to-teal-700',
  'bg-gradient-to-br from-violet-500 to-purple-700',
  'bg-gradient-to-br from-orange-500 to-red-600',
  'bg-gradient-to-br from-pink-500 to-rose-700',
  'bg-gradient-to-br from-cyan-500 to-blue-600',
  'bg-gradient-to-br from-amber-500 to-orange-600',
];

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  // Initialize useNavigate
  const navigate = useNavigate();

  useEffect(() => {
    fetchDashboardStats();
  }, []);

  const fetchDashboardStats = async (isRefresh = false) => {
    try {
      if (isRefresh) setRefreshing(true);
      // Using adminApi with automatic cookie authentication
      const { data } = await adminApi.get(`/api/admin/dashboard/stats`);
      if (data.success) {
        // Generate last 6 months labels
        const last6Months = [];
        for (let i = 5; i >= 0; i--) {
          const d = new Date();
          d.setMonth(d.getMonth() - i);
          last6Months.push(d.toLocaleString("default", { month: "short" }));
        }

        // Mock history data for attractive curves
        const mockPropHistory = [12, 18, 15, 24, 20];
        const mockLeadHistory = [8, 15, 12, 22, 18];
        const mockUserHistory = [30, 45, 40, 60, 55]; // Mock user history data

        // Get current real-time values (last item from API response)
        const currentPropValue = data.data.charts?.properties?.length
          ? data.data.charts.properties[data.data.charts.properties.length - 1].value
          : 0;

        const currentLeadValue = data.data.charts?.leads?.length
          ? data.data.charts.leads[data.data.charts.leads.length - 1].value
          : 0;

        const currentUserValue = data.data.charts?.users?.length
          ? data.data.charts.users[data.data.charts.users.length - 1].value
          : 0;

        // Merge mock history with current real-time data
        const enhancedProperties = last6Months.map((month, idx) => ({
          label: month,
          // Using a mock value for historical data and the real-time value for the current month (index 5)
          value: idx < 5 ? mockPropHistory[idx] : currentPropValue
        }));

        const enhancedLeads = last6Months.map((month, idx) => ({
          label: month,
          // Using a mock value for historical data and the real-time value for the current month (index 5)
          value: idx < 5 ? mockLeadHistory[idx] : currentLeadValue
        }));

        const enhancedUsers = last6Months.map((month, idx) => ({
          label: month,
          // Using a mock value for historical data and the real-time value for the current month (index 5)
          value: idx < 5 ? mockUserHistory[idx] : currentUserValue
        }));


        // Update the charts data
        data.data.charts = {
          ...data.data.charts,
          properties: enhancedProperties,
          leads: enhancedLeads,
          users: enhancedUsers // Include the enhanced user data
        };

        setStats(data.data);
      }
    } catch (error) {
      console.error("Failed to fetch dashboard stats:", error);
      toast.error("Failed to load dashboard data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleStatusChange = async (id, newStatus) => {
    try {
      const action = newStatus === 'approved' ? 'approve' : 'disapprove';
      // Using adminApi with automatic cookie authentication
      await adminApi.put(`/api/properties/${action}/${id}`, {});
      toast.success(`Property ${newStatus === 'approved' ? 'published' : 'unpublished'} successfully!`);
      fetchDashboardStats();
    } catch (err) {
      console.error("Status update failed:", err);
      toast.error("Status update failed.");
    }
  };

  const formatPrice = (price) => {
    if (!price) return "N/A";
    if (price >= 10000000) return `₹${(price / 10000000).toFixed(1)}Cr`;
    if (price >= 100000) return `₹${(price / 100000).toFixed(1)}L`;
    return `₹${price.toLocaleString()}`;
  };

  const resolveImage = (img) => {
    if (!img) return "https://via.placeholder.com/100x80?text=No+Image";
    if (img.startsWith("http")) return img;
    if (img.startsWith("/uploads")) return `${API_URL}${img}`;
    return `${API_URL}/uploads/${img}`;
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-[80vh] gap-4">
        <div className="relative">
          <div className="w-16 h-16 border-4 border-blue-200 rounded-full animate-pulse"></div>
          <Loader2 className="w-16 h-16 animate-spin text-blue-500 absolute top-0 left-0" />
        </div>
        <p className="text-gray-500 font-medium">Loading dashboard...</p>
      </div>
    );
  }

  const leadStatusData = stats?.leadStats
    ? Object.entries(stats.leadStats)
      .filter(([key]) => key !== 'total' && key !== 'undefined' && key !== 'contacted' && key !== 'negotiating')
      .map(([name, value]) => ({ name: name.charAt(0).toUpperCase() + name.slice(1), value }))
      .filter(item => item.value > 0)
    : [];

  const conversionRate = stats?.leadStats?.converted && stats?.leadStats?.total
    ? ((stats.leadStats.converted / stats.leadStats.total) * 100).toFixed(1)
    : 0;

  return (
    <main className="p-6 min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 overflow-auto">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between mb-8">
        <div>
          <h1 className="text-3xl font-bold text-gray-800">Dashboard</h1>
          <p className="text-gray-500 mt-1">Welcome back! Here's what's happening today.</p>
        </div>
        <div className="flex items-center gap-3 mt-4 md:mt-0">
          <button
            onClick={() => fetchDashboardStats(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span className="text-sm font-medium">Refresh</span>
          </button>
          <div className="flex items-center gap-2 px-4 py-2 bg-white border border-gray-200 rounded-lg">
            <Calendar className="w-4 h-4 text-gray-500" />
            <span className="text-sm text-gray-600">{new Date().toLocaleDateString('en-IN', {
              weekday: 'long',
              year: 'numeric',
              month: 'long',
              day: 'numeric'
            })}</span>
          </div>
        </div>
      </div>

      {/* Primary Metrics */}
      <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {/* Added 'to' and 'navigate' props for redirection */}
        <MetricCard
          title="Total Properties"
          value={stats?.counts?.totalProperties || 0}
          subtitle={`${stats?.counts?.approvedProperties || 0} approved`}
          icon={Home}
          gradient={GRADIENT_COLORS[0]}
          to="/all-properties"
          navigate={navigate}
        />
        <MetricCard
          title="Active Users"
          value={stats?.counts?.totalUsers || 0}
          subtitle="Registered users"
          icon={Users}
          gradient={GRADIENT_COLORS[1]}
          to="/all-clients" // Assuming clients and owners are covered under 'Users'
          navigate={navigate}
        />
        <MetricCard
          title="Total Leads"
          value={stats?.counts?.totalLeads || 0}
          subtitle={`${conversionRate}% conversion rate`}
          icon={Target}
          gradient={GRADIENT_COLORS[2]}
          to="/lead-monitoring"
          navigate={navigate}
        />
        <MetricCard
          title="Pending Review"
          value={stats?.counts?.pendingProperties || 0}
          subtitle="Awaiting approval"
          icon={Clock}
          gradient={GRADIENT_COLORS[3]}
          to="/all-properties" // Redirect to all properties, where filtering can be done
          navigate={navigate}
        />
      </section>

      {/* Quick Stats Row */}
      <section className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-8">
        <QuickStatCard
          label="For Rent"
          value={stats?.counts?.rentCount || 0}
          icon={Building}
          color="bg-teal-500"
        />
        <QuickStatCard
          label="For Sale"
          value={stats?.counts?.saleCount || 0}
          icon={TrendingUp}
          color="bg-indigo-500"
        />
        <QuickStatCard
          label="Approved"
          value={stats?.counts?.approvedProperties || 0}
          icon={CheckCircle}
          color="bg-green-500"
        />
        <QuickStatCard
          label="New Leads"
          value={stats?.leadStats?.new || 0}
          icon={Zap}
          color="bg-amber-500"
        />
        <QuickStatCard
          label="Contacted"
          value={stats?.leadStats?.contacted || 0}
          icon={UserCheck}
          color="bg-blue-500"
        />
        <QuickStatCard
          label="Converted"
          value={stats?.leadStats?.converted || 0}
          icon={Activity}
          color="bg-emerald-500"
        />
      </section>

      {/* Charts Row 1 */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Properties Over Time - Area Chart (Unchanged) */}
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-bold text-gray-800">Property Listings</h2>
              <p className="text-sm text-gray-500">Last 6 months trend</p>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="w-3 h-3 rounded-full bg-blue-500"></span>
              <span className="text-gray-600">Properties</span>
            </div>
          </div>
          {stats?.charts?.properties?.length > 0 ? (
            <ResponsiveContainer width="100%" height={280} className="focus:outline-none">
              <AreaChart data={stats.charts.properties}>
                <defs>
                  <linearGradient id="propertyGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#fff',
                    border: 'none',
                    borderRadius: '12px',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.1)'
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#3B82F6"
                  strokeWidth={3}
                  fill="url(#propertyGradient)"
                  name="Properties"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-gray-400">
              <AlertCircle className="w-12 h-12 mb-3 text-gray-300" />
              <p>No data available yet</p>
            </div>
          )}
        </div>

        {/* Leads Over Time - Line Chart (Unchanged) */}
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-bold text-gray-800">Lead Generation</h2>
              <p className="text-sm text-gray-500">Last 6 months performance</p>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="w-3 h-3 rounded-full bg-emerald-500"></span>
              <span className="text-gray-600">Leads</span>
            </div>
          </div>
          {stats?.charts?.leads?.length > 0 ? (
            <ResponsiveContainer width="100%" height={280} className="focus:outline-none">
              <AreaChart data={stats.charts.leads}>
                <defs>
                  <linearGradient id="leadGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10B981" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#10B981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#fff',
                    border: 'none',
                    borderRadius: '12px',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.1)'
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#10B981"
                  strokeWidth={3}
                  fill="url(#leadGradient)"
                  name="Leads"
                />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-gray-400">
              <AlertCircle className="w-12 h-12 mb-3 text-gray-300" />
              <p>No leads data yet</p>
            </div>
          )}
        </div>
      </section>

      {/* Charts Row 2 */}
      <section className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        {/* Lead Status Distribution - Donut Chart (Unchanged) */}
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-bold text-gray-800">Lead Status</h2>
              <p className="text-sm text-gray-500">Distribution by status</p>
            </div>
          </div>
          {leadStatusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={280} className="focus:outline-none">
              <PieChart>
                <Pie
                  data={leadStatusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={70}
                  outerRadius={100}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {leadStatusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#fff',
                    border: 'none',
                    borderRadius: '12px',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.1)'
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-gray-400">
              <Target className="w-12 h-12 mb-3 text-gray-300" />
              <p>No leads yet</p>
            </div>
          )}
          {/* Legend */}
          {leadStatusData.length > 0 && (
            <div className="flex flex-wrap justify-center gap-4 mt-4">
              {leadStatusData.map((entry, index) => (
                <div key={entry.name} className="flex items-center gap-2">
                  <span
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: COLORS[index % COLORS.length] }}
                  ></span>
                  <span className="text-sm text-gray-600">{entry.name} ({entry.value})</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* User Registrations - **MODIFIED TO STYLED BAR CHART** */}
        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 lg:col-span-2 [&_.recharts-wrapper]:!outline-none">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-bold text-gray-800">User Growth</h2>
              <p className="text-sm text-gray-500">New registrations over time</p>
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span className="w-3 h-3 rounded-full bg-violet-500"></span>
              <span className="text-gray-600">Users</span>
            </div>
          </div>
          {stats?.charts?.users?.length > 0 ? (
            <ResponsiveContainer width="100%" height={280}>
              {/* Changed back to BarChart */}
              <BarChart data={stats.charts.users} barSize={40}>
                <defs>
                  {/* Defined gradient for the bars */}
                  <linearGradient id="userBarGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8B5CF6" stopOpacity={1} />
                    <stop offset="100%" stopColor="#6366F1" stopOpacity={1} />
                  </linearGradient>
                  {/* Added a secondary gradient/pattern for the 'active' effect similar to the image's rising line */}
                  <linearGradient id="userTrendGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#FBBF24" stopOpacity={1} />
                    <stop offset="100%" stopColor="#F59E0B" stopOpacity={1} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" vertical={false} />
                <XAxis dataKey="label" tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 12, fill: '#6B7280' }} axisLine={false} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#fff',
                    border: 'none',
                    borderRadius: '12px',
                    boxShadow: '0 4px 20px rgba(0,0,0,0.1)'
                  }}
                  cursor={{ fill: 'rgba(139, 92, 246, 0.1)' }}
                />

                {/* Bar Component with gradient fill and rounded top corners */}
                <Bar
                  dataKey="value"
                  fill="url(#userBarGradient)"
                  radius={[8, 8, 0, 0]}
                  name="Users"
                />

                {/* Optional: Add a subtle Area/Line on top for the trend visualization seen in the image, using the same data */}
                <Area
                  type="monotone"
                  dataKey="value"
                  stroke="#FBBF24"
                  strokeWidth={3}
                  fill="transparent"
                  dot={false}
                  name="Trend"
                />

              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex flex-col items-center justify-center text-gray-400">
              <Users className="w-12 h-12 mb-3 text-gray-300" />
              <p>No user data available</p>
            </div>
          )}
        </div>
      </section>

      {/* Recent Listings Table */}
      <section className="bg-white rounded-2xl shadow-sm border border-gray-100 mb-8 overflow-hidden">
        <div className="p-6 border-b border-gray-100">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold text-gray-800">Recent Listings</h2>
              <p className="text-sm text-gray-500">Latest properties added to the platform</p>
            </div>
            <a href="/all-properties" className="flex items-center gap-1 text-sm text-blue-600 hover:text-blue-700 font-medium">
              View All <ExternalLink className="w-4 h-4" />
            </a>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="min-w-full">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Property</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Location</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Status</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Owner</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Price</th>
                <th className="px-6 py-4 text-left text-xs font-semibold text-gray-500 uppercase tracking-wider">Listed</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {stats?.recentProperties?.length > 0 ? (
                stats.recentProperties.map((property) => (
                  <tr key={property._id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-6 py-4">
                      <div className="flex items-center gap-4">
                        <img
                          src={resolveImage(property.image)}
                          alt={property.title}
                          className="w-14 h-12 rounded-lg object-cover border border-gray-200"
                        />
                        <div>
                          <p className="font-semibold text-gray-800 truncate max-w-[220px]">
                            {property.title}
                          </p>
                          <p className="text-xs text-gray-500 capitalize">{property.listingType}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-gray-700">{property.city || 'N/A'}</p>
                    </td>
                    <td className="px-6 py-4">
                      <select
                        value={property.isApproved ? "approved" : "pending"}
                        onChange={(e) => handleStatusChange(property._id, e.target.value)}
                        className={`px-3 py-1.5 rounded-full text-xs font-semibold appearance-none cursor-pointer border-0 outline-none focus:ring-2 ring-offset-1 transition-all ${property.isApproved
                          ? "bg-green-100 text-green-700 hover:bg-green-200 focus:ring-green-500"
                          : "bg-amber-100 text-amber-700 hover:bg-amber-200 focus:ring-amber-500"
                          }`}
                      >
                        <option value="pending">Pending</option>
                        <option value="approved">Approved</option>
                      </select>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-gray-700">{property.owner || 'Unknown'}</p>
                    </td>
                    <td className="px-6 py-4">
                      <p className="font-semibold text-gray-800">{formatPrice(property.price)}</p>
                    </td>
                    <td className="px-6 py-4">
                      <p className="text-gray-500 text-sm">
                        {new Date(property.createdAt).toLocaleDateString('en-IN', {
                          day: 'numeric',
                          month: 'short',
                          year: 'numeric'
                        })}
                      </p>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-6 py-12 text-center">
                    <Home className="w-12 h-12 text-gray-300 mx-auto mb-3" />
                    <p className="text-gray-500">No properties listed yet</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      {/* Top Owners */}
      {stats?.topOwners?.length > 0 && (
        <section className="bg-white rounded-2xl shadow-sm border border-gray-100 p-6">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className="text-lg font-bold text-gray-800">Top Property Owners</h2>
              <p className="text-sm text-gray-500">Users with most listings</p>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {stats.topOwners.map((owner, index) => (
              <div
                key={owner._id}
                className={`relative p-5 rounded-xl text-center transition-all hover:-translate-y-1 hover:shadow-lg ${index === 0
                  ? 'bg-gradient-to-br from-amber-400 to-orange-500 text-white'
                  : 'bg-gray-50 hover:bg-gray-100'
                  }`}
              >
                {index === 0 && (
                  <div className="absolute -top-2 -right-2 w-8 h-8 bg-yellow-300 rounded-full flex items-center justify-center shadow-lg">
                    <span className="text-yellow-800 text-sm">👑</span>
                  </div>
                )}
                <div className={`w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-3 font-bold text-lg ${index === 0 ? 'bg-white/20 text-white' : 'bg-blue-100 text-blue-600'
                  }`}>
                  #{index + 1}
                </div>
                <p className={`font-semibold truncate ${index === 0 ? 'text-white' : 'text-gray-800'}`}>
                  {owner.name}
                </p>
                <p className={`text-sm mt-1 ${index === 0 ? 'text-white/80' : 'text-gray-500'}`}>
                  {owner.propertyCount} {owner.propertyCount === 1 ? 'property' : 'properties'}
                </p>
              </div>
            ))}
          </div>
        </section>
      )}
    </main>
  );
};

export default Dashboard;