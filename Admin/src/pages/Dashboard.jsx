import React, { useEffect, useState } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  ArrowUpRight,
  Building2,
  Clock,
  ImageOff,
  RefreshCw,
  Target,
  Users,
} from "lucide-react";
import {
  Button,
  Card,
  CardBody,
  CardHeader,
  CHART,
  EmptyState,
  Loading,
  PageHeader,
  Stat,
  statusChartColor,
  Table,
  TableWrap,
  TBody,
  TD,
  TH,
  THead,
  toneForStatus,
  TR,
} from "../components/ui";

const API_URL = import.meta.env.VITE_API_BASE_URL;

/**
 * Secondary counters.
 *
 * Six of these used to be six separate cards, each with its own coloured icon
 * chip — six hues for six equivalent numbers, which made the row read as six
 * unrelated things instead of one breakdown. They are one strip now, divided
 * by hairlines, ranked below the primary metrics by size alone.
 */
const CounterStrip = ({ items }) => (
  <Card className="overflow-hidden">
    {/*
      `gap-px` over a line-coloured background draws the hairlines. Doing it
      with `divide-x` would follow DOM order rather than grid position, so the
      rules would land in the wrong places once the grid wraps to two columns.
    */}
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-px bg-line">
      {items.map(({ label, value }) => (
        <div key={label} className="bg-surface px-4 py-3">
          <p className="type-label text-ink-muted truncate">{label}</p>
          <p className="mt-1 text-lg font-semibold tracking-tight text-ink tabular leading-none">
            {value}
          </p>
        </div>
      ))}
    </div>
  </Card>
);

/**
 * Shared axis/grid setup, so all four charts sit on the same visual grid.
 *
 * Recharts flattens fragments when it scans for axis children, so returning
 * one here is safe. `cursor` differs by chart type: a line reads correctly
 * against a continuous area, a tinted band against discrete bars.
 */
const chartAxes = (cursor = { stroke: CHART.grid }) => (
  <>
    <CartesianGrid strokeDasharray="2 4" stroke={CHART.grid} vertical={false} />
    <XAxis dataKey="label" tick={CHART.tick} axisLine={false} tickLine={false} />
    <YAxis tick={CHART.tick} axisLine={false} tickLine={false} width={32} allowDecimals={false} />
    <Tooltip
      contentStyle={CHART.tooltip}
      labelStyle={CHART.tooltipLabel}
      cursor={cursor}
    />
  </>
);

/**
 * Status control in the listings table.
 *
 * Kept as a real <select> because approving from the dashboard is the point,
 * but bordered and chevroned so it reads as something you can change. The old
 * version was a borderless pill, which looked exactly like the read-only
 * status badges elsewhere in the panel.
 */
const STATUS_SELECT_TONES = {
  ok: "border-ok-line bg-ok-soft text-ok",
  warn: "border-warn-line bg-warn-soft text-warn",
  danger: "border-danger-line bg-danger-soft text-danger",
  info: "border-accent-line bg-accent-soft text-accent",
  neutral: "border-neutral-line bg-neutral-soft text-ink-muted",
};

const StatusSelect = ({ value, onChange }) => (
  <select
    value={value}
    onChange={onChange}
    aria-label="Listing status"
    className={`rounded-control border px-2 py-1 text-micro font-medium capitalize cursor-pointer transition-colors ${STATUS_SELECT_TONES[toneForStatus(value)]
      }`}
  >
    <option value="pending">Pending</option>
    <option value="approved">Approved</option>
  </select>
);

const Dashboard = () => {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

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
        // Use the API response charts directly — no fake historical data
        // The backend sends data.data.charts.properties / leads / users as arrays.
        // If the backend only returns the current month, that's what the chart shows.
        // Empty arrays cause the existing empty-state UI to render naturally.
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
      const action = newStatus === "approved" ? "approve" : "disapprove";
      // Using adminApi with automatic cookie authentication
      await adminApi.put(`/api/properties/${action}/${id}`, {});
      toast.success(
        `Property ${newStatus === "approved" ? "published" : "unpublished"} successfully!`
      );
      fetchDashboardStats();
    } catch (err) {
      console.error("Status update failed:", err);
      toast.error("Status update failed.");
    }
  };

  const formatPrice = (price) => {
    if (!price) return "—";
    if (price >= 10000000) return `₹${(price / 10000000).toFixed(1)}Cr`;
    if (price >= 100000) return `₹${(price / 100000).toFixed(1)}L`;
    return `₹${price.toLocaleString("en-IN")}`;
  };

  const resolveImage = (img) => {
    if (!img) return null;
    if (img.startsWith("http")) return img;
    if (img.startsWith("/uploads")) return `${API_URL}${img}`;
    return `${API_URL}/uploads/${img}`;
  };

  if (loading) {
    return <Loading label="Loading dashboard" className="h-[60vh]" />;
  }

  const leadStatusData = stats?.leadStats
    ? Object.entries(stats.leadStats)
      .filter(
        ([key]) =>
          key !== "total" &&
          key !== "undefined" &&
          key !== "contacted" &&
          key !== "negotiating"
      )
      .map(([name, value]) => ({
        name: name.charAt(0).toUpperCase() + name.slice(1),
        value,
      }))
      .filter((item) => item.value > 0)
    : [];

  const conversionRate =
    stats?.leadStats?.converted && stats?.leadStats?.total
      ? ((stats.leadStats.converted / stats.leadStats.total) * 100).toFixed(1)
      : 0;

  const today = new Date().toLocaleDateString("en-IN", {
    weekday: "long",
    day: "numeric",
    month: "long",
    year: "numeric",
  });

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={today}
        actions={
          <Button
            icon={RefreshCw}
            loading={refreshing}
            onClick={() => fetchDashboardStats(true)}
            disabled={refreshing}
          >
            Refresh
          </Button>
        }
      />

      {/*
        Primary metrics. Still no coloured cards — the operator is comparing
        magnitudes across the row, and a different fill behind each number
        makes that harder. What each tile does carry is the series behind the
        figure, so the total reads with its direction attached.
      */}
      <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
        <Stat
          label="Total properties"
          value={stats?.counts?.totalProperties ?? 0}
          hint={`${stats?.counts?.approvedProperties ?? 0} approved`}
          series={stats?.charts?.properties}
          seriesLabel="new per month"
          icon={Building2}
          onClick={() => navigate("/all-properties")}
        />
        <Stat
          label="Registered users"
          value={stats?.counts?.totalUsers ?? 0}
          series={stats?.charts?.users}
          seriesLabel="signups per month"
          icon={Users}
          onClick={() => navigate("/all-clients")}
        />
        <Stat
          label="Total leads"
          value={stats?.counts?.totalLeads ?? 0}
          hint={`${conversionRate}% converted`}
          series={stats?.charts?.leads}
          seriesLabel="new per month"
          icon={Target}
          onClick={() => navigate("/lead-monitoring")}
        />
        {/*
          The only metric that gets colour, and only when there is something
          in the queue. A pending count of zero is good news and should look
          like every other number on the row.
        */}
        <Stat
          label="Pending review"
          value={stats?.counts?.pendingProperties ?? 0}
          hint="Awaiting approval"
          tone={stats?.counts?.pendingProperties > 0 ? "warn" : "default"}
          icon={Clock}
          onClick={() => navigate("/all-properties")}
        />
      </section>

      <div className="mb-6">
        <CounterStrip
          items={[
            { label: "For rent", value: stats?.counts?.rentCount ?? 0 },
            { label: "For sale", value: stats?.counts?.saleCount ?? 0 },
            { label: "Approved", value: stats?.counts?.approvedProperties ?? 0 },
            { label: "New leads", value: stats?.leadStats?.new ?? 0 },
            { label: "Contacted", value: stats?.leadStats?.contacted ?? 0 },
            { label: "Converted", value: stats?.leadStats?.converted ?? 0 },
          ]}
        />
      </div>

      {/* Trends. One measure per chart, therefore one colour per chart. */}
      <section className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        <Card>
          <CardHeader title="Property listings" subtitle="New listings per month" />
          <CardBody className="pl-1 pr-3">
            {stats?.charts?.properties?.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats.charts.properties} margin={{ top: 4, right: 4 }}>
                  <defs>
                    <linearGradient id="propertyFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.series} stopOpacity={0.16} />
                      <stop offset="100%" stopColor={CHART.series} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  {chartAxes()}
                  <Area
                    type="monotone"
                    dataKey="value"
                    name="Properties"
                    stroke={CHART.series}
                    strokeWidth={2}
                    fill="url(#propertyFill)"
                    dot={false}
                    activeDot={{ r: 3, strokeWidth: 0 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No listings yet" description="New listings will appear here as owners publish them." />
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Lead generation" subtitle="New leads per month" />
          <CardBody className="pl-1 pr-3">
            {stats?.charts?.leads?.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats.charts.leads} margin={{ top: 4, right: 4 }}>
                  <defs>
                    <linearGradient id="leadFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor={CHART.series} stopOpacity={0.16} />
                      <stop offset="100%" stopColor={CHART.series} stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  {chartAxes()}
                  <Area
                    type="monotone"
                    dataKey="value"
                    name="Leads"
                    stroke={CHART.series}
                    strokeWidth={2}
                    fill="url(#leadFill)"
                    dot={false}
                    activeDot={{ r: 3, strokeWidth: 0 }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState title="No leads yet" description="Buyer enquiries will appear here once they start coming in." />
            )}
          </CardBody>
        </Card>
      </section>

      <section className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        {/* Lead status. Slices take their colour from the status itself, so a
            slice and the badge for the same status agree. */}
        <Card>
          <CardHeader title="Lead status" subtitle="Share of pipeline" />
          <CardBody>
            {leadStatusData.length > 0 ? (
              <>
                <ResponsiveContainer width="100%" height={180}>
                  <PieChart>
                    <Pie
                      data={leadStatusData}
                      cx="50%"
                      cy="50%"
                      innerRadius={52}
                      outerRadius={76}
                      paddingAngle={2}
                      dataKey="value"
                      stroke="none"
                    >
                      {leadStatusData.map((entry, index) => (
                        <Cell key={entry.name} fill={statusChartColor(entry.name, index)} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={CHART.tooltip} labelStyle={CHART.tooltipLabel} />
                  </PieChart>
                </ResponsiveContainer>

                <ul className="mt-4 space-y-1.5">
                  {leadStatusData.map((entry, index) => (
                    <li
                      key={entry.name}
                      className="flex items-center gap-2 type-label"
                    >
                      <span
                        className="h-2 w-2 rounded-full shrink-0"
                        style={{ backgroundColor: statusChartColor(entry.name, index) }}
                      />
                      <span className="type-label text-ink-body truncate">{entry.name}</span>
                      <span className="ml-auto type-label text-ink-muted tabular">{entry.value}</span>
                    </li>
                  ))}
                </ul>
              </>
            ) : (
              <EmptyState icon={Target} title="No leads yet" />
            )}
          </CardBody>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader title="User growth" subtitle="New registrations per month" />
          <CardBody className="pl-1 pr-3">
            {stats?.charts?.users?.length > 0 ? (
              <ResponsiveContainer width="100%" height={220}>
                {/*
                  The previous version drew an amber <Area> on top of these
                  bars, labelled "Trend", plotting the exact same dataKey. It
                  was the same numbers twice in two colours, so it is gone.
                */}
                <BarChart data={stats.charts.users} margin={{ top: 4, right: 4 }} barSize={28}>
                  {chartAxes(CHART.cursor)}
                  <Bar
                    dataKey="value"
                    name="Users"
                    fill={CHART.series}
                    radius={[3, 3, 0, 0]}
                  />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <EmptyState icon={Users} title="No registrations yet" />
            )}
          </CardBody>
        </Card>
      </section>

      <Card className="mb-4 overflow-hidden">
        <CardHeader
          title="Recent listings"
          subtitle="Latest properties added to the platform"
          action={
            <Button
              as="a"
              href="/all-properties"
              variant="ghost"
              size="sm"
              className="text-accent hover:text-accent-hover"
            >
              View all
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Button>
          }
        />
        <TableWrap>
          <Table>
            <THead>
              <TR className="hover:bg-transparent">
                <TH>Property</TH>
                <TH>Location</TH>
                <TH>Status</TH>
                <TH>Owner</TH>
                <TH align="right">Price</TH>
                <TH align="right">Listed</TH>
              </TR>
            </THead>
            <TBody>
              {stats?.recentProperties?.length > 0 ? (
                stats.recentProperties.map((property) => {
                  const src = resolveImage(property.image);
                  return (
                    <TR key={property._id}>
                      <TD>
                        <div className="flex items-center gap-3">
                          {/*
                            A missing image renders a local placeholder tile.
                            This used to point at via.placeholder.com, an
                            external service the panel would sit waiting on.
                          */}
                          {src ? (
                            <img
                              src={src}
                              alt=""
                              className="h-9 w-12 rounded-control object-cover border border-line shrink-0"
                            />
                          ) : (
                            <div className="h-9 w-12 rounded-control border border-line bg-surface-sunken flex items-center justify-center shrink-0">
                              <ImageOff className="h-3.5 w-3.5 text-ink-faint" />
                            </div>
                          )}
                          <div className="min-w-0">
                            <p className="font-medium text-ink truncate max-w-[220px]">
                              {property.title}
                            </p>
                            <p className="type-label text-ink-muted capitalize">
                              {property.listingType}
                            </p>
                          </div>
                        </div>
                      </TD>
                      <TD>{property.city || "—"}</TD>
                      <TD>
                        <StatusSelect
                          value={property.isApproved ? "approved" : "pending"}
                          onChange={(e) =>
                            handleStatusChange(property._id, e.target.value)
                          }
                        />
                      </TD>
                      <TD>{property.owner || "Unknown"}</TD>
                      <TD numeric className="font-medium text-ink">
                        {formatPrice(property.price)}
                      </TD>
                      <TD numeric className="text-ink-muted">
                        {new Date(property.createdAt).toLocaleDateString("en-IN", {
                          day: "numeric",
                          month: "short",
                          year: "numeric",
                        })}
                      </TD>
                    </TR>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6}>
                    <EmptyState
                      icon={Building2}
                      title="No properties listed yet"
                      description="Listings appear here as soon as owners publish them."
                    />
                  </td>
                </tr>
              )}
            </TBody>
          </Table>
        </TableWrap>
      </Card>

      {/* Top owners. Was five cards, the first one gold-gradient with a crown
          emoji. It is a ranked list, so it is a list now. */}
      {stats?.topOwners?.length > 0 && (
        <Card>
          <CardHeader title="Top property owners" subtitle="Ranked by listing count" />
          <ul className="divide-y divide-line">
            {stats.topOwners.map((owner, index) => (
              <li
                key={owner._id}
                className="flex items-center gap-3 px-4 py-2.5"
              >
                <span className="w-5 type-label text-ink-faint tabular text-right">
                  {index + 1}
                </span>
                <span className="type-body text-ink truncate">{owner.name}</span>
                <span className="ml-auto type-label text-ink-muted tabular whitespace-nowrap">
                  {owner.propertyCount}{" "}
                  {owner.propertyCount === 1 ? "property" : "properties"}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      )}
    </>
  );
};

export default Dashboard;
