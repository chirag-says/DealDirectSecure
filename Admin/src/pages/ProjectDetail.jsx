import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import { projectApi, unitTypeApi, campaignApi } from "../api/adminApi";
import { Plus, Building2, IndianRupee, Home, Layers, ChevronRight, Trash2, ToggleLeft, ToggleRight, HardHat, Upload, X } from "lucide-react";

const badge = (status) => {
  const map = {
    "New Launch": "bg-blue-100 text-blue-700",
    "Under Construction": "bg-yellow-100 text-yellow-700",
    "Ready To Move": "bg-green-100 text-green-700",
    "Completed": "bg-gray-100 text-gray-700",
  };
  return `px-2 py-0.5 rounded-full text-xs font-medium ${map[status] || "bg-gray-100 text-gray-600"}`;
};

export default function ProjectDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [project, setProject] = useState(null);
  const [unitTypes, setUnitTypes] = useState([]);
  const [campaigns, setCampaigns] = useState([]);
  const [tab, setTab] = useState("units");
  const [loading, setLoading] = useState(true);
  const [updateForm, setUpdateForm] = useState({ title: "", description: "", percentComplete: "" });
  const [updateImages, setUpdateImages] = useState([]);
  const [postingUpdate, setPostingUpdate] = useState(false);

  const load = async () => {
    try {
      const [pRes, uRes, cRes] = await Promise.all([
        projectApi.getById(id),
        unitTypeApi.getByProject(id),
        campaignApi.getByProject(id),
      ]);
      setProject(pRes.data || pRes);
      setUnitTypes(uRes.data || []);
      setCampaigns(cRes.data || []);
    } catch {
      toast.error("Failed to load project.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [id]);

  const toggleProjectActive = async () => {
    try {
      await projectApi.update(id, { isActive: !project.isActive });
      setProject(p => ({ ...p, isActive: !p.isActive }));
      toast.success(`Project ${project.isActive ? "deactivated" : "activated"}.`);
    } catch { toast.error("Failed to update status."); }
  };

  const deleteUnitType = async (utId) => {
    if (!window.confirm("Delete this unit type?")) return;
    try {
      await unitTypeApi.delete(utId);
      setUnitTypes(p => p.filter(u => u._id !== utId));
      toast.success("Unit type deleted.");
    } catch (err) {
      toast.error(err.response?.data?.message || "Cannot delete.");
    }
  };

  const postConstructionUpdate = async (e) => {
    e.preventDefault();
    if (!updateForm.title.trim()) return toast.error("Title is required.");
    setPostingUpdate(true);
    try {
      const fd = new FormData();
      fd.append("title", updateForm.title.trim());
      if (updateForm.description.trim()) fd.append("description", updateForm.description.trim());
      if (updateForm.percentComplete) fd.append("percentComplete", updateForm.percentComplete);
      updateImages.forEach(f => fd.append("images", f));
      const res = await projectApi.addConstructionUpdate(id, fd);
      // Reload project to get fresh constructionUpdates array
      const pRes = await projectApi.getById(id);
      setProject(pRes.data || pRes);
      setUpdateForm({ title: "", description: "", percentComplete: "" });
      setUpdateImages([]);
      toast.success("Construction update posted.");
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to post update.");
    } finally {
      setPostingUpdate(false);
    }
  };

  if (loading) return (
    <div className="flex items-center justify-center h-64">
      <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-blue-600" />
    </div>
  );

  if (!project) return <div className="p-6 text-red-500">Project not found.</div>;

  const p = project;
  const loc = [p.location?.locality, p.location?.city, p.location?.state].filter(Boolean).join(", ");

  return (
    <div className="max-w-5xl mx-auto py-6 px-4 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <button onClick={() => navigate("/builder-management")} className="text-sm text-blue-600 hover:underline mb-1">← Back to Builders</button>
          <h1 className="text-2xl font-bold text-gray-900">{p.basics?.name}</h1>
          <div className="flex items-center gap-3 mt-1">
            <span className={badge(p.basics?.status)}>{p.basics?.status}</span>
            <span className="text-sm text-gray-500">{p.basics?.category} · {p.basics?.subType}</span>
            {p.basics?.reraNumber && <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded-full">RERA: {p.basics.reraNumber}</span>}
          </div>
          <p className="text-gray-500 text-sm mt-1">{loc}</p>
        </div>
        <div className="flex items-center gap-3">
          <button onClick={toggleProjectActive}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium ${p.isActive ? "bg-red-50 text-red-600 hover:bg-red-100" : "bg-green-50 text-green-600 hover:bg-green-100"}`}>
            {p.isActive ? <ToggleRight size={16} /> : <ToggleLeft size={16} />}
            {p.isActive ? "Deactivate" : "Activate"}
          </button>
          <button onClick={() => navigate(`/project/${id}/add-unit-type`)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">
            <Plus size={16} /> Add Unit Type
          </button>
        </div>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-4">
        {[
          { label: "Unit Types", value: unitTypes.length, icon: <Layers size={18} className="text-blue-500" /> },
          { label: "Total Units", value: p.overview?.totalUnits || "—", icon: <Home size={18} className="text-green-500" /> },
          { label: "Towers", value: p.overview?.totalTowers || "—", icon: <Building2 size={18} className="text-purple-500" /> },
          { label: "Active Campaigns", value: campaigns.filter(c => c.status === "active").length, icon: <IndianRupee size={18} className="text-orange-500" /> },
        ].map((s) => (
          <div key={s.label} className="bg-white rounded-xl border border-gray-200 p-4 flex items-center gap-3">
            <div className="p-2 bg-gray-50 rounded-lg">{s.icon}</div>
            <div>
              <p className="text-2xl font-bold text-gray-800">{s.value}</p>
              <p className="text-xs text-gray-500">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200">
        {["units", "campaigns", "updates", "info"].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-5 py-2.5 text-sm font-medium capitalize border-b-2 transition-colors ${tab === t ? "border-blue-600 text-blue-600" : "border-transparent text-gray-500 hover:text-gray-700"}`}>
            {t === "units" ? "Unit Types" : t === "campaigns" ? "Campaigns" : t === "updates" ? "Construction Updates" : "Project Info"}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "units" && (
        <div className="space-y-3">
          {unitTypes.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-xl border border-dashed border-gray-300">
              <Home size={40} className="mx-auto text-gray-300 mb-3" />
              <p className="text-gray-500 font-medium">No unit types yet</p>
              <button onClick={() => navigate(`/project/${id}/add-unit-type`)}
                className="mt-3 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700">
                Add First Unit Type
              </button>
            </div>
          ) : (
            unitTypes.map(u => (
              <div key={u._id} className="bg-white rounded-xl border border-gray-200 p-4 flex items-center justify-between hover:shadow-sm transition">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-800">{u.config?.name}</h3>
                    <span className={`px-2 py-0.5 rounded-full text-xs ${u.isActive ? "bg-green-100 text-green-700" : "bg-red-100 text-red-600"}`}>
                      {u.isActive ? "Active" : "Inactive"}
                    </span>
                    {u.activeCampaignCount > 0 && (
                      <span className="bg-orange-100 text-orange-700 px-2 py-0.5 rounded-full text-xs">{u.activeCampaignCount} campaign(s)</span>
                    )}
                  </div>
                  <p className="text-sm text-gray-500 mt-0.5">
                    {[u.config?.bedrooms && `${u.config.bedrooms} BHK`, u.area?.carpetSqft && `${u.area.carpetSqft} sqft (carpet)`, u.pricing?.effectivePrice && `₹${(u.pricing.effectivePrice / 1e6).toFixed(2)}L`].filter(Boolean).join(" · ")}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Available: {u.inventory?.availableUnits ?? "—"} / {u.inventory?.totalUnits ?? "—"} units
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => navigate(`/project/${id}/campaign/new?unitTypeId=${u._id}`)}
                    className="px-3 py-1.5 bg-orange-50 text-orange-600 rounded-lg text-xs font-medium hover:bg-orange-100">
                    + Campaign
                  </button>
                  <button onClick={() => navigate(`/project/${id}/add-unit-type?edit=${u._id}`)}
                    className="p-2 text-gray-400 hover:text-blue-600 rounded-lg hover:bg-blue-50">
                    <ChevronRight size={16} />
                  </button>
                  <button onClick={() => deleteUnitType(u._id)}
                    className="p-2 text-gray-400 hover:text-red-500 rounded-lg hover:bg-red-50">
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "campaigns" && (
        <div className="space-y-3">
          {campaigns.length === 0 ? (
            <div className="text-center py-16 bg-white rounded-xl border border-dashed border-gray-300">
              <IndianRupee size={40} className="mx-auto text-gray-300 mb-3" />
              <p className="text-gray-500">No campaigns yet. Add unit types first, then create campaigns.</p>
            </div>
          ) : (
            campaigns.map(c => (
              <div key={c._id} className="bg-white rounded-xl border border-gray-200 p-4 flex items-center justify-between hover:shadow-sm transition cursor-pointer"
                onClick={() => navigate(`/campaign/${c._id}`)}>
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-gray-800">{c.basics?.name}</h3>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${c.status === "active" ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-600"}`}>{c.status}</span>
                  </div>
                  <p className="text-sm text-gray-500 mt-0.5">
                    {c.memberCount}/{c.buyerTargets?.maxBuyers} buyers · ₹{c.tokenAmount?.toLocaleString()} token · Ends {new Date(c.duration?.endDate).toLocaleDateString("en-IN")}
                  </p>
                </div>
                <div className="text-right">
                  <p className="text-sm font-bold text-green-600">Save ₹{c.pricing?.savings?.toLocaleString()}</p>
                  <p className="text-xs text-gray-400">{c.paidMemberCount} paid</p>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {tab === "updates" && (
        <div className="space-y-5">
          {/* Post new update */}
          <div className="bg-white rounded-xl border border-gray-200 p-5">
            <h3 className="font-semibold text-gray-800 mb-4 flex items-center gap-2">
              <HardHat size={18} className="text-orange-500" /> Post Construction Update
            </h3>
            <form onSubmit={postConstructionUpdate} className="space-y-3">
              <div className="grid grid-cols-4 gap-3">
                <div className="col-span-3">
                  <label className="block text-xs font-medium text-gray-500 mb-1">Title *</label>
                  <input className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                    value={updateForm.title} onChange={e => setUpdateForm(p => ({ ...p, title: e.target.value }))}
                    placeholder="e.g. Ground Floor Slab Completed" />
                </div>
                <div>
                  <label className="block text-xs font-medium text-gray-500 mb-1">% Complete</label>
                  <input type="number" min="0" max="100"
                    className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20"
                    value={updateForm.percentComplete} onChange={e => setUpdateForm(p => ({ ...p, percentComplete: e.target.value }))}
                    placeholder="e.g. 35" />
                </div>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1">Description</label>
                <textarea rows={2} className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500/20 resize-none"
                  value={updateForm.description} onChange={e => setUpdateForm(p => ({ ...p, description: e.target.value }))}
                  placeholder="Additional details about progress..." />
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1">Progress Photos</label>
                <div className="flex items-center gap-2 flex-wrap">
                  <label className="flex items-center gap-1.5 px-3 py-2 border border-dashed border-gray-300 rounded-lg text-sm text-gray-500 cursor-pointer hover:bg-gray-50">
                    <Upload size={14} /> Add Photos
                    <input type="file" accept="image/*" multiple className="hidden"
                      onChange={e => setUpdateImages(p => [...p, ...Array.from(e.target.files || [])])} />
                  </label>
                  {updateImages.map((f, i) => (
                    <span key={i} className="flex items-center gap-1 bg-blue-50 text-blue-700 px-2 py-1 rounded text-xs border border-blue-100">
                      {f.name.slice(0, 20)}{f.name.length > 20 ? "…" : ""}
                      <button type="button" onClick={() => setUpdateImages(p => p.filter((_, j) => j !== i))} className="text-blue-300 hover:text-red-500"><X size={10} /></button>
                    </span>
                  ))}
                </div>
              </div>
              <button type="submit" disabled={postingUpdate}
                className="px-5 py-2 bg-orange-500 text-white rounded-lg text-sm font-medium hover:bg-orange-600 disabled:opacity-50">
                {postingUpdate ? "Posting…" : "Post Update"}
              </button>
            </form>
          </div>

          {/* Existing updates */}
          {(p.constructionUpdates || []).length === 0 ? (
            <div className="text-center py-12 bg-white rounded-xl border border-dashed border-gray-300">
              <HardHat size={36} className="mx-auto text-gray-300 mb-2" />
              <p className="text-gray-500 text-sm">No construction updates posted yet.</p>
            </div>
          ) : (
            [...(p.constructionUpdates || [])].reverse().map((u, i) => (
              <div key={i} className="bg-white rounded-xl border border-gray-200 p-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h4 className="font-semibold text-gray-800">{u.title}</h4>
                    {u.description && <p className="text-sm text-gray-500 mt-0.5">{u.description}</p>}
                    <p className="text-xs text-gray-400 mt-1">{u.date ? new Date(u.date).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : ""}</p>
                  </div>
                  {u.percentComplete !== undefined && (
                    <span className="bg-orange-100 text-orange-700 px-3 py-1 rounded-full text-sm font-semibold whitespace-nowrap">{u.percentComplete}%</span>
                  )}
                </div>
                {u.images?.length > 0 && (
                  <div className="flex gap-2 mt-3 flex-wrap">
                    {u.images.map((img, j) => (
                      <a key={j} href={img} target="_blank" rel="noopener noreferrer">
                        <img src={img} alt="progress" className="w-20 h-20 object-cover rounded-lg border border-gray-100 hover:opacity-90 transition" />
                      </a>
                    ))}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      )}

      {tab === "info" && (
        <div className="bg-white rounded-xl border border-gray-200 p-5 space-y-4 text-sm">
          {[
            ["Possession Date", p.overview?.possessionDate ? new Date(p.overview.possessionDate).toLocaleDateString("en-IN") : "—"],
            ["Land Area", p.overview?.totalLandArea || "—"],
            ["Open Space", p.overview?.openSpacePercentage ? `${p.overview.openSpacePercentage}%` : "—"],
            ["Floors / Tower", p.overview?.floorsPerTower || "—"],
            ["Ownership", p.basics?.ownershipType || "—"],
            ["Vastu", p.basics?.isVastuCompliant ? "Yes" : "No"],
            ["Litigation", p.legal?.litigationStatus || "—"],
            ["Sales Manager", p.salesContact?.managerName || "—"],
            ["Sales Phone", p.salesContact?.phone || "—"],
          ].map(([k, v]) => (
            <div key={k} className="flex justify-between border-b border-gray-50 pb-2">
              <span className="text-gray-500">{k}</span>
              <span className="font-medium text-gray-800">{v}</span>
            </div>
          ))}
          {p.basics?.highlights?.length > 0 && (
            <div>
              <p className="text-gray-500 mb-1">Highlights</p>
              <div className="flex flex-wrap gap-1.5">
                {p.basics.highlights.map((h, i) => <span key={i} className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded text-xs">{h}</span>)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
