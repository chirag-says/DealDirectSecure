import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import { projectApi, unitTypeApi } from "../api/adminApi";
import { Plus, Building2, Home, Layers, ChevronRight, Trash2, HardHat, Upload, X, Eye, EyeOff, CheckCircle2, AlertTriangle, XCircle, Circle } from "lucide-react";

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
  const [tab, setTab] = useState("units");
  const [loading, setLoading] = useState(true);
  const [updateForm, setUpdateForm] = useState({ title: "", description: "", percentComplete: "" });
  const [updateImages, setUpdateImages] = useState([]);
  const [postingUpdate, setPostingUpdate] = useState(false);

  const [readiness, setReadiness] = useState(null);
  const [publishing, setPublishing] = useState(false);

  const load = async () => {
    try {
      const [pRes, uRes, rRes] = await Promise.all([
        projectApi.getById(id),
        unitTypeApi.getByProject(id),
        // Readiness must never block the page: a project that fails to
        // evaluate should still be viewable and editable.
        projectApi.getReadiness(id).catch(() => null),
      ]);
      setProject(pRes.data || pRes);
      setUnitTypes(uRes.data || []);
      setReadiness(rRes?.data || null);
    } catch {
      toast.error("Failed to load project.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [id]);

  const publishStatus = project?.publication?.status
    // Records predating the lifecycle field carry only isActive, and the server
    // reads them the same way. Showing "draft" for a project that is live on the
    // site would be a lie the admin would act on.
    ?? (project?.isActive === false ? "draft" : "published");

  const doPublish = async () => {
    setPublishing(true);
    try {
      const res = await projectApi.publish(id);
      toast.success(res.message || "Project published.");
      await load();
    } catch (e) {
      const body = e?.response?.data;
      if (body?.blockers?.length) {
        // Name the first blocker in the toast; the panel lists them all. A
        // toast that only says "not ready" makes the admin hunt.
        toast.error(`Cannot publish: ${body.blockers[0].message}`);
        setReadiness({ ...body, status: "draft" });
      } else {
        toast.error(body?.message || "Failed to publish.");
      }
    } finally { setPublishing(false); }
  };

  const doUnpublish = async () => {
    if (!window.confirm(
      "Take this project off the public site?\n\n" +
      "Existing enquiries are not affected."
    )) return;
    setPublishing(true);
    try {
      await projectApi.unpublish(id);
      toast.success("Project unpublished.");
      await load();
    } catch (e) {
      toast.error(e?.response?.data?.message || "Failed to unpublish.");
    } finally { setPublishing(false); }
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
          {publishStatus === "published" ? (
            <button onClick={doUnpublish} disabled={publishing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-amber-50 text-amber-700 hover:bg-amber-100 disabled:opacity-60">
              <EyeOff size={16} /> Unpublish
            </button>
          ) : (
            <button onClick={doPublish} disabled={publishing || readiness?.canPublish === false}
              title={readiness?.canPublish === false
                ? "Complete the required items below first"
                : "Make this project visible to buyers"}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium bg-green-600 text-white hover:bg-green-700 disabled:bg-gray-200 disabled:text-gray-400 disabled:cursor-not-allowed">
              <Eye size={16} /> {publishing ? "Publishing…" : "Publish"}
            </button>
          )}
          <button onClick={() => navigate(`/project/${id}/add-unit-type`)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg text-sm font-medium hover:bg-blue-700">
            <Plus size={16} /> Add Unit Type
          </button>
        </div>
      </div>

      {/* ── Readiness ──────────────────────────────────────────────────────
          Shows PASSING rules too, not only failures. An admin who can see
          only complaints cannot tell progress from stagnation, and the census
          says the trailing steps of the wizard are exactly where attention
          runs out. */}
      {readiness && (
        <div className={`rounded-xl border p-5 ${
          publishStatus === "published"
            ? "bg-green-50/50 border-green-200"
            : readiness.canPublish ? "bg-blue-50/50 border-blue-200" : "bg-amber-50/50 border-amber-200"
        }`}>
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold text-gray-800 flex items-center gap-2">
              {publishStatus === "published"
                ? <><Eye size={16} className="text-green-600" /> Live on the site</>
                : readiness.canPublish
                  ? <><CheckCircle2 size={16} className="text-blue-600" /> Ready to publish</>
                  : <><AlertTriangle size={16} className="text-amber-600" /> Not ready to publish</>}
            </h3>
            <span className="text-xs text-gray-500">
              {readiness.checklist?.filter(c => c.passed).length}/{readiness.checklist?.length} complete
            </span>
          </div>

          {readiness.blockers?.length > 0 && (
            <div className="mb-3">
              <p className="text-xs font-semibold text-amber-800 uppercase tracking-wide mb-1.5">Required</p>
              <ul className="space-y-1.5">
                {readiness.blockers.map(b => (
                  <li key={b.rule} className="flex items-start gap-2 text-sm text-gray-700">
                    <XCircle size={14} className="text-amber-600 shrink-0 mt-0.5" /> {b.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {readiness.warnings?.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-gray-500 uppercase tracking-wide mb-1.5">
                Recommended — these never block publishing
              </p>
              <ul className="space-y-1 opacity-80">
                {readiness.warnings.map(w => (
                  <li key={w.rule} className="flex items-start gap-2 text-sm text-gray-600">
                    <Circle size={12} className="text-gray-400 shrink-0 mt-1" /> {w.message}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {readiness.blockers?.length === 0 && readiness.warnings?.length === 0 && (
            <p className="text-sm text-gray-600">Everything on the checklist is complete.</p>
          )}
        </div>
      )}

      {/* Stats bar */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Unit Types", value: unitTypes.length, icon: <Layers size={18} className="text-blue-500" /> },
          { label: "Total Units", value: p.overview?.totalUnits || "—", icon: <Home size={18} className="text-green-500" /> },
          { label: "Towers", value: p.overview?.totalTowers || "—", icon: <Building2 size={18} className="text-purple-500" /> },
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
        {["units", "updates", "info"].map(t => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-5 py-2.5 text-sm font-medium capitalize border-b-2 transition-colors ${tab === t ? "border-blue-600 text-blue-600" : "border-transparent text-gray-500 hover:text-gray-700"}`}>
            {t === "units" ? "Unit Types" : t === "updates" ? "Construction Updates" : "Project Info"}
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
                  </div>
                  <p className="text-sm text-gray-500 mt-0.5">
                    {[u.config?.bedrooms && `${u.config.bedrooms} BHK`, u.area?.carpetSqft && `${u.area.carpetSqft} sqft (carpet)`, u.pricing?.effectivePrice && `₹${(u.pricing.effectivePrice / 1e6).toFixed(2)}L`].filter(Boolean).join(" · ")}
                  </p>
                  <p className="text-xs text-gray-400 mt-0.5">
                    Available: {u.inventory?.availableUnits ?? "—"} / {u.inventory?.totalUnits ?? "—"} units
                  </p>
                </div>
                <div className="flex items-center gap-2">
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
            ["Sales Contact", "DealDirect Admin"],
            ["Sales Phone", "6360122696"],
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
