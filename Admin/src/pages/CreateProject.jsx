import React, { useState, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { toast } from "react-toastify";
import { builderApi, projectApi } from "../api/adminApi";
import LocationPicker from "../components/LocationPicker";
import Wizard from "../components/wizard/Wizard";
import { inp, lbl } from "../components/wizard/FormField";
import ConfirmModal from "../components/wizard/ConfirmModal";
import { useFormDraft } from "../components/wizard/useFormDraft";
import { validateProjectStep } from "../schemas/projectSchema";

const STEPS = [
  { id: 1, label: "Basics" },
  { id: 2, label: "Location" },
  { id: 3, label: "Nearby" },
  { id: 4, label: "Overview" },
  { id: 5, label: "Amenities" },
  { id: 6, label: "Media" },
  { id: 7, label: "Docs & Legal" },
  { id: 8, label: "Payment & Sales" },
  { id: 9, label: "Review" },
];

const AMENITY_PRESETS = {
  Lifestyle: ["Clubhouse", "Swimming Pool", "Spa", "Salon", "Concierge", "Amphitheatre", "Party Hall"],
  Fitness: ["Gym", "Yoga Room", "Jogging Track", "Cycling Track", "Indoor Sports"],
  Recreation: ["Children's Play Area", "Game Room", "Mini Theatre", "Library", "Pet Park"],
  Safety: ["24x7 Security", "CCTV Surveillance", "Boom Barrier", "Video Door Phone", "Fire Safety"],
  Utilities: ["Power Backup", "Rainwater Harvesting", "Solar Panels", "EV Charging", "Wi-Fi Enabled"],
};

// ── Thumbnail component that safely manages blob URL lifecycle ────────────────
function FilePreviewThumbnail({ file }) {
  const [url, setUrl] = useState(null);

  useEffect(() => {
    if (!file) return;
    const objectUrl = URL.createObjectURL(file);
    setUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file]);

  if (!url) return <div className="w-full h-24 bg-gray-100 animate-pulse rounded" />;

  return (
    <img
      src={url}
      alt={file.name}
      className="w-full h-24 object-cover"
    />
  );
}

export default function CreateProject() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const builderId = searchParams.get("builderId");

  const [step, setStep] = useState(1);
  const [builder, setBuilder] = useState(null);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [confirmClearDraft, setConfirmClearDraft] = useState(false);

  // Per-step errors
  const [errors, setErrors] = useState({});

  // Draft persistence via the shared hook
  const DRAFT_KEY = `createProjectDraft_${builderId}`;
  const { draftExists, saveDraft, loadDraft, clearDraft } = useFormDraft(DRAFT_KEY);

  const [form, setForm] = useState({
    name: "", description: "", category: "Residential", subType: "Apartment",
    status: "New Launch", ownershipType: "Freehold", isVastuCompliant: false,
    highlights: [], reraNumber: "", country: "India", state: "", city: "",
    locality: "", microMarket: "", addressLine: "", landmark: "", pincode: "",
    lat: "", lng: "", distanceToMetro: "", distanceToAirport: "", distanceToRailway: "",
    distanceToBusStop: "", nearbyPlaces: [], launchDate: "", possessionDate: "",
    totalLandArea: "", totalTowers: "", floorsPerTower: "", totalUnits: "",
    openSpacePercentage: "", amenities: [], paymentPlans: [], bookingAmount: "",
    gstPercentage: "", stampDutyPercentage: "", registrationCharges: "",
    managerName: "", salesPhone: "", salesWhatsapp: "", salesEmail: "",
    landTitleType: "Freehold", titleClear: true, litigationStatus: "None",
    encumbrances: "", litigationDetails: "", walkthroughVideoUrl: "",
  });


  const [files, setFiles] = useState({
    exteriorImages: [], droneImages: [], masterPlan: [], locationMap: [],
    constructionProgressImages: [], brochureUrl: [], reraCertificateUrl: [],
    commencementCertificateUrl: [], occupancyCertificateUrl: [],
    environmentalClearanceUrl: [], approvalDocumentUrls: [],
  });

  const [highlightInput, setHighlightInput] = useState("");
  const [nearbyInput, setNearbyInput] = useState({ category: "Education", name: "", distance: "" });


  // Per-step validation — now backed by Zod schemas from projectSchema.js
  const validateStep = (s) => validateProjectStep(s, form, files);


  // ── localStorage persistence — now via useFormDraft hook ──────────────────
  useEffect(() => {
    if (builderId) saveDraft(form, step);
  }, [form, step, builderId]);

  useEffect(() => {
    if (!builderId) return;
    const saved = loadDraft();
    if (saved) { setForm(saved.form); setStep(saved.step); }
  }, [builderId]);


  useEffect(() => {
    if (!builderId) { toast.error("No builder selected."); navigate("/builder-management"); return; }
    builderApi.getById(builderId)
      .then(r => setBuilder(r.data || r))
      .catch(() => { toast.error("Builder not found."); navigate("/builder-management"); });
  }, [builderId]);

  // `set` writes a top-level form field AND clears any active error for that key,
  // so the red border disappears as soon as the user starts typing.
  const set = (key, val) => {
    setForm(p => ({ ...p, [key]: val }));
    if (errors[key]) {
      const { [key]: _drop, ...rest } = errors;
      setErrors(rest);
    }
  };

  const addHighlight = () => {
    if (!highlightInput.trim()) return;
    set("highlights", [...form.highlights, highlightInput.trim()]);
    setHighlightInput("");
  };

  const toggleAmenity = (category, name) => {
    const exists = form.amenities.find(a => a.category === category && a.name === name);
    if (exists) set("amenities", form.amenities.filter(a => !(a.category === category && a.name === name)));
    else set("amenities", [...form.amenities, { category, name }]);
  };

  const [customAmenity, setCustomAmenity] = useState({ category: "Lifestyle", name: "" });
  const addCustomAmenity = () => {
    const name = customAmenity.name.trim();
    if (!name) return;
    // Prevent duplicates (case-insensitive)
    if (form.amenities.some(a => a.category === customAmenity.category && a.name.toLowerCase() === name.toLowerCase())) {
      toast.info("This amenity is already added.");
      return;
    }
    set("amenities", [...form.amenities, { category: customAmenity.category, name }]);
    setCustomAmenity(p => ({ ...p, name: "" }));
  };

  const addNearby = () => {
    if (!nearbyInput.name.trim()) return;
    set("nearbyPlaces", [...form.nearbyPlaces, { ...nearbyInput }]);
    setNearbyInput({ category: "Education", name: "", distance: "" });
  };



  const handleFiles = (field, e) => {
    const selectedFiles = Array.from(e.target.files || []);
    if (selectedFiles.length === 0) return;
    setFiles(p => ({ ...p, [field]: [...(p[field] || []), ...selectedFiles] }));
    // Reset the input so the same file can be re-selected after removal
    e.target.value = "";
    // Clear the validation error for this field once a file is added
    if (errors[field]) {
      const { [field]: _drop, ...rest } = errors;
      setErrors(rest);
    }
  };

  const removeFile = (field, index) => {
    setFiles(p => ({
      ...p,
      [field]: p[field].filter((_, i) => i !== index),
    }));
  };

  const handleSubmit = async () => {
    // Run validation across EVERY step, not just step 9. The "Next" button already
    // gates each individual step, but a user could still click Step 9 in the indicator
    // and try to submit from there. This is the final safety net.
    const allErrors = {};
    for (let s = 1; s <= 8; s++) {
      Object.assign(allErrors, validateStep(s));
    }
    if (Object.keys(allErrors).length > 0) {
      setErrors(allErrors);
      const count = Object.keys(allErrors).length;
      toast.error(`${count} field${count > 1 ? "s" : ""} need${count > 1 ? "" : "s"} attention. Please review the form.`);
      // Jump to the first step that has an error
      for (let s = 1; s <= 8; s++) {
        if (Object.keys(validateStep(s)).length > 0) {
          setStep(s);
          setTimeout(() => {
            const firstField = Object.keys(validateStep(s))[0];
            const el = stepContainerRef.current?.querySelector(`[data-field="${firstField}"]`);
            if (el) {
              if (typeof el.focus === "function") el.focus();
              el.scrollIntoView({ behavior: "smooth", block: "center" });
            }
          }, 50);
          break;
        }
      }
      return;
    }
    setErrors({});
    setSubmitting(true);
    try {
      const fd = new FormData();
      fd.append("builderId", builderId);
      Object.entries(form).forEach(([k, v]) => {
        if (Array.isArray(v)) fd.append(k, JSON.stringify(v));
        else if (typeof v === "boolean") fd.append(k, String(v));
        else if (v !== "" && v !== null && v !== undefined) fd.append(k, v);
      });
      Object.entries(files).forEach(([field, fileArr]) => {
        fileArr.forEach(f => fd.append(field, f));
      });
      const res = await projectApi.create(fd);
      toast.success("Project created!");
      // Clear the saved draft once the project is created
      clearDraft();
      navigate(`/project/${res.data._id}`);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to create project.");
    } finally {
      setSubmitting(false);
    }
  };

  const renderStep = () => {
    switch (step) {
      case 1: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Project Basics</h2>
          {builder && (
            <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 flex items-center gap-3">
              <div>
                <p className="text-xs text-blue-600 font-medium">Creating project for</p>
                <p className="font-semibold text-blue-800">{builder.company || builder.name}</p>
              </div>
            </div>
          )}
          <div>
            <label className={lbl}>Project Name *</label>
            <input
              data-field="name"
              className={inp}
              value={form.name}
              onChange={e => set("name", e.target.value)}
              placeholder="e.g. Prestige Lake View"
            />
          </div>
          <div>
            <label className={lbl}>Description</label>
            <textarea
              data-field="description"
              className={inp}
              rows={3}
              value={form.description}
              onChange={e => set("description", e.target.value)}
              placeholder="Marketing description..."
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={lbl}>Category *</label>
              <select
                data-field="category"
                className={inp}
                value={form.category}
                onChange={e => set("category", e.target.value)}
              >
                {["Residential","Commercial","Mixed Use"].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className={lbl}>Sub Type</label>
              <select
                data-field="subType"
                className={inp}
                value={form.subType}
                onChange={e => set("subType", e.target.value)}
              >
                {["Apartment","Villa Community","Plotted Development","Integrated Township","Commercial Office","Retail","Mall","Business Park"].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className={lbl}>Status</label>
              <select
                data-field="status"
                className={inp}
                value={form.status}
                onChange={e => set("status", e.target.value)}
              >
                {["New Launch","Under Construction","Ready To Move","Completed"].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className={lbl}>Ownership</label>
              <select
                data-field="ownershipType"
                className={inp}
                value={form.ownershipType}
                onChange={e => set("ownershipType", e.target.value)}
              >
                {["Freehold","Leasehold","Cooperative Housing Society","Power of Attorney"].map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className={lbl}>RERA Number</label>
            <input className={inp} value={form.reraNumber} onChange={e => set("reraNumber", e.target.value)} placeholder="e.g. P52100012345" />
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="vastu" checked={form.isVastuCompliant} onChange={e => set("isVastuCompliant", e.target.checked)} />
            <label htmlFor="vastu" className="text-sm text-gray-700">Vastu Compliant</label>
          </div>
          <div>
            <label className={lbl}>Project Highlights</label>
            <div className="flex gap-2">
              <input className={inp} value={highlightInput} onChange={e => setHighlightInput(e.target.value)} onKeyDown={e => e.key === "Enter" && addHighlight()} placeholder="Add USP and press Enter..." />
              <button onClick={addHighlight} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm">Add</button>
            </div>
            <div className="flex flex-wrap gap-2 mt-2">
              {form.highlights.map((h, i) => (
                <span key={i} className="bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-xs flex items-center gap-1">
                  {h}<button onClick={() => set("highlights", form.highlights.filter((_, j) => j !== i))} className="ml-1 text-blue-400 hover:text-red-500">×</button>
                </span>
              ))}
            </div>
          </div>
        </div>
      );
      case 2: return (
        <LocationPicker
          value={form}
          errors={errors}
          onChange={(patch) => {
            // Merge partial updates from LocationPicker
            Object.entries(patch).forEach(([k, val]) => set(k, val));
          }}
        />
      );
      case 3: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Nearby Infrastructure</h2>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className={lbl}>Category</label>
              <select className={inp} value={nearbyInput.category} onChange={e => setNearbyInput(p => ({ ...p, category: e.target.value }))}>
                {["Education","Healthcare","Shopping","Business","Entertainment","Worship","Government","Transit"].map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className={lbl}>Name</label>
              <input className={inp} value={nearbyInput.name} onChange={e => setNearbyInput(p => ({ ...p, name: e.target.value }))} placeholder="e.g. DPS School" />
            </div>
            <div>
              <label className={lbl}>Distance</label>
              <input className={inp} value={nearbyInput.distance} onChange={e => setNearbyInput(p => ({ ...p, distance: e.target.value }))} placeholder="e.g. 500 m" />
            </div>
          </div>
          <button onClick={addNearby} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm">Add Nearby Place</button>
          <div className="space-y-2 mt-2">
            {form.nearbyPlaces.map((n, i) => (
              <div key={i} className="flex items-center justify-between bg-gray-50 rounded-lg p-2 text-sm">
                <span><strong>{n.category}</strong> — {n.name} ({n.distance})</span>
                <button onClick={() => set("nearbyPlaces", form.nearbyPlaces.filter((_, j) => j !== i))} className="text-red-400 hover:text-red-600">Remove</button>
              </div>
            ))}
          </div>
        </div>
      );
      case 4: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Project Overview</h2>
          <div className="grid grid-cols-2 gap-4">
            {[
              ["launchDate","Launch Date *","date"],
              ["possessionDate","Possession Date *","date"],
              ["totalLandArea","Total Land Area *","text"],
              ["totalTowers","Number of Towers *","number"],
              ["floorsPerTower","Floors per Tower","text"],
              ["totalUnits","Total Units","number"],
              ["openSpacePercentage","Open Space %","number"],
            ].map(([k,l,t]) => (
              <div key={k}>
                <label className={lbl}>{l}</label>
                <input
                  data-field={k}
                  className={errors[k] ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
                  type={t}
                  value={form[k]}
                  onChange={e => set(k, e.target.value)}
                  placeholder={t === "text" ? "e.g. 10 Acres" : ""}
                />
                {errors[k] && <p className="text-xs text-red-500 mt-1">{errors[k]}</p>}
              </div>
            ))}
          </div>
        </div>
      );
      case 5: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Amenities</h2>
          <p className="text-xs text-gray-500">Select from presets or add custom amenities. At least one required *</p>
          {Object.entries(AMENITY_PRESETS).map(([cat, items]) => (
            <div key={cat}>
              <h3 className="font-medium text-gray-700 mb-2">{cat}</h3>
              <div className="flex flex-wrap gap-2">
                {items.map(item => {
                  const checked = form.amenities.some(a => a.category === cat && a.name === item);
                  return (
                    <button
                      key={item}
                      onClick={() => {
                        toggleAmenity(cat, item);
                        if (errors.amenities && form.amenities.length === 0) {
                          const { amenities: _, ...rest } = errors;
                          setErrors(rest);
                        }
                      }}
                      data-field="amenities"
                      className={`px-3 py-1.5 rounded-full text-sm border transition-all ${checked ? "bg-blue-600 text-white border-blue-600" : "bg-white text-gray-600 border-gray-300 hover:border-blue-400"}`}>
                      {item}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}

          {/* ── Custom Amenity Input ── */}
          <div className="border-t border-gray-200 pt-4">
            <h3 className="font-medium text-gray-700 mb-2">Add Custom Amenity</h3>
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className={lbl}>Category</label>
                <select className={inp} value={customAmenity.category} onChange={e => setCustomAmenity(p => ({ ...p, category: e.target.value }))}>
                  {["Lifestyle","Fitness","Recreation","Safety","Utilities"].map(c => <option key={c}>{c}</option>)}
                </select>
              </div>
              <div className="col-span-2">
                <label className={lbl}>Amenity Name</label>
                <div className="flex gap-2">
                  <input className={inp} value={customAmenity.name} onChange={e => setCustomAmenity(p => ({ ...p, name: e.target.value }))}
                    onKeyDown={e => { if (e.key === "Enter") { e.preventDefault(); addCustomAmenity(); } }}
                    placeholder="e.g. Rooftop Lifestyle Zone, Basketball Court..." />
                  <button type="button" onClick={addCustomAmenity} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm whitespace-nowrap">Add</button>
                </div>
              </div>
            </div>
          </div>

          {/* ── Show all selected amenities (including custom) ── */}
          {form.amenities.length > 0 && (
            <div className="border-t border-gray-200 pt-3">
              <p className="text-xs text-gray-500 mb-2">{form.amenities.length} amenities selected</p>
              <div className="flex flex-wrap gap-2">
                {form.amenities.map((a, i) => {
                  const isPreset = Object.entries(AMENITY_PRESETS).some(([cat, items]) => cat === a.category && items.includes(a.name));
                  return (
                    <span key={i} className={`px-3 py-1 rounded-full text-xs flex items-center gap-1 border ${isPreset ? "bg-blue-100 text-blue-700 border-blue-200" : "bg-emerald-100 text-emerald-700 border-emerald-200"}`}>
                      <span className="text-[10px] text-gray-400">{a.category}:</span> {a.name}
                      {!isPreset && <button type="button" onClick={() => set("amenities", form.amenities.filter((_, j) => j !== i))} className="ml-1 text-emerald-400 hover:text-red-500">×</button>}
                    </span>
                  );
                })}
              </div>
            </div>
          )}
          {errors.amenities && <p className="text-xs text-red-500">{errors.amenities}</p>}
        </div>
      );
      case 6: return (
        <div className="space-y-5">
          <h2 className="text-lg font-semibold text-gray-800">Media</h2>
          {[
            ["exteriorImages","Exterior Images (multiple) *","image/*",true],
            ["droneImages","Drone/Aerial Images","image/*",true],
            ["masterPlan","Master Plan","image/*",true],
            ["locationMap","Location Map","image/*",true],
            ["constructionProgressImages","Construction Progress","image/*",true],
            ["brochureUrl","Project Brochure (PDF)","application/pdf",false],
          ].map(([field,label,accept,multiple]) => {
            const isImage = accept.startsWith("image");
            return (
              <div key={field} className={`border rounded-xl p-4 ${errors[field] ? "border-red-400 bg-red-50/30" : "border-gray-200 bg-gray-50/50"}`}>
                <label className={lbl}>{label}</label>
                <input
                  data-field={field}
                  type="file"
                  accept={accept}
                  multiple={multiple}
                  onChange={e => handleFiles(field, e)}
                  className="block w-full text-sm text-gray-500 file:mr-3 file:py-1.5 file:px-4 file:rounded-lg file:border-0 file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100 cursor-pointer"
                />
                {errors[field] && <p className="text-xs text-red-500 mt-1">{errors[field]}</p>}

                {/* ── Image Preview Grid ── */}
                {files[field]?.length > 0 && (
                  <div className="mt-3">
                    <p className="text-xs text-gray-500 mb-2">{files[field].length} file(s) selected</p>
                    <div className="grid grid-cols-3 sm:grid-cols-4 md:grid-cols-5 gap-3">
                      {files[field].map((file, i) => (
                        <div key={`${field}-${i}-${file.name}`} className="group relative rounded-lg overflow-hidden border border-gray-200 bg-white shadow-sm">
                          {isImage ? (
                            <FilePreviewThumbnail file={file} />
                          ) : (
                            <div className="w-full h-24 flex items-center justify-center bg-gray-100">
                              <svg className="w-10 h-10 text-red-400" fill="currentColor" viewBox="0 0 24 24">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8l-6-6zm-1 1.5L18.5 9H13V3.5zM6 20V4h5v7h7v9H6z"/>
                              </svg>
                            </div>
                          )}
                          {/* Remove button */}
                          <button
                            type="button"
                            onClick={() => removeFile(field, i)}
                            className="absolute top-1 right-1 w-5 h-5 flex items-center justify-center rounded-full bg-red-500 text-white text-xs opacity-0 group-hover:opacity-100 transition-opacity hover:bg-red-600 shadow"
                            title="Remove"
                          >
                            ×
                          </button>
                          {/* File name + size */}
                          <div className="px-1.5 py-1 border-t border-gray-100">
                            <p className="text-[10px] text-gray-600 truncate" title={file.name}>{file.name}</p>
                            <p className="text-[9px] text-gray-400">{(file.size / 1024).toFixed(0)} KB</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
          <div>
            <label className={lbl}>Walkthrough Video URL</label>
            <input className={inp} value={form.walkthroughVideoUrl} onChange={e => set("walkthroughVideoUrl", e.target.value)} placeholder="YouTube / Vimeo URL" />
          </div>
        </div>
      );
      case 7: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Documents & Legal</h2>
          {[
            ["reraCertificateUrl","RERA Certificate *"],
            ["commencementCertificateUrl","Commencement Certificate"],
            ["occupancyCertificateUrl","Occupancy Certificate"],
            ["environmentalClearanceUrl","Environmental Clearance"],
            ["approvalDocumentUrls","Other Approvals (multiple)"],
          ].map(([field, label]) => (
            <div key={field} className={`border rounded-xl p-4 ${errors[field] ? "border-red-400 bg-red-50/30" : "border-gray-200 bg-gray-50/50"}`}>
              <label className={lbl}>{label}</label>
              <input
                data-field={field}
                type="file"
                accept=".pdf,.jpg,.jpeg,.png"
                multiple={field === "approvalDocumentUrls"}
                onChange={e => handleFiles(field, e)}
                className="block w-full text-sm text-gray-500 file:mr-3 file:py-1.5 file:px-4 file:rounded-lg file:border-0 file:bg-gray-50 file:text-gray-600 hover:file:bg-gray-100 cursor-pointer"
              />
              {errors[field] && <p className="text-xs text-red-500 mt-1">{errors[field]}</p>}

              {/* ── Selected Files List ── */}
              {files[field]?.length > 0 && (
                <div className="mt-3 space-y-1.5">
                  <p className="text-xs text-emerald-600 font-medium">✓ {files[field].length} file(s) selected</p>
                  {files[field].map((file, i) => (
                    <div key={`${field}-${i}-${file.name}`} className="flex items-center justify-between bg-white rounded-lg px-3 py-2 border border-gray-100 text-sm">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="text-gray-400 text-xs">📄</span>
                        <span className="text-gray-700 truncate">{file.name}</span>
                        <span className="text-gray-400 text-xs whitespace-nowrap">({(file.size / 1024).toFixed(0)} KB)</span>
                      </div>
                      <button type="button" onClick={() => removeFile(field, i)}
                        className="text-red-400 hover:text-red-600 text-xs ml-2 whitespace-nowrap">Remove</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
          <h3 className="font-medium text-gray-700 pt-2">Legal Status</h3>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={lbl}>Land Title Type</label>
              <select className={inp} value={form.landTitleType} onChange={e => set("landTitleType", e.target.value)}>
                {["Freehold","Leasehold"].map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
            <div>
              <label className={lbl}>Litigation Status</label>
              <select className={inp} value={form.litigationStatus} onChange={e => set("litigationStatus", e.target.value)}>
                {["None","Pending","Resolved"].map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <input
              data-field="titleClear"
              type="checkbox"
              id="titleClear"
              checked={form.titleClear}
              onChange={e => {
                set("titleClear", e.target.checked);
                if (e.target.checked && errors.titleClear) {
                  const { titleClear: _, ...rest } = errors;
                  setErrors(rest);
                }
              }}
            />
            <label htmlFor="titleClear" className="text-sm text-gray-700">Title Clear *</label>
          </div>
          {errors.titleClear && <p className="text-xs text-red-500">{errors.titleClear}</p>}
          <div>
            <label className={lbl}>Encumbrances</label>
            <input className={inp} value={form.encumbrances} onChange={e => set("encumbrances", e.target.value)}
              placeholder="e.g. Mortgage with SBI (to be cleared before registration)" />
          </div>
          {form.litigationStatus !== "None" && (
            <div>
              <label className={lbl}>Litigation Details</label>
              <textarea className={inp} rows={2} value={form.litigationDetails} onChange={e => set("litigationDetails", e.target.value)}
                placeholder="Describe the pending/resolved litigation..." />
            </div>
          )}
        </div>
      );
      case 8: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Payment & Banking</h2>
          <div className="grid grid-cols-2 gap-4">
            {[
              ["bookingAmount","Booking Amount (₹) *"],
              ["gstPercentage","GST %"],
              ["stampDutyPercentage","Stamp Duty %"],
              ["registrationCharges","Registration Charges (₹)"],
            ].map(([k,l]) => (
              <div key={k}>
                <label className={lbl}>{l}</label>
                <input
                  data-field={k}
                  className={errors[k] ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
                  type="number"
                  min="0"
                  value={form[k]}
                  onChange={e => set(k, e.target.value)}
                />
                {errors[k] && <p className="text-xs text-red-500 mt-1">{errors[k]}</p>}
              </div>
            ))}
          </div>

          <h3 className="font-medium text-gray-700 pt-2">Sales Contact</h3>
          <div className="grid grid-cols-2 gap-4">
            {[
              ["managerName","Manager Name"],
              ["salesPhone","Phone *"],
              ["salesWhatsapp","WhatsApp"],
              ["salesEmail","Email *"],
            ].map(([k,l]) => (
              <div key={k}>
                <label className={lbl}>{l}</label>
                <input
                  data-field={k}
                  className={errors[k] ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
                  value={form[k]}
                  onChange={e => set(k, e.target.value)}
                />
                {errors[k] && <p className="text-xs text-red-500 mt-1">{errors[k]}</p>}
              </div>
            ))}
          </div>
        </div>
      );
      case 9: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-gray-800">Review & Submit</h2>
          <div className="bg-gray-50 rounded-xl p-4 space-y-3 text-sm">
            <div className="grid grid-cols-2 gap-2">
              <div><span className="text-gray-500">Project Name:</span><p className="font-medium">{form.name || "—"}</p></div>
              <div><span className="text-gray-500">Category:</span><p className="font-medium">{form.category} / {form.subType}</p></div>
              <div><span className="text-gray-500">Status:</span><p className="font-medium">{form.status}</p></div>
              <div><span className="text-gray-500">Location:</span><p className="font-medium">{[form.locality, form.city, form.state].filter(Boolean).join(", ") || "—"}</p></div>
              <div><span className="text-gray-500">RERA:</span><p className="font-medium">{form.reraNumber || "Not provided"}</p></div>
              <div><span className="text-gray-500">Amenities:</span><p className="font-medium">{form.amenities.length} selected</p></div>
              <div><span className="text-gray-500">Nearby Places:</span><p className="font-medium">{form.nearbyPlaces.length} added</p></div>

            </div>
            <div>
              <span className="text-gray-500">Highlights:</span>
              <div className="flex flex-wrap gap-1 mt-1">
                {form.highlights.map((h, i) => <span key={i} className="bg-blue-100 text-blue-700 px-2 py-0.5 rounded text-xs">{h}</span>)}
              </div>
            </div>
          </div>
          <button onClick={handleSubmit} disabled={submitting}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition disabled:opacity-50 disabled:cursor-not-allowed">
            {submitting ? "Creating Project..." : "Create Project"}
          </button>
        </div>
      );
      default: return null;
    }
  };

  return (
    <div>
      {/* Header */}
      <div className="max-w-3xl mx-auto pt-6 px-4">
        <button type="button" onClick={() => navigate("/builder-management")}
          className="text-sm text-blue-600 hover:underline mb-2">
          ← Back to Builders
        </button>
        <h1 className="text-2xl font-bold text-gray-900">Create New Project</h1>
        {builder && <p className="text-gray-500 text-sm mt-1">for {builder.company || builder.name}</p>}
      </div>

      <Wizard
        steps={STEPS}
        currentStep={step}
        onStepChange={setStep}
        validateStep={validateStep}
        onSetErrors={setErrors}
        onSubmit={handleSubmit}
        submitting={submitting}
        submitLabel="Create Project"
        draftBanner={draftExists && (
          <div className="flex items-center justify-between gap-3 bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-2.5 text-sm">
            <div className="flex items-center gap-2 text-emerald-700">
              <span>✓</span>
              <span>Your progress is auto-saved in this browser.</span>
            </div>
            <button
              type="button"
              onClick={() => setConfirmClearDraft(true)}
              className="text-xs px-3 py-1 border border-emerald-300 text-emerald-700 rounded hover:bg-emerald-100 whitespace-nowrap"
            >
              Clear draft
            </button>
          </div>
        )}
      >
        {renderStep()}
      </Wizard>

      {confirmClearDraft && (
        <ConfirmModal
          title="Clear saved draft?"
          message="This will reset the entire form to empty. This cannot be undone."
          confirmLabel="Clear Draft"
          cancelLabel="Keep Draft"
          variant="warn"
          onConfirm={() => {
            clearDraft();
            setForm({
              name: "", description: "", category: "Residential", subType: "Apartment",
              status: "New Launch", ownershipType: "Freehold", isVastuCompliant: false,
              highlights: [], reraNumber: "", country: "India", state: "", city: "",
              locality: "", microMarket: "", addressLine: "", landmark: "", pincode: "",
              lat: "", lng: "", distanceToMetro: "", distanceToAirport: "", distanceToRailway: "",
              distanceToBusStop: "", nearbyPlaces: [], launchDate: "", possessionDate: "",
              totalLandArea: "", totalTowers: "", floorsPerTower: "", totalUnits: "",
              openSpacePercentage: "", amenities: [], paymentPlans: [], bookingAmount: "",
              gstPercentage: "", stampDutyPercentage: "", registrationCharges: "",
              managerName: "", salesPhone: "", salesWhatsapp: "", salesEmail: "",
              landTitleType: "Freehold", titleClear: true, litigationStatus: "None",
              encumbrances: "", litigationDetails: "", walkthroughVideoUrl: "",
            });
            setFiles({
              exteriorImages: [], droneImages: [], masterPlan: [], locationMap: [],
              constructionProgressImages: [], brochureUrl: [], reraCertificateUrl: [],
              commencementCertificateUrl: [], occupancyCertificateUrl: [],
              environmentalClearanceUrl: [], approvalDocumentUrls: [],
            });
            setStep(1);
            setErrors({});
            toast.success("Draft cleared.");
            setConfirmClearDraft(false);
          }}
          onCancel={() => setConfirmClearDraft(false)}
        />
      )}
    </div>
  );
}
