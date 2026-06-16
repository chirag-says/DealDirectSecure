import React, { useState, useEffect, useRef } from "react";

// ── Thumbnail component that safely manages blob URL lifecycle ────────────────
function FloorPlanPreview({ file }) {
  const [url, setUrl] = useState(null);
  const isImage = file?.type?.startsWith("image/");

  useEffect(() => {
    if (!file || !isImage) return;
    const objectUrl = URL.createObjectURL(file);
    setUrl(objectUrl);
    return () => URL.revokeObjectURL(objectUrl);
  }, [file, isImage]);

  if (!file) return null;

  if (isImage && url) {
    return <img src={url} alt={file.name} className="mt-2 rounded-lg border border-gray-200 max-h-48 object-contain bg-gray-50" />;
  }

  // PDF or non-image: show file info card
  return (
    <div className="mt-2 flex items-center gap-2 bg-gray-50 rounded-lg px-3 py-2 border border-gray-100">
      <span className="text-gray-400">📄</span>
      <span className="text-sm text-gray-700 truncate">{file.name}</span>
      <span className="text-xs text-gray-400">({(file.size / 1024).toFixed(0)} KB)</span>
    </div>
  );
}
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "react-toastify";
import { unitTypeApi, projectApi } from "../api/adminApi";

const STEPS = [
  { id: 1, label: "Config" }, { id: 2, label: "Area" }, { id: 3, label: "Facing" },
  { id: 4, label: "Furnishing" }, { id: 5, label: "Parking" }, { id: 6, label: "Specs" },
  { id: 7, label: "Floor Plans" }, { id: 8, label: "Pricing" }, { id: 9, label: "Inventory" },
  { id: 10, label: "Highlights" },
];

const FACING_OPTIONS = ["East", "West", "North", "South", "North East", "North West", "South East", "South West"];

export default function CreateUnitType() {
  const { projectId } = useParams();
  const [searchParams] = useSearchParams();
  const editId = searchParams.get("edit");
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [project, setProject] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [highlightInput, setHighlightInput] = useState("");

  const [form, setForm] = useState({
    name: "", bedrooms: "", bathrooms: "", balconies: "", hasUtilityArea: false,
    carpetSqft: "", builtUpSqft: "", superBuiltUpSqft: "",
    facing: [], furnishing: "Bare Shell",
    coveredParking: 0, openParking: 0, evParking: 0,
    specifications: {
      structure: "",
      flooring: { livingDining: "", bedrooms: "", kitchen: "", bathroom: "", balcony: "" },
      kitchen: { countertop: "", isModular: false, chimney: false, sink: "" },
      bathroom: { sanitaryBrand: "", fittingsBrand: "", dadoHeight: "" },
      doors: { mainDoor: "", internalDoors: "", finish: "" },
      windows: { type: "", mosquitoMesh: false },
      electrical: { wiringType: "", switchBrand: "", acPointsPerRoom: "" },
    },
    basePrice: "", plc: 0, parkingCharges: 0, clubhouse: 0, legal: 0, maintenance: 0,
    floorRisePerSqft: 0, viewPremium: 0,
    totalUnits: "", availableUnits: "", bookedUnits: 0, blockedUnits: 0,
    towerAllocation: [], highlights: [],
  });

  const [files, setFiles] = useState({ twoDFloorPlan: null, threeDFloorPlan: null });

  // ── Per-step validation ──
  const [errors, setErrors] = useState({});
  const stepContainerRef = useRef(null);

  const isFilled = (val) => {
    if (val === null || val === undefined) return false;
    if (typeof val === "string") return val.trim() !== "";
    if (typeof val === "number") return Number.isFinite(val);
    if (typeof val === "boolean") return true;
    if (Array.isArray(val)) return val.length > 0;
    return true;
  };

  const validateStep = (s) => {
    const e = {};
    if (s === 1) {
      if (!isFilled(form.name)) e.name = "Unit type name is required";
      else if (String(form.name).trim().length > 100) e.name = "Name cannot exceed 100 characters";
      if (!isFilled(form.bedrooms) && !isFilled(form.bathrooms)) {
        e.bedrooms = "Specify at least bedrooms or bathrooms";
      }
    } else if (s === 2) {
      if (!isFilled(form.carpetSqft)) e.carpetSqft = "Carpet area is required";
      else {
        const c = Number(form.carpetSqft);
        if (c <= 0) e.carpetSqft = "Carpet area must be greater than 0";
      }
      // Sanity: built-up ≥ carpet, super-built-up ≥ built-up
      if (isFilled(form.builtUpSqft) && isFilled(form.carpetSqft)) {
        if (Number(form.builtUpSqft) < Number(form.carpetSqft)) {
          e.builtUpSqft = "Built-up area must be ≥ carpet area";
        }
      }
      if (isFilled(form.superBuiltUpSqft) && isFilled(form.builtUpSqft)) {
        if (Number(form.superBuiltUpSqft) < Number(form.builtUpSqft)) {
          e.superBuiltUpSqft = "Super built-up must be ≥ built-up area";
        }
      }
    } else if (s === 3) {
      // Facing is optional in real-estate — no required fields
    } else if (s === 4) {
      // Furnishing always has a default — no required fields
    } else if (s === 5) {
      ["coveredParking", "openParking", "evParking"].forEach((k) => {
        const v = form[k];
        if (isFilled(v) && (!Number.isInteger(Number(v)) || Number(v) < 0)) {
          e[k] = "Must be a non-negative whole number";
        }
      });
    } else if (s === 6) {
      // Specs are optional but useful — no required fields
    } else if (s === 7) {
      if (!files.twoDFloorPlan) e.twoDFloorPlan = "2D floor plan is required";
    } else if (s === 8) {
      if (!isFilled(form.basePrice)) e.basePrice = "Base price is required";
      else if (Number(form.basePrice) <= 0) e.basePrice = "Base price must be greater than 0";
      if (isFilled(form.floorRisePerSqft) && Number(form.floorRisePerSqft) < 0) {
        e.floorRisePerSqft = "Floor rise cannot be negative";
      }
      if (isFilled(form.viewPremium) && Number(form.viewPremium) < 0) {
        e.viewPremium = "View premium cannot be negative";
      }
    } else if (s === 9) {
      if (!isFilled(form.totalUnits)) e.totalUnits = "Total units is required";
      else if (Number(form.totalUnits) <= 0) e.totalUnits = "Total units must be greater than 0";
      else {
        const total = Number(form.totalUnits);
        const available = Number(form.availableUnits) || 0;
        const booked = Number(form.bookedUnits) || 0;
        const blocked = Number(form.blockedUnits) || 0;
        if (Number(form.availableUnits) === "" || form.availableUnits === undefined) {
          e.availableUnits = "Available units is required";
        } else if (available < 0) {
          e.availableUnits = "Available units cannot be negative";
        } else if (available + booked + blocked > total) {
          e.availableUnits = `Available (${available}) + Booked (${booked}) + Blocked (${blocked}) cannot exceed Total (${total})`;
        }
        if (booked < 0) e.bookedUnits = "Booked units cannot be negative";
        if (blocked < 0) e.blockedUnits = "Blocked units cannot be negative";
      }
    }
    return e;
  };

  // Try to advance. If invalid, surface errors + scroll to first invalid field.
  const goNext = () => {
    const e = validateStep(step);
    setErrors(e);
    if (Object.keys(e).length > 0) {
      const firstField = Object.keys(e)[0];
      toast.error(e[firstField]);
      if (stepContainerRef.current) {
        stepContainerRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      setTimeout(() => {
        const el = stepContainerRef.current?.querySelector(`[data-field="${firstField}"]`);
        if (el) {
          if (typeof el.focus === "function") el.focus();
          el.scrollIntoView({ behavior: "smooth", block: "center" });
        }
      }, 50);
      return;
    }
    setErrors({});
    setStep(s => Math.min(10, s + 1));
  };

  useEffect(() => {
    projectApi.getById(projectId)
      .then(r => setProject(r.data || r))
      .catch(() => { toast.error("Project not found."); navigate(-1); });

    if (editId) {
      unitTypeApi.getById(editId).then(r => {
        const u = r.data || r;
        // Deep-merge specs with the empty skeleton so partial DB specs don't drop sections.
        const EMPTY_SPECS = {
          structure: "",
          flooring: { livingDining: "", bedrooms: "", kitchen: "", bathroom: "", balcony: "" },
          kitchen: { countertop: "", isModular: false, chimney: false, sink: "" },
          bathroom: { sanitaryBrand: "", fittingsBrand: "", dadoHeight: "" },
          doors: { mainDoor: "", internalDoors: "", finish: "" },
          windows: { type: "", mosquitoMesh: false },
          electrical: { wiringType: "", switchBrand: "", acPointsPerRoom: "" },
        };
        const mergedSpecs = {
          ...EMPTY_SPECS,
          ...(u.specifications || {}),
          flooring: { ...EMPTY_SPECS.flooring, ...(u.specifications?.flooring || {}) },
          kitchen: { ...EMPTY_SPECS.kitchen, ...(u.specifications?.kitchen || {}) },
          bathroom: { ...EMPTY_SPECS.bathroom, ...(u.specifications?.bathroom || {}) },
          doors: { ...EMPTY_SPECS.doors, ...(u.specifications?.doors || {}) },
          windows: { ...EMPTY_SPECS.windows, ...(u.specifications?.windows || {}) },
          electrical: { ...EMPTY_SPECS.electrical, ...(u.specifications?.electrical || {}) },
        };
        setForm({
          name: u.config?.name || "", bedrooms: u.config?.bedrooms || "",
          bathrooms: u.config?.bathrooms || "", balconies: u.config?.balconies || "",
          hasUtilityArea: u.config?.hasUtilityArea || false,
          carpetSqft: u.area?.carpetSqft || "", builtUpSqft: u.area?.builtUpSqft || "",
          superBuiltUpSqft: u.area?.superBuiltUpSqft || "",
          facing: u.facing || [], furnishing: u.furnishing || "Bare Shell",
          coveredParking: u.parking?.covered || 0, openParking: u.parking?.open || 0, evParking: u.parking?.ev || 0,
          specifications: mergedSpecs,
          basePrice: u.pricing?.basePrice || "", plc: u.pricing?.additionalCharges?.plc || 0,
          parkingCharges: u.pricing?.additionalCharges?.parking || 0,
          clubhouse: u.pricing?.additionalCharges?.clubhouse || 0,
          legal: u.pricing?.additionalCharges?.legal || 0,
          maintenance: u.pricing?.additionalCharges?.maintenance || 0,
          floorRisePerSqft: u.pricing?.floorRisePerSqft || 0, viewPremium: u.pricing?.viewPremium || 0,
          totalUnits: u.inventory?.totalUnits || "", availableUnits: u.inventory?.availableUnits || "",
          bookedUnits: u.inventory?.bookedUnits || 0, blockedUnits: u.inventory?.blockedUnits || 0,
          towerAllocation: u.inventory?.towerAllocation || [], highlights: u.highlights || [],
        });
        // Reset any prior errors when loading a record for edit
        setErrors({});
        setStep(1);
        // Discard any saved draft for this unit type — we just loaded the source of truth
        clearDraft();
      }).catch(() => toast.error("Failed to load unit type."));
    }
    // form.specifications intentionally NOT in deps — we use EMPTY_SPECS instead
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [projectId, editId]);

  // Top-level setter — also clears the field's error as soon as the user edits.
  const set = (key, val) => {
    setForm(p => ({ ...p, [key]: val }));
    if (errors[key]) {
      const { [key]: _drop, ...rest } = errors;
      setErrors(rest);
    }
  };
  // For nested spec sections (flooring / kitchen / etc.)
  const setSpec = (section, key, val) => setForm(p => ({
    ...p,
    specifications: { ...p.specifications, [section]: { ...p.specifications[section], [key]: val } }
  }));
  // For top-level string fields directly on specifications (e.g. structure)
  const setSpecField = (key, val) => setForm(p => ({
    ...p, specifications: { ...p.specifications, [key]: val }
  }));

  const toggleFacing = (f) => {
    set("facing", form.facing.includes(f) ? form.facing.filter(x => x !== f) : [...form.facing, f]);
  };

  // Wrap setFiles to also clear the field's validation error
  const setFileWithClear = (field, file) => {
    setFiles(p => ({ ...p, [field]: file }));
    if (errors[field]) {
      const { [field]: _drop, ...rest } = errors;
      setErrors(rest);
    }
  };

  // ── localStorage persistence ──
  const DRAFT_KEY = `createUnitTypeDraft_${projectId}_${editId || "new"}`;
  const [draftExists, setDraftExists] = useState(false);
  const saveTimeoutRef = useRef(null);

  useEffect(() => {
    if (projectId) {
      clearTimeout(saveTimeoutRef.current);
      saveTimeoutRef.current = setTimeout(() => {
        // In edit mode, don't save a "draft" — the source of truth is the DB.
        if (editId) return;
        // Don't persist files (File objects don't survive JSON.stringify)
        localStorage.setItem(DRAFT_KEY, JSON.stringify({ form, step, timestamp: Date.now() }));
        setDraftExists(true);
      }, 1000);
    }
    return () => clearTimeout(saveTimeoutRef.current);
  }, [form, step, projectId, editId]);

  useEffect(() => {
    if (!projectId) return;
    // In edit mode, the edit fetch is the source of truth — never restore a draft on top of it.
    if (editId) return;
    const saved = localStorage.getItem(DRAFT_KEY);
    if (saved) {
      try {
        const draft = JSON.parse(saved);
        if (draft.step && Date.now() - draft.timestamp < 86400000) {
          setForm(draft.form);
          setStep(draft.step);
          setDraftExists(true);
        }
      } catch { /* skip invalid */ }
    }
  }, [projectId, editId]);

  const clearDraft = () => {
    if (projectId) {
      localStorage.removeItem(DRAFT_KEY);
      setDraftExists(false);
    }
  };

  const resetForm = () => {
    setForm({
      name: "", bedrooms: "", bathrooms: "", balconies: "", hasUtilityArea: false,
      carpetSqft: "", builtUpSqft: "", superBuiltUpSqft: "",
      facing: [], furnishing: "Bare Shell",
      coveredParking: 0, openParking: 0, evParking: 0,
      specifications: {
        structure: "",
        flooring: { livingDining: "", bedrooms: "", kitchen: "", bathroom: "", balcony: "" },
        kitchen: { countertop: "", isModular: false, chimney: false, sink: "" },
        bathroom: { sanitaryBrand: "", fittingsBrand: "", dadoHeight: "" },
        doors: { mainDoor: "", internalDoors: "", finish: "" },
        windows: { type: "", mosquitoMesh: false },
        electrical: { wiringType: "", switchBrand: "", acPointsPerRoom: "" },
      },
      basePrice: "", plc: 0, parkingCharges: 0, clubhouse: 0, legal: 0, maintenance: 0,
      floorRisePerSqft: 0, viewPremium: 0,
      totalUnits: "", availableUnits: "", bookedUnits: 0, blockedUnits: 0,
      towerAllocation: [], highlights: [],
    });
    setFiles({ twoDFloorPlan: null, threeDFloorPlan: null });
    setStep(1);
    setErrors({});
  };

  const addHighlight = () => {
    if (!highlightInput.trim()) return;
    set("highlights", [...form.highlights, highlightInput.trim()]);
    setHighlightInput("");
  };

  const effectivePrice = () => {
    const b = Number(form.basePrice) || 0;
    return b + (Number(form.plc) || 0) + (Number(form.parkingCharges) || 0) +
      (Number(form.clubhouse) || 0) + (Number(form.legal) || 0) +
      (Number(form.maintenance) || 0) + (Number(form.viewPremium) || 0);
  };

  const handleSubmit = async () => {
    // Run validation across all relevant steps. The "Next" button already gates
    // each step, but the user could still click Step 10 in the indicator and try
    // to submit. This is the final safety net.
    const allErrors = {};
    for (let s = 1; s <= 9; s++) {
      Object.assign(allErrors, validateStep(s));
    }
    if (Object.keys(allErrors).length > 0) {
      setErrors(allErrors);
      const count = Object.keys(allErrors).length;
      toast.error(`${count} field${count > 1 ? "s" : ""} need${count > 1 ? "" : "s"} attention. Please review the form.`);
      for (let s = 1; s <= 9; s++) {
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
      fd.append("projectId", projectId);
      const { specifications, facing, highlights, towerAllocation, ...rest } = form;
      Object.entries(rest).forEach(([k, v]) => fd.append(k, v));
      fd.append("specifications", JSON.stringify(specifications));
      fd.append("facing", JSON.stringify(facing));
      fd.append("highlights", JSON.stringify(highlights));
      fd.append("towerAllocation", JSON.stringify(towerAllocation));
      if (files.twoDFloorPlan) fd.append("twoDFloorPlan", files.twoDFloorPlan);
      if (files.threeDFloorPlan) fd.append("threeDFloorPlan", files.threeDFloorPlan);

      if (editId) await unitTypeApi.update(editId, fd);
      else await unitTypeApi.create(fd);

      toast.success(editId ? "Unit type updated!" : "Unit type created!");
      clearDraft();
      navigate(`/project/${projectId}`);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to save unit type.");
    } finally {
      setSubmitting(false);
    }
  };

  const inp = "w-full border border-gray-300 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500";
  const lbl = "block text-sm font-medium text-gray-700 mb-1";

  const renderStep = () => {
    switch (step) {
      case 1: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Configuration</h2>
          <div>
            <label className={lbl}>Unit Type Name *</label>
            <input
              data-field="name"
              className={errors.name ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
              value={form.name}
              onChange={e => set("name", e.target.value)}
              placeholder="e.g. 2 BHK Premium"
            />
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>
          <div className="grid grid-cols-3 gap-4">
            {[["bedrooms","Bedrooms"],["bathrooms","Bathrooms"],["balconies","Balconies"]].map(([k,l]) => (
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
          <div className="flex items-center gap-2">
            <input type="checkbox" id="util" checked={form.hasUtilityArea} onChange={e => set("hasUtilityArea", e.target.checked)} />
            <label htmlFor="util" className="text-sm text-gray-700">Has Utility / Store Room</label>
          </div>
        </div>
      );
      case 2: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Area Details</h2>
          {[["carpetSqft","Carpet Area (sqft) *"],["builtUpSqft","Built-Up Area (sqft)"],["superBuiltUpSqft","Super Built-Up Area (sqft)"]].map(([k,l]) => (
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
          {form.carpetSqft && form.basePrice && (
            <p className="text-sm text-blue-600 bg-blue-50 rounded-lg p-2">
              ₹{Math.round(Number(form.basePrice) / Number(form.carpetSqft)).toLocaleString()} per sqft (carpet)
            </p>
          )}
        </div>
      );
      case 3: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Facing Options</h2>
          <div className="grid grid-cols-4 gap-3">
            {FACING_OPTIONS.map(f => (
              <button key={f} onClick={() => toggleFacing(f)}
                className={`py-2.5 rounded-xl text-sm font-medium border transition-all ${form.facing.includes(f) ? "bg-blue-600 text-white border-blue-600" : "bg-white text-gray-600 border-gray-200 hover:border-blue-400"}`}>
                {f}
              </button>
            ))}
          </div>
        </div>
      );
      case 4: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Furnishing</h2>
          <div className="grid grid-cols-2 gap-3">
            {["Bare Shell","Unfurnished","Semi Furnished","Fully Furnished"].map(f => (
              <button key={f} onClick={() => set("furnishing", f)}
                className={`py-3 rounded-xl text-sm font-medium border transition-all ${form.furnishing === f ? "bg-blue-600 text-white border-blue-600" : "bg-white text-gray-600 border-gray-200 hover:border-blue-400"}`}>
                {f}
              </button>
            ))}
          </div>
        </div>
      );
      case 5: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Parking</h2>
          <div className="grid grid-cols-3 gap-4">
            {[["coveredParking","Covered Parking"],["openParking","Open Parking"],["evParking","EV Charging"]].map(([k,l]) => (
              <div key={k}>
                <label className={lbl}>{l} (whole numbers)</label>
                <input
                  data-field={k}
                  className={errors[k] ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
                  type="number"
                  min="0"
                  step="1"
                  value={form[k]}
                  onChange={e => set(k, e.target.value)}
                />
                {errors[k] && <p className="text-xs text-red-500 mt-1">{errors[k]}</p>}
              </div>
            ))}
          </div>
        </div>
      );
      case 6: return (
        <div className="space-y-5">
          <h2 className="text-lg font-semibold">Construction Specifications</h2>
          <div>
            <label className={lbl}>Structure</label>
            <input className={inp} value={form.specifications.structure} onChange={e => setSpecField("structure", e.target.value)}
              placeholder="e.g. RCC Framed Structure, Seismic Zone II" />
          </div>
          <div>
            <p className={`${lbl} mb-2`}>Flooring</p>
            <div className="grid grid-cols-2 gap-3">
              {["livingDining","bedrooms","kitchen","bathroom","balcony"].map(r => (
                <div key={r}>
                  <label className="text-xs text-gray-500 capitalize">{r === "livingDining" ? "Living / Dining" : r}</label>
                  <input className={inp} value={form.specifications.flooring[r]}
                    onChange={e => setSpec("flooring", r, e.target.value)} placeholder="e.g. Vitrified Tiles" />
                </div>
              ))}
            </div>
          </div>
          <div>
            <p className={`${lbl} mb-2`}>Kitchen</p>
            <div className="grid grid-cols-2 gap-3">
              <div><label className="text-xs text-gray-500">Countertop</label>
                <input className={inp} value={form.specifications.kitchen.countertop} onChange={e => setSpec("kitchen","countertop",e.target.value)} placeholder="e.g. Granite" /></div>
              <div><label className="text-xs text-gray-500">Sink</label>
                <input className={inp} value={form.specifications.kitchen.sink} onChange={e => setSpec("kitchen","sink",e.target.value)} placeholder="e.g. SS Double Bowl" /></div>
            </div>
            <div className="flex gap-4 mt-2">
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.specifications.kitchen.isModular} onChange={e => setSpec("kitchen","isModular",e.target.checked)} />
                Modular Kitchen
              </label>
              <label className="flex items-center gap-2 text-sm">
                <input type="checkbox" checked={form.specifications.kitchen.chimney} onChange={e => setSpec("kitchen","chimney",e.target.checked)} />
                Chimney Provision
              </label>
            </div>
          </div>
          <div>
            <p className={`${lbl} mb-2`}>Bathroom</p>
            <div className="grid grid-cols-2 gap-3">
              {[["sanitaryBrand","Sanitary Brand"],["fittingsBrand","Fittings Brand"],["dadoHeight","Dado Height"]].map(([k,l]) => (
                <div key={k}><label className="text-xs text-gray-500">{l}</label>
                  <input className={inp} value={form.specifications.bathroom[k]} onChange={e => setSpec("bathroom",k,e.target.value)} /></div>
              ))}
            </div>
          </div>
          <div>
            <p className={`${lbl} mb-2`}>Electrical</p>
            <div className="grid grid-cols-2 gap-3">
              {[["wiringType","Wiring Type"],["switchBrand","Switch Brand"],["acPointsPerRoom","AC Points / Room"]].map(([k,l]) => (
                <div key={k}><label className="text-xs text-gray-500">{l}</label>
                  <input className={inp} value={form.specifications.electrical[k]} onChange={e => setSpec("electrical",k,e.target.value)} /></div>
              ))}
            </div>
          </div>
        </div>
      );
      case 7: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Floor Plans</h2>
          {[["twoDFloorPlan","2D Floor Plan *"],["threeDFloorPlan","3D Floor Plan"]].map(([field,label]) => (
            <div key={field} className={`border rounded-xl p-4 ${errors[field] ? "border-red-400 bg-red-50/30" : "border-gray-200 bg-gray-50/50"}`}>
              <label className={lbl}>{label}</label>
              <input
                data-field={field}
                type="file"
                accept="image/*,.pdf"
                onChange={e => {
                  const f = e.target.files[0];
                  if (f) {
                    // 10 MB cap to prevent accidental huge uploads
                    if (f.size > 10 * 1024 * 1024) {
                      toast.error("File too large (max 10 MB).");
                      e.target.value = "";
                      return;
                    }
                    setFileWithClear(field, f);
                  }
                }}
                className="block w-full text-sm text-gray-500 file:mr-3 file:py-1.5 file:px-4 file:rounded-lg file:border-0 file:bg-blue-50 file:text-blue-600 hover:file:bg-blue-100 cursor-pointer"
              />
              {errors[field] && <p className="text-xs text-red-500 mt-1">{errors[field]}</p>}
              {files[field] && (
                <div>
                  <div className="flex items-center justify-between mt-2">
                    <p className="text-xs text-emerald-600 font-medium">✓ {files[field].name} ({(files[field].size / 1024).toFixed(0)} KB)</p>
                    <button type="button" onClick={() => setFileWithClear(field, null)}
                      className="text-xs text-red-400 hover:text-red-600">Remove</button>
                  </div>
                  <FloorPlanPreview file={files[field]} />
                </div>
              )}
            </div>
          ))}
        </div>
      );
      case 8: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Pricing</h2>
          <div>
            <label className={lbl}>Base Price (₹) *</label>
            <input
              data-field="basePrice"
              className={errors.basePrice ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
              type="number"
              min="0"
              value={form.basePrice}
              onChange={e => set("basePrice", e.target.value)}
              placeholder="Total base unit price"
            />
            {errors.basePrice && <p className="text-xs text-red-500 mt-1">{errors.basePrice}</p>}
          </div>
          <div className="grid grid-cols-2 gap-4">
            {[["plc","PLC (Preferential Location)"],["parkingCharges","Parking Charges"],["clubhouse","Clubhouse"],["legal","Legal Charges"],["maintenance","Maintenance"],["viewPremium","View Premium"],["floorRisePerSqft","Floor Rise (₹/sqft)"]].map(([k,l]) => (
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
          {form.basePrice && (
            <div className="bg-blue-50 rounded-xl p-4">
              <p className="text-sm text-blue-600 font-medium">Effective Price</p>
              <p className="text-2xl font-bold text-blue-800">₹{effectivePrice().toLocaleString()}</p>
              {form.carpetSqft && <p className="text-xs text-blue-500 mt-0.5">₹{Math.round(effectivePrice() / Number(form.carpetSqft)).toLocaleString()} / sqft (carpet)</p>}
            </div>
          )}
        </div>
      );
      case 9: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Inventory</h2>
          <div className="grid grid-cols-2 gap-4">
            {[["totalUnits","Total Units *"],["availableUnits","Available Units *"],["bookedUnits","Booked Units"],["blockedUnits","Admin Blocked"]].map(([k,l]) => (
              <div key={k}>
                <label className={lbl}>{l}</label>
                <input
                  data-field={k}
                  className={errors[k] ? "w-full border border-red-400 rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-300" : inp}
                  type="number"
                  min="0"
                  step="1"
                  value={form[k]}
                  onChange={e => set(k, e.target.value)}
                />
                {errors[k] && <p className="text-xs text-red-500 mt-1">{errors[k]}</p>}
              </div>
            ))}
          </div>
        </div>
      );
      case 10: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Highlights & Submit</h2>
          <div>
            <label className={lbl}>Unit Highlights</label>
            <div className="flex gap-2">
              <input className={inp} value={highlightInput} onChange={e => setHighlightInput(e.target.value)}
                onKeyDown={e => e.key === "Enter" && addHighlight()} placeholder="Add USP and press Enter..." />
              <button onClick={addHighlight} className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm">Add</button>
            </div>
            <div className="flex flex-wrap gap-2 mt-2">
              {form.highlights.map((h, i) => (
                <span key={i} className="bg-blue-100 text-blue-700 px-3 py-1 rounded-full text-xs flex items-center gap-1">
                  {h}<button onClick={() => set("highlights", form.highlights.filter((_,j) => j !== i))} className="ml-1 hover:text-red-500">×</button>
                </span>
              ))}
            </div>
          </div>
          <div className="bg-gray-50 rounded-xl p-4 text-sm space-y-2">
            <p className="font-medium text-gray-700">Summary</p>
            <div className="grid grid-cols-2 gap-2">
              <div><span className="text-gray-500">Name:</span> <span className="font-medium">{form.name || "—"}</span></div>
              <div><span className="text-gray-500">Config:</span> <span className="font-medium">{form.bedrooms || "—"} BHK</span></div>
              <div><span className="text-gray-500">Carpet:</span> <span className="font-medium">{form.carpetSqft || "—"} sqft</span></div>
              <div><span className="text-gray-500">Effective Price:</span> <span className="font-medium">₹{effectivePrice().toLocaleString()}</span></div>
              <div><span className="text-gray-500">Total Units:</span> <span className="font-medium">{form.totalUnits || "—"}</span></div>
              <div><span className="text-gray-500">Available:</span> <span className="font-medium">{form.availableUnits || "—"}</span></div>
            </div>
          </div>
          <button onClick={handleSubmit} disabled={submitting}
            className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-semibold rounded-xl transition disabled:opacity-50">
            {submitting ? "Saving..." : editId ? "Update Unit Type" : "Create Unit Type"}
          </button>
        </div>
      );
      default: return null;
    }
  };

  return (
    <div className="max-w-2xl mx-auto py-6 px-4">
      <div className="mb-6">
        <button onClick={() => navigate(`/project/${projectId}`)} className="text-sm text-blue-600 hover:underline mb-2">← Back to Project</button>
        <h1 className="text-2xl font-bold text-gray-900">{editId ? "Edit" : "Add"} Unit Type</h1>
        {project && <p className="text-gray-500 text-sm mt-1">{project.basics?.name}</p>}
      </div>

      {/* Draft saved banner */}
      {draftExists && (
        <div className="mb-4 flex items-center justify-between gap-3 bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-2.5 text-sm">
          <div className="flex items-center gap-2 text-emerald-700">
            <span>✓</span>
            <span>Your progress is auto-saved in this browser.</span>
          </div>
          <button
            onClick={() => {
              if (window.confirm("Clear saved draft? This will reset the form to empty.")) {
                clearDraft();
                resetForm();
                toast.success("Draft cleared.");
              }
            }}
            className="text-xs px-3 py-1 border border-emerald-300 text-emerald-700 rounded hover:bg-emerald-100 whitespace-nowrap"
          >
            Clear draft
          </button>
        </div>
      )}
      <div className="flex items-center mb-8 overflow-x-auto pb-2">
        {STEPS.map((s, i) => {
          // Allow clicking a step only if it is the current step, a previous one,
          // or the immediately next one. Anything further is locked.
          const reachable = s.id === step || s.id < step || s.id === step + 1;
          return (
            <React.Fragment key={s.id}>
              <button
                onClick={() => reachable && setStep(s.id)}
                disabled={!reachable}
                className={`flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${step === s.id ? "bg-blue-600 text-white" : step > s.id ? "bg-green-100 text-green-700" : "bg-gray-100 text-gray-500"} ${!reachable ? "opacity-50 cursor-not-allowed" : ""}`}>
                {step > s.id ? "✓" : s.id}. {s.label}
              </button>
              {i < STEPS.length - 1 && <div className={`flex-1 h-0.5 mx-0.5 min-w-[6px] ${step > s.id ? "bg-green-400" : "bg-gray-200"}`} />}
            </React.Fragment>
          );
        })}
      </div>
      <div ref={stepContainerRef} className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
        {renderStep()}
      </div>
      <div className="flex justify-between mt-6">
        <button onClick={() => setStep(s => Math.max(1, s - 1))} disabled={step === 1}
          className="px-5 py-2 border border-gray-300 rounded-lg text-sm text-gray-600 hover:bg-gray-50 disabled:opacity-40">
          ← Previous
        </button>
        {step < 10 && (
          <button onClick={goNext}
            className="px-5 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700">
            Next →
          </button>
        )}
      </div>
    </div>
  );
}
