import React, { useState, useEffect } from "react";
import { useNavigate, useParams, useSearchParams } from "react-router-dom";
import { toast } from "react-toastify";
import { campaignApi, unitTypeApi } from "../api/adminApi";
import Wizard from "../components/wizard/Wizard";
import { inp, lbl } from "../components/wizard/FormField";
import { validateCampaignStep } from "../schemas/campaignSchema";

const STEPS = [
  { id: 1, label: "Basics" },
  { id: 2, label: "Buyers" },
  { id: 3, label: "Duration" },
  { id: 4, label: "Discount & Perks" },
];

export default function CreateCampaign() {
  const { projectId } = useParams();
  const [searchParams] = useSearchParams();
  const unitTypeId = searchParams.get("unitTypeId");
  const navigate = useNavigate();

  const [step, setStep] = useState(1);
  const [errors, setErrors] = useState({});
  const [unitType, setUnitType] = useState(null);
  const [submitting, setSubmitting] = useState(false);
  const [perkInput, setPerkInput] = useState("");

  const [form, setForm] = useState({
    name: "", description: "",
    minBuyers: 3, maxBuyers: "",
    startDate: "", endDate: "",
    discountPerBuyer: "",
    perks: [],
    adminNotes: "",
  });

  useEffect(() => {
    if (!unitTypeId) { toast.error("No unit type selected."); navigate(-1); return; }
    unitTypeApi.getById(unitTypeId).then(r => {
      const u = r.data || r;
      setUnitType(u);
    }).catch(() => { toast.error("Unit type not found."); navigate(-1); });
  }, [unitTypeId]);

  const set = (key, val) => {
    setForm(p => ({ ...p, [key]: val }));
    if (errors[key]) setErrors(e => { const { [key]: _, ...rest } = e; return rest; });
  };

  const addPerk = () => {
    if (!perkInput.trim()) return;
    set("perks", [...form.perks, perkInput.trim()]);
    setPerkInput("");
  };

  const removePerk = (idx) => {
    set("perks", form.perks.filter((_, i) => i !== idx));
  };

  const formatDiscount = (val) => {
    const n = Number(val);
    if (!n) return "";
    if (n >= 1e7) return `₹${(n / 1e7).toFixed(2)} Cr`;
    if (n >= 1e5) return `₹${(n / 1e5).toFixed(2)} L`;
    return `₹${n.toLocaleString("en-IN")}`;
  };

  const validateStep = (s) => validateCampaignStep(s, form, unitType);

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      await campaignApi.create({
        unitTypeId,
        name: form.name,
        description: form.description,
        minBuyers: Number(form.minBuyers),
        maxBuyers: form.maxBuyers ? Number(form.maxBuyers) : null,
        startDate: form.startDate,
        endDate: form.endDate,
        discountPerBuyer: Number(form.discountPerBuyer),
        perks: form.perks,
        adminNotes: form.adminNotes,
      });
      toast.success("Campaign created!");
      navigate(`/project/${projectId}`);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to create campaign.");
    } finally {
      setSubmitting(false);
    }
  };

  const renderStep = () => {
    switch (step) {
      case 1: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Campaign Basics</h2>
          {unitType && (
            <div className="bg-orange-50 border border-orange-200 rounded-lg p-3">
              <p className="text-xs text-orange-600 font-medium">Unit Type</p>
              <p className="font-semibold text-orange-800">{unitType.config?.name}</p>
              <p className="text-xs text-orange-600">
                {unitType.config?.bedrooms} BHK · ₹{unitType.pricing?.effectivePrice?.toLocaleString("en-IN")} effective price
              </p>
            </div>
          )}
          <div>
            <label className={lbl}>Campaign Name <span className="text-red-500">*</span></label>
            <input
              data-field="name"
              className={`${inp} ${errors.name ? "border-red-400" : ""}`}
              value={form.name}
              onChange={e => set("name", e.target.value)}
              placeholder="e.g. Group Buy — 2BHK Special Offer"
            />
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>
          <div>
            <label className={lbl}>Description</label>
            <textarea className={inp} rows={3} value={form.description}
              onChange={e => set("description", e.target.value)}
              placeholder="What buyers get when they join this group buy" />
          </div>
        </div>
      );
      case 2: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Buyer Targets</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={lbl}>Minimum Buyers <span className="text-red-500">*</span></label>
              <input
                data-field="minBuyers"
                className={`${inp} ${errors.minBuyers ? "border-red-400" : ""}`}
                type="number" min="2"
                value={form.minBuyers} onChange={e => set("minBuyers", e.target.value)}
              />
              {errors.minBuyers
                ? <p className="text-xs text-red-500 mt-1">{errors.minBuyers}</p>
                : <p className="text-xs text-gray-400 mt-1">Discount activates when this is reached</p>}
            </div>
            <div>
              <label className={lbl}>Maximum Buyers <span className="text-gray-400 text-xs">(optional)</span></label>
              <input
                data-field="maxBuyers"
                className={`${inp} ${errors.maxBuyers ? "border-red-400" : ""}`}
                type="number" min={form.minBuyers}
                value={form.maxBuyers} onChange={e => set("maxBuyers", e.target.value)}
                placeholder="Leave empty for unlimited"
              />
              {errors.maxBuyers && <p className="text-xs text-red-500 mt-1">{errors.maxBuyers}</p>}
            </div>
          </div>
        </div>
      );
      case 3: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Campaign Duration</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className={lbl}>Start Date <span className="text-red-500">*</span></label>
              <input data-field="startDate" className={`${inp} ${errors.startDate ? "border-red-400" : ""}`}
                type="date" value={form.startDate} onChange={e => set("startDate", e.target.value)} />
              {errors.startDate && <p className="text-xs text-red-500 mt-1">{errors.startDate}</p>}
            </div>
            <div>
              <label className={lbl}>End Date <span className="text-red-500">*</span></label>
              <input data-field="endDate" className={`${inp} ${errors.endDate ? "border-red-400" : ""}`}
                type="date" value={form.endDate} min={form.startDate} onChange={e => set("endDate", e.target.value)} />
              {errors.endDate && <p className="text-xs text-red-500 mt-1">{errors.endDate}</p>}
            </div>
          </div>
          {form.startDate && form.endDate && !errors.endDate && (
            <p className="text-sm text-blue-600 bg-blue-50 rounded-lg p-2">
              Campaign duration: {Math.ceil((new Date(form.endDate) - new Date(form.startDate)) / 86400000)} days
            </p>
          )}
        </div>
      );
      case 4: return (
        <div className="space-y-5">
          <h2 className="text-lg font-semibold">Discount & Perks</h2>

          {/* Discount Per Buyer */}
          <div>
            <label className={lbl}>Discount Per Buyer (₹) <span className="text-red-500">*</span></label>
            <input data-field="discountPerBuyer" className={`${inp} ${errors.discountPerBuyer ? "border-red-400" : ""}`}
              type="number" value={form.discountPerBuyer} onChange={e => set("discountPerBuyer", e.target.value)}
              placeholder="e.g. 10000000 for ₹1 Cr" />
            {errors.discountPerBuyer
              ? <p className="text-xs text-red-500 mt-1">{errors.discountPerBuyer}</p>
              : <p className="text-xs text-gray-400 mt-1">Flat discount each buyer gets. Pre-agreed with builder.</p>}
            {Number(form.discountPerBuyer) > 0 && (
              <div className="bg-green-50 border border-green-200 rounded-xl p-3 mt-2">
                <p className="text-sm text-green-600">Each buyer saves</p>
                <p className="text-xl font-bold text-green-700">{formatDiscount(form.discountPerBuyer)}</p>
              </div>
            )}
          </div>

          {/* Perks */}
          <div>
            <label className={lbl}>Perks <span className="text-gray-400 text-xs">(optional)</span></label>
            <div className="flex gap-2">
              <input className={inp} value={perkInput}
                onChange={e => setPerkInput(e.target.value)}
                placeholder="e.g. DealDirect covers GST"
                onKeyDown={e => e.key === "Enter" && (e.preventDefault(), addPerk())} />
              <button type="button" onClick={addPerk}
                className="px-4 py-2 bg-indigo-600 text-white rounded-lg text-sm hover:bg-indigo-700 transition-colors whitespace-nowrap">
                + Add
              </button>
            </div>
            {form.perks.length > 0 && (
              <div className="space-y-2 mt-3">
                {form.perks.map((p, i) => (
                  <div key={i} className="flex items-center justify-between bg-indigo-50 rounded-lg px-3 py-2">
                    <span className="text-sm text-indigo-800 font-medium">🎁 {p}</span>
                    <button type="button" onClick={() => removePerk(i)}
                      className="text-red-400 hover:text-red-600 text-xs">Remove</button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Admin Notes */}
          <div>
            <label className={lbl}>Admin Notes <span className="text-gray-400 text-xs">(internal)</span></label>
            <textarea className={inp} rows={2} value={form.adminNotes}
              onChange={e => set("adminNotes", e.target.value)}
              placeholder="Internal notes — not visible to buyers" />
          </div>
        </div>
      );
      default: return null;
    }
  };

  return (
    <div>
      <div className="max-w-2xl mx-auto pt-6 px-4">
        <button type="button" onClick={() => navigate(`/project/${projectId}`)}
          className="text-sm text-blue-600 hover:underline mb-2">
          ← Back to Project
        </button>
        <h1 className="text-2xl font-bold text-gray-900 mb-6">Create Group Buy Campaign</h1>
      </div>
      <Wizard
        steps={STEPS}
        currentStep={step}
        onStepChange={setStep}
        validateStep={validateStep}
        onSetErrors={setErrors}
        onSubmit={handleSubmit}
        submitting={submitting}
        submitLabel="🚀 Launch Campaign"
      >
        {renderStep()}
      </Wizard>
    </div>
  );
}
