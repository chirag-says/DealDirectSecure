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
  { id: 4, label: "Pricing" },
  { id: 5, label: "Inventory" },
  { id: 6, label: "Milestones" },
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
  const [milestoneInput, setMilestoneInput] = useState({ buyerCount: "", benefit: "" });

  const [form, setForm] = useState({
    name: "", description: "",
    minBuyers: 5, maxBuyers: 20,
    startDate: "", endDate: "",
    regularPrice: "", groupBuyPrice: "", tokenAmount: "",
    unitsReserved: 1,
    milestones: [],
  });

  useEffect(() => {
    if (!unitTypeId) { toast.error("No unit type selected."); navigate(-1); return; }
    unitTypeApi.getById(unitTypeId).then(r => {
      const u = r.data || r;
      setUnitType(u);
      setForm(p => ({
        ...p,
        regularPrice: u.pricing?.effectivePrice || u.pricing?.basePrice || "",
        unitsReserved: Math.min(1, u.inventory?.availableUnits || 1),
      }));
    }).catch(() => { toast.error("Unit type not found."); navigate(-1); });
  }, [unitTypeId]);

  const set = (key, val) => {
    setForm(p => ({ ...p, [key]: val }));
    if (errors[key]) setErrors(e => { const { [key]: _, ...rest } = e; return rest; });
  };

  const savings = () => {
    const r = Number(form.regularPrice) || 0;
    const g = Number(form.groupBuyPrice) || 0;
    return r > g ? r - g : 0;
  };

  const addMilestone = () => {
    if (!milestoneInput.buyerCount || !milestoneInput.benefit.trim()) return;
    set("milestones", [...form.milestones, {
      buyerCount: Number(milestoneInput.buyerCount),
      benefit: milestoneInput.benefit.trim(),
      isAchieved: false,
    }]);
    setMilestoneInput({ buyerCount: "", benefit: "" });
  };

  // Per-step validation — backed by Zod from campaignSchema.js
  const validateStep = (s) => validateCampaignStep(s, form, unitType);

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      await campaignApi.create({
        unitTypeId,
        name: form.name,
        description: form.description,
        minBuyers: Number(form.minBuyers),
        maxBuyers: Number(form.maxBuyers),
        startDate: form.startDate,
        endDate: form.endDate,
        regularPrice: Number(form.regularPrice),
        groupBuyPrice: Number(form.groupBuyPrice),
        tokenAmount: Number(form.tokenAmount),
        unitsReserved: Number(form.unitsReserved),
        milestones: JSON.stringify(form.milestones),
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
                {unitType.inventory?.availableUnits} units available · ₹{unitType.pricing?.effectivePrice?.toLocaleString()} effective price
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
              placeholder="e.g. Pre-Launch Group Buy — 2BHK"
            />
            {errors.name && <p className="text-xs text-red-500 mt-1">{errors.name}</p>}
          </div>
          <div>
            <label className={lbl}>Description</label>
            <textarea className={inp} rows={3} value={form.description}
              onChange={e => set("description", e.target.value)}
              placeholder="Campaign details, what buyers get, etc." />
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
                type="number" min="3"
                value={form.minBuyers} onChange={e => set("minBuyers", e.target.value)}
              />
              {errors.minBuyers
                ? <p className="text-xs text-red-500 mt-1">{errors.minBuyers}</p>
                : <p className="text-xs text-gray-400 mt-1">Campaign activates when this is reached</p>}
            </div>
            <div>
              <label className={lbl}>Maximum Buyers <span className="text-red-500">*</span></label>
              <input
                data-field="maxBuyers"
                className={`${inp} ${errors.maxBuyers ? "border-red-400" : ""}`}
                type="number" min={form.minBuyers}
                value={form.maxBuyers} onChange={e => set("maxBuyers", e.target.value)}
              />
              {errors.maxBuyers
                ? <p className="text-xs text-red-500 mt-1">{errors.maxBuyers}</p>
                : <p className="text-xs text-gray-400 mt-1">Campaign closes when full</p>}
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
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Pricing</h2>
          <div>
            <label className={lbl}>Regular Price (₹) <span className="text-red-500">*</span></label>
            <input data-field="regularPrice" className={`${inp} ${errors.regularPrice ? "border-red-400" : ""}`}
              type="number" value={form.regularPrice} onChange={e => set("regularPrice", e.target.value)} />
            {errors.regularPrice
              ? <p className="text-xs text-red-500 mt-1">{errors.regularPrice}</p>
              : <p className="text-xs text-gray-400 mt-1">Pre-filled from unit type effective price</p>}
          </div>
          <div>
            <label className={lbl}>Group Buy Price (₹) <span className="text-red-500">*</span></label>
            <input data-field="groupBuyPrice" className={`${inp} ${errors.groupBuyPrice ? "border-red-400" : ""}`}
              type="number" value={form.groupBuyPrice} onChange={e => set("groupBuyPrice", e.target.value)} />
            {errors.groupBuyPrice && <p className="text-xs text-red-500 mt-1">{errors.groupBuyPrice}</p>}
          </div>
          {savings() > 0 && (
            <div className="bg-green-50 border border-green-200 rounded-xl p-4">
              <p className="text-sm text-green-600">Buyer Savings</p>
              <p className="text-2xl font-bold text-green-700">₹{savings().toLocaleString()}</p>
              <p className="text-xs text-green-500">{((savings() / Number(form.regularPrice)) * 100).toFixed(1)}% off regular price</p>
            </div>
          )}
          <div>
            <label className={lbl}>Token Amount (₹) — Collected by DealDirect <span className="text-red-500">*</span></label>
            <input data-field="tokenAmount" className={`${inp} ${errors.tokenAmount ? "border-red-400" : ""}`}
              type="number" value={form.tokenAmount} onChange={e => set("tokenAmount", e.target.value)} placeholder="e.g. 50000" />
            {errors.tokenAmount
              ? <p className="text-xs text-red-500 mt-1">{errors.tokenAmount}</p>
              : <p className="text-xs text-orange-500 mt-1">⚠ Collected via DealDirect UPI/Netbanking. Admin verifies manually.</p>}
          </div>
        </div>
      );
      case 5: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Inventory Allocation</h2>
          {unitType && (
            <div className="bg-gray-50 rounded-lg p-3 text-sm">
              <p className="text-gray-500">Available in this unit type:{" "}
                <span className="font-semibold text-gray-800">{unitType.inventory?.availableUnits || 0} units</span>
              </p>
            </div>
          )}
          <div>
            <label className={lbl}>Units Reserved for this Campaign <span className="text-red-500">*</span></label>
            <input data-field="unitsReserved"
              className={`${inp} ${errors.unitsReserved ? "border-red-400" : ""}`}
              type="number" min="1" max={unitType?.inventory?.availableUnits || 999}
              value={form.unitsReserved} onChange={e => set("unitsReserved", e.target.value)} />
            {errors.unitsReserved && <p className="text-xs text-red-500 mt-1">{errors.unitsReserved}</p>}
          </div>
        </div>
      );
      case 6: return (
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Milestone Benefits</h2>
          <p className="text-sm text-gray-500">Define buyer count milestones that unlock benefits (optional)</p>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={lbl}>Buyer Count</label>
              <input className={inp} type="number" min="1" value={milestoneInput.buyerCount}
                onChange={e => setMilestoneInput(p => ({ ...p, buyerCount: e.target.value }))} placeholder="e.g. 5" />
            </div>
            <div>
              <label className={lbl}>Benefit</label>
              <input className={inp} value={milestoneInput.benefit}
                onChange={e => setMilestoneInput(p => ({ ...p, benefit: e.target.value }))}
                placeholder="e.g. Free Modular Kitchen"
                onKeyDown={e => e.key === "Enter" && addMilestone()} />
            </div>
          </div>
          <button type="button" onClick={addMilestone}
            className="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700 transition-colors">
            Add Milestone
          </button>
          <div className="space-y-2">
            {form.milestones.sort((a, b) => a.buyerCount - b.buyerCount).map((m, i) => (
              <div key={i} className="flex items-center justify-between bg-blue-50 rounded-lg p-3">
                <div>
                  <span className="text-sm font-medium text-blue-800">{m.buyerCount} buyers</span>
                  <span className="text-sm text-blue-600 ml-2">→ {m.benefit}</span>
                </div>
                <button type="button"
                  onClick={() => set("milestones", form.milestones.filter((_, j) => j !== i))}
                  className="text-red-400 hover:text-red-600 text-xs">
                  Remove
                </button>
              </div>
            ))}
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
