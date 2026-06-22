import React, { useRef, useEffect, useState } from "react";
import { toast } from "react-toastify";
import Stepper from "./Stepper";

/**
 * Wizard — orchestrates a multi-step form.
 *
 * Props:
 *   steps          {Array<{ id: number, label: string }>}
 *   currentStep    {number}
 *   onStepChange   {(step: number) => void}
 *   validateStep   {(step: number) => object}  — returns { fieldKey: "error msg" } or {}
 *   onSetErrors    {(errors: object) => void}   — pushes validation errors back to parent
 *   onSubmit       {() => Promise<void>}         — called on final submit
 *   submitting     {boolean}
 *   submitLabel    {string}                      — default: "Submit"
 *   draftBanner    {ReactNode|null}              — optional draft-saved banner
 *   children       {ReactNode}                   — the step content panel
 */
export default function Wizard({
  steps,
  currentStep,
  onStepChange,
  validateStep,
  onSetErrors,
  onSubmit,
  submitting = false,
  submitLabel = "Submit",
  draftBanner = null,
  children,
}) {
  const stepContainerRef = useRef(null);
  const [maxReached, setMaxReached] = useState(currentStep);
  const lastStep = steps[steps.length - 1]?.id;

  useEffect(() => {
    setMaxReached(prev => Math.max(prev, currentStep));
  }, [currentStep]);

  /** Scroll to the first invalid field after validation fires. */
  const scrollToFirstError = (errors) => {
    if (!stepContainerRef.current) return;
    const firstField = Object.keys(errors)[0];
    if (!firstField) return;
    // Try data-field attribute first, then fallback to name
    const el =
      stepContainerRef.current.querySelector(`[data-field="${firstField}"]`) ||
      stepContainerRef.current.querySelector(`[name="${firstField}"]`);
    if (!el) return;
    setTimeout(() => {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      if (typeof el.focus === "function") el.focus();
    }, 50);
  };

  const goNext = () => {
    const errors = validateStep(currentStep);
    onSetErrors(errors);
    if (Object.keys(errors).length > 0) {
      toast.error(Object.values(errors)[0]);
      scrollToFirstError(errors);
      return;
    }
    onSetErrors({});
    const next = Math.min(lastStep, currentStep + 1);
    onStepChange(next);
    setMaxReached(prev => Math.max(prev, next));
    stepContainerRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const goBack = () => {
    onStepChange(Math.max(steps[0].id, currentStep - 1));
    stepContainerRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const handleStepClick = (stepId) => {
    // Validate current step before jumping forward
    if (stepId > currentStep) {
      const errors = validateStep(currentStep);
      onSetErrors(errors);
      if (Object.keys(errors).length > 0) {
        toast.error(Object.values(errors)[0]);
        scrollToFirstError(errors);
        return;
      }
    }
    onSetErrors({});
    onStepChange(stepId);
  };

  const handleSubmit = async () => {
    // Validate every step before final submit
    const allErrors = {};
    for (const s of steps.slice(0, -1)) {
      Object.assign(allErrors, validateStep(s.id));
    }
    if (Object.keys(allErrors).length > 0) {
      onSetErrors(allErrors);
      const count = Object.keys(allErrors).length;
      toast.error(`${count} field${count > 1 ? "s" : ""} need${count > 1 ? "" : "s"} attention.`);
      // Jump to first failing step
      for (const s of steps.slice(0, -1)) {
        if (Object.keys(validateStep(s.id)).length > 0) {
          onStepChange(s.id);
          setTimeout(() => scrollToFirstError(validateStep(s.id)), 50);
          break;
        }
      }
      return;
    }
    onSetErrors({});
    await onSubmit();
  };

  const isLastStep = currentStep === lastStep;
  const isFirstStep = currentStep === steps[0]?.id;

  return (
    <div className="max-w-2xl mx-auto py-6 px-4">
      {/* Draft banner slot */}
      {draftBanner && <div className="mb-4">{draftBanner}</div>}

      {/* Stepper */}
      <Stepper
        steps={steps}
        currentStep={currentStep}
        onStepClick={handleStepClick}
        maxReached={maxReached}
      />

      {/* Step content */}
      <div ref={stepContainerRef} className="bg-white rounded-2xl shadow-sm border border-gray-200 p-6">
        {children}
      </div>

      {/* Navigation */}
      <div className="flex justify-between mt-6 gap-3">
        <button
          type="button"
          onClick={goBack}
          disabled={isFirstStep}
          className="px-5 py-2.5 border border-gray-300 rounded-xl text-sm text-gray-600 hover:bg-gray-50 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          ← Previous
        </button>

        {isLastStep ? (
          <button
            type="button"
            onClick={handleSubmit}
            disabled={submitting}
            className="px-6 py-2.5 bg-blue-600 text-white rounded-xl text-sm font-semibold hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
          >
            {submitting ? (
              <>
                <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Saving...
              </>
            ) : submitLabel}
          </button>
        ) : (
          <button
            type="button"
            onClick={goNext}
            className="px-6 py-2.5 bg-blue-600 text-white rounded-xl text-sm font-semibold hover:bg-blue-700 transition-colors"
          >
            Next →
          </button>
        )}
      </div>
    </div>
  );
}
