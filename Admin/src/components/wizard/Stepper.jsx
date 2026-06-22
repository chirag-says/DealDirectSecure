import React from "react";

/**
 * Stepper — renders the horizontal step-indicator pills for a multi-step wizard.
 *
 * Props:
 *   steps        {Array<{ id: number, label: string }>}
 *   currentStep  {number}
 *   onStepClick  {(stepId: number) => void}  — called when a reachable step is clicked
 *   maxReached   {number}  — highest step the user has navigated to (controls reachability)
 */
export default function Stepper({ steps, currentStep, onStepClick, maxReached }) {
  return (
    <div className="flex items-center overflow-x-auto pb-2 mb-6">
      {steps.map((s, i) => {
        const isDone = currentStep > s.id;
        const isCurrent = currentStep === s.id;
        // A step is reachable if it's already been visited OR is the next step
        const reachable = s.id <= (maxReached ?? currentStep) || s.id === currentStep + 1;

        return (
          <React.Fragment key={s.id}>
            <button
              type="button"
              onClick={() => reachable && onStepClick(s.id)}
              disabled={!reachable}
              aria-current={isCurrent ? "step" : undefined}
              className={[
                "flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold whitespace-nowrap transition-all select-none",
                isCurrent
                  ? "bg-blue-600 text-white shadow-sm"
                  : isDone
                  ? "bg-emerald-100 text-emerald-700 hover:bg-emerald-200"
                  : "bg-gray-100 text-gray-500",
                !reachable ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
              ].join(" ")}
            >
              <span className={[
                "w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0",
                isCurrent ? "bg-white/30 text-white" : isDone ? "bg-emerald-600 text-white" : "bg-gray-300 text-gray-600",
              ].join(" ")}>
                {isDone ? "✓" : s.id}
              </span>
              {s.label}
            </button>
            {i < steps.length - 1 && (
              <div className={`flex-1 h-0.5 mx-1 min-w-[6px] transition-colors ${isDone ? "bg-emerald-400" : "bg-gray-200"}`} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
