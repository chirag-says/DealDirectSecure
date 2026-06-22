import { z } from "zod";

/**
 * campaignSchema — Zod validation for all 6 steps of CreateCampaign.
 *
 * Usage:
 *   import { validateCampaignStep } from "../schemas/campaignSchema";
 *   const errors = validateCampaignStep(stepNumber, form, unitType);
 */

// ── Reusable ───────────────────────────────────────────────────────────────────
const positiveNumber = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z.number({ invalid_type_error: "Must be a number" }).positive("Must be greater than 0")
);

// ── Step schemas ──────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z.string().min(1, "Campaign name is required").max(200, "Name too long"),
});

export const step2Schema = z.object({
  minBuyers: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Minimum buyers is required" }).min(3, "Minimum buyers must be at least 3")
  ),
  maxBuyers: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Maximum buyers is required" }).positive("Maximum buyers must be positive")
  ),
}).superRefine((data, ctx) => {
  const min = Number(data.minBuyers) || 0;
  const max = Number(data.maxBuyers) || 0;
  if (max < min) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Maximum buyers must be ≥ minimum buyers",
      path: ["maxBuyers"],
    });
  }
});

export const step3Schema = z.object({
  startDate: z.string().min(1, "Start date is required"),
  endDate: z.string().min(1, "End date is required"),
}).superRefine((data, ctx) => {
  if (data.startDate && data.endDate) {
    if (new Date(data.endDate) <= new Date(data.startDate)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "End date must be after start date",
        path: ["endDate"],
      });
    }
  }
});

export const step4Schema = z.object({
  regularPrice: positiveNumber,
  groupBuyPrice: positiveNumber,
  tokenAmount: positiveNumber,
}).superRefine((data, ctx) => {
  const regular = Number(data.regularPrice) || 0;
  const group = Number(data.groupBuyPrice) || 0;
  if (regular > 0 && group >= regular) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Group buy price must be less than regular price",
      path: ["groupBuyPrice"],
    });
  }
});

export const step5Schema = z.object({
  unitsReserved: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "At least 1 unit must be reserved" }).min(1, "At least 1 unit must be reserved")
  ),
});

/**
 * validateCampaignStep — returns { fieldKey: "error" } or {}.
 *
 * @param {number} stepId
 * @param {object} form       — full campaign form state
 * @param {object} unitType   — loaded unit type (for max inventory check on step 5)
 */
export function validateCampaignStep(stepId, form, unitType = null) {
  const schemaMap = {
    1: step1Schema,
    2: step2Schema,
    3: step3Schema,
    4: step4Schema,
    5: step5Schema,
  };

  const schema = schemaMap[stepId];
  if (!schema) return {}; // Step 6 (milestones) has no required fields

  const result = schema.safeParse(form);
  const errors = {};

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0];
      if (key && !errors[key]) errors[key] = issue.message;
    }
  }

  // Step 5 extra: check against actual available inventory
  if (stepId === 5 && unitType) {
    const reserved = Number(form.unitsReserved) || 0;
    const available = unitType?.inventory?.availableUnits || 0;
    if (reserved > available) {
      errors.unitsReserved = `Cannot reserve more than available units (${available})`;
    }
  }

  return errors;
}
