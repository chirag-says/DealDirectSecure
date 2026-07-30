import { z } from "zod";

/**
 * campaignSchema — Zod validation for all 4 steps of CreateCampaign.
 *
 * Steps:
 *   1. Basics (name)
 *   2. Buyers (min/max)
 *   3. Duration (start/end dates)
 *   4. Discount & Perks (discountPerBuyer, tokenAmount)
 *
 * Usage:
 *   import { validateCampaignStep } from "../schemas/campaignSchema";
 *   const errors = validateCampaignStep(stepNumber, form);
 */

// ── Step 1: Basics ────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z.string().min(1, "Campaign name is required").max(200, "Name too long"),
});

// ── Step 2: Buyers ────────────────────────────────────────────────────────────
export const step2Schema = z.object({
  minBuyers: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Minimum buyers is required" }).min(2, "Minimum buyers must be at least 2")
  ),
}).superRefine((data, ctx) => {
  // maxBuyers is optional — only validate if provided
  const max = data.maxBuyers;
  if (max !== "" && max !== undefined && max !== null) {
    const maxNum = Number(max);
    const minNum = Number(data.minBuyers) || 0;
    if (maxNum < minNum) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Maximum buyers must be ≥ minimum buyers",
        path: ["maxBuyers"],
      });
    }
  }
});

// ── Step 3: Duration ──────────────────────────────────────────────────────────
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

// ── Step 4: Discount & Perks ──────────────────────────────────────────────────
export const step4Schema = z.object({
  discountPerBuyer: z.preprocess(
    (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
    z.number({ invalid_type_error: "Must be a number", required_error: "Discount is required" })
      .positive("Discount must be greater than 0")
  ),
});

/**
 * validateCampaignStep — returns { fieldKey: "error" } or {}.
 *
 * @param {number} stepId
 * @param {object} form — full campaign form state
 */
export function validateCampaignStep(stepId, form) {
  const schemaMap = {
    1: step1Schema,
    2: step2Schema,
    3: step3Schema,
    4: step4Schema,
  };

  const schema = schemaMap[stepId];
  if (!schema) return {};

  const result = schema.safeParse(form);
  const errors = {};

  if (!result.success) {
    for (const issue of result.error.issues) {
      const key = issue.path[0];
      if (key && !errors[key]) errors[key] = issue.message;
    }
  }

  return errors;
}
