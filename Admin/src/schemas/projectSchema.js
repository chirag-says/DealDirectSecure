import { z } from "zod";

/**
 * projectSchema — Zod validation for the CreateProject wizard.
 *
 * ADMIN-ONLY FORM: nothing is compulsory. The admin decides what a project
 * record needs; a partially filled project can be saved and completed later.
 *
 * What survives here are consistency checks that only fire when a value is
 * actually entered — format (pincode digits), ranges (lat/lng), and cross-field
 * contradictions (possession before launch). A blank field never blocks.
 *
 * Usage in CreateProject.jsx's validateStep():
 *   import { validateProjectStep } from "../schemas/projectSchema";
 *   const errors = validateProjectStep(stepNumber, formValues);
 */

// ── Reusable primitives ────────────────────────────────────────────────────────
// Blank ("" / null / undefined) → undefined, so .optional() lets it through.
const blankToUndefined = (val) =>
  val === "" || val === null || val === undefined ? undefined : Number(val);

const optionalNonNegative = z.preprocess(
  blankToUndefined,
  z.number({ invalid_type_error: "Must be a number" }).min(0, "Cannot be negative").optional()
);

// ── Step schemas ──────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z.string().max(150, "Name cannot exceed 150 characters").optional(),
});

export const step2Schema = z.object({
  // Only checked when the admin actually types a pincode.
  pincode: z
    .string()
    .refine((v) => v === "" || /^\d{6}$/.test(v), "Pincode must be exactly 6 digits")
    .optional(),
  lat: z.preprocess(
    blankToUndefined,
    z
      .number({ invalid_type_error: "Must be a number" })
      .min(-90, "Latitude must be between -90 and 90")
      .max(90, "Latitude must be between -90 and 90")
      .optional()
  ),
  lng: z.preprocess(
    blankToUndefined,
    z
      .number({ invalid_type_error: "Must be a number" })
      .min(-180, "Longitude must be between -180 and 180")
      .max(180, "Longitude must be between -180 and 180")
      .optional()
  ),
});

export const step4Schema = z
  .object({
    // Declared so Zod keeps them for superRefine (unknown keys are stripped).
    launchDate: z.string().optional(),
    possessionDate: z.string().optional(),
    totalLandArea: z.string().optional(),
    totalTowers: optionalNonNegative,
  })
  .superRefine((data, ctx) => {
    // Only a contradiction between two filled-in dates is worth flagging.
    if (data.launchDate && data.possessionDate) {
      if (new Date(data.possessionDate) < new Date(data.launchDate)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: "Possession date must be on or after the launch date",
          path: ["possessionDate"],
        });
      }
    }
  });

// Step 5 (amenities), 6 (media), 7 (documents/legal) and 8 (sales contact)
// collect optional data only — no schema.

/**
 * validateProjectStep — runs Zod validation for a given step and returns
 * a flat { fieldKey: "error message" } map (same contract as before).
 *
 * @param {number} stepId
 * @param {object} form       — the full CreateProject form state
 * @param {object} files      — the full CreateProject files state
 * @returns {object}          — { fieldKey: "error message" } or {}
 */
export function validateProjectStep(stepId, form, files = {}) {
  const schemaMap = {
    1: step1Schema,
    2: step2Schema,
    4: step4Schema,
  };

  const schema = schemaMap[stepId];
  if (!schema) return {}; // No blocking rules on the remaining steps

  // superRefine needs the raw dates; pass the whole form through.
  const result = schema.safeParse(form);
  if (result.success) return {};

  // Flatten Zod errors into the { field: message } contract
  const errors = {};
  for (const issue of result.error.issues) {
    const key = issue.path[0];
    if (key && !errors[key]) errors[key] = issue.message;
  }
  return errors;
}
