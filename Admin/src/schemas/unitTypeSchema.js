import { z } from "zod";

/**
 * unitTypeSchema — Zod validation for CreateUnitType wizard steps.
 * Mirrors the existing validateStep() contract exactly.
 *
 * Usage:
 *   import { validateUnitTypeStep } from "../schemas/unitTypeSchema";
 *   const errors = validateUnitTypeStep(stepNumber, form, files);
 */

// ── Reusable primitives ────────────────────────────────────────────────────────
const positiveArea = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z.number({ invalid_type_error: "Must be a number" }).positive("Must be greater than 0")
);

const nonNegativeInt = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z
    .number({ invalid_type_error: "Must be a number" })
    .int("Must be a whole number")
    .min(0, "Cannot be negative")
);

// ── Step schemas ──────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z
    .string()
    .min(1, "Unit type name is required")
    .max(100, "Name cannot exceed 100 characters"),
  // Either bedrooms or bathrooms must have a value
}).superRefine((data, ctx) => {
  const hasBedrooms = data.bedrooms !== "" && data.bedrooms !== undefined && data.bedrooms !== null;
  const hasBathrooms = data.bathrooms !== "" && data.bathrooms !== undefined && data.bathrooms !== null;
  if (!hasBedrooms && !hasBathrooms) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Specify at least bedrooms or bathrooms",
      path: ["bedrooms"],
    });
  }
});

export const step2Schema = z.object({
  carpetSqft: positiveArea,
}).superRefine((data, ctx) => {
  const carpet = Number(data.carpetSqft) || 0;
  const builtUp = Number(data.builtUpSqft) || 0;
  const superBuiltUp = Number(data.superBuiltUpSqft) || 0;

  if (builtUp > 0 && carpet > 0 && builtUp < carpet) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Built-up area must be ≥ carpet area",
      path: ["builtUpSqft"],
    });
  }
  if (superBuiltUp > 0 && builtUp > 0 && superBuiltUp < builtUp) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "Super built-up must be ≥ built-up area",
      path: ["superBuiltUpSqft"],
    });
  }
});

export const step5Schema = z.object({
  coveredParking: nonNegativeInt,
  openParking: nonNegativeInt,
  evParking: nonNegativeInt,
});

export const step8Schema = z.object({
  basePrice: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Base price is required" }).positive("Base price must be greater than 0")
  ),
  floorRisePerSqft: z.preprocess(
    (val) => (val === "" || val === undefined ? 0 : Number(val)),
    z.number().min(0, "Floor rise cannot be negative")
  ),
  viewPremium: z.preprocess(
    (val) => (val === "" || val === undefined ? 0 : Number(val)),
    z.number().min(0, "View premium cannot be negative")
  ),
});

export const step9Schema = z.object({
  totalUnits: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Total units is required" }).positive("Total units must be greater than 0")
  ),
  availableUnits: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Available units is required" }).min(0, "Available units cannot be negative")
  ),
  bookedUnits: z.preprocess(
    (val) => (val === "" || val === undefined ? 0 : Number(val)),
    z.number().min(0, "Booked units cannot be negative")
  ),
  blockedUnits: z.preprocess(
    (val) => (val === "" || val === undefined ? 0 : Number(val)),
    z.number().min(0, "Blocked units cannot be negative")
  ),
}).superRefine((data, ctx) => {
  const total = Number(data.totalUnits) || 0;
  const available = Number(data.availableUnits) || 0;
  const booked = Number(data.bookedUnits) || 0;
  const blocked = Number(data.blockedUnits) || 0;

  if (total > 0 && available + booked + blocked > total) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: `Available (${available}) + Booked (${booked}) + Blocked (${blocked}) cannot exceed Total (${total})`,
      path: ["availableUnits"],
    });
  }
});

/**
 * validateUnitTypeStep — runs Zod validation for a given step.
 *
 * @param {number} stepId
 * @param {object} form    — full form state
 * @param {object} files   — { twoDFloorPlan: File|null, threeDFloorPlan: File|null }
 * @returns {object}       — { fieldKey: "error message" } or {}
 */
export function validateUnitTypeStep(stepId, form, files = {}) {
  const schemaMap = {
    1: step1Schema,
    2: step2Schema,
    5: step5Schema,
    8: step8Schema,
    9: step9Schema,
  };

  // Step 7 — floor plan file upload
  if (stepId === 7) {
    const errs = {};
    if (!files.twoDFloorPlan) errs.twoDFloorPlan = "2D floor plan is required";
    return errs;
  }

  const schema = schemaMap[stepId];
  if (!schema) return {}; // Steps 3, 4, 6, 10 have no required fields

  const result = schema.safeParse(form);
  if (result.success) return {};

  const errors = {};
  for (const issue of result.error.issues) {
    const key = issue.path[0];
    if (key && !errors[key]) errors[key] = issue.message;
  }
  return errors;
}
