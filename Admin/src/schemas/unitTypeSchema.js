import { z } from "zod";

/**
 * unitTypeSchema — Zod validation for the CreateUnitType wizard.
 *
 * ADMIN-ONLY FORM: nothing is compulsory. Every field can be left blank and
 * filled in later. The rules below only fire on values the admin actually
 * entered — negative counts, an area smaller than the one it contains, unit
 * counts that don't add up, tax percentages beyond the legal ceiling.
 *
 * Usage:
 *   import { validateUnitTypeStep } from "../schemas/unitTypeSchema";
 *   const errors = validateUnitTypeStep(stepNumber, form, files);
 */

// ── Reusable primitives ────────────────────────────────────────────────────────
const blankToUndefined = (val) =>
  val === "" || val === null || val === undefined ? undefined : Number(val);

const optionalPositive = z.preprocess(
  blankToUndefined,
  z.number({ invalid_type_error: "Must be a number" }).positive("Must be greater than 0").optional()
);

const optionalCount = z.preprocess(
  blankToUndefined,
  z
    .number({ invalid_type_error: "Must be a number" })
    .int("Must be a whole number")
    .min(0, "Cannot be negative")
    .optional()
);

const optionalNonNegative = z.preprocess(
  blankToUndefined,
  z.number({ invalid_type_error: "Must be a number" }).min(0, "Cannot be negative").optional()
);

// ── Step schemas ──────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z.string().max(100, "Name cannot exceed 100 characters").optional(),
  bedrooms: optionalCount,
  bathrooms: optionalCount,
  balconies: optionalCount,
});

export const step2Schema = z
  .object({
    carpetSqft: optionalPositive,
    builtUpSqft: optionalPositive,
    superBuiltUpSqft: optionalPositive,
  })
  .superRefine((data, ctx) => {
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
  coveredParking: optionalCount,
  openParking: optionalCount,
  evParking: optionalCount,
});

export const step8Schema = z.object({
  basePrice: optionalPositive,
  floorRisePerSqft: optionalNonNegative,
  viewPremium: optionalNonNegative,
  // Payment terms — bounds are statutory ceilings, checked only when filled in.
  bookingAmount: optionalNonNegative,
  gstPercentage: z.preprocess(
    blankToUndefined,
    z.number().min(0, "Cannot be negative").max(28, "GST cannot exceed 28%").optional()
  ),
  stampDutyPercentage: z.preprocess(
    blankToUndefined,
    z.number().min(0, "Cannot be negative").max(20, "Stamp duty cannot exceed 20%").optional()
  ),
  registrationCharges: optionalNonNegative,
});

export const step9Schema = z
  .object({
    totalUnits: optionalNonNegative,
    availableUnits: optionalNonNegative,
    bookedUnits: optionalNonNegative,
    blockedUnits: optionalNonNegative,
  })
  .superRefine((data, ctx) => {
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

  const schema = schemaMap[stepId];
  if (!schema) return {}; // Remaining steps (incl. floor-plan uploads) never block

  const result = schema.safeParse(form);
  if (result.success) return {};

  const errors = {};
  for (const issue of result.error.issues) {
    const key = issue.path[0];
    if (key && !errors[key]) errors[key] = issue.message;
  }
  return errors;
}
