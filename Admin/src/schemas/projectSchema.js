import { z } from "zod";

/**
 * projectSchema — Zod validation for all 8 data-entry steps of CreateProject.
 * Step 9 is the review/submit step — no new fields are collected there.
 *
 * Usage in CreateProject.jsx's validateStep():
 *   import { validateProjectStep } from "../schemas/projectSchema";
 *   const errors = validateProjectStep(stepNumber, formValues);
 *
 * Each step schema uses .partial() so that independent step schemas
 * don't break when the whole form object is not yet fully filled.
 */

// ── Reusable primitives ────────────────────────────────────────────────────────
const positiveNumber = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z.number({ invalid_type_error: "Must be a number" }).positive("Must be greater than 0")
);

const nonNegativeNumber = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z.number({ invalid_type_error: "Must be a number" }).min(0, "Cannot be negative")
);

const optionalNonNegative = z.preprocess(
  (val) => (val === "" || val === null || val === undefined ? undefined : Number(val)),
  z.number().min(0, "Cannot be negative").optional()
);

// ── Step schemas ──────────────────────────────────────────────────────────────
export const step1Schema = z.object({
  name: z.string().min(1, "Project name is required").max(150, "Name cannot exceed 150 characters"),
  category: z.string().min(1, "Category is required"),
});

export const step2Schema = z.object({
  state: z.string().min(1, "State is required"),
  city: z.string().min(1, "City is required"),
  locality: z.string().min(1, "Locality is required"),
  pincode: z
    .string()
    .min(1, "Pincode is required")
    .length(6, "Pincode must be exactly 6 digits")
    .regex(/^\d+$/, "Pincode must contain only digits"),
  lat: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Please pick a location on the map" })
      .min(-90, "Latitude must be between -90 and 90")
      .max(90, "Latitude must be between -90 and 90")
  ),
  lng: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number({ required_error: "Please pick a location on the map" })
      .min(-180, "Longitude must be between -180 and 180")
      .max(180, "Longitude must be between -180 and 180")
  ),
});

export const step4Schema = z.object({
  launchDate: z.string().min(1, "Launch date is required"),
  possessionDate: z.string().min(1, "Possession date is required"),
  totalLandArea: positiveNumber,
  totalTowers: z.preprocess(
    (val) => (val === "" ? undefined : Number(val)),
    z.number().positive("Number of towers is required")
  ),
}).superRefine((data, ctx) => {
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

export const step5Schema = z.object({
  amenities: z.array(z.any()).min(1, "Select at least one amenity"),
});

export const step8Schema = z.object({
  bookingAmount: nonNegativeNumber,
  salesPhone: z
    .string()
    .min(1, "Sales phone is required")
    .regex(/^[+\d\s\-()]{7,20}$/, "Enter a valid phone number"),
  salesEmail: z
    .string()
    .min(1, "Sales email is required")
    .email("Enter a valid email address"),
});

/**
 * validateProjectStep — runs Zod validation for a given step and returns
 * a flat { fieldKey: "error message" } map (same contract as the existing validateStep).
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
    5: step5Schema,
    8: step8Schema,
  };

  const schema = schemaMap[stepId];
  if (!schema) return {}; // Steps 3, 6, 7, 9 have no schema (optional or file-only)

  // Steps 6 & 7 validate files — handled below
  if (stepId === 6) {
    const errs = {};
    if (!files.exteriorImages || files.exteriorImages.length === 0) {
      errs.exteriorImages = "At least one exterior image is required";
    }
    return errs;
  }

  if (stepId === 7) {
    const errs = {};
    if (!files.reraCertificateUrl || files.reraCertificateUrl.length === 0) {
      errs.reraCertificateUrl = "RERA certificate is required";
    }
    if (!form.titleClear) {
      errs.titleClear = "Title must be clear to publish";
    }
    return errs;
  }

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
