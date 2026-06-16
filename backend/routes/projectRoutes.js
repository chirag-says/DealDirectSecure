/**
 * Project Routes — DealDirect
 * Mounted at: /api/projects
 *
 * Admin routes: protected by protectAdmin
 * Public routes: GET (for client display) — no auth required
 */
import express from "express";
import multer from "multer";
import {
  createProject,
  getProject,
  listProjects,
  listProjectsByBuilder,
  updateProject,
  addConstructionUpdate,
  deleteProject,
} from "../controllers/projectController.js";
import { protectAdmin } from "../middleware/authAdmin.js";
import { memoryUpload, memoryUploadWithDocs, uploadConcurrencyGuard } from "../middleware/upload.js";

const router = express.Router();

// ── Multer error handler ────────────────────────────────────────────────────
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    console.error(`[Multer] ${err.code}: ${err.message} (field: ${err.field || "unknown"})`);
    const messages = {
      LIMIT_UNEXPECTED_FILE: `Unexpected file field "${err.field}".`,
      LIMIT_FILE_SIZE: "File too large. Maximum 15MB per file.",
      LIMIT_FILE_COUNT: "Too many files uploaded.",
      LIMIT_PART_COUNT: "Too many form fields.",
    };
    return res.status(400).json({ success: false, message: messages[err.code] || err.message });
  }
  if (err?.message?.includes("Invalid file")) {
    return res.status(400).json({ success: false, message: err.message });
  }
  next(err);
};

// ── Middleware: Organize files from .any() into req.files object by fieldname ──
const ALLOWED_PROJECT_FIELDS = new Set([
  "exteriorImages", "droneImages", "masterPlan", "locationMap",
  "constructionProgressImages", "brochureUrl", "reraCertificateUrl",
  "commencementCertificateUrl", "occupancyCertificateUrl",
  "environmentalClearanceUrl", "approvalDocumentUrls",
]);

const organizeProjectFiles = (req, res, next) => {
  // .any() puts all files in req.files as a flat array — group by fieldname
  if (Array.isArray(req.files)) {
    const grouped = {};
    for (const file of req.files) {
      if (!ALLOWED_PROJECT_FIELDS.has(file.fieldname)) {
        return res.status(400).json({
          success: false,
          message: `Unexpected file field "${file.fieldname}".`,
        });
      }
      if (!grouped[file.fieldname]) grouped[file.fieldname] = [];
      grouped[file.fieldname].push(file);
    }
    req.files = grouped;
  }
  next();
};

// ── Public routes ─────────────────────────────────────────────────────────────
router.get("/builder/:builderId", listProjectsByBuilder); // MUST be before /:id
router.get("/", listProjects);
router.get("/:id", getProject);

// ── Admin routes ──────────────────────────────────────────────────────────────
router.post(
  "/",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUploadWithDocs.any(),
  handleMulterError,
  organizeProjectFiles,
  createProject
);

router.put(
  "/:id",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUploadWithDocs.any(),
  handleMulterError,
  organizeProjectFiles,
  updateProject
);

router.post(
  "/:id/construction-update",
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUpload.fields([{ name: "images", maxCount: 10 }]),
  handleMulterError,
  addConstructionUpdate
);

router.delete("/:id", protectAdmin, deleteProject);

export default router;
