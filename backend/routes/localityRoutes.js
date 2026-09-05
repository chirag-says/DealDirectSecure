import express from "express";
import { getLocality, getPriceGuidance, listLocalities } from "../controllers/localityController.js";

/**
 * Locality price pages (Phase 4, F18/F19). Mounted at /api/localities.
 *
 * Entirely public: these pages are the SEO surface, and a statistic computed
 * from published listings is not private to anyone.
 *
 * ROUTE ORDER: `/guidance` is a literal path and must precede `/:slug`, or
 * every guidance request is read as a locality named "guidance".
 */
const router = express.Router();

router.get("/", listLocalities);
router.get("/guidance", getPriceGuidance);
router.get("/:slug", getLocality);

export default router;
