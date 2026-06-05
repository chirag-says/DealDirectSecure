/**
 * Document Upload Middleware
 * Handles PDF and image uploads for deal closure proof documents.
 * Uses Cloudinary with resource_type: "auto" to accept both PDFs and images.
 */
import multer from "multer";
import { Readable } from "stream";
import { cloudinary, isCloudinaryConfigured } from "./upload.js";

// ============================================
// FILE FILTER — Allow images AND PDFs
// ============================================

const documentFileFilter = (req, file, cb) => {
  const allowedMimes = [
    "image/jpeg",
    "image/jpg",
    "image/png",
    "image/gif",
    "image/webp",
    "application/pdf",
  ];

  if (!allowedMimes.includes(file.mimetype)) {
    console.warn(`⚠️ Rejected document with invalid MIME type: ${file.mimetype}`);
    return cb(
      new Error("Invalid file type. Only JPEG, PNG, GIF, WebP images and PDF documents are allowed."),
      false
    );
  }

  const ext = file.originalname.split(".").pop()?.toLowerCase();
  const allowedExtensions = ["jpg", "jpeg", "png", "gif", "webp", "pdf"];

  if (!allowedExtensions.includes(ext)) {
    console.warn(`⚠️ Rejected document with invalid extension: ${ext}`);
    return cb(new Error("Invalid file extension."), false);
  }

  cb(null, true);
};

// ============================================
// MULTER INSTANCE — Memory storage for documents
// ============================================

export const documentUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 15 * 1024 * 1024, // 15MB per file (PDFs can be larger)
    files: 5, // Max 5 documents
  },
  fileFilter: documentFileFilter,
});

// ============================================
// UPLOAD TO CLOUDINARY — resource_type: "auto"
// ============================================

/**
 * Middleware: validate document buffers and upload to Cloudinary
 * Uses resource_type: "auto" so Cloudinary accepts both images and raw PDFs.
 */
export const uploadDocumentsToCloudinary = async (req, res, next) => {
  try {
    if (!isCloudinaryConfigured()) {
      console.error("❌ CRITICAL: Cloudinary is not configured.");
      return res.status(503).json({
        success: false,
        message: "Document upload service is not configured.",
        code: "STORAGE_NOT_CONFIGURED",
      });
    }

    // Collect all files
    const allFiles = [];

    if (req.files) {
      if (Array.isArray(req.files)) {
        allFiles.push(...req.files.map((f) => ({ file: f, fieldname: f.fieldname })));
      } else {
        for (const [fieldname, files] of Object.entries(req.files)) {
          if (Array.isArray(files)) {
            allFiles.push(...files.map((f) => ({ file: f, fieldname })));
          }
        }
      }
    }

    if (allFiles.length === 0) {
      return next(); // No files to process
    }

    // Upload each file to Cloudinary
    const uploadPromises = allFiles.map(async ({ file, fieldname }) => {
      return new Promise((resolve, reject) => {
        const uploadTimeout = setTimeout(() => {
          reject(new Error(`Upload timeout for ${file.originalname}`));
        }, 60000);

        const isPdf = file.mimetype === "application/pdf";

        const uploadOptions = {
          folder: "dealdirect/deal-documents",
          resource_type: isPdf ? "raw" : "image", // PDFs must use 'raw' to get /raw/upload/ URL
          timeout: 60000,
          // Apply transformations only for images
          ...(isPdf
            ? {}
            : {
                transformation: [{ width: 1200, height: 800, crop: "limit", quality: "auto" }],
              }),
        };

        const uploadStream = cloudinary.uploader.upload_stream(
          uploadOptions,
          (error, result) => {
            clearTimeout(uploadTimeout);
            if (error) {
              console.error("Cloudinary document upload error:", error);
              reject(error);
            } else {
              console.log(`✅ Document uploaded: ${file.originalname} -> ${result.secure_url}`);
              resolve({
                fieldname,
                originalname: file.originalname,
                path: result.secure_url,
                secure_url: result.secure_url,
                public_id: result.public_id,
                format: result.format,
                resource_type: result.resource_type,
              });
            }
          }
        );

        const readableStream = Readable.from(file.buffer);
        readableStream.pipe(uploadStream);
      });
    });

    try {
      const uploadedFiles = await Promise.all(uploadPromises);

      // Group by fieldname
      const filesGrouped = {};
      for (const uploaded of uploadedFiles) {
        if (!filesGrouped[uploaded.fieldname]) {
          filesGrouped[uploaded.fieldname] = [];
        }
        filesGrouped[uploaded.fieldname].push(uploaded);
      }

      req.files = filesGrouped;
      console.log(`✅ ${uploadedFiles.length} documents uploaded to Cloudinary`);
      next();
    } catch (uploadError) {
      console.error("❌ Document upload to Cloudinary failed:", uploadError.message);
      return res.status(500).json({
        success: false,
        message: "Failed to upload documents",
        code: "UPLOAD_FAILED",
      });
    }
  } catch (error) {
    console.error("Document upload processing error:", error);
    return res.status(500).json({
      success: false,
      message: "Document processing error",
      code: "PROCESSING_ERROR",
    });
  }
};
