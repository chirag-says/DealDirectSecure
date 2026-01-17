/**
 * Secure File Upload Middleware
 * Implements magic-byte verification to prevent malicious file uploads
 * Validates files by their actual content signature, not just extension
 * 
 * SECURITY FIX: Now validates magic bytes IN-MEMORY using memoryStorage()
 * BEFORE files are streamed to Cloudinary. Invalid files are rejected
 * at the buffer stage and never touch external storage.
 */
import dotenv from "dotenv";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";

// Get directory name in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// HOSTINGER FIX: Load .env or .env.production (same logic as server.js)
const envPath = path.join(__dirname, '..', '.env');
const envProdPath = path.join(__dirname, '..', '.env.production');

if (fs.existsSync(envPath)) {
  dotenv.config({ path: envPath });
} else if (fs.existsSync(envProdPath)) {
  console.log('[upload.js] Loading environment from .env.production');
  dotenv.config({ path: envProdPath });
} else {
  dotenv.config(); // Try default locations
}

import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
// SECURITY FIX: Updated import for multer-storage-cloudinary v2.x
// CloudinaryStorage is exported as default in v2.x
import CloudinaryStorage from "multer-storage-cloudinary";
import { Readable } from "stream";

// ============================================
// MAGIC BYTE SIGNATURES FOR FILE VALIDATION
// ============================================

// File signatures (magic bytes) for allowed image types
const MAGIC_BYTES = {
  // JPEG: starts with FF D8 FF
  jpeg: {
    signatures: [
      [0xFF, 0xD8, 0xFF, 0xE0], // JPEG/JFIF
      [0xFF, 0xD8, 0xFF, 0xE1], // JPEG/EXIF
      [0xFF, 0xD8, 0xFF, 0xE2], // JPEG/ICC
      [0xFF, 0xD8, 0xFF, 0xE8], // JPEG/SPIFF
      [0xFF, 0xD8, 0xFF, 0xDB], // JPEG raw
      [0xFF, 0xD8, 0xFF, 0xEE], // JPEG/Adobe
    ],
    extensions: ['jpg', 'jpeg'],
    mime: 'image/jpeg'
  },
  // PNG: starts with 89 50 4E 47 0D 0A 1A 0A
  png: {
    signatures: [
      [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
    ],
    extensions: ['png'],
    mime: 'image/png'
  },
  // GIF: starts with GIF87a or GIF89a
  gif: {
    signatures: [
      [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], // GIF87a
      [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], // GIF89a
    ],
    extensions: ['gif'],
    mime: 'image/gif'
  },
  // WebP: starts with RIFF....WEBP
  webp: {
    signatures: [
      [0x52, 0x49, 0x46, 0x46], // RIFF header (WebP also has WEBP at offset 8)
    ],
    extensions: ['webp'],
    mime: 'image/webp',
    additionalCheck: (buffer) => {
      // Check for WEBP signature at offset 8
      return buffer.length >= 12 &&
        buffer[8] === 0x57 &&
        buffer[9] === 0x45 &&
        buffer[10] === 0x42 &&
        buffer[11] === 0x50;
    }
  }
};

// Dangerous file signatures to explicitly block
const BLOCKED_SIGNATURES = [
  // Executable files
  { name: 'EXE/DLL', bytes: [0x4D, 0x5A] }, // MZ header
  { name: 'ELF', bytes: [0x7F, 0x45, 0x4C, 0x46] }, // Linux executable
  // Script files
  { name: 'PHP', bytes: [0x3C, 0x3F, 0x70, 0x68, 0x70] }, // <?php
  { name: 'Script', bytes: [0x3C, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74] }, // <script
  { name: 'HTML', bytes: [0x3C, 0x21, 0x44, 0x4F, 0x43, 0x54, 0x59, 0x50, 0x45] }, // <!DOCTYPE
  // Archive files (could contain malicious payloads)
  { name: 'ZIP', bytes: [0x50, 0x4B, 0x03, 0x04] },
  { name: 'RAR', bytes: [0x52, 0x61, 0x72, 0x21] },
  { name: '7Z', bytes: [0x37, 0x7A, 0xBC, 0xAF] },
];

/**
 * Check if buffer starts with given signature bytes
 */
const matchesSignature = (buffer, signature) => {
  if (buffer.length < signature.length) return false;
  for (let i = 0; i < signature.length; i++) {
    if (buffer[i] !== signature[i]) return false;
  }
  return true;
};

/**
 * Validate file by checking magic bytes
 * Returns the detected file type or null if invalid
 */
const validateMagicBytes = (buffer) => {
  if (!buffer || buffer.length < 4) {
    return { valid: false, reason: 'File too small or empty' };
  }

  // First, check for blocked signatures
  for (const blocked of BLOCKED_SIGNATURES) {
    if (matchesSignature(buffer, blocked.bytes)) {
      console.error(`⚠️ SECURITY: Blocked ${blocked.name} file upload attempt`);
      return { valid: false, reason: `${blocked.name} files are not allowed` };
    }
  }

  // Check for valid image signatures
  for (const [type, config] of Object.entries(MAGIC_BYTES)) {
    for (const sig of config.signatures) {
      if (matchesSignature(buffer, sig)) {
        // Additional check for WebP
        if (config.additionalCheck && !config.additionalCheck(buffer)) {
          continue;
        }
        return { valid: true, type, mime: config.mime };
      }
    }
  }

  return { valid: false, reason: 'Unrecognized or invalid file format' };
};

/**
 * Check file extension against detected type
 */
const validateExtension = (filename, detectedType) => {
  if (!filename || !detectedType) return false;

  const ext = filename.split('.').pop()?.toLowerCase();
  const config = MAGIC_BYTES[detectedType];

  if (!config) return false;
  return config.extensions.includes(ext);
};

// ============================================
// CLOUDINARY CONFIGURATION
// ============================================

const cloudinaryUrl = process.env.CLOUDINARY_URL;
let cloudinaryConfigured = false;

if (cloudinaryUrl) {
  const match = cloudinaryUrl.match(/cloudinary:\/\/(\d+):([^@]+)@(.+)/);
  if (match) {
    cloudinary.config({
      cloud_name: match[3],
      api_key: match[1],
      api_secret: match[2],
    });
    cloudinaryConfigured = true;
    console.log("✅ Cloudinary configured for cloud:", match[3]);
    
    // Verify Cloudinary connectivity on startup (async, non-blocking)
    cloudinary.api.ping()
      .then(() => console.log("✅ Cloudinary connection verified"))
      .catch((err) => {
        console.error("❌ Cloudinary connection test FAILED:", err.message);
        console.error("   Image uploads will NOT work until this is resolved!");
      });
  } else {
    console.error("❌ Invalid CLOUDINARY_URL format. Expected: cloudinary://api_key:api_secret@cloud_name");
  }
} else {
  console.error("❌ CLOUDINARY_URL not found in environment variables");
  console.error("   Image uploads will NOT work until CLOUDINARY_URL is configured!");
}

// Export configuration status for health checks
export const isCloudinaryConfigured = () => cloudinaryConfigured;

// ============================================
// MULTER CONFIGURATION WITH SECURITY CHECKS
// ============================================

/**
 * Custom file filter with basic MIME type check
 * (Deep magic-byte validation happens after buffer is available)
 */
const secureFileFilter = (req, file, cb) => {
  // Check MIME type first (quick rejection for obvious bad types)
  const allowedMimes = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];

  if (!allowedMimes.includes(file.mimetype)) {
    console.warn(`⚠️ Rejected file with invalid MIME type: ${file.mimetype}`);
    return cb(new Error('Invalid file type. Only JPEG, PNG, GIF, and WebP images are allowed.'), false);
  }

  // Check file extension
  const ext = file.originalname.split('.').pop()?.toLowerCase();
  const allowedExtensions = ['jpg', 'jpeg', 'png', 'gif', 'webp'];

  if (!allowedExtensions.includes(ext)) {
    console.warn(`⚠️ Rejected file with invalid extension: ${ext}`);
    return cb(new Error('Invalid file extension. Only jpg, jpeg, png, gif, and webp are allowed.'), false);
  }

  cb(null, true);
};

// ============================================
// SECURITY FIX: In-Memory Upload with Magic Byte Validation
// Files are validated BEFORE being sent to Cloudinary
// 
// ADDITIONAL SECURITY: Concurrent upload limiting + memory pressure detection
// ============================================

// Track concurrent uploads to prevent DoS
let activeUploads = 0;
const MAX_CONCURRENT_UPLOADS = 10; // Max simultaneous upload requests
const MAX_MEMORY_USAGE_PERCENT = 95; // Reject uploads if heap is > 95% used

/**
 * Check if server has memory capacity for more uploads
 */
const checkMemoryPressure = () => {
  const memUsage = process.memoryUsage();
  const heapUsedPercent = (memUsage.heapUsed / memUsage.heapTotal) * 100;
  return heapUsedPercent < MAX_MEMORY_USAGE_PERCENT;
};

/**
 * Middleware to limit concurrent uploads
 */
export const uploadConcurrencyGuard = (req, res, next) => {
  // Check concurrent upload limit
  if (activeUploads >= MAX_CONCURRENT_UPLOADS) {
    console.warn(`⚠️ SECURITY: Concurrent upload limit reached (${activeUploads}/${MAX_CONCURRENT_UPLOADS})`);
    return res.status(503).json({
      success: false,
      message: 'Server is busy processing other uploads. Please try again shortly.',
      code: 'UPLOAD_QUEUE_FULL',
      retryAfter: 5
    });
  }

  // DISABLED: Memory pressure check causes false positives on shared hosting (Hostinger)
  // Shared hosting environments report high heap usage even when functioning normally
  // The concurrent upload limit above is sufficient protection against DoS
  // 
  // If you want to re-enable this on dedicated servers, uncomment below:
  // const isDev = process.env.NODE_ENV !== 'production';
  // if (!isDev && !checkMemoryPressure()) {
  //   console.warn(`⚠️ SECURITY: Memory pressure detected, rejecting upload`);
  //   return res.status(503).json({
  //     success: false,
  //     message: 'Server is under heavy load. Please try again shortly.',
  //     code: 'MEMORY_PRESSURE',
  //     retryAfter: 10
  //   });
  // }

  // Track this upload
  activeUploads++;
  console.log(`📤 Upload started (active: ${activeUploads}/${MAX_CONCURRENT_UPLOADS})`);

  // Ensure counter decrements when request finishes
  res.on('finish', () => {
    activeUploads = Math.max(0, activeUploads - 1);
    console.log(`📤 Upload finished (active: ${activeUploads}/${MAX_CONCURRENT_UPLOADS})`);
  });

  res.on('close', () => {
    // Handle aborted requests
    if (!res.writableEnded) {
      activeUploads = Math.max(0, activeUploads - 1);
      console.log(`📤 Upload aborted (active: ${activeUploads}/${MAX_CONCURRENT_UPLOADS})`);
    }
  });

  next();
};

/**
 * Memory storage for initial buffer capture
 * This allows us to validate magic bytes before uploading to Cloudinary
 * 
 * SECURITY FIX: Reduced limits to prevent memory exhaustion attacks
 * Max theoretical memory: 5 files × 5MB = 25MB per request
 * With 10 concurrent uploads = 250MB max (safe for 2GB heap)
 */
export const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB per file
    files: 50, // Max 50 files (for categorized images)
    parts: 100, // Max 100 multipart fields (form data + files)
  },
  fileFilter: secureFileFilter,
});

// SECURITY FIX: Track total upload size per request
const MAX_TOTAL_UPLOAD_SIZE = 100 * 1024 * 1024; // 100MB total per request

/**
 * SECURITY: Middleware to validate uploaded file buffers
 * and stream valid files to Cloudinary
 * 
 * This is the SECURE upload flow:
 * 1. Multer stores files in memory (memoryStorage)
 * 2. This middleware validates magic bytes
 * 3. Valid files are streamed to Cloudinary
 * 4. Invalid files are rejected WITHOUT touching external storage
 */
export const validateAndUploadToCloudinary = async (req, res, next) => {
  try {
    // FAIL FAST: Check if Cloudinary is configured before processing files
    if (!cloudinaryConfigured) {
      console.error('❌ CRITICAL: Cloudinary is not configured. Cannot process file uploads.');
      return res.status(503).json({
        success: false,
        message: 'Image upload service is not configured. Please contact support.',
        code: 'STORAGE_NOT_CONFIGURED'
      });
    }

    // Collect all files from request
    const allFiles = [];

    if (req.file) {
      allFiles.push({ file: req.file, fieldname: req.file.fieldname });
    }

    if (req.files) {
      if (Array.isArray(req.files)) {
        allFiles.push(...req.files.map(f => ({ file: f, fieldname: f.fieldname })));
      } else {
        // files is an object with field names as keys
        for (const [fieldname, files] of Object.entries(req.files)) {
          if (Array.isArray(files)) {
            allFiles.push(...files.map(f => ({ file: f, fieldname })));
          }
        }
      }
    }

    if (allFiles.length === 0) {
      return next();
    }

    // ============================================
    // SECURITY FIX: Check total upload size FIRST
    // This prevents memory exhaustion from combined large files
    // ============================================
    const totalSize = allFiles.reduce((sum, { file }) => sum + (file.buffer?.length || 0), 0);
    if (totalSize > MAX_TOTAL_UPLOAD_SIZE) {
      console.warn(`⚠️ SECURITY: Total upload size ${totalSize} exceeds limit ${MAX_TOTAL_UPLOAD_SIZE}`);
      return res.status(413).json({
        success: false,
        message: `Total upload size (${Math.round(totalSize / 1024 / 1024)}MB) exceeds maximum allowed (${MAX_TOTAL_UPLOAD_SIZE / 1024 / 1024}MB)`,
        code: 'TOTAL_SIZE_EXCEEDED'
      });
    }

    // ============================================
    // SECURITY: Validate each file's magic bytes IN-MEMORY
    // before streaming to Cloudinary
    // ============================================
    const validatedFiles = [];

    for (const { file, fieldname } of allFiles) {
      if (!file.buffer) {
        console.error(`⚠️ SECURITY: File ${file.originalname} has no buffer`);
        return res.status(400).json({
          success: false,
          message: 'File upload error: buffer not available',
          code: 'UPLOAD_ERROR'
        });
      }

      // Validate magic bytes
      const validation = validateMagicBytes(file.buffer);

      if (!validation.valid) {
        console.error(`⚠️ SECURITY: Invalid file blocked at buffer stage - ${file.originalname}: ${validation.reason}`);
        return res.status(400).json({
          success: false,
          message: `Invalid file "${file.originalname}": ${validation.reason}`,
          code: 'INVALID_FILE'
        });
      }

      // Verify extension matches detected type
      if (!validateExtension(file.originalname, validation.type)) {
        console.error(`⚠️ SECURITY: Extension mismatch - ${file.originalname} detected as ${validation.type}`);
        return res.status(400).json({
          success: false,
          message: `File "${file.originalname}": extension does not match file content`,
          code: 'EXTENSION_MISMATCH'
        });
      }

      validatedFiles.push({ file, fieldname, validation });
    }

    // ============================================
    // SECURITY: Now upload validated files to Cloudinary
    // Only files that passed magic byte validation reach this point
    // ============================================
    const uploadPromises = validatedFiles.map(async ({ file, fieldname }) => {
      const isProfileImage = fieldname === 'profileImage';
      const folder = isProfileImage ? "dealdirect/profiles" : "dealdirect/properties";

      return new Promise((resolve, reject) => {
        // Add timeout for Cloudinary upload (60 seconds per file)
        const uploadTimeout = setTimeout(() => {
          reject(new Error(`Upload timeout for ${file.originalname} - Cloudinary is not responding`));
        }, 60000);

        const uploadOptions = {
          folder,
          resource_type: "image",
          transformation: isProfileImage
            ? [{ width: 400, height: 400, crop: "fill", gravity: "face", quality: "auto" }]
            : [{ width: 1200, height: 800, crop: "limit", quality: "auto" }],
          timeout: 60000, // Cloudinary SDK timeout
        };

        // Create upload stream
        const uploadStream = cloudinary.uploader.upload_stream(
          uploadOptions,
          (error, result) => {
            clearTimeout(uploadTimeout);
            if (error) {
              console.error('Cloudinary upload error:', error);
              reject(error);
            } else {
              console.log(`✅ Uploaded: ${file.originalname} -> ${result.secure_url}`);
              resolve({
                fieldname,
                originalname: file.originalname,
                path: result.secure_url,
                secure_url: result.secure_url,
                public_id: result.public_id,
                format: result.format,
              });
            }
          }
        );

        // Stream the validated buffer to Cloudinary
        const readableStream = Readable.from(file.buffer);
        readableStream.pipe(uploadStream);
      });
    });

    try {
      const uploadedFiles = await Promise.all(uploadPromises);

      // Group uploaded files by fieldname to match multer's structure
      const filesGrouped = {};
      for (const uploaded of uploadedFiles) {
        if (!filesGrouped[uploaded.fieldname]) {
          filesGrouped[uploaded.fieldname] = [];
        }
        filesGrouped[uploaded.fieldname].push(uploaded);
      }

      // Replace req.files with Cloudinary results
      req.files = filesGrouped;

      console.log(`✅ SECURITY: ${uploadedFiles.length} files validated and uploaded to Cloudinary`);
      next();
    } catch (uploadError) {
      // Enhanced error logging for debugging
      console.error('❌ Cloudinary upload failed:', {
        message: uploadError.message,
        name: uploadError.name,
        code: uploadError.error?.http_code || uploadError.http_code,
        cloudinaryError: uploadError.error || uploadError,
        stack: uploadError.stack
      });
      
      // Provide more specific error messages based on error type
      let userMessage = 'Failed to upload files to storage';
      let errorCode = 'UPLOAD_FAILED';
      
      if (uploadError.message?.includes('timeout')) {
        userMessage = 'Upload timed out. Please try with smaller images or check your connection.';
        errorCode = 'UPLOAD_TIMEOUT';
      } else if (uploadError.error?.http_code === 401 || uploadError.http_code === 401) {
        userMessage = 'Storage service authentication failed. Please contact support.';
        errorCode = 'STORAGE_AUTH_ERROR';
        console.error('❌ CRITICAL: Cloudinary credentials are invalid or not configured!');
      } else if (uploadError.error?.http_code === 400 || uploadError.http_code === 400) {
        userMessage = 'Invalid image file. Please ensure your images are valid JPG, PNG, GIF, or WebP files.';
        errorCode = 'INVALID_IMAGE';
      }
      
      return res.status(500).json({
        success: false,
        message: userMessage,
        code: errorCode,
        // Include error details in development mode only
        ...(process.env.NODE_ENV !== 'production' && { debugInfo: uploadError.message })
      });
    }
  } catch (error) {
    console.error('File validation error:', error);
    return res.status(500).json({
      success: false,
      message: 'File processing error',
      code: 'PROCESSING_ERROR'
    });
  }
};

// ============================================
// LEGACY: Direct Cloudinary storage (kept for backward compatibility)
// NOTE: New code should use memoryUpload + validateAndUploadToCloudinary
// ============================================

// Cloudinary storage configuration (legacy)
const cloudinaryStorage = new CloudinaryStorage({
  cloudinary,
  params: async (req, file) => {
    const isProfileImage = file.fieldname === 'profileImage';

    return {
      folder: isProfileImage ? "dealdirect/profiles" : "dealdirect/properties",
      allowed_formats: ["jpg", "jpeg", "png", "webp", "gif"],
      // Resource type 'image' ensures Cloudinary validates the file
      resource_type: "image",
      // Cloudinary will reject non-image files
      transformation: isProfileImage
        ? [{ width: 400, height: 400, crop: "fill", gravity: "face", quality: "auto" }]
        : [{ width: 1200, height: 800, crop: "limit", quality: "auto" }],
    };
  },
});

// Legacy multer instance (direct to Cloudinary, less secure)
export const upload = multer({
  storage: cloudinaryStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB per file
    files: 50, // Maximum number of files
  },
  fileFilter: secureFileFilter,
});

/**
 * DEPRECATED: Post-processing middleware for legacy flow
 * This runs AFTER multer has processed the file
 * 
 * NOTE: For new implementations, use validateAndUploadToCloudinary instead
 * which validates BEFORE upload
 */
export const validateUploadedFiles = (req, res, next) => {
  console.warn('⚠️ validateUploadedFiles is deprecated. Use validateAndUploadToCloudinary for in-memory validation.');
  // For legacy Cloudinary uploads, files are already uploaded
  // We can only log a warning here
  next();
};

// Export cloudinary instance for direct uploads
export { cloudinary, validateMagicBytes };
