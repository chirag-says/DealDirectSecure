/**
 * Secure File Upload Middleware
 * Implements magic-byte verification to prevent malicious file uploads
 * Validates files by their actual content signature, not just extension
 */
import dotenv from "dotenv";
dotenv.config();

import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { CloudinaryStorage } from "multer-storage-cloudinary";

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
if (cloudinaryUrl) {
  const match = cloudinaryUrl.match(/cloudinary:\/\/(\d+):([^@]+)@(.+)/);
  if (match) {
    cloudinary.config({
      cloud_name: match[3],
      api_key: match[1],
      api_secret: match[2],
    });
    console.log("✅ Cloudinary configured for cloud:", match[3]);
  } else {
    console.error("❌ Invalid CLOUDINARY_URL format");
  }
} else {
  console.error("❌ CLOUDINARY_URL not found in environment");
}

// ============================================
// MULTER CONFIGURATION WITH SECURITY CHECKS
// ============================================

/**
 * Custom file filter with magic-byte validation
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

/**
 * Post-processing middleware to validate magic bytes
 * This runs AFTER multer has processed the file buffer
 */
export const validateUploadedFiles = (req, res, next) => {
  const files = [];

  // Collect all uploaded files
  if (req.file) files.push(req.file);
  if (req.files) {
    if (Array.isArray(req.files)) {
      files.push(...req.files);
    } else {
      // files is an object with field names as keys
      for (const fieldFiles of Object.values(req.files)) {
        if (Array.isArray(fieldFiles)) {
          files.push(...fieldFiles);
        }
      }
    }
  }

  // Validate each file's magic bytes
  for (const file of files) {
    // For Cloudinary uploads, the file is already uploaded
    // We validate based on the buffer if available, or trust Cloudinary's processing
    if (file.buffer) {
      const validation = validateMagicBytes(file.buffer);

      if (!validation.valid) {
        console.error(`⚠️ SECURITY: Invalid file upload blocked - ${file.originalname}: ${validation.reason}`);
        return res.status(400).json({
          success: false,
          message: 'Invalid file detected: ' + validation.reason,
          code: 'INVALID_FILE'
        });
      }

      // Verify extension matches detected type
      if (!validateExtension(file.originalname, validation.type)) {
        console.error(`⚠️ SECURITY: Extension mismatch - ${file.originalname} detected as ${validation.type}`);
        return res.status(400).json({
          success: false,
          message: 'File extension does not match file content',
          code: 'EXTENSION_MISMATCH'
        });
      }
    }
  }

  next();
};

// Cloudinary storage configuration
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

// Create multer instance with security settings
export const upload = multer({
  storage: cloudinaryStorage,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB per file
    files: 50, // Maximum number of files
  },
  fileFilter: secureFileFilter,
});

// Memory storage for when we need to validate magic bytes before upload
export const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024,
    files: 50,
  },
  fileFilter: secureFileFilter,
});

// Export cloudinary instance for direct uploads
export { cloudinary, validateMagicBytes };
