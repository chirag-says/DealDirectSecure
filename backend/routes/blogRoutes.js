import express from 'express';
import {
    getBlogs,
    getBlogBySlug,
    getBlogCategories,
    getBlogTags,
    getAdminBlogs,
    getAdminBlogById,
    createBlog,
    updateBlog,
    publishBlog,
    unpublishBlog,
    deleteBlog,
} from '../controllers/blogController.js';
import { protectAdmin } from '../middleware/authAdmin.js';
import { memoryUpload, validateAndUploadToCloudinary, uploadConcurrencyGuard } from '../middleware/upload.js';

const router = express.Router();

// ============================================
// PUBLIC ROUTES
// ============================================
router.get('/meta/categories', getBlogCategories);
router.get('/meta/tags', getBlogTags);
router.get('/', getBlogs);
router.get('/:slug', getBlogBySlug);

// ============================================
// ADMIN ROUTES (protected)
// ============================================
router.get('/admin/all', protectAdmin, getAdminBlogs);
router.get('/admin/:id', protectAdmin, getAdminBlogById);
router.post('/admin', protectAdmin, createBlog);
router.put('/admin/:id', protectAdmin, updateBlog);
router.patch('/admin/:id/publish', protectAdmin, publishBlog);
router.patch('/admin/:id/unpublish', protectAdmin, unpublishBlog);
router.delete('/admin/:id', protectAdmin, deleteBlog);

// Blog cover image upload — reuses existing secure upload pipeline
router.post(
  '/admin/upload-cover',
  protectAdmin,
  uploadConcurrencyGuard,
  memoryUpload.single('coverImage'),
  validateAndUploadToCloudinary,
  (req, res) => {
    // After validateAndUploadToCloudinary, req.files contains Cloudinary results
    const uploaded = req.files?.coverImage?.[0];
    if (!uploaded) {
      return res.status(400).json({ success: false, message: 'No image uploaded' });
    }
    res.json({ success: true, url: uploaded.secure_url });
  }
);

export default router;
