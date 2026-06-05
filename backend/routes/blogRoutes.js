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

export default router;
