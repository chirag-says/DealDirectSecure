/**
 * Blog Controller — DealDirect
 * Handles public blog reads + admin CRUD
 */
import Blog from '../models/Blog.js';
import slugify from 'slugify';

// ============================================
// PUBLIC ENDPOINTS
// ============================================

/**
 * GET /api/blogs
 * List published blogs — paginated, filterable by category/tag
 */
export const getBlogs = async (req, res) => {
    try {
        const { page = 1, limit = 10, category, tag, q } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);

        const filter = { status: 'published' };
        if (category) filter.category = category;
        if (tag) filter.tags = { $in: [tag] };
        if (q) filter.$text = { $search: q };

        const [blogs, total] = await Promise.all([
            Blog.find(filter)
                .sort({ publishedAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .select('title slug excerpt coverImage author tags category publishedAt readTime views'),
            Blog.countDocuments(filter),
        ]);

        res.json({
            success: true,
            data: blogs,
            pagination: {
                page: parseInt(page),
                limit: parseInt(limit),
                total,
                pages: Math.ceil(total / parseInt(limit)),
            },
        });
    } catch (err) {
        console.error('getBlogs error:', err);
        res.status(500).json({ success: false, message: 'Failed to fetch blogs' });
    }
};

/**
 * GET /api/blogs/:slug
 * Get single published blog by slug + increment views
 */
export const getBlogBySlug = async (req, res) => {
    try {
        const blog = await Blog.findOne({ slug: req.params.slug, status: 'published' });
        if (!blog) {
            return res.status(404).json({ success: false, message: 'Blog post not found' });
        }

        // Increment view count (non-blocking)
        Blog.findByIdAndUpdate(blog._id, { $inc: { views: 1 } }).exec();

        // Fetch related posts (same category, excluding current)
        const related = await Blog.find({
            status: 'published',
            category: blog.category,
            _id: { $ne: blog._id },
        })
            .sort({ publishedAt: -1 })
            .limit(3)
            .select('title slug excerpt coverImage publishedAt readTime');

        res.json({ success: true, data: blog, related });
    } catch (err) {
        console.error('getBlogBySlug error:', err);
        res.status(500).json({ success: false, message: 'Failed to fetch blog post' });
    }
};

/**
 * GET /api/blogs/meta/categories
 * Get all categories with published post counts
 */
export const getBlogCategories = async (req, res) => {
    try {
        const categories = await Blog.aggregate([
            { $match: { status: 'published' } },
            { $group: { _id: '$category', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
        ]);
        res.json({ success: true, data: categories });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch categories' });
    }
};

/**
 * GET /api/blogs/meta/tags
 * Get popular tags from published posts
 */
export const getBlogTags = async (req, res) => {
    try {
        const tags = await Blog.aggregate([
            { $match: { status: 'published' } },
            { $unwind: '$tags' },
            { $group: { _id: '$tags', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 30 },
        ]);
        res.json({ success: true, data: tags });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch tags' });
    }
};

// ============================================
// ADMIN ENDPOINTS
// ============================================

/**
 * GET /api/admin/blogs
 * Admin: list ALL blogs including drafts
 */
export const getAdminBlogs = async (req, res) => {
    try {
        const { page = 1, limit = 20, status } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const filter = {};
        if (status) filter.status = status;

        const [blogs, total] = await Promise.all([
            Blog.find(filter)
                .sort({ updatedAt: -1 })
                .skip(skip)
                .limit(parseInt(limit))
                .select('title slug status category publishedAt readTime views createdAt'),
            Blog.countDocuments(filter),
        ]);

        res.json({
            success: true,
            data: blogs,
            pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) },
        });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch admin blogs' });
    }
};

/**
 * GET /api/admin/blogs/:id
 * Admin: get single blog by ID (for editing)
 */
export const getAdminBlogById = async (req, res) => {
    try {
        const blog = await Blog.findById(req.params.id);
        if (!blog) return res.status(404).json({ success: false, message: 'Blog not found' });
        res.json({ success: true, data: blog });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to fetch blog' });
    }
};

/**
 * POST /api/admin/blogs
 * Admin: create new blog
 */
export const createBlog = async (req, res) => {
    try {
        const { title, excerpt, content, coverImage, author, tags, category, status, seoTitle, seoDescription } = req.body;

        // Generate unique slug from title
        let baseSlug = slugify(title, { lower: true, strict: true, trim: true });
        let slug = baseSlug;
        let counter = 1;
        while (await Blog.exists({ slug })) {
            slug = `${baseSlug}-${counter++}`;
        }

        const blog = await Blog.create({
            title, slug, excerpt, content, coverImage, author, tags, category, status, seoTitle, seoDescription,
        });

        res.status(201).json({ success: true, data: blog, message: 'Blog created successfully' });
    } catch (err) {
        console.error('createBlog error:', err);
        if (err.code === 11000) {
            return res.status(409).json({ success: false, message: 'A blog with this title already exists' });
        }
        res.status(500).json({ success: false, message: 'Failed to create blog' });
    }
};

/**
 * PUT /api/admin/blogs/:id
 * Admin: update blog
 */
export const updateBlog = async (req, res) => {
    try {
        const { title, excerpt, content, coverImage, author, tags, category, status, seoTitle, seoDescription } = req.body;
        const blog = await Blog.findById(req.params.id);
        if (!blog) return res.status(404).json({ success: false, message: 'Blog not found' });

        // Regenerate slug if title changed
        if (title && title !== blog.title) {
            let baseSlug = slugify(title, { lower: true, strict: true, trim: true });
            let slug = baseSlug;
            let counter = 1;
            while (await Blog.exists({ slug, _id: { $ne: blog._id } })) {
                slug = `${baseSlug}-${counter++}`;
            }
            blog.slug = slug;
        }

        if (title !== undefined) blog.title = title;
        if (excerpt !== undefined) blog.excerpt = excerpt;
        if (content !== undefined) blog.content = content;
        if (coverImage !== undefined) blog.coverImage = coverImage;
        if (author !== undefined) blog.author = author;
        if (tags !== undefined) blog.tags = tags;
        if (category !== undefined) blog.category = category;
        if (status !== undefined) blog.status = status;
        if (seoTitle !== undefined) blog.seoTitle = seoTitle;
        if (seoDescription !== undefined) blog.seoDescription = seoDescription;

        await blog.save();
        res.json({ success: true, data: blog, message: 'Blog updated successfully' });
    } catch (err) {
        console.error('updateBlog error:', err);
        res.status(500).json({ success: false, message: 'Failed to update blog' });
    }
};

/**
 * PATCH /api/admin/blogs/:id/publish
 */
export const publishBlog = async (req, res) => {
    try {
        const blog = await Blog.findByIdAndUpdate(
            req.params.id,
            { status: 'published', publishedAt: new Date() },
            { new: true }
        );
        if (!blog) return res.status(404).json({ success: false, message: 'Blog not found' });
        res.json({ success: true, data: blog, message: 'Blog published' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to publish blog' });
    }
};

/**
 * PATCH /api/admin/blogs/:id/unpublish
 */
export const unpublishBlog = async (req, res) => {
    try {
        const blog = await Blog.findByIdAndUpdate(
            req.params.id,
            { status: 'draft' },
            { new: true }
        );
        if (!blog) return res.status(404).json({ success: false, message: 'Blog not found' });
        res.json({ success: true, data: blog, message: 'Blog moved to draft' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to unpublish blog' });
    }
};

/**
 * DELETE /api/admin/blogs/:id
 */
export const deleteBlog = async (req, res) => {
    try {
        const blog = await Blog.findByIdAndDelete(req.params.id);
        if (!blog) return res.status(404).json({ success: false, message: 'Blog not found' });
        res.json({ success: true, message: 'Blog deleted successfully' });
    } catch (err) {
        res.status(500).json({ success: false, message: 'Failed to delete blog' });
    }
};
