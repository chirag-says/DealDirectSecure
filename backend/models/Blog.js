/**
 * Blog Model — DealDirect
 * Admin-managed blog posts for SEO
 */
import mongoose from 'mongoose';

const blogSchema = new mongoose.Schema(
    {
        title: {
            type: String,
            required: [true, 'Blog title is required'],
            trim: true,
            maxlength: [200, 'Title cannot exceed 200 characters'],
        },
        slug: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true,
            index: true,
        },
        excerpt: {
            type: String,
            required: [true, 'Excerpt is required for SEO'],
            trim: true,
            maxlength: [300, 'Excerpt cannot exceed 300 characters'],
        },
        content: {
            type: String,
            required: [true, 'Blog content is required'],
        },
        coverImage: {
            type: String,
            default: null,
        },
        author: {
            type: String,
            default: 'DealDirect Team',
            trim: true,
        },
        tags: {
            type: [String],
            default: [],
            index: true,
        },
        category: {
            type: String,
            enum: ['Buyer Guide', 'Seller Guide', 'Market Trends', 'Legal', 'Finance', 'Vastu & Design', 'News'],
            default: 'Buyer Guide',
            index: true,
        },
        status: {
            type: String,
            enum: ['draft', 'published'],
            default: 'draft',
            index: true,
        },
        publishedAt: {
            type: Date,
            default: null,
            index: true,
        },
        readTime: {
            type: Number, // minutes
            default: 1,
        },
        views: {
            type: Number,
            default: 0,
        },
        // SEO overrides
        seoTitle: {
            type: String,
            trim: true,
            maxlength: [70, 'SEO title cannot exceed 70 characters'],
            default: null,
        },
        seoDescription: {
            type: String,
            trim: true,
            maxlength: [160, 'SEO description cannot exceed 160 characters'],
            default: null,
        },
    },
    {
        timestamps: true,
    }
);

// Auto-calculate readTime before save (avg 200 wpm)
blogSchema.pre('save', function (next) {
    if (this.isModified('content')) {
        const wordCount = this.content.replace(/<[^>]+>/g, '').split(/\s+/).filter(Boolean).length;
        this.readTime = Math.max(1, Math.ceil(wordCount / 200));
    }
    // Set publishedAt when first published
    if (this.isModified('status') && this.status === 'published' && !this.publishedAt) {
        this.publishedAt = new Date();
    }
    next();
});

// Compound index for public listing queries
blogSchema.index({ status: 1, publishedAt: -1 });
blogSchema.index({ status: 1, category: 1, publishedAt: -1 });
// Text index for search
blogSchema.index({ title: 'text', excerpt: 'text', content: 'text', tags: 'text', category: 'text' });


const Blog = mongoose.model('Blog', blogSchema);
export default Blog;
