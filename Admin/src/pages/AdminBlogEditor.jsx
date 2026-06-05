import React, { useState, useEffect } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
    ArrowLeft,
    Save,
    Send,
    ChevronDown,
    ChevronUp,
    Search,
    BookOpen,
    FileText,
    Image as ImageIcon,
} from "lucide-react";
import { toast } from "react-toastify";
import { blogManagementApi } from "../api/adminApi";

const CATEGORIES = [
    "Buyer Guide",
    "Seller Guide",
    "Market Trends",
    "Legal",
    "Finance",
    "Vastu & Design",
    "News",
];

const EMPTY_FORM = {
    title: "",
    excerpt: "",
    content: "",
    coverImage: "",
    author: "DealDirect Team",
    tags: "",
    category: "Buyer Guide",
    status: "draft",
    seoTitle: "",
    seoDescription: "",
};

const AdminBlogEditor = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const isEditing = !!id;

    const [form, setForm] = useState(EMPTY_FORM);
    const [loading, setLoading] = useState(isEditing);
    const [saving, setSaving] = useState(false);
    const [showSeo, setShowSeo] = useState(false);
    const [preview, setPreview] = useState(false);

    useEffect(() => {
        if (!isEditing) return;
        const load = async () => {
            try {
                const res = await blogManagementApi.getById(id);
                if (res.success) {
                    const b = res.data;
                    setForm({
                        title: b.title || "",
                        excerpt: b.excerpt || "",
                        content: b.content || "",
                        coverImage: b.coverImage || "",
                        author: b.author || "DealDirect Team",
                        tags: b.tags?.join(", ") || "",
                        category: b.category || "Buyer Guide",
                        status: b.status || "draft",
                        seoTitle: b.seoTitle || "",
                        seoDescription: b.seoDescription || "",
                    });
                }
            } catch {
                toast.error("Failed to load blog post");
                navigate("/blog-management");
            } finally {
                setLoading(false);
            }
        };
        load();
    }, [id, isEditing, navigate]);

    const handleChange = (field, value) => {
        setForm((prev) => ({ ...prev, [field]: value }));
    };

    const buildPayload = (statusOverride) => ({
        ...form,
        status: statusOverride || form.status,
        tags: form.tags
            .split(",")
            .map((t) => t.trim())
            .filter(Boolean),
        seoTitle: form.seoTitle || undefined,
        seoDescription: form.seoDescription || undefined,
    });

    const handleSave = async (statusOverride) => {
        if (!form.title.trim()) {
            toast.error("Title is required");
            return;
        }
        if (!form.excerpt.trim()) {
            toast.error("Excerpt is required for SEO");
            return;
        }
        if (!form.content.trim()) {
            toast.error("Content cannot be empty");
            return;
        }

        setSaving(true);
        try {
            const payload = buildPayload(statusOverride);
            if (isEditing) {
                await blogManagementApi.update(id, payload);
                toast.success("Blog updated!");
            } else {
                const res = await blogManagementApi.create(payload);
                toast.success(
                    statusOverride === "published"
                        ? "Blog published!"
                        : "Saved as draft!"
                );
                navigate(`/blog-editor/${res.data._id}`, { replace: true });
            }
        } catch (err) {
            toast.error(
                err?.response?.data?.message || "Failed to save blog"
            );
        } finally {
            setSaving(false);
        }
    };

    // SEO preview
    const seoPreviewTitle = form.seoTitle || form.title || "Your blog title...";
    const seoPreviewDesc =
        form.seoDescription || form.excerpt || "Your excerpt will appear here...";
    const titleLen = (form.seoTitle || form.title).length;
    const descLen = (form.seoDescription || form.excerpt).length;

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <div className="text-gray-500 animate-pulse">
                    Loading blog editor...
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-[calc(100vh-120px)]">
            {/* Top Bar */}
            <div className="bg-white border-b border-gray-200 sticky top-0 z-20 shadow-sm -mx-4 sm:-mx-6 -mt-4 sm:-mt-6 px-4 sm:px-6">
                <div className="max-w-7xl mx-auto py-3 flex items-center justify-between gap-4">
                    <div className="flex items-center gap-4">
                        <button
                            onClick={() => navigate("/blog-management")}
                            className="flex items-center gap-1 text-gray-500 hover:text-gray-800 text-sm transition-colors"
                        >
                            <ArrowLeft className="w-4 h-4" /> Back
                        </button>
                        <span className="text-gray-300">|</span>
                        <h1 className="font-bold text-gray-900 text-sm md:text-base">
                            {isEditing ? "Edit Blog Post" : "New Blog Post"}
                        </h1>
                    </div>
                    <div className="flex items-center gap-2">
                        <span
                            className={`text-xs font-semibold px-2.5 py-1 rounded-full hidden sm:inline-flex ${form.status === "published"
                                    ? "bg-green-100 text-green-700"
                                    : "bg-yellow-100 text-yellow-700"
                                }`}
                        >
                            {form.status === "published" ? "Published" : "Draft"}
                        </span>
                        <button
                            onClick={() => handleSave("draft")}
                            disabled={saving}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-gray-300 text-sm font-medium text-gray-700 hover:bg-gray-50 transition-colors disabled:opacity-60"
                        >
                            <Save className="w-4 h-4" />
                            {saving ? "Saving..." : "Save Draft"}
                        </button>
                        <button
                            onClick={() => handleSave("published")}
                            disabled={saving}
                            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-700 text-white text-sm font-semibold transition-colors disabled:opacity-60 shadow-md"
                        >
                            <Send className="w-4 h-4" />
                            {saving ? "Publishing..." : "Publish"}
                        </button>
                    </div>
                </div>
            </div>

            <div className="max-w-7xl mx-auto py-8 flex flex-col lg:flex-row gap-8">
                {/* Editor Column */}
                <div className="flex-1 min-w-0 space-y-6">
                    {/* Title */}
                    <div>
                        <input
                            type="text"
                            placeholder="Blog post title..."
                            value={form.title}
                            onChange={(e) =>
                                handleChange("title", e.target.value)
                            }
                            className="w-full text-3xl font-extrabold text-gray-900 bg-transparent border-0 border-b-2 border-gray-200 focus:border-indigo-500 focus:outline-none pb-3 placeholder-gray-300 transition-colors"
                        />
                    </div>

                    {/* Excerpt */}
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                            Excerpt (shown in listings + SEO)
                        </label>
                        <textarea
                            placeholder="A brief compelling summary of this post..."
                            value={form.excerpt}
                            onChange={(e) =>
                                handleChange("excerpt", e.target.value)
                            }
                            rows={3}
                            maxLength={300}
                            className="w-full text-gray-700 bg-white border border-gray-200 rounded-xl px-4 py-3 resize-none focus:outline-none focus:ring-2 focus:ring-indigo-400 text-sm"
                        />
                        <p
                            className={`text-xs mt-1 text-right ${form.excerpt.length > 260
                                    ? "text-orange-500"
                                    : "text-gray-400"
                                }`}
                        >
                            {form.excerpt.length}/300 chars
                        </p>
                    </div>

                    {/* Cover Image URL */}
                    <div>
                        <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide mb-2">
                            Cover Image URL
                        </label>
                        <div className="flex gap-2">
                            <div className="relative flex-1">
                                <ImageIcon className="absolute left-3 top-3 w-4 h-4 text-gray-400" />
                                <input
                                    type="text"
                                    placeholder="https://images.unsplash.com/..."
                                    value={form.coverImage}
                                    onChange={(e) =>
                                        handleChange(
                                            "coverImage",
                                            e.target.value
                                        )
                                    }
                                    className="w-full pl-9 bg-white border border-gray-200 rounded-xl px-4 py-3 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400 text-gray-700"
                                />
                            </div>
                        </div>
                        {form.coverImage && (
                            <div className="mt-3 rounded-xl overflow-hidden border border-gray-200 max-h-48">
                                <img
                                    src={form.coverImage}
                                    alt="Cover preview"
                                    className="w-full h-48 object-cover"
                                    onError={(e) => {
                                        e.target.style.display = "none";
                                    }}
                                />
                            </div>
                        )}
                    </div>

                    {/* Content (Markdown) */}
                    <div>
                        <div className="flex items-center justify-between mb-2">
                            <label className="block text-xs font-semibold text-gray-500 uppercase tracking-wide">
                                Content (Markdown)
                            </label>
                            <button
                                onClick={() => setPreview(!preview)}
                                className="text-xs text-indigo-600 font-medium hover:underline"
                            >
                                {preview ? "Edit" : "Preview"}
                            </button>
                        </div>

                        {preview ? (
                            <div className="bg-white border border-gray-200 rounded-xl p-6 prose prose-sm max-w-none min-h-[400px]">
                                {/* Simple markdown preview - renders raw for now */}
                                <div style={{ whiteSpace: "pre-wrap" }}>
                                    {form.content || "Nothing to preview yet..."}
                                </div>
                            </div>
                        ) : (
                            <textarea
                                placeholder="Write your blog content in Markdown..."
                                value={form.content}
                                onChange={(e) =>
                                    handleChange("content", e.target.value)
                                }
                                rows={20}
                                className="w-full text-gray-700 bg-white border border-gray-200 rounded-xl px-4 py-3 resize-y focus:outline-none focus:ring-2 focus:ring-indigo-400 text-sm font-mono leading-relaxed"
                            />
                        )}
                        <p className="text-xs text-gray-400 mt-1">
                            Supports Markdown: **bold**, *italic*, ## Headings,
                            - lists, [links](url), ![images](url)
                        </p>
                    </div>

                    {/* SEO Panel */}
                    <div className="bg-white rounded-2xl border border-gray-200 overflow-hidden">
                        <button
                            onClick={() => setShowSeo(!showSeo)}
                            className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-gray-50 transition-colors"
                        >
                            <span className="font-semibold text-gray-800 text-sm flex items-center gap-2">
                                <Search className="w-4 h-4 text-gray-500" />
                                SEO Settings
                            </span>
                            {showSeo ? (
                                <ChevronUp className="w-4 h-4 text-gray-400" />
                            ) : (
                                <ChevronDown className="w-4 h-4 text-gray-400" />
                            )}
                        </button>
                        {showSeo && (
                            <div className="px-5 pb-5 space-y-4 border-t border-gray-100 pt-4">
                                {/* Google Preview */}
                                <div className="bg-white border border-gray-200 rounded-xl p-4 mb-2">
                                    <p className="text-xs font-semibold text-gray-400 uppercase mb-3">
                                        Google preview
                                    </p>
                                    <p className="text-[#1a0dab] text-lg font-medium hover:underline cursor-pointer truncate">
                                        {seoPreviewTitle} | DealDirect
                                    </p>
                                    <p className="text-green-700 text-sm mt-0.5">
                                        https://dealdirect.in/blog/
                                        {form.title
                                            ? form.title
                                                .toLowerCase()
                                                .replace(/\s+/g, "-")
                                                .replace(/[^a-z0-9-]/g, "")
                                            : "your-slug"}
                                    </p>
                                    <p className="text-gray-600 text-sm mt-1 line-clamp-2">
                                        {seoPreviewDesc}
                                    </p>
                                </div>

                                <div>
                                    <label className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase mb-1.5">
                                        SEO Title{" "}
                                        <span
                                            className={
                                                titleLen > 60
                                                    ? "text-red-500"
                                                    : "text-gray-400"
                                            }
                                        >
                                            {titleLen}/70
                                        </span>
                                    </label>
                                    <input
                                        type="text"
                                        maxLength={70}
                                        placeholder="Defaults to post title if empty..."
                                        value={form.seoTitle}
                                        onChange={(e) =>
                                            handleChange(
                                                "seoTitle",
                                                e.target.value
                                            )
                                        }
                                        className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400"
                                    />
                                </div>

                                <div>
                                    <label className="flex items-center justify-between text-xs font-semibold text-gray-500 uppercase mb-1.5">
                                        Meta Description{" "}
                                        <span
                                            className={
                                                descLen > 150
                                                    ? "text-red-500"
                                                    : "text-gray-400"
                                            }
                                        >
                                            {descLen}/160
                                        </span>
                                    </label>
                                    <textarea
                                        maxLength={160}
                                        rows={3}
                                        placeholder="Defaults to excerpt if empty..."
                                        value={form.seoDescription}
                                        onChange={(e) =>
                                            handleChange(
                                                "seoDescription",
                                                e.target.value
                                            )
                                        }
                                        className="w-full border border-gray-200 rounded-xl px-4 py-2.5 text-sm resize-none focus:outline-none focus:ring-2 focus:ring-indigo-400"
                                    />
                                </div>
                            </div>
                        )}
                    </div>
                </div>

                {/* Settings Sidebar */}
                <aside className="lg:w-72 xl:w-80 flex-shrink-0 space-y-5">
                    {/* Post Settings */}
                    <div className="bg-white rounded-2xl border border-gray-200 p-5 space-y-4">
                        <h3 className="font-bold text-gray-800 text-sm">
                            Post Settings
                        </h3>

                        <div>
                            <label className="block text-xs font-semibold text-gray-500 uppercase mb-1.5">
                                Category
                            </label>
                            <select
                                value={form.category}
                                onChange={(e) =>
                                    handleChange("category", e.target.value)
                                }
                                className="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white"
                            >
                                {CATEGORIES.map((c) => (
                                    <option key={c}>{c}</option>
                                ))}
                            </select>
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-gray-500 uppercase mb-1.5">
                                Author
                            </label>
                            <input
                                type="text"
                                value={form.author}
                                onChange={(e) =>
                                    handleChange("author", e.target.value)
                                }
                                className="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400"
                            />
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-gray-500 uppercase mb-1.5">
                                Tags (comma-separated)
                            </label>
                            <input
                                type="text"
                                placeholder="real estate, buyer guide, Mumbai..."
                                value={form.tags}
                                onChange={(e) =>
                                    handleChange("tags", e.target.value)
                                }
                                className="w-full border border-gray-200 rounded-xl px-3 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400"
                            />
                        </div>

                        <div className="pt-3 border-t border-gray-100 flex flex-col gap-2">
                            <button
                                onClick={() => handleSave("published")}
                                disabled={saving}
                                className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-semibold py-3 rounded-xl transition-colors flex items-center justify-center gap-2 disabled:opacity-60"
                            >
                                <Send className="w-4 h-4" />
                                {saving ? "Publishing..." : "Publish Now"}
                            </button>
                            <button
                                onClick={() => handleSave("draft")}
                                disabled={saving}
                                className="w-full bg-gray-100 hover:bg-gray-200 text-gray-700 font-medium py-2.5 rounded-xl transition-colors flex items-center justify-center gap-2 disabled:opacity-60 text-sm"
                            >
                                <Save className="w-4 h-4" />
                                Save as Draft
                            </button>
                        </div>
                    </div>

                    {/* Tips */}
                    <div className="bg-indigo-50 border border-indigo-100 rounded-2xl p-5">
                        <h3 className="font-bold text-indigo-800 text-sm mb-3 flex items-center gap-2">
                            <BookOpen className="w-4 h-4" />
                            SEO Writing Tips
                        </h3>
                        <ul className="space-y-2 text-xs text-indigo-700">
                            <li>
                                • Use the target keyword in the title and first
                                paragraph
                            </li>
                            <li>
                                • Aim for 800-1500 words for in-depth guides
                            </li>
                            <li>
                                • Use H2/H3 headings to structure content
                            </li>
                            <li>
                                • Add internal links to property listings
                            </li>
                            <li>• Keep sentences short and scannable</li>
                            <li>
                                • Answer the exact question users are searching
                                for
                            </li>
                        </ul>
                    </div>
                </aside>
            </div>
        </div>
    );
};

export default AdminBlogEditor;
