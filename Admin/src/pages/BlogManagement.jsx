import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
    FileText,
    Plus,
    Search,
    Filter,
    Edit,
    Trash2,
    Eye,
    EyeOff,
    RefreshCw,
    Calendar,
    Tag,
} from "lucide-react";
import { toast } from "react-toastify";
import { blogManagementApi } from "../api/adminApi";

const BlogManagement = () => {
    const navigate = useNavigate();
    const [blogs, setBlogs] = useState([]);
    const [loading, setLoading] = useState(true);
    const [searchTerm, setSearchTerm] = useState("");
    const [statusFilter, setStatusFilter] = useState("all");

    const fetchBlogs = async () => {
        setLoading(true);
        try {
            const params = {};
            if (statusFilter !== "all") params.status = statusFilter;
            if (searchTerm.trim()) params.q = searchTerm.trim();

            const res = await blogManagementApi.getAll(params);
            setBlogs(res.data || []);
        } catch (err) {
            console.error(err);
            toast.error("Failed to fetch blogs");
        }
        setLoading(false);
    };

    useEffect(() => {
        fetchBlogs();
    }, [statusFilter]);

    const handleKeyDown = (e) => {
        if (e.key === "Enter") fetchBlogs();
    };

    const handleDelete = async (id, title) => {
        if (!window.confirm(`Delete "${title}"? This cannot be undone.`)) return;
        try {
            await blogManagementApi.delete(id);
            toast.success("Blog deleted");
            setBlogs((prev) => prev.filter((b) => b._id !== id));
        } catch (err) {
            toast.error("Failed to delete blog");
        }
    };

    const handlePublish = async (id) => {
        try {
            await blogManagementApi.publish(id);
            toast.success("Blog published");
            fetchBlogs();
        } catch (err) {
            toast.error("Failed to publish");
        }
    };

    const handleUnpublish = async (id) => {
        try {
            await blogManagementApi.unpublish(id);
            toast.success("Blog unpublished");
            fetchBlogs();
        } catch (err) {
            toast.error("Failed to unpublish");
        }
    };

    const formatDate = (d) =>
        d ? new Date(d).toLocaleDateString("en-IN", { day: "numeric", month: "short", year: "numeric" }) : "—";

    return (
        <div className="p-2 sm:p-4 bg-gray-50 min-h-screen">
            {/* Header */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-6 gap-4">
                <h2 className="text-3xl font-extrabold text-gray-900 flex items-center gap-2">
                    <FileText className="w-8 h-8 text-indigo-600" /> Blog Management
                </h2>
                <button
                    onClick={() => navigate("/blog-editor")}
                    className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2.5 rounded-lg font-semibold text-sm transition shadow-md"
                >
                    <Plus className="w-4 h-4" /> New Blog Post
                </button>
            </div>

            {/* Filters */}
            <div className="bg-white p-4 rounded-xl shadow-sm border border-gray-200 grid grid-cols-1 md:grid-cols-12 gap-4 items-end mb-6">
                <div className="md:col-span-5">
                    <label className="block text-xs font-bold text-gray-500 mb-1">SEARCH</label>
                    <div className="relative">
                        <Search className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                        <input
                            type="text"
                            placeholder="Search by title, content, tags..."
                            value={searchTerm}
                            onChange={(e) => setSearchTerm(e.target.value)}
                            onKeyDown={handleKeyDown}
                            className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm"
                        />
                    </div>
                </div>

                <div className="md:col-span-3">
                    <label className="block text-xs font-bold text-gray-500 mb-1">STATUS</label>
                    <div className="relative">
                        <Filter className="absolute left-3 top-2.5 w-4 h-4 text-gray-400" />
                        <select
                            value={statusFilter}
                            onChange={(e) => setStatusFilter(e.target.value)}
                            className="w-full pl-9 pr-3 py-2 border rounded-lg focus:ring-2 focus:ring-indigo-500 outline-none text-sm bg-white"
                        >
                            <option value="all">All Posts</option>
                            <option value="published">Published</option>
                            <option value="draft">Drafts</option>
                        </select>
                    </div>
                </div>

                <div className="md:col-span-4 flex gap-2">
                    <button
                        onClick={fetchBlogs}
                        className="flex-1 bg-indigo-600 hover:bg-indigo-700 text-white py-2 rounded-lg font-semibold text-sm transition"
                    >
                        Search
                    </button>
                    <button
                        onClick={() => {
                            setSearchTerm("");
                            setStatusFilter("all");
                            setTimeout(() => fetchBlogs(), 100);
                        }}
                        className="px-3 bg-gray-100 hover:bg-gray-200 text-gray-600 rounded-lg transition"
                    >
                        <RefreshCw className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* Blog Table */}
            <div className="bg-white rounded-xl shadow-sm border border-gray-200 overflow-hidden">
                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead className="bg-gray-50 border-b border-gray-200">
                            <tr>
                                <th className="text-left px-5 py-3 text-xs font-bold text-gray-500 uppercase">Title</th>
                                <th className="text-left px-5 py-3 text-xs font-bold text-gray-500 uppercase hidden md:table-cell">Category</th>
                                <th className="text-left px-5 py-3 text-xs font-bold text-gray-500 uppercase hidden lg:table-cell">Author</th>
                                <th className="text-center px-5 py-3 text-xs font-bold text-gray-500 uppercase">Status</th>
                                <th className="text-left px-5 py-3 text-xs font-bold text-gray-500 uppercase hidden lg:table-cell">Date</th>
                                <th className="text-center px-5 py-3 text-xs font-bold text-gray-500 uppercase">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-gray-100">
                            {loading && (
                                <tr>
                                    <td colSpan={6} className="text-center py-12 text-gray-400">
                                        Loading blogs...
                                    </td>
                                </tr>
                            )}

                            {!loading && blogs.length === 0 && (
                                <tr>
                                    <td colSpan={6} className="text-center py-16">
                                        <FileText className="w-12 h-12 text-gray-200 mx-auto mb-3" />
                                        <p className="text-gray-500 font-medium">No blog posts found</p>
                                        <p className="text-gray-400 text-xs mt-1">Click "New Blog Post" to get started</p>
                                    </td>
                                </tr>
                            )}

                            {!loading &&
                                blogs.map((blog) => (
                                    <tr key={blog._id} className="hover:bg-gray-50 transition-colors">
                                        {/* Title */}
                                        <td className="px-5 py-4">
                                            <div className="flex items-start gap-3">
                                                {blog.coverImage ? (
                                                    <img
                                                        src={blog.coverImage}
                                                        alt=""
                                                        className="w-12 h-12 rounded-lg object-cover flex-shrink-0 hidden sm:block"
                                                    />
                                                ) : (
                                                    <div className="w-12 h-12 rounded-lg bg-indigo-50 flex items-center justify-center flex-shrink-0 hidden sm:flex">
                                                        <FileText className="w-5 h-5 text-indigo-400" />
                                                    </div>
                                                )}
                                                <div className="min-w-0">
                                                    <p className="font-semibold text-gray-900 truncate max-w-xs">{blog.title}</p>
                                                    <p className="text-xs text-gray-400 truncate max-w-xs mt-0.5">{blog.excerpt}</p>
                                                    {blog.tags?.length > 0 && (
                                                        <div className="flex gap-1 mt-1.5 flex-wrap">
                                                            {blog.tags.slice(0, 3).map((tag) => (
                                                                <span key={tag} className="inline-flex items-center gap-0.5 text-[10px] bg-gray-100 text-gray-500 px-1.5 py-0.5 rounded-full">
                                                                    <Tag className="w-2.5 h-2.5" />{tag}
                                                                </span>
                                                            ))}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </td>

                                        {/* Category */}
                                        <td className="px-5 py-4 text-gray-600 hidden md:table-cell">
                                            <span className="bg-indigo-50 text-indigo-600 text-xs font-medium px-2 py-1 rounded-full">
                                                {blog.category || "—"}
                                            </span>
                                        </td>

                                        {/* Author */}
                                        <td className="px-5 py-4 text-gray-600 text-xs hidden lg:table-cell">{blog.author || "—"}</td>

                                        {/* Status */}
                                        <td className="px-5 py-4 text-center">
                                            <span
                                                className={`inline-block text-xs font-bold px-2.5 py-1 rounded-full ${blog.status === "published"
                                                    ? "bg-green-100 text-green-700"
                                                    : "bg-yellow-100 text-yellow-700"
                                                    }`}
                                            >
                                                {blog.status === "published" ? "Published" : "Draft"}
                                            </span>
                                        </td>

                                        {/* Date */}
                                        <td className="px-5 py-4 text-gray-500 text-xs hidden lg:table-cell">
                                            <div className="flex items-center gap-1">
                                                <Calendar className="w-3 h-3" />
                                                {formatDate(blog.publishedAt || blog.createdAt)}
                                            </div>
                                        </td>

                                        {/* Actions */}
                                        <td className="px-5 py-4">
                                            <div className="flex items-center justify-center gap-1.5">
                                                <button
                                                    onClick={() => navigate(`/blog-editor/${blog._id}`)}
                                                    className="p-2 rounded-lg text-gray-500 hover:text-indigo-600 hover:bg-indigo-50 transition"
                                                    title="Edit"
                                                >
                                                    <Edit className="w-4 h-4" />
                                                </button>

                                                {blog.status === "draft" ? (
                                                    <button
                                                        onClick={() => handlePublish(blog._id)}
                                                        className="p-2 rounded-lg text-gray-500 hover:text-green-600 hover:bg-green-50 transition"
                                                        title="Publish"
                                                    >
                                                        <Eye className="w-4 h-4" />
                                                    </button>
                                                ) : (
                                                    <button
                                                        onClick={() => handleUnpublish(blog._id)}
                                                        className="p-2 rounded-lg text-gray-500 hover:text-yellow-600 hover:bg-yellow-50 transition"
                                                        title="Unpublish"
                                                    >
                                                        <EyeOff className="w-4 h-4" />
                                                    </button>
                                                )}

                                                <button
                                                    onClick={() => handleDelete(blog._id, blog.title)}
                                                    className="p-2 rounded-lg text-gray-500 hover:text-red-600 hover:bg-red-50 transition"
                                                    title="Delete"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
};

export default BlogManagement;
