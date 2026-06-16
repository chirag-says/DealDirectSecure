'use client';
import { useState, useEffect, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import BlogCard from '../../components/Blog/BlogCard';
import { FiSearch, FiFileText } from 'react-icons/fi';


const CATEGORIES = ['All', 'Buyer Guide', 'Seller Guide', 'Market Trends', 'Legal', 'Finance', 'Vastu & Design', 'News'];
const API_BASE = process.env.NEXT_PUBLIC_API_BASE || 'http://localhost:9000';

export default function BlogListContent({ initialPosts = [], initialPagination = { page: 1, pages: 1, total: 0 } }) {
    const searchParams = useSearchParams();
    const router = useRouter();

    const [posts, setPosts] = useState(initialPosts);
    const [loading, setLoading] = useState(false);
    const [pagination, setPagination] = useState(initialPagination);
    const [activeCategory, setActiveCategory] = useState(searchParams.get('category') || 'All');
    const [search, setSearch] = useState('');
    const [page, setPage] = useState(1);
    const [hasUserInteracted, setHasUserInteracted] = useState(false);

    const fetchPosts = useCallback(async () => {
        setLoading(true);
        try {
            const params = new URLSearchParams({ page, limit: 9 });
            if (activeCategory !== 'All') params.set('category', activeCategory);
            if (search.trim()) params.set('q', search.trim());
            const res = await fetch(`${API_BASE}/api/blogs?${params}`);
            const data = await res.json();
            if (data.success) {
                setPosts(data.data);
                setPagination(data.pagination);
            }
        } catch (err) {
            console.error('Failed to fetch blogs:', err);
        } finally {
            setLoading(false);
        }
    }, [page, activeCategory, search]);

    // Only re-fetch after user changes filters/page, not on initial mount
    useEffect(() => {
        if (hasUserInteracted) {
            fetchPosts();
        }
    }, [fetchPosts, hasUserInteracted]);

    const handleCategoryChange = (cat) => {
        setActiveCategory(cat);
        setPage(1);
        setHasUserInteracted(true);
    };

    return (
        <div className="min-h-screen bg-white">
            {/* Clean Hero Header */}
            <section className="bg-white border-b border-gray-100 pt-12 pb-10 px-4">
                <div className="max-w-4xl mx-auto text-center">
                    <p className="text-xs font-semibold uppercase tracking-[0.2em] text-gray-400 mb-4">
                        DealDirect Blog
                    </p>
                    <h1 className="text-3xl md:text-5xl font-extrabold text-gray-900 mb-4 leading-tight tracking-tight">
                        Real Estate Guides &
                        <span className="text-blue-600"> Market Insights</span>
                    </h1>
                    <p className="text-gray-500 text-base md:text-lg max-w-xl mx-auto mb-8 leading-relaxed">
                        Expert tips on buying, selling, and renting property in India — no brokerage, just knowledge.
                    </p>

                    {/* Search */}
                    <div className="relative max-w-md mx-auto">
                        <FiSearch className="absolute left-4 top-1/2 -translate-y-1/2 text-gray-400 w-4 h-4" />
                        <input
                            type="text"
                            placeholder="Search guides, tips, topics..."
                            value={search}
                            onChange={(e) => { setSearch(e.target.value); setPage(1); setHasUserInteracted(true); }}
                            className="w-full pl-11 pr-4 py-3 bg-gray-50 border border-gray-200 rounded-xl text-gray-800 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm transition-all"
                        />
                    </div>
                </div>
            </section>

            {/* Category Tabs */}
            <div className="bg-white border-b border-gray-100 sticky top-0 z-10">
                <div className="max-w-7xl mx-auto px-4">
                    <div className="flex gap-1 overflow-x-auto py-3 scrollbar-hide">
                        {CATEGORIES.map((cat) => (
                            <button
                                key={cat}
                                onClick={() => handleCategoryChange(cat)}
                                className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition-all flex-shrink-0 ${activeCategory === cat
                                    ? 'bg-gray-900 text-white'
                                    : 'text-gray-500 hover:text-gray-900 hover:bg-gray-50'
                                    }`}
                            >
                                {cat}
                            </button>
                        ))}
                    </div>
                </div>
            </div>

            {/* Blog Grid */}
            <div className="max-w-7xl mx-auto px-4 py-12">
                {loading ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                        {[...Array(9)].map((_, i) => (
                            <div key={i} className="bg-white rounded-2xl overflow-hidden border border-gray-100 animate-pulse">
                                <div className="h-48 bg-gray-100" />
                                <div className="p-5 space-y-3">
                                    <div className="h-5 bg-gray-100 rounded w-3/4" />
                                    <div className="h-4 bg-gray-100 rounded w-full" />
                                    <div className="h-4 bg-gray-100 rounded w-5/6" />
                                </div>
                            </div>
                        ))}
                    </div>
                ) : posts.length === 0 ? (
                    <div className="text-center py-24">
                        <div className="w-16 h-16 bg-gray-50 rounded-2xl flex items-center justify-center mx-auto mb-5">
                            <FiFileText className="w-7 h-7 text-gray-300" />
                        </div>
                        <h2 className="text-xl font-bold text-gray-800 mb-2">No posts found</h2>
                        <p className="text-gray-400 text-sm">Try adjusting your search or category filter.</p>
                    </div>
                ) : (
                    <>
                        {/* Featured top card */}
                        {page === 1 && posts[0] && activeCategory === 'All' && !search && (
                            <div className="mb-10">
                                <BlogCard post={posts[0]} featured />
                            </div>
                        )}

                        {/* Grid */}
                        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-7">
                            {(page === 1 && activeCategory === 'All' && !search ? posts.slice(1) : posts).map((post) => (
                                <BlogCard key={post._id} post={post} />
                            ))}
                        </div>

                        {/* Pagination */}
                        {pagination.pages > 1 && (
                            <div className="flex items-center justify-center gap-2 mt-14">
                                <button
                                    onClick={() => { setPage((p) => p - 1); setHasUserInteracted(true); }}
                                    disabled={page === 1}
                                    className="px-5 py-2.5 rounded-lg border border-gray-200 text-sm font-medium disabled:opacity-30 hover:bg-gray-50 transition-colors text-gray-700"
                                >
                                    Previous
                                </button>
                                <span className="text-sm text-gray-400 px-4">
                                    {pagination.page} / {pagination.pages}
                                </span>
                                <button
                                    onClick={() => { setPage((p) => p + 1); setHasUserInteracted(true); }}
                                    disabled={page === pagination.pages}
                                    className="px-5 py-2.5 rounded-lg border border-gray-200 text-sm font-medium disabled:opacity-30 hover:bg-gray-50 transition-colors text-gray-700"
                                >
                                    Next
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}
