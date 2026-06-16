'use client';
import { useState } from 'react';
import Image from 'next/image';
import Link from 'next/link';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import TableOfContents from '../../../components/Blog/TableOfContents';
import BlogCard from '../../../components/Blog/BlogCard';
import {
    FiCalendar, FiClock, FiEye, FiTag, FiChevronRight,
    FiTwitter, FiLinkedin, FiLink, FiArrowLeft,
} from 'react-icons/fi';
import { FaWhatsapp } from 'react-icons/fa';
import { toast } from 'react-toastify';

const CATEGORY_COLORS = {
    'Buyer Guide': 'bg-blue-50 text-blue-600',
    'Seller Guide': 'bg-emerald-50 text-emerald-600',
    'Market Trends': 'bg-violet-50 text-violet-600',
    'Legal': 'bg-amber-50 text-amber-700',
    'Finance': 'bg-cyan-50 text-cyan-700',
    'Vastu & Design': 'bg-rose-50 text-rose-600',
    'News': 'bg-gray-100 text-gray-600',
};

export default function BlogPostContent({ blog, related }) {
    const [copied, setCopied] = useState(false);

    const formattedDate = blog.publishedAt
        ? new Date(blog.publishedAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' })
        : '';

    const categoryColor = CATEGORY_COLORS[blog.category] || 'bg-gray-100 text-gray-600';
    const pageUrl = typeof window !== 'undefined' ? window.location.href : `https://dealdirect.in/blog/${blog.slug}`;
    const encodedUrl = encodeURIComponent(pageUrl);
    const encodedTitle = encodeURIComponent(blog.title);

    const handleCopyLink = async () => {
        try {
            await navigator.clipboard.writeText(pageUrl);
            setCopied(true);
            toast.success('Link copied!');
            setTimeout(() => setCopied(false), 2000);
        } catch {
            toast.error('Failed to copy link');
        }
    };

    return (
        <div className="min-h-screen bg-white">
            {/* Cover Image */}
            {blog.coverImage && (
                <div className="relative h-56 md:h-[420px] w-full bg-gray-100 overflow-hidden">
                    <Image
                        src={blog.coverImage}
                        alt={blog.title}
                        fill
                        className="object-cover"
                        priority
                    />
                    <div className="absolute inset-0 bg-gradient-to-t from-black/40 via-transparent to-transparent" />
                </div>
            )}

            <div className="max-w-7xl mx-auto px-4 py-8 md:py-12">
                {/* Back */}
                <Link href="/blog" className="inline-flex items-center gap-2 text-gray-400 hover:text-gray-700 text-sm font-medium mb-8 transition-colors">
                    <FiArrowLeft className="w-4 h-4" />
                    Back to Blog
                </Link>

                <div className="flex flex-col lg:flex-row gap-12">
                    {/* Main Article */}
                    <main className="flex-1 min-w-0">
                        {/* Meta */}
                        <div className="mb-5 flex flex-wrap items-center gap-3">
                            <span className={`text-[11px] font-semibold px-3 py-1 rounded-md uppercase tracking-wider ${categoryColor}`}>
                                {blog.category}
                            </span>
                            <span className="flex items-center gap-1.5 text-gray-400 text-sm"><FiCalendar className="w-3.5 h-3.5" />{formattedDate}</span>
                            <span className="flex items-center gap-1.5 text-gray-400 text-sm"><FiClock className="w-3.5 h-3.5" />{blog.readTime} min read</span>
                            <span className="flex items-center gap-1.5 text-gray-400 text-sm"><FiEye className="w-3.5 h-3.5" />{blog.views?.toLocaleString()} views</span>
                        </div>

                        {/* Title */}
                        <h1 className="text-3xl md:text-4xl font-extrabold text-gray-900 mb-5 leading-tight tracking-tight">
                            {blog.title}
                        </h1>

                        {/* Excerpt */}
                        <p className="text-lg text-gray-500 mb-8 border-l-[3px] border-blue-500 pl-5 leading-relaxed">
                            {blog.excerpt}
                        </p>

                        {/* Author */}
                        <div className="flex items-center gap-3 mb-10 pb-8 border-b border-gray-100">
                            <div className="w-10 h-10 bg-gray-900 rounded-full flex items-center justify-center text-white font-semibold text-sm flex-shrink-0">
                                {blog.author?.charAt(0) || 'D'}
                            </div>
                            <div>
                                <p className="font-semibold text-gray-800 text-sm">{blog.author}</p>
                                <p className="text-xs text-gray-400">DealDirect Editorial Team</p>
                            </div>
                        </div>

                        {/* Article Content */}
                        <article
                            id="blog-content"
                            className="prose prose-lg max-w-none
                prose-headings:font-bold prose-headings:text-gray-900 prose-headings:scroll-mt-24
                prose-h2:text-2xl prose-h2:mt-10 prose-h2:mb-4 prose-h3:text-xl prose-h3:mt-6
                prose-p:text-gray-600 prose-p:leading-relaxed
                prose-a:text-blue-600 prose-a:no-underline hover:prose-a:underline prose-a:font-medium
                prose-strong:text-gray-800
                prose-code:bg-gray-50 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-sm prose-code:text-gray-700 prose-code:border prose-code:border-gray-200
                prose-pre:bg-gray-900 prose-pre:text-gray-100
                prose-blockquote:border-l-blue-500 prose-blockquote:bg-gray-50 prose-blockquote:py-1 prose-blockquote:rounded-r-xl prose-blockquote:text-gray-600
                prose-img:rounded-xl
                prose-ul:list-disc prose-ol:list-decimal
                prose-li:text-gray-600
                prose-table:text-sm prose-th:bg-gray-50 prose-th:font-semibold prose-td:border-gray-100"
                        >
                            <ReactMarkdown remarkPlugins={[remarkGfm]}>
                                {blog.content}
                            </ReactMarkdown>
                        </article>

                        {/* Tags */}
                        {blog.tags?.length > 0 && (
                            <div className="mt-12 pt-8 border-t border-gray-100">
                                <h3 className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-4">
                                    <FiTag className="w-3.5 h-3.5" />Tags
                                </h3>
                                <div className="flex flex-wrap gap-2">
                                    {blog.tags.map((tag) => (
                                        <Link
                                            key={tag}
                                            href={`/blog?tag=${encodeURIComponent(tag)}`}
                                            className="bg-gray-50 hover:bg-gray-100 text-gray-500 hover:text-gray-700 text-xs font-medium px-3 py-1.5 rounded-lg transition-colors border border-gray-100"
                                        >
                                            {tag}
                                        </Link>
                                    ))}
                                </div>
                            </div>
                        )}

                        {/* Share */}
                        <div className="mt-10 p-6 bg-gray-50 rounded-2xl border border-gray-100">
                            <h3 className="font-semibold text-gray-800 text-sm mb-4">Share this article</h3>
                            <div className="flex flex-wrap gap-2.5">
                                <a
                                    href={`https://api.whatsapp.com/send?text=${encodedTitle}%20${encodedUrl}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 bg-[#25D366] hover:bg-[#1da851] text-white px-4 py-2.5 rounded-xl text-xs font-semibold transition-colors"
                                >
                                    <FaWhatsapp className="w-4 h-4" />WhatsApp
                                </a>
                                <a
                                    href={`https://twitter.com/intent/tweet?text=${encodedTitle}&url=${encodedUrl}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 bg-gray-900 hover:bg-black text-white px-4 py-2.5 rounded-xl text-xs font-semibold transition-colors"
                                >
                                    <FiTwitter className="w-4 h-4" />Twitter
                                </a>
                                <a
                                    href={`https://www.linkedin.com/sharing/share-offsite/?url=${encodedUrl}`}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="flex items-center gap-2 bg-[#0A66C2] hover:bg-[#004182] text-white px-4 py-2.5 rounded-xl text-xs font-semibold transition-colors"
                                >
                                    <FiLinkedin className="w-4 h-4" />LinkedIn
                                </a>
                                <button
                                    onClick={handleCopyLink}
                                    className="flex items-center gap-2 bg-white hover:bg-gray-100 text-gray-700 border border-gray-200 px-4 py-2.5 rounded-xl text-xs font-semibold transition-colors"
                                >
                                    <FiLink className="w-4 h-4" />{copied ? 'Copied!' : 'Copy link'}
                                </button>
                            </div>
                        </div>
                    </main>

                    {/* Sidebar */}
                    <aside className="lg:w-72 xl:w-80 flex-shrink-0 space-y-6">
                        <TableOfContents content={blog.content} />

                        {/* CTA */}
                        <div className="bg-gray-900 text-white rounded-2xl p-6 text-center">
                            <h3 className="font-bold text-lg mb-2">Find Your Dream Property</h3>
                            <p className="text-gray-400 text-sm mb-5 leading-relaxed">Browse thousands of listings directly from owners. No brokerage.</p>
                            <Link
                                href="/properties"
                                className="inline-flex items-center gap-1.5 bg-white text-gray-900 font-semibold px-5 py-2.5 rounded-xl text-sm hover:bg-gray-100 transition-colors"
                            >
                                Browse Properties <FiChevronRight className="w-4 h-4" />
                            </Link>
                        </div>
                    </aside>
                </div>

                {/* Related Posts */}
                {related?.length > 0 && (
                    <section className="mt-20 pt-12 border-t border-gray-100">
                        <h2 className="text-2xl font-bold text-gray-900 mb-8">Related Articles</h2>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-7">
                            {related.map((post) => (
                                <BlogCard key={post._id} post={post} />
                            ))}
                        </div>
                    </section>
                )}
            </div>
        </div>
    );
}
