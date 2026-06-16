import Link from 'next/link';
import Image from 'next/image';
import { FiClock, FiCalendar, FiArrowRight } from 'react-icons/fi';

const CATEGORY_COLORS = {
    'Buyer Guide': 'bg-blue-50 text-blue-600',
    'Seller Guide': 'bg-emerald-50 text-emerald-600',
    'Market Trends': 'bg-violet-50 text-violet-600',
    'Legal': 'bg-amber-50 text-amber-700',
    'Finance': 'bg-cyan-50 text-cyan-700',
    'Vastu & Design': 'bg-rose-50 text-rose-600',
    'News': 'bg-gray-100 text-gray-600',
};

export default function BlogCard({ post, featured = false }) {
    const formattedDate = post.publishedAt
        ? new Date(post.publishedAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })
        : '';

    const categoryColor = CATEGORY_COLORS[post.category] || 'bg-gray-100 text-gray-600';

    if (featured) {
        return (
            <Link href={`/blog/${post.slug}`} className="group block">
                <article className="relative overflow-hidden rounded-2xl bg-white border border-gray-100 hover:border-gray-200 transition-all duration-300 flex flex-col md:flex-row h-full">
                    {/* Cover */}
                    <div className="relative w-full md:w-[55%] h-64 md:h-[360px] overflow-hidden flex-shrink-0 bg-gray-100">
                        {post.coverImage ? (
                            <Image
                                src={post.coverImage}
                                alt={post.title}
                                fill
                                className="object-cover group-hover:scale-[1.03] transition-transform duration-700 ease-out"
                            />
                        ) : (
                            <div className="w-full h-full bg-gray-100 flex items-center justify-center">
                                <span className="text-gray-300 text-5xl font-bold">DD</span>
                            </div>
                        )}
                    </div>

                    {/* Content */}
                    <div className="p-7 md:p-10 flex flex-col justify-center flex-1">
                        <span className={`inline-block text-[11px] font-semibold px-3 py-1 rounded-md w-fit mb-4 uppercase tracking-wider ${categoryColor}`}>
                            {post.category}
                        </span>
                        <h2 className="text-2xl md:text-3xl font-bold text-gray-900 group-hover:text-blue-600 transition-colors mb-3 leading-snug">
                            {post.title}
                        </h2>
                        <p className="text-gray-500 text-sm md:text-base leading-relaxed line-clamp-3 mb-6">{post.excerpt}</p>
                        <div className="flex items-center gap-5 text-xs text-gray-400">
                            <span className="flex items-center gap-1.5"><FiCalendar className="w-3.5 h-3.5" />{formattedDate}</span>
                            <span className="flex items-center gap-1.5"><FiClock className="w-3.5 h-3.5" />{post.readTime} min read</span>
                        </div>
                        <div className="mt-6">
                            <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-blue-600 group-hover:gap-3 transition-all duration-300">
                                Read article <FiArrowRight className="w-4 h-4" />
                            </span>
                        </div>
                    </div>
                </article>
            </Link>
        );
    }

    return (
        <Link href={`/blog/${post.slug}`} className="group block">
            <article className="bg-white rounded-2xl overflow-hidden border border-gray-100 hover:border-gray-200 transition-all duration-300 flex flex-col h-full">
                {/* Cover */}
                <div className="relative h-48 overflow-hidden flex-shrink-0 bg-gray-100">
                    {post.coverImage ? (
                        <Image
                            src={post.coverImage}
                            alt={post.title}
                            fill
                            className="object-cover group-hover:scale-[1.03] transition-transform duration-700 ease-out"
                        />
                    ) : (
                        <div className="w-full h-full bg-gray-100 flex items-center justify-center">
                            <span className="text-gray-300 text-4xl font-bold">DD</span>
                        </div>
                    )}
                </div>

                {/* Content */}
                <div className="p-5 flex flex-col flex-1">
                    <span className={`inline-block text-[10px] font-semibold px-2.5 py-0.5 rounded-md w-fit mb-3 uppercase tracking-wider ${categoryColor}`}>
                        {post.category}
                    </span>
                    <h2 className="font-bold text-gray-900 text-[15px] leading-snug group-hover:text-blue-600 transition-colors mb-2 line-clamp-2 flex-1">
                        {post.title}
                    </h2>
                    <p className="text-gray-400 text-sm leading-relaxed line-clamp-2 mb-4">{post.excerpt}</p>
                    <div className="flex items-center justify-between mt-auto pt-4 border-t border-gray-50">
                        <div className="flex items-center gap-3 text-xs text-gray-400">
                            <span className="flex items-center gap-1"><FiCalendar className="w-3 h-3" />{formattedDate}</span>
                            <span className="flex items-center gap-1"><FiClock className="w-3 h-3" />{post.readTime} min</span>
                        </div>
                        <FiArrowRight className="w-4 h-4 text-gray-300 group-hover:text-blue-500 group-hover:translate-x-1 transition-all duration-300" />
                    </div>
                </div>
            </article>
        </Link>
    );
}
