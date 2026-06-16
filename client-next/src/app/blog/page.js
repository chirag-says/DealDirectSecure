import { Suspense } from 'react';
import BlogListContent from './BlogListContent';
import { ssrFetch } from '../../utils/ssrFetch';

// Force dynamic rendering — never pre-render at build time
export const dynamic = 'force-dynamic';

export const metadata = {
    title: 'Real Estate Tips, Guides & Market Insights | DealDirect Blog',
    description:
        'Read expert guides on buying, selling, and renting property in India. Topics include RERA, stamp duty, home loans, legal tips, and market trends — all free, no brokerage.',
    openGraph: {
        title: 'Real Estate Tips, Guides & Market Insights | DealDirect Blog',
        description: 'Expert property guides for Indian homebuyers and sellers. No brokerage, just knowledge.',
        type: 'website',
        url: 'https://dealdirect.in/blog',
    },
    alternates: { canonical: 'https://dealdirect.in/blog' },
};

// Server-side data fetching with timeout + graceful fallback
async function getInitialPosts() {
    const data = await ssrFetch('/api/blogs?page=1&limit=9', { revalidate: 120 });

    if (data?.success) {
        return {
            posts: data.data || [],
            pagination: data.pagination || { page: 1, pages: 1, total: 0 },
        };
    }

    return { posts: [], pagination: { page: 1, pages: 1, total: 0 } };
}

export default async function BlogPage() {
    const { posts, pagination } = await getInitialPosts();

    return (
        <Suspense fallback={<BlogListSkeleton />}>
            <BlogListContent initialPosts={posts} initialPagination={pagination} />
        </Suspense>
    );
}

function BlogListSkeleton() {
    return (
        <div className="min-h-screen bg-gray-50">
            <div className="max-w-7xl mx-auto px-4 py-16">
                <div className="h-10 bg-gray-200 rounded-xl w-64 mx-auto mb-12 animate-pulse" />
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                    {[...Array(6)].map((_, i) => (
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
            </div>
        </div>
    );
}
