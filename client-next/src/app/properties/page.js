import { Suspense } from 'react';
import ClientPropertyList from './ClientPropertyList';
import { BreadcrumbJsonLd } from '../../components/JsonLd';
import { ssrFetchAll } from '../../utils/ssrFetch';
import { formatPrice } from '../../utils/formatPrice';

// Force dynamic rendering — never pre-render at build time
export const dynamic = 'force-dynamic';

export const metadata = {
    title: 'Properties for Sale & Rent',
    description: 'Browse thousands of verified properties for sale and rent directly from owners. No brokerage, full transparency.',
    openGraph: {
        title: 'Properties for Sale & Rent | DealDirect',
        description: 'Browse thousands of verified properties for sale and rent directly from owners. No brokerage, full transparency.',
    },
    twitter: {
        card: 'summary',
        title: 'Properties for Sale & Rent | DealDirect',
        description: 'Browse verified properties directly from owners.',
    },
    alternates: {
        canonical: 'https://dealdirect.in/properties',
    },
};

// Server-side data fetching with timeout + graceful fallback
async function getInitialProperties() {
    const [propsData, catsData] = await ssrFetchAll([
        { path: '/api/properties/list?limit=50', revalidate: 120 },
        { path: '/api/categories/list-category', revalidate: 3600 },
    ]);

    return {
        properties: propsData?.data || propsData?.properties || [],
        categories: catsData?.data || catsData || [],
    };
}

export default async function PropertiesPage() {
    const { properties, categories } = await getInitialProperties();

    return (
        <>
            <BreadcrumbJsonLd items={[
                { name: 'Home', href: '/' },
                { name: 'Properties', href: '/properties' },
            ]} />

            {/* Hidden SEO content that crawlers can read */}
            <div className="sr-only" aria-hidden="true">
                <h1>Properties for Sale and Rent on DealDirect</h1>
                <p>Browse {properties.length} verified properties directly from owners. No brokerage fees.</p>
                <ul>
                    {properties.slice(0, 20).map((p) => (
                        <li key={p._id}>
                            {p.title || `Property in ${p.address?.city || p.city || 'India'}`} —
                            {formatPrice(p.price)} —
                            {p.address?.city || p.city}, {p.address?.state || p.state}
                        </li>
                    ))}
                </ul>
            </div>

            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading properties map...</div>}>
                <ClientPropertyList initialProperties={properties} initialCategories={categories} />
            </Suspense>
        </>
    );
}
