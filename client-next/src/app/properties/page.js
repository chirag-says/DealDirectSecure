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

    // `/api/properties/list` returns a BARE ARRAY, not an envelope — mobile's
    // type definitions record that explicitly, and Phase 4.3 deliberately kept
    // the shape rather than making a breaking change. An array has neither
    // `.data` nor `.properties`, so the previous
    //     propsData?.data || propsData?.properties || []
    // always evaluated to [] and the hidden SEO block below rendered zero
    // listings on every request.
    //
    // ssrFetch returns null when the request fails. That stays distinct from an
    // empty result: null falls through to [], but only after the array and
    // envelope shapes have been ruled out, so a failure is not mistaken for a
    // genuinely empty corpus by anything reading `propsData` itself.
    const properties = Array.isArray(propsData)
        ? propsData
        : (propsData?.data ?? propsData?.properties ?? []);

    return {
        properties,
        categories: Array.isArray(catsData) ? catsData : (catsData?.data ?? []),
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
