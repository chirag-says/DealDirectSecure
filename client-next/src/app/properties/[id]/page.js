import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import PropertyDetailsContent from './PropertyDetailsContent';
import { getServerApiBase, ssrFetchWithStatus } from '../../../utils/ssrFetch';
import { PropertyJsonLd, BreadcrumbJsonLd } from '../../../components/JsonLd';

// Force dynamic rendering — never pre-render at build time
export const dynamic = 'force-dynamic';

/**
 * Fetch the property, keeping "does not exist" separate from "could not ask".
 *
 * This page used to render 200 with an empty body for a property that is not
 * there — a soft 404. Search engines index that as real content, and users get
 * a page instead of an error.
 *
 * The fix is not simply `if (!property) notFound()`. `ssrFetch` returns null for
 * a timeout too, so that version would answer 404 for every live property while
 * the backend was restarting, and Google de-indexes URLs that return 404. Only
 * a definitive absence — 404, 410, or a malformed id — may become a 404 here.
 */
async function getProperty(id) {
    if (!id) return { property: null, missing: true };
    const { data, notFound: missing } = await ssrFetchWithStatus(
        `/api/properties/${id}`, { revalidate: 60 }
    );
    return { property: data, missing };
}

export async function generateMetadata(props) {
    const params = await props.params;
    const id = params?.id;

    if (!id) return {};

    const { property } = await getProperty(id);

    if (!property) {
        // No canonical here, deliberately. A canonical URL on a page that is
        // about to answer 404 asks search engines to index the 404 as the
        // authoritative version of itself.
        return {
            title: 'Property Not Found',
            description: 'The requested property could not be found.',
            robots: { index: false, follow: false },
        };
    }

    const title = property.title || `${property.bhk || ''} ${property.category?.name || 'Property'} for ${property.listingType} in ${property.city}`;
    const description = property.description?.substring(0, 160) || `Check out this ${property.category?.name} in ${property.city} on DealDirect.`;

    const apiBase = getServerApiBase();
    const images = property.images && property.images.length > 0
        ? property.images.map(img => img.startsWith('http') ? img : `${apiBase}/uploads/${img}`)
        : [];

    return {
        title: title,
        description,
        openGraph: {
            title,
            description,
            type: 'article',
            images: images.length > 0 ? images.map(url => ({ url, width: 1200, height: 630 })) : undefined,
        },
        twitter: {
            card: 'summary_large_image',
            title,
            description,
            images: images.length > 0 ? [images[0]] : undefined,
        },
        alternates: {
            canonical: `https://dealdirect.in/properties/${id}`,
        },
    };
}

export default async function PropertyDetailsPage(props) {
    const params = await props.params;
    const id = params?.id;

    const { property, missing } = await getProperty(id);

    // Definitively absent → a real 404. Unreachable backend → fall through and
    // render, so a transient outage does not de-index a live listing.
    if (missing) notFound();

    // Build breadcrumb items
    const breadcrumbItems = [
        { name: 'Home', href: '/' },
        { name: 'Properties', href: '/properties' },
    ];
    if (property) {
        const propertyTitle = property.title || `${property.bhk || ''} ${property.category?.name || 'Property'} in ${property.city || ''}`;
        breadcrumbItems.push({
            name: propertyTitle,
            href: `/properties/${id}`,
        });
    }

    return (
        <>
            {property && <PropertyJsonLd property={property} />}
            <BreadcrumbJsonLd items={breadcrumbItems} />
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Loading property details...</div>}>
                <PropertyDetailsContent initialProperty={property} />
            </Suspense>
        </>
    );
}
