import { Suspense } from 'react';
import PropertyDetailsContent from './PropertyDetailsContent';
import { getServerApiBase, ssrFetch } from '../../../utils/ssrFetch';
import { PropertyJsonLd, BreadcrumbJsonLd } from '../../../components/JsonLd';

// Force dynamic rendering — never pre-render at build time
export const dynamic = 'force-dynamic';

// Helper to fetch property data with timeout
async function getProperty(id) {
    if (!id) return null;
    return await ssrFetch(`/api/properties/${id}`, { revalidate: 60 });
}

export async function generateMetadata(props) {
    const params = await props.params;
    const id = params?.id;

    if (!id) return {};

    const property = await getProperty(id);

    if (!property) {
        return {
            title: 'Property Not Found',
            description: 'The requested property could not be found.',
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

    const property = await getProperty(id);

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
