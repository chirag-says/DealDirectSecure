/**
 * JSON-LD Structured Data Components for DealDirect
 * These generate schema.org markup that Google uses for rich results.
 *
 * Usage:
 *   <OrganizationJsonLd />           — on homepage
 *   <WebsiteJsonLd />                — on homepage
 *   <BreadcrumbJsonLd items={[...]} /> — on any page
 *   <PropertyJsonLd property={...} /> — on property detail page
 */

const SITE_URL = 'https://dealdirect.in';
const SITE_NAME = 'DealDirect';

// ─── Organization Schema ────────────────────────────────────────────────
export function OrganizationJsonLd() {
    const schema = {
        '@context': 'https://schema.org',
        '@type': 'Organization',
        name: SITE_NAME,
        url: SITE_URL,
        logo: `${SITE_URL}/logo.png`,
        description:
            "India's #1 platform for buying, selling, and renting properties directly from owners — no brokerage, no middlemen.",
        contactPoint: {
            '@type': 'ContactPoint',
            contactType: 'customer service',
            email: 'support@dealdirect.in',
            availableLanguage: ['English', 'Hindi'],
        },
        address: {
            '@type': 'PostalAddress',
            streetAddress: 'Growmore Tower, Sector 2, Plot No 5',
            addressLocality: 'Kharghar, Navi Mumbai',
            addressRegion: 'Maharashtra',
            postalCode: '410210',
            addressCountry: 'IN',
        },
        sameAs: [
            'https://www.facebook.com/dealdirect.in',
            'https://www.instagram.com/dealdirect.in',
            'https://twitter.com/dealdirect_in',
            'https://www.linkedin.com/company/dealdirect',
            'https://www.youtube.com/@dealdirect',
        ],
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}

// ─── Website Schema (with SearchAction for Google Sitelinks Search) ─────
export function WebsiteJsonLd() {
    const schema = {
        '@context': 'https://schema.org',
        '@type': 'WebSite',
        name: SITE_NAME,
        url: SITE_URL,
        description:
            'Find your dream property directly from owners. No brokerage, no middlemen.',
        potentialAction: {
            '@type': 'SearchAction',
            target: {
                '@type': 'EntryPoint',
                urlTemplate: `${SITE_URL}/properties?search={search_term_string}`,
            },
            'query-input': 'required name=search_term_string',
        },
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}

// ─── Breadcrumb Schema ──────────────────────────────────────────────────
/**
 * @param {{ items: Array<{ name: string, href: string }> }} props
 * Example: <BreadcrumbJsonLd items={[
 *   { name: 'Home', href: '/' },
 *   { name: 'Properties', href: '/properties' },
 *   { name: '2BHK Flat in Andheri', href: '/properties/abc123' }
 * ]} />
 */
export function BreadcrumbJsonLd({ items }) {
    if (!items || items.length === 0) return null;

    const schema = {
        '@context': 'https://schema.org',
        '@type': 'BreadcrumbList',
        itemListElement: items.map((item, index) => ({
            '@type': 'ListItem',
            position: index + 1,
            name: item.name,
            item: item.href.startsWith('http') ? item.href : `${SITE_URL}${item.href}`,
        })),
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}

// ─── Real Estate Listing Schema (for Property Detail Pages) ─────────────
/**
 * @param {{ property: Object }} props — The property object from the API
 */
export function PropertyJsonLd({ property }) {
    if (!property) return null;

    const title =
        property.title ||
        `${property.bhk || ''} ${property.category?.name || 'Property'} for ${property.listingType || 'Sale'} in ${property.city || ''}`;

    const description =
        property.description?.substring(0, 300) ||
        `${property.category?.name || 'Property'} available for ${property.listingType || 'sale'} in ${property.city || ''}.`;

    // Resolve images
    const images =
        property.images && property.images.length > 0
            ? property.images.map((img) =>
                img.startsWith('http') ? img : `${SITE_URL}/uploads/${img}`
            )
            : [];

    // Build price specification
    const priceSpec = {};
    if (property.price) {
        priceSpec.price = property.price;
        priceSpec.priceCurrency = 'INR';
    }

    const schema = {
        '@context': 'https://schema.org',
        '@type': 'RealEstateListing',
        name: title,
        description,
        url: `${SITE_URL}/properties/${property._id}`,
        datePosted: property.createdAt,
        dateModified: property.updatedAt,
        ...(images.length > 0 && { image: images }),
        address: {
            '@type': 'PostalAddress',
            addressLocality: property.city || property.locality || '',
            addressRegion: property.state || 'Maharashtra',
            addressCountry: 'IN',
            ...(property.pincode && { postalCode: property.pincode }),
            ...(property.address && { streetAddress: property.address }),
        },
        ...(property.price && {
            offers: {
                '@type': 'Offer',
                price: property.price,
                priceCurrency: 'INR',
                availability: 'https://schema.org/InStock',
                itemCondition: property.furnishing
                    ? 'https://schema.org/NewCondition'
                    : undefined,
            },
        }),
        ...(property.area && {
            floorSize: {
                '@type': 'QuantitativeValue',
                value: property.area,
                unitCode: 'FTK', // Square feet
            },
        }),
        ...(property.bhk && {
            numberOfRooms: property.bhk.replace(/\D/g, '') || undefined,
        }),
        ...(property.furnishing && {
            amenityFeature: [
                {
                    '@type': 'LocationFeatureSpecification',
                    name: 'Furnishing',
                    value: property.furnishing,
                },
            ],
        }),
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}

// ─── FAQ Schema (optional, for Why Us / About pages) ────────────────────
/**
 * @param {{ faqs: Array<{ question: string, answer: string }> }} props
 */
export function FAQJsonLd({ faqs }) {
    if (!faqs || faqs.length === 0) return null;

    const schema = {
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        mainEntity: faqs.map((faq) => ({
            '@type': 'Question',
            name: faq.question,
            acceptedAnswer: {
                '@type': 'Answer',
                text: faq.answer,
            },
        })),
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}
