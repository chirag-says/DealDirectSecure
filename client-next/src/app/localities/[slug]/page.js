import { Suspense } from 'react';
import { notFound } from 'next/navigation';

import LocalityContent from './LocalityContent';
import { BreadcrumbJsonLd, LocalityStatsJsonLd } from '../../../components/JsonLd';
import { ssrFetchWithStatus } from '../../../utils/ssrFetch';
import {
    localityLabel,
    localityMetaDescription,
    localityPageTitle,
    normalizeListingType,
} from '../../../utils/localityFormat';

// Force dynamic rendering — the figures move with the nightly aggregate.
export const dynamic = 'force-dynamic';

const SITE_URL = 'https://dealdirect.in';

/**
 * Fetch one locality, keeping three outcomes apart.
 *
 *   missing     — the API answered 404 LOCALITY_NOT_FOUND. That is a NORMAL
 *                 answer meaning "fewer listings here than the sample floor,
 *                 so nothing is published", not a failure. It must become a
 *                 real 404 so a page with no numbers on it is never indexed as
 *                 thin content.
 *   unavailable — we could not ask (5xx, timeout). Never a 404: a backend blip
 *                 must not de-index every locality page at once.
 *   detail      — the statistics.
 */
async function getLocality(slug, listingType) {
    if (!slug) return { detail: null, sampleFloor: null, missing: true, unavailable: false };

    const { data, notFound: missing, unavailable } = await ssrFetchWithStatus(
        `/api/localities/${encodeURIComponent(slug)}?listingType=${listingType}`,
        { revalidate: 1800 }
    );

    const detail = data?.data ?? null;

    return {
        detail,
        sampleFloor: detail?.sampleFloor ?? data?.sampleFloor ?? null,
        missing,
        // A 200 with no payload is not a 404 — treat it like an outage so the
        // URL stays indexable and the page shows the calm unavailable state.
        unavailable: unavailable || (!missing && !detail),
    };
}

export async function generateMetadata(props) {
    const params = await props.params;
    const searchParams = await props.searchParams;

    const slug = params?.slug;
    const listingType = normalizeListingType(searchParams?.listingType);

    if (!slug) return {};

    const { detail } = await getLocality(slug, listingType);

    if (!detail) {
        // No canonical: this response is about to be a 404 or an error state,
        // and a canonical would nominate it as the authoritative version of
        // itself.
        return {
            title: 'Locality prices not published',
            description: 'There are not enough live listings in this locality to publish a price.',
            robots: { index: false, follow: true },
        };
    }

    const title = localityPageTitle(detail);
    const description = localityMetaDescription(detail);
    const canonical =
        listingType === 'rent'
            ? `${SITE_URL}/localities/${slug}?listingType=rent`
            : `${SITE_URL}/localities/${slug}`;

    return {
        title,
        description,
        openGraph: {
            type: 'article',
            title: `${title} | DealDirect`,
            description,
            url: canonical,
        },
        twitter: {
            card: 'summary',
            title: `${title} | DealDirect`,
            description,
        },
        alternates: { canonical },
        robots: { index: true, follow: true },
    };
}

export default async function LocalityPage(props) {
    const params = await props.params;
    const searchParams = await props.searchParams;

    const slug = params?.slug;
    const listingType = normalizeListingType(searchParams?.listingType);

    const { detail, sampleFloor, missing, unavailable } = await getLocality(slug, listingType);

    // Under the sample floor → a genuine 404, rendered by ./not-found.jsx.
    if (missing) notFound();

    const place = localityLabel(detail) || slug;

    return (
        <>
            {detail && <LocalityStatsJsonLd detail={detail} sampleFloor={sampleFloor} />}
            <BreadcrumbJsonLd
                items={[
                    { name: 'Home', href: '/' },
                    { name: 'Locality prices', href: '/localities' },
                    { name: place, href: `/localities/${slug}` },
                ]}
            />
            <Suspense
                fallback={
                    <div className="min-h-screen flex items-center justify-center text-slate-500">
                        Loading locality prices...
                    </div>
                }
            >
                <LocalityContent
                    detail={detail}
                    sampleFloor={sampleFloor}
                    slug={slug}
                    listingType={listingType}
                    unavailable={unavailable}
                />
            </Suspense>
        </>
    );
}
