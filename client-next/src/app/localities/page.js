import { Suspense } from 'react';
import LocalitiesContent from './LocalitiesContent';
import { BreadcrumbJsonLd } from '../../components/JsonLd';
import { ssrFetchAll } from '../../utils/ssrFetch';

// Force dynamic rendering — the published set changes with the nightly
// aggregate, and a build-time snapshot would go stale silently.
export const dynamic = 'force-dynamic';

export const metadata = {
    title: 'Locality asking prices across India',
    description:
        'Median asking prices and rents by locality, measured from live DealDirect listings. Published only where enough listings exist. Asking prices, not valuations.',
    openGraph: {
        title: 'Locality asking prices | DealDirect',
        description:
            'Median asking prices and rents by locality, measured from live DealDirect listings.',
    },
    twitter: {
        card: 'summary',
        title: 'Locality asking prices | DealDirect',
        description: 'Median asking prices and rents by locality, from live listings.',
    },
    alternates: {
        canonical: 'https://dealdirect.in/localities',
    },
};

/**
 * Both listing types are fetched explicitly rather than relying on an
 * unfiltered call. `listingType` is documented as an accepted filter, so two
 * narrow requests are guaranteed to work; an omitted filter is only assumed to
 * return everything. Each is isolated by `ssrFetchAll`, so rents still render
 * if the sale query fails.
 */
async function getLocalities() {
    const [saleRes, rentRes] = await ssrFetchAll([
        { path: '/api/localities?listingType=sale&limit=500', revalidate: 1800 },
        { path: '/api/localities?listingType=rent&limit=500', revalidate: 1800 },
    ]);

    const rows = (res) => (Array.isArray(res?.data) ? res.data : []);

    // Each row already carries its own `listingType`, but it is defaulted here
    // so a row missing the field still lands in the right filter bucket.
    const sale = rows(saleRes).map((r) => ({ ...r, listingType: r.listingType || 'sale' }));
    const rent = rows(rentRes).map((r) => ({ ...r, listingType: r.listingType || 'rent' }));

    return {
        localities: [...sale, ...rent],
        sampleFloor: saleRes?.sampleFloor ?? rentRes?.sampleFloor ?? null,
        // Distinguishes "the API said there is nothing published" from "we could
        // not ask" — the empty state wording differs.
        unavailable: saleRes === null && rentRes === null,
    };
}

export default async function LocalitiesPage() {
    const { localities, sampleFloor, unavailable } = await getLocalities();

    return (
        <>
            <BreadcrumbJsonLd
                items={[
                    { name: 'Home', href: '/' },
                    { name: 'Locality prices', href: '/localities' },
                ]}
            />
            <Suspense
                fallback={
                    <div className="min-h-screen flex items-center justify-center text-slate-500">
                        Loading locality prices...
                    </div>
                }
            >
                <LocalitiesContent
                    localities={localities}
                    sampleFloor={sampleFloor}
                    unavailable={unavailable}
                />
            </Suspense>
        </>
    );
}
