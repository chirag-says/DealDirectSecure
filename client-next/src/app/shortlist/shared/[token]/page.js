import { Suspense } from 'react';
import { notFound } from 'next/navigation';

import SharedShortlistContent from './SharedShortlistContent';
import { ssrFetchWithStatus } from '../../../../utils/ssrFetch';

// Force dynamic rendering — a share token is per-recipient and must never be
// served from a build-time cache.
export const dynamic = 'force-dynamic';

/**
 * A share link is a private URL handed to one spouse or parent, not content.
 * It is `noindex, nofollow` everywhere: in the metadata below, in robots.js,
 * and by its absence from the sitemap. A crawler that somehow reaches the URL
 * must not put someone's saved homes into a search index.
 */
export const metadata = {
    title: 'A shared shortlist',
    description: 'Homes shared with you from a DealDirect shortlist.',
    robots: { index: false, follow: false, nocache: true },
};

async function getSharedList(token) {
    if (!token) return { list: null, missing: true, unavailable: false };

    const { data, notFound: missing, unavailable } = await ssrFetchWithStatus(
        `/api/shortlist/shared/${encodeURIComponent(token)}`,
        { revalidate: 0, timeoutMs: 8000 }
    );

    return {
        list: data?.data ?? null,
        missing,
        unavailable: unavailable || (!missing && !data?.data),
    };
}

export default async function SharedShortlistPage(props) {
    const params = await props.params;
    const token = params?.token;

    const { list, missing, unavailable } = await getSharedList(token);

    // 404 LINK_NOT_FOUND — the link was revoked, mistyped, or has expired.
    if (missing) notFound();

    return (
        <Suspense
            fallback={
                <div className="min-h-screen flex items-center justify-center text-slate-500">
                    Loading shared shortlist...
                </div>
            }
        >
            <SharedShortlistContent list={list} unavailable={unavailable} />
        </Suspense>
    );
}
