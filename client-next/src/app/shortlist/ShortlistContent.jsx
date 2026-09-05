'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { BookmarkIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-toastify';

import api from '../../utils/api';
import { useAuth } from '../../context/AuthContext';
import ShortlistCard from '../../components/Shortlist/ShortlistCard';
import { SAVE_PRIVACY_NOTE } from '../../components/Shortlist/SaveButton';
import { loadShortlistIds } from '../../utils/shortlistStore';
import ShareShortlist from '../../components/Shortlist/ShareShortlist';

const PAGE_SIZE = 24;

/**
 * The buyer's private shortlist.
 *
 * Distinct from /saved-properties, which is the older `properties/saved` list.
 * This one is the server-backed shortlist from Phase 1: unlimited, cross-device,
 * silent. Nothing on this page contacts an owner or creates a lead.
 */
export default function ShortlistContent() {
    const { isAuthenticated, loading: authLoading } = useAuth();
    const router = useRouter();

    const [entries, setEntries] = useState([]);
    const [pagination, setPagination] = useState(null);
    const [page, setPage] = useState(1);
    const [loading, setLoading] = useState(true);
    const [failed, setFailed] = useState(false);
    const [removingId, setRemovingId] = useState(null);

    useEffect(() => {
        if (!authLoading && !isAuthenticated) {
            router.push(`/login?from=${encodeURIComponent('/shortlist')}`);
        }
    }, [authLoading, isAuthenticated, router]);

    const fetchPage = useCallback(async (targetPage) => {
        setLoading(true);
        setFailed(false);
        try {
            const res = await api.get('/shortlist', {
                params: { page: targetPage, limit: PAGE_SIZE },
            });
            setEntries(Array.isArray(res.data?.data) ? res.data.data : []);
            setPagination(res.data?.pagination || null);
        } catch (error) {
            if (error?.response?.status !== 401) setFailed(true);
            setEntries([]);
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        if (isAuthenticated) fetchPage(page);
    }, [isAuthenticated, page, fetchPage]);

    const handleRemove = async (propertyId) => {
        setRemovingId(propertyId);
        try {
            await api.delete(`/shortlist/${propertyId}`);
            setEntries((prev) =>
                prev.filter((e) => String(e.property?._id || e.property?.id) !== String(propertyId))
            );
            // Keep the save buttons elsewhere in the app in step.
            await loadShortlistIds({ force: true });
            toast.success('Removed from your shortlist');
        } catch (error) {
            toast.error(error?.response?.data?.message || 'Could not remove that home');
        } finally {
            setRemovingId(null);
        }
    };

    if (authLoading || (loading && entries.length === 0 && !failed)) {
        return (
            <div className="flex min-h-screen items-center justify-center text-slate-500">
                Loading your shortlist...
            </div>
        );
    }

    if (!isAuthenticated) return null;

    const totalPages = pagination?.totalPages || pagination?.pages || 1;

    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-5xl px-4 py-10 sm:px-6 sm:py-14">
                <header className="mb-8">
                    <h1 className="text-3xl font-semibold tracking-tight text-slate-900 sm:text-4xl">
                        Your shortlist
                    </h1>
                    <p className="mt-2 text-sm text-slate-600">
                        {SAVE_PRIVACY_NOTE} To contact an owner, open the listing and use
                        &ldquo;I&apos;m Interested&rdquo;.
                    </p>
                </header>

                <div className="mb-6">
                    <ShareShortlist count={pagination?.total ?? entries.length} />
                </div>

                {failed ? (
                    <div className="rounded-3xl border border-slate-200 bg-white p-8 text-center">
                        <h2 className="text-lg font-semibold text-slate-900">
                            Your shortlist did not load
                        </h2>
                        <p className="mt-2 text-sm text-slate-600">
                            Nothing has been lost. Try again in a moment.
                        </p>
                        <button
                            type="button"
                            onClick={() => fetchPage(page)}
                            className="mt-5 rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0c3f8f]"
                        >
                            Try again
                        </button>
                    </div>
                ) : entries.length === 0 ? (
                    <div className="rounded-3xl border border-slate-200 bg-white p-10 text-center">
                        <BookmarkIcon className="mx-auto h-9 w-9 text-slate-300" />
                        <h2 className="mt-3 text-lg font-semibold text-slate-900">
                            Nothing saved yet
                        </h2>
                        <p className="mx-auto mt-2 max-w-md text-sm leading-relaxed text-slate-600">
                            Use the bookmark on any listing to keep it here. Saving is silent — the
                            owner hears nothing until you choose to get in touch.
                        </p>
                        <Link
                            href="/properties"
                            className="mt-5 inline-block rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white hover:bg-[#0c3f8f]"
                        >
                            Browse properties
                        </Link>
                    </div>
                ) : (
                    <>
                        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                            {entries.map((entry) => (
                                <ShortlistCard
                                    key={entry.id || entry.property?._id}
                                    entry={entry}
                                    onRemove={handleRemove}
                                    removing={
                                        removingId ===
                                        String(entry.property?._id || entry.property?.id)
                                    }
                                />
                            ))}
                        </div>

                        {totalPages > 1 && (
                            <div className="mt-8 flex items-center justify-center gap-3">
                                <button
                                    type="button"
                                    onClick={() => setPage((p) => Math.max(1, p - 1))}
                                    disabled={page <= 1 || loading}
                                    className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 disabled:opacity-50"
                                >
                                    Previous
                                </button>
                                <span className="text-sm text-slate-500">
                                    Page {page} of {totalPages}
                                </span>
                                <button
                                    type="button"
                                    onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                                    disabled={page >= totalPages || loading}
                                    className="rounded-xl border border-slate-200 bg-white px-4 py-2 text-sm font-semibold text-slate-700 disabled:opacity-50"
                                >
                                    Next
                                </button>
                            </div>
                        )}
                    </>
                )}
            </div>
        </div>
    );
}
