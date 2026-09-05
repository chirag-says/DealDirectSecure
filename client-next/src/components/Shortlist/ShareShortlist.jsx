'use client';

import { useCallback, useState } from 'react';
import { LinkIcon, ClipboardDocumentIcon, XMarkIcon } from '@heroicons/react/24/outline';
import { toast } from 'react-toastify';

import api from '../../utils/api';

/**
 * Create, copy and withdraw a read-only link to your shortlist.
 *
 * Buying a home is a group decision far more often than not — the research
 * behind this feature is explicit about it — so the share exists to put the
 * list in front of a spouse or a parent without either of them needing an
 * account. What the link grants is deliberately narrow, and the copy says so
 * rather than making the reader guess: the homes and a first name, no notes,
 * no contact details, no way to change anything, and it stops working when
 * the author says so.
 *
 * `POST /shortlist/share` ROTATES. Creating a link revokes whatever came
 * before it, which is also the fastest way to withdraw one: share again. The
 * button copy says "Create a new link" once a link exists, because a person
 * who clicks it needs to know the old one dies.
 */
export default function ShareShortlist({ count = 0 }) {
    const [share, setShare] = useState(null);
    const [busy, setBusy] = useState(false);

    const shareUrl = share
        ? `${typeof window === 'undefined' ? '' : window.location.origin}/shortlist/shared/${share.token}`
        : '';

    const create = useCallback(async () => {
        setBusy(true);
        try {
            const res = await api.post('/shortlist/share', {});
            setShare(res.data?.data || null);
        } catch (error) {
            // The one refusal worth its own words: there is nothing to share.
            if (error?.response?.data?.code === 'EMPTY_SHORTLIST') {
                toast.info('Save a home first, then you can share the list.');
            } else {
                toast.error('That link could not be created. Try again in a moment.');
            }
        } finally {
            setBusy(false);
        }
    }, []);

    const revoke = useCallback(async () => {
        setBusy(true);
        try {
            await api.delete('/shortlist/share');
            setShare(null);
            toast.success('The link no longer works.');
        } catch {
            toast.error('That link could not be withdrawn. Try again in a moment.');
        } finally {
            setBusy(false);
        }
    }, []);

    const copy = useCallback(async () => {
        try {
            await navigator.clipboard.writeText(shareUrl);
            toast.success('Link copied.');
        } catch {
            // A clipboard the browser refuses is not an error worth a toast:
            // the input below is selectable and the link is right there.
        }
    }, [shareUrl]);

    if (count === 0) return null;

    return (
        <div className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-6">
            <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="max-w-xl">
                    <h2 className="flex items-center gap-2 text-base font-semibold text-slate-900">
                        <LinkIcon className="h-5 w-5 text-slate-400" />
                        Share this list
                    </h2>
                    <p className="mt-1 text-sm leading-relaxed text-slate-600">
                        Anyone with the link sees these homes and your first name. Your notes,
                        your contact details and the rest of your account stay private, and they
                        cannot change anything. The link expires in 30 days, or the moment you
                        withdraw it.
                    </p>
                </div>

                <button
                    type="button"
                    onClick={create}
                    disabled={busy}
                    className="rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-[#0c3f8f] disabled:opacity-60"
                >
                    {share ? 'Create a new link' : 'Create a link'}
                </button>
            </div>

            {share ? (
                <div className="mt-5 border-t border-slate-100 pt-5">
                    <div className="flex flex-wrap items-center gap-2">
                        <input
                            readOnly
                            value={shareUrl}
                            onFocus={(event) => event.target.select()}
                            aria-label="Your shortlist link"
                            className="min-w-0 flex-1 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700"
                        />
                        <button
                            type="button"
                            onClick={copy}
                            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 px-4 py-2 text-sm font-medium text-slate-700 transition hover:bg-slate-50"
                        >
                            <ClipboardDocumentIcon className="h-4 w-4" />
                            Copy
                        </button>
                        <button
                            type="button"
                            onClick={revoke}
                            disabled={busy}
                            className="inline-flex items-center gap-1.5 rounded-xl border border-slate-200 px-4 py-2 text-sm font-medium text-slate-600 transition hover:bg-slate-50 disabled:opacity-60"
                        >
                            <XMarkIcon className="h-4 w-4" />
                            Withdraw
                        </button>
                    </div>
                    <p className="mt-2 text-xs text-slate-500">
                        Creating another link stops this one working.
                    </p>
                </div>
            ) : null}
        </div>
    );
}
