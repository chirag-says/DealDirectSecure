'use client';

import { useEffect, useState } from 'react';
import { usePathname, useRouter, useSearchParams } from 'next/navigation';
import { BookmarkIcon } from '@heroicons/react/24/outline';
import { BookmarkIcon as BookmarkSolidIcon } from '@heroicons/react/24/solid';
import { toast } from 'react-toastify';

import { useAuth } from '../../context/AuthContext';
import {
    addToShortlist,
    clearShortlistCache,
    loadShortlistIds,
    removeFromShortlist,
    useShortlistIds,
} from '../../utils/shortlistStore';

/**
 * The one-line promise that makes saving different from expressing interest.
 * Exported so the detail page can print it next to the button without
 * duplicating the wording.
 */
export const SAVE_PRIVACY_NOTE = 'Saving is private. The owner is not told and no enquiry is sent.';

/**
 * Save a property to the private shortlist.
 *
 * DELIBERATELY NOT A HEART. The heart on this site already means "I'm
 * Interested", which notifies the owner, creates a Lead and counts against a
 * cap of five. Saving does none of that. Reusing the heart, the red, or the
 * word "interested" here would merge two controls with opposite consequences,
 * so this is a slate-toned bookmark and it says what it does.
 *
 * @param {{
 *   propertyId: string,
 *   variant?: 'icon'|'full',
 *   className?: string,
 *   onDone?: (saved: boolean) => void
 * }} props
 */
export default function SaveButton({ propertyId, variant = 'icon', className = '', onDone }) {
    const { isAuthenticated } = useAuth();
    const router = useRouter();
    const pathname = usePathname();
    const searchParams = useSearchParams();

    const ids = useShortlistIds();
    const [busy, setBusy] = useState(false);

    const id = propertyId ? String(propertyId) : null;
    const saved = id ? ids.has(id) : false;

    // One request per session, shared by every button on the page.
    //
    // Losing the session drops the cache. Without this, a shortlist read as
    // user A would still be memoised when user B signs in on the same tab, and
    // B would see A's homes marked as saved. Doing it here rather than in
    // `logout()` also covers a session that simply expired.
    useEffect(() => {
        if (isAuthenticated) loadShortlistIds();
        else clearShortlistCache();
    }, [isAuthenticated]);

    if (!id) return null;

    const handleClick = async (event) => {
        event?.stopPropagation?.();
        event?.preventDefault?.();

        if (!isAuthenticated) {
            toast.info('Log in to save homes to your private shortlist');
            const query = searchParams?.toString();
            const from = `${pathname}${query ? `?${query}` : ''}`;
            router.push(`/login?from=${encodeURIComponent(from)}`);
            return;
        }

        setBusy(true);
        try {
            if (saved) {
                await removeFromShortlist(id);
                toast.success('Removed from your shortlist');
                onDone?.(false);
            } else {
                await addToShortlist(id);
                toast.success('Saved. Only you can see this.');
                onDone?.(true);
            }
        } catch (error) {
            toast.error(
                error?.response?.data?.message ||
                (saved ? 'Could not remove from shortlist' : 'Could not save this home')
            );
        } finally {
            setBusy(false);
        }
    };

    const label = saved ? 'Saved to your shortlist' : 'Save to your shortlist (private)';

    if (variant === 'icon') {
        return (
            <button
                type="button"
                onClick={handleClick}
                disabled={busy}
                title={label}
                aria-label={label}
                aria-pressed={saved}
                className={`rounded-full p-2 backdrop-blur-sm transition-colors ${saved
                    ? 'bg-slate-900 text-white'
                    : 'bg-black/20 text-white hover:bg-slate-900/70'
                    }${busy ? ' cursor-not-allowed opacity-70' : ''} ${className}`}
            >
                {saved ? (
                    <BookmarkSolidIcon className="h-4 w-4" />
                ) : (
                    <BookmarkIcon className="h-4 w-4" />
                )}
            </button>
        );
    }

    return (
        <button
            type="button"
            onClick={handleClick}
            disabled={busy}
            aria-pressed={saved}
            className={`inline-flex w-full items-center justify-center gap-2 rounded-2xl border px-5 py-3.5 text-sm font-semibold tracking-wide transition-colors disabled:cursor-not-allowed disabled:opacity-70 ${saved
                ? 'border-slate-900 bg-slate-900 text-white hover:bg-slate-800'
                : 'border-slate-300 bg-white text-slate-800 hover:bg-slate-50'
                } ${className}`}
        >
            {saved ? (
                <BookmarkSolidIcon className="h-5 w-5" />
            ) : (
                <BookmarkIcon className="h-5 w-5" />
            )}
            <span>{saved ? 'Saved' : 'Save for later'}</span>
        </button>
    );
}
