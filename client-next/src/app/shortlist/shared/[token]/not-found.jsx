import Link from 'next/link';
import { LinkSlashIcon } from '@heroicons/react/24/outline';

export const metadata = {
    title: 'This share link no longer works',
    description: 'The shared shortlist link has expired or been revoked.',
    robots: { index: false, follow: false },
};

/** Shown when `GET /shortlist/shared/:token` answers 404 LINK_NOT_FOUND. */
export default function SharedShortlistNotFound() {
    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-xl px-4 py-20 text-center sm:px-6">
                <LinkSlashIcon className="mx-auto h-10 w-10 text-slate-300" />
                <h1 className="mt-4 text-2xl font-semibold tracking-tight text-slate-900 sm:text-3xl">
                    This share link no longer works
                </h1>
                <p className="mt-3 text-sm leading-relaxed text-slate-600 sm:text-base">
                    Share links expire, and the person who created it can revoke it at any time.
                    Ask them to send a fresh one.
                </p>
                <Link
                    href="/properties"
                    className="mt-7 inline-block rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0c3f8f]"
                >
                    Browse properties
                </Link>
            </div>
        </div>
    );
}
