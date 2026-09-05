import Link from 'next/link';
import { MapPinIcon } from '@heroicons/react/24/outline';

export const metadata = {
    title: 'Not enough listings here yet',
    description: 'There are not enough live listings in this locality to publish a price.',
    robots: { index: false, follow: true },
};

/**
 * Shown when `GET /localities/:slug` answers 404 LOCALITY_NOT_FOUND.
 *
 * That is not an error and the page does not shout. It is the sample floor
 * doing its job: below it we withhold the number rather than publish one we
 * cannot stand behind. Rendering this through `notFound()` gives it a real 404
 * status, which keeps a page with no data on it out of the index.
 */
export default function LocalityNotFound() {
    return (
        <div className="min-h-screen bg-slate-50/60">
            <div className="mx-auto max-w-xl px-4 py-20 text-center sm:px-6">
                <MapPinIcon className="mx-auto h-10 w-10 text-slate-300" />
                <h1 className="mt-4 text-2xl font-semibold tracking-tight text-slate-900 sm:text-3xl">
                    Not enough listings here yet
                </h1>
                <p className="mt-3 text-sm leading-relaxed text-slate-600 sm:text-base">
                    We publish a median asking price for a locality only once enough homes are
                    listed there in the quarter. This one is below that floor, so there is no
                    figure to show. We would rather withhold a number than estimate one.
                </p>
                <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
                    <Link
                        href="/localities"
                        className="inline-flex items-center gap-2 rounded-xl bg-[#0f4fb5] px-5 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-[#0c3f8f]"
                    >
                        See published localities
                    </Link>
                    <Link
                        href="/properties"
                        className="inline-flex items-center gap-2 rounded-xl border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50"
                    >
                        Browse properties
                    </Link>
                </div>
            </div>
        </div>
    );
}
