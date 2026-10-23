'use client';

import Link from 'next/link';
import { ArrowRight } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

/** The one part of the rewards page that depends on who is looking. */
export default function RewardsCta({ tone = 'light', secondary = true }) {
    const { isAuthenticated } = useAuth();
    const href = isAuthenticated ? '/rewards/dashboard' : '/register';
    const label = isAuthenticated ? 'Go to my rewards' : 'Create a free account';

    const primary =
        tone === 'dark'
            ? 'bg-white text-slate-900 hover:bg-slate-100 focus-visible:ring-offset-slate-900'
            : 'bg-red-600 text-white hover:bg-red-700 focus-visible:ring-offset-white';

    return (
        <div className="flex flex-wrap items-center gap-3">
            <Link
                href={href}
                className={`inline-flex items-center gap-2 rounded-lg px-6 py-3 text-sm font-semibold shadow-sm transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2 ${primary}`}
            >
                {label} <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Link>
            {secondary && (
                <a
                    href="#how-points-work"
                    className={`inline-flex items-center rounded-lg px-4 py-3 text-sm font-semibold transition-colors ${
                        tone === 'dark' ? 'text-white/80 hover:text-white' : 'text-slate-700 hover:text-slate-900'
                    }`}
                >
                    How points work
                </a>
            )}
        </div>
    );
}
