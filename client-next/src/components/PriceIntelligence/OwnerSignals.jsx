'use client';

import {
    CheckBadgeIcon,
    ChatBubbleLeftRightIcon,
    StarIcon,
} from '@heroicons/react/24/outline';

import {
    describeOwnerResponse,
    describeReviews,
    ownerBadges,
} from '../../utils/priceIntelligence';

/**
 * The three honest signals about the person on the other end of a listing:
 * what they have had verified, how fast they usually reply, and what past
 * buyers scored them.
 *
 * Response time is withheld below three answered leads — an average over one
 * reply is not a habit, and the plan is explicit that a dishonest number costs
 * more than a missing one. That gate lives in `describeOwnerResponse`, not
 * here.
 *
 * @param {{ stats: object|null|undefined }} props
 */
export default function OwnerSignals({ stats }) {
    if (!stats) return null;

    const badges = ownerBadges(stats);
    const response = describeOwnerResponse(stats);
    const reviews = describeReviews(stats.reviews);

    if (badges.length === 0 && !response && !reviews) return null;

    return (
        <div className="mt-3 space-y-2">
            {badges.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                    {badges.map((badge) => (
                        <span
                            key={badge.key}
                            className="inline-flex items-center gap-1 rounded-full border border-emerald-100 bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold text-emerald-700"
                        >
                            <CheckBadgeIcon className="h-3.5 w-3.5" />
                            {badge.label}
                        </span>
                    ))}
                </div>
            )}

            {response && (
                <p className="flex items-center gap-1.5 text-xs text-slate-600">
                    <ChatBubbleLeftRightIcon className="h-4 w-4 flex-shrink-0 text-slate-400" />
                    {response}
                </p>
            )}

            {reviews && (
                <p className="flex items-center gap-1.5 text-xs text-slate-600">
                    <StarIcon className="h-4 w-4 flex-shrink-0 text-amber-500" />
                    {reviews}
                </p>
            )}
        </div>
    );
}
