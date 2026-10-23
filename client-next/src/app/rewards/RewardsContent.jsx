import Link from 'next/link';
import { ChevronDown } from 'lucide-react';
import {
    DealIcon, ListingIcon, EnquiryIcon, PhotosIcon, ReferralIcon, FriendActiveIcon, FriendDealIcon,
    ReportIcon, GiftIcon, FairPlayIcon, TierBadge,
} from '../../components/Rewards/RewardIcons';
import RewardsCta from './RewardsCta';
import {
    DRAW_POOLS, FIXED_POINTS, LIMITS, TIERS, poolSummary,
} from '../../data/rewardsProgramme.mjs';

/*
 * DealDirect Rewards, public page.
 *
 * Every number on this page comes from data/rewardsProgramme.mjs, which the
 * backend test tests/rewards-website-contract.test.js holds to the reward
 * engine. The page states the real rules (the listing reward is once per
 * account, enquiries are rewarded five a day, only the referrer earns
 * referral points) and says that smaller prizes are the most common, so it
 * promises nothing the engine does not pay. By product decision (2026-10-23)
 * the page shows points only: no odds and no rupee values. Points have no cash value; they are spent
 * in the Hubble rewards store, as the Terms of Use say.
 */

const DRAWS = [
    {
        key: 'property_sale',
        icon: DealIcon,
        title: 'Close a verified deal',
        rule: 'When a sale or letting made through DealDirect is verified, the owner and the buyer or tenant each get a Deal Shagun draw.',
    },
    {
        key: 'property_posting',
        icon: ListingIcon,
        title: 'List your first property',
        rule: 'One draw when you publish your first listing. Once per account.',
    },
    {
        key: 'property_enquiry',
        icon: EnquiryIcon,
        title: 'Send an enquiry',
        rule: `One draw per enquiry, for up to ${LIMITS.enquiryRewardsPerDay} enquiries a day.`,
    },
].map((d) => ({ ...d, ...poolSummary(DRAW_POOLS[d.key]) }));

const BONUSES = [
    { icon: PhotosIcon, title: 'Publish a listing with 5 or more photos', points: FIXED_POINTS.upload_5_photos, note: 'Counted when the listing is created, once per listing.' },
    { icon: ReferralIcon, title: 'A friend signs up with your referral code', points: FIXED_POINTS.referral_signup, note: 'Paid to you, the referrer.' },
    { icon: FriendActiveIcon, title: 'Your referred friend makes their first move', points: FIXED_POINTS.referral_first_action, note: 'Their first listing or enquiry.' },
    { icon: FriendDealIcon, title: 'Your referred friend closes a verified deal', points: FIXED_POINTS.referral_deal_closure, note: 'Paid to you, the referrer.' },
    { icon: ReportIcon, title: 'Report a listing', points: FIXED_POINTS.report_property, note: 'One report per listing while it is reviewed.' },
];

const FAQS = [
    {
        q: 'Can I exchange points for cash?',
        a: 'No. Points have no cash value and cannot be withdrawn or transferred. You spend them on gift cards and vouchers in the rewards store, where each item shows its price in points.',
    },
    {
        q: 'How is a draw decided?',
        a: 'The system picks one prize at random from that action’s prizes. Smaller prizes come up most often, and the top prizes are rare.',
    },
    {
        q: 'Do my tier bonus and my draw combine?',
        a: 'Yes. Your tier bonus multiplies every reward you receive after reaching that tier, draws and fixed bonuses alike.',
    },
    {
        q: 'Do points expire?',
        a: 'Not at present. If we introduce expiry for inactive accounts, we will announce the period in advance and remind you at least 14 days before any points lapse.',
    },
    {
        q: 'Can I earn as an owner and as a buyer?',
        a: 'Yes. Each account has one wallet, and rewards from both roles go into it.',
    },
    {
        q: 'Where do I spend points?',
        a: 'In the rewards store in your DealDirect account, run by our partner Hubble. Gift cards and vouchers are delivered digitally.',
    },
];

const eyebrow = 'text-xs font-semibold uppercase tracking-[0.14em] text-red-600';
const h2 = 'mt-2 text-2xl font-bold tracking-tight text-slate-900 sm:text-3xl';
const lead = 'mt-3 max-w-2xl text-base leading-relaxed text-slate-600';

function Points({ points }) {
    return <span className="tabular-nums">{points.toLocaleString('en-IN')} pts</span>;
}

export default function RewardsContent() {
    const [sale, posting, enquiry] = DRAWS;

    return (
        <div className="min-h-screen bg-white text-slate-900">
            {/* ===== Hero ===== */}
            <section className="border-b border-slate-200 bg-gradient-to-b from-slate-50 to-white">
                <div className="mx-auto grid max-w-6xl gap-12 px-4 py-16 sm:px-6 lg:grid-cols-[1.15fr_1fr] lg:items-center lg:py-24">
                    <div>
                        <p className={eyebrow}>DealDirect Rewards</p>
                        <h1 className="mt-3 text-4xl font-bold leading-tight tracking-tight text-slate-900 sm:text-5xl">
                            Earn points as you use DealDirect. Spend them on gift cards.
                        </h1>
                        <p className="mt-5 max-w-xl text-lg leading-relaxed text-slate-600">
                            Points for verified deals, your first listing, enquiries and referrals. Free to join, with
                            no fees.
                        </p>
                        <div className="mt-8">
                            <RewardsCta />
                        </div>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm sm:p-8">
                        <p className="text-sm font-semibold text-slate-900">Top prizes, before tier bonuses</p>
                        <dl className="mt-5 divide-y divide-slate-100">
                            {[sale, posting, enquiry].map((d) => {
                                const Icon = d.icon;
                                return (
                                    <div key={d.key} className="flex items-center justify-between gap-4 py-4 first:pt-0 last:pb-0">
                                        <dt className="flex items-center gap-3 text-sm text-slate-600">
                                            <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-red-50">
                                                <Icon className="h-6 w-6 text-red-600" />
                                            </span>
                                            {d.title}
                                        </dt>
                                        <dd className="text-right text-xl font-bold text-slate-900">
                                            <Points points={d.top.points} />
                                        </dd>
                                    </div>
                                );
                            })}
                        </dl>
                        <p className="mt-5 border-t border-slate-100 pt-4 text-xs leading-relaxed text-slate-500">
                            Top prizes are the rarest outcomes; most draws give one of the smaller prizes.
                        </p>
                    </div>
                </div>
            </section>

            {/* ===== Ways to earn ===== */}
            <section id="how-points-work" className="scroll-mt-24 px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto max-w-6xl">
                    <p className={eyebrow}>Ways to earn</p>
                    <h2 className={h2}>Three actions earn a draw. Five earn a fixed bonus.</h2>
                    <p className={lead}>
                        A draw picks one prize at random from that action&rsquo;s prizes. Smaller prizes come up most
                        often and the top prizes are rare. Fixed bonuses are always the same amount.
                    </p>

                    <div className="mt-10 grid gap-5 md:grid-cols-3">
                        {DRAWS.map((d) => {
                            const Icon = d.icon;
                            return (
                                <article key={d.key} className="flex flex-col rounded-2xl border border-slate-200 p-6">
                                    <span className="flex h-12 w-12 items-center justify-center rounded-xl bg-red-50">
                                        <Icon className="h-7 w-7 text-red-600" />
                                    </span>
                                    <h3 className="mt-4 text-lg font-semibold text-slate-900">{d.title}</h3>
                                    <p className="mt-2 text-sm leading-relaxed text-slate-600">{d.rule}</p>
                                    <dl className="mt-auto border-t border-slate-100 pt-5 text-sm">
                                        <dt className="text-xs text-slate-500">Prizes</dt>
                                        <dd className="mt-0.5 font-semibold text-slate-900">
                                            <Points points={d.rows[0].points} /> to <Points points={d.top.points} />
                                        </dd>
                                    </dl>
                                </article>
                            );
                        })}
                    </div>

                    <div className="mt-10 overflow-hidden rounded-2xl border border-slate-200">
                        <table className="w-full text-left text-sm">
                            <caption className="sr-only">Fixed bonuses</caption>
                            <thead className="bg-slate-50 text-slate-600">
                                <tr>
                                    <th scope="col" className="px-5 py-3 font-semibold">Fixed bonus</th>
                                    <th scope="col" className="hidden px-5 py-3 font-semibold sm:table-cell">Conditions</th>
                                    <th scope="col" className="px-5 py-3 text-right font-semibold">Points</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100">
                                {BONUSES.map((b) => {
                                    const Icon = b.icon;
                                    return (
                                        <tr key={b.title}>
                                            <td className="px-5 py-3.5">
                                                <span className="flex items-center gap-3 font-medium text-slate-900">
                                                    <Icon className="h-5 w-5 flex-shrink-0 text-red-600" />
                                                    {b.title}
                                                </span>
                                                <span className="mt-1 block pl-8 text-xs text-slate-500 sm:hidden">{b.note}</span>
                                            </td>
                                            <td className="hidden px-5 py-3.5 text-slate-600 sm:table-cell">{b.note}</td>
                                            <td className="px-5 py-3.5 text-right font-semibold tabular-nums text-slate-900">+{b.points.toLocaleString('en-IN')}</td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                </div>
            </section>

            {/* ===== Tiers ===== */}
            <section className="px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto max-w-6xl">
                    <p className={eyebrow}>Tiers</p>
                    <h2 className={h2}>The more you earn, the more each reward is worth.</h2>
                    <p className={lead}>
                        Your tier is set by the total points you have ever earned. From then on, its bonus applies to
                        every reward you receive.
                    </p>
                    <ol className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                        {TIERS.map((t, i) => {
                            const next = TIERS[i + 1];
                            return (
                                <li key={t.key} className="rounded-2xl border border-slate-200 p-5">
                                    <TierBadge tier={t.key} className="h-11 w-11" />
                                    <p className="mt-3 text-sm font-semibold text-slate-900">{t.name}</p>
                                    <p className="mt-1 text-xs tabular-nums text-slate-500">
                                        {next
                                            ? `${t.min.toLocaleString('en-IN')} to ${(next.min - 1).toLocaleString('en-IN')} points`
                                            : `${t.min.toLocaleString('en-IN')}+ points`}
                                    </p>
                                    <p className="mt-4 text-2xl font-bold text-slate-900">
                                        {t.multiplier === 1 ? 'Standard' : `+${Math.round((t.multiplier - 1) * 100)}%`}
                                    </p>
                                    <p className="text-xs text-slate-500">{t.multiplier === 1 ? 'rewards' : 'on every reward'}</p>
                                </li>
                            );
                        })}
                    </ol>
                </div>
            </section>

            {/* ===== Redeem ===== */}
            <section className="border-y border-slate-200 bg-slate-50 px-4 py-16 sm:px-6">
                <div className="mx-auto grid max-w-6xl gap-8 md:grid-cols-2">
                    <div className="flex gap-4">
                        <span className="flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl bg-white ring-1 ring-slate-200">
                            <GiftIcon className="h-6 w-6 text-red-600" />
                        </span>
                        <div>
                            <h2 className="text-lg font-semibold text-slate-900">Spend points in the rewards store</h2>
                            <p className="mt-2 text-sm leading-relaxed text-slate-600">
                                Choose gift cards and vouchers from brands in the store in your account, run by our partner
                                Hubble. They are delivered digitally.
                            </p>
                        </div>
                    </div>
                    <div className="flex gap-4">
                        <span className="flex h-11 w-11 flex-shrink-0 items-center justify-center rounded-xl bg-white ring-1 ring-slate-200">
                            <FairPlayIcon className="h-6 w-6 text-red-600" />
                        </span>
                        <div>
                            <h2 className="text-lg font-semibold text-slate-900">Fair play</h2>
                            <p className="mt-2 text-sm leading-relaxed text-slate-600">
                                Points have no cash value and cannot be withdrawn or transferred. Points gained through fake
                                listings, fake referrals or other abuse may be cancelled. See the{' '}
                                <Link href="/rewards/terms" className="font-medium text-red-600 underline underline-offset-2 hover:text-red-700">rewards terms</Link>{' '}
                                and our{' '}
                                <Link href="/terms" className="font-medium text-red-600 underline underline-offset-2 hover:text-red-700">Terms of Use</Link>.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* ===== FAQ ===== */}
            <section className="px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto grid max-w-6xl gap-10 lg:grid-cols-[1fr_1.6fr] lg:gap-16">
                    <div>
                        <p className={eyebrow}>Questions</p>
                        <h2 className={h2}>About rewards</h2>
                        <p className="mt-3 text-sm leading-relaxed text-slate-600">
                            For listings, safety and everything else, see the{' '}
                            <Link href="/faq" className="font-medium text-red-600 underline underline-offset-2 hover:text-red-700">help centre</Link>.
                        </p>
                    </div>
                    <div className="divide-y divide-slate-200 rounded-2xl border border-slate-200 px-6">
                        {FAQS.map((f) => (
                            <details key={f.q} className="group py-1">
                                <summary className="flex cursor-pointer list-none items-center justify-between gap-4 py-4 text-[15px] font-semibold text-slate-800 hover:text-slate-950">
                                    {f.q}
                                    <ChevronDown className="h-4 w-4 flex-shrink-0 text-slate-400 transition-transform group-open:rotate-180" aria-hidden="true" />
                                </summary>
                                <p className="max-w-[65ch] pb-4 text-sm leading-relaxed text-slate-600">{f.a}</p>
                            </details>
                        ))}
                    </div>
                </div>
            </section>

            {/* ===== Close ===== */}
            <section className="bg-slate-900 px-4 py-16 sm:px-6">
                <div className="mx-auto flex max-w-6xl flex-col items-start justify-between gap-6 md:flex-row md:items-center">
                    <div>
                        <h2 className="text-2xl font-bold tracking-tight text-white">Start earning on your next listing or enquiry.</h2>
                        <p className="mt-2 text-sm text-slate-400">Free to join. No fees, ever.</p>
                    </div>
                    <RewardsCta tone="dark" secondary={false} />
                </div>
            </section>
        </div>
    );
}
