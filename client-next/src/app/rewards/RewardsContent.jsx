'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useAuth } from '../../context/AuthContext';
import {
    Home, Handshake, MessageSquareText, TrendingUp, Medal, Award, Trophy, Gem,
    ArrowRight, ChevronDown, Rocket, Users, Flag, Coins, Check,
} from 'lucide-react';

// ============================================
// SCROLL REVEAL
// ============================================
function useRevealOnScroll(threshold = 0.15) {
    const ref = useRef(null);
    const [visible, setVisible] = useState(false);
    useEffect(() => {
        const el = ref.current;
        if (!el) return;
        const obs = new IntersectionObserver(
            ([entry]) => { if (entry.isIntersecting) { setVisible(true); obs.disconnect(); } },
            { threshold }
        );
        obs.observe(el);
        return () => obs.disconnect();
    }, [threshold]);
    return [ref, visible];
}

/**
 * Wrapper so the hook is called once per component instance.
 *
 * The previous version called useRevealOnScroll() inside a .map() callback,
 * which breaks the Rules of Hooks — React matches hooks by call order, so the
 * moment that list changed length the hook state would be handed to the wrong
 * element. It happened to work only because the array was a constant.
 */
function Reveal({ delay = 0, className = '', children }) {
    const [ref, visible] = useRevealOnScroll(0.1);
    return (
        <div
            ref={ref}
            style={{ transitionDelay: `${delay}ms` }}
            className={`transition-all duration-700 ${visible ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0'} ${className}`}
        >
            {children}
        </div>
    );
}

// ============================================
// DATA
// ============================================
const POINT_VALUE = 0.05; // 1 point = ₹0.05

const rupees = (pts) => {
    const v = pts * POINT_VALUE;
    return `₹${v.toLocaleString('en-IN', { maximumFractionDigits: 0 })}`;
};

/**
 * The three prize pools. `rarity` is the odds band, not decoration — lower
 * prizes are drawn far more often than higher ones.
 */
const POOLS = [
    {
        id: 'post',
        icon: Home,
        label: 'Post a property',
        blurb: 'Every listing you publish opens a door.',
        max: 100000,
        tiers: [
            { points: 40, rarity: 'Common' },
            { points: 100, rarity: 'Common' },
            { points: 200, rarity: 'Common' },
            { points: 1000, rarity: 'Uncommon' },
            { points: 5000, rarity: 'Rare' },
            { points: 10000, rarity: 'Rare' },
            { points: 40000, rarity: 'Epic' },
            { points: 100000, rarity: 'Legendary' },
        ],
    },
    {
        id: 'sell',
        icon: Handshake,
        label: 'Sell a property',
        blurb: 'Close a deal on DealDirect and collect Shagun.',
        max: 420000,
        tiers: [
            { points: 1000, rarity: 'Common' },
            { points: 2000, rarity: 'Common' },
            { points: 10000, rarity: 'Uncommon' },
            { points: 30000, rarity: 'Rare' },
            { points: 50000, rarity: 'Rare' },
            { points: 102000, rarity: 'Epic' },
            { points: 300000, rarity: 'Epic' },
            { points: 420000, rarity: 'Legendary' },
        ],
    },
    {
        id: 'enquire',
        icon: MessageSquareText,
        label: 'Send an enquiry',
        blurb: 'Ask about a listing, open a door.',
        max: 2000,
        tiers: [
            { points: 20, rarity: 'Common' },
            { points: 40, rarity: 'Common' },
            { points: 100, rarity: 'Uncommon' },
            { points: 400, rarity: 'Rare' },
            { points: 1000, rarity: 'Rare' },
            { points: 1600, rarity: 'Epic' },
            { points: 2000, rarity: 'Legendary' },
        ],
    },
];

const TIERS = [
    { icon: Medal, name: 'Bronze', range: '0 – 999 pts', bonus: 'Standard rewards' },
    { icon: Award, name: 'Silver', range: '1,000 – 4,999 pts', bonus: '+10% on every reward' },
    { icon: Trophy, name: 'Gold', range: '5,000 – 14,999 pts', bonus: '+25% on every reward' },
    { icon: Gem, name: 'Diamond', range: '15,000+ pts', bonus: '+50% on every reward' },
];

/**
 * Rewards-specific questions only. The general FAQ lives at /faq and used to be
 * duplicated here in full — thirteen questions that had already drifted out of
 * sync with the canonical copy, and a chunk of duplicate content on a second URL.
 */
const FAQS = [
    { q: 'How much is one point worth?', a: '1 point = ₹0.05. So 1,000 points is ₹50 of real redeemable value.' },
    { q: 'How is my reward decided?', a: 'Posting, selling or enquiring enters you into a Property Hunt. The system draws your reward at random from that pool. Lower prizes come up far more often than the jackpot.' },
    { q: 'Do my points expire?', a: 'No. As long as your account is active, your points stay with you.' },
    { q: 'Can I earn as both an owner and a buyer?', a: 'Yes. There is one wallet per account, and every action across both roles adds to the same balance.' },
    { q: 'How are redeemed vouchers delivered?', a: 'Digitally, to your registered email, within 24 hours of redemption.' },
];

// ============================================
// PIECES
// ============================================
function PrizePool({ pool, delay }) {
    const Icon = pool.icon;
    return (
        <Reveal delay={delay} className="h-full">
            <div className="flex h-full flex-col rounded-2xl border border-slate-200 bg-white">
                <div className="border-b border-slate-100 p-6">
                    <div className="flex h-11 w-11 items-center justify-center rounded-xl bg-red-50">
                        <Icon className="h-5 w-5 text-red-600" aria-hidden="true" />
                    </div>
                    <h3 className="mt-4 text-lg font-bold tracking-tight text-slate-900">{pool.label}</h3>
                    <p className="mt-1 text-sm text-slate-500">{pool.blurb}</p>
                    <p className="mt-4 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                        Top prize
                    </p>
                    <p className="text-2xl font-extrabold tracking-tight text-slate-900 tabular-nums">
                        {rupees(pool.max)}
                    </p>
                </div>

                {/* The rupee column is the point of this table. The old version
                    listed points only, and the exchange rate sat in an FAQ six
                    screens further down — so nobody could tell what a prize
                    was actually worth. */}
                <table className="w-full flex-1 text-sm">
                    <caption className="sr-only">{pool.label} prize tiers, rarest last</caption>
                    <thead>
                        <tr className="text-[10px] uppercase tracking-wider text-slate-400">
                            <th scope="col" className="px-6 pb-2 pt-4 text-left font-semibold">Odds</th>
                            <th scope="col" className="px-2 pb-2 pt-4 text-right font-semibold">Points</th>
                            <th scope="col" className="px-6 pb-2 pt-4 text-right font-semibold">Value</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-100">
                        {pool.tiers.map((t) => {
                            const top = t.rarity === 'Legendary';
                            return (
                                <tr key={t.points} className={top ? 'bg-amber-50/60' : undefined}>
                                    <td className={`px-6 py-2.5 text-xs ${top ? 'font-semibold text-amber-700' : 'text-slate-500'}`}>
                                        {t.rarity}
                                    </td>
                                    <td className="px-2 py-2.5 text-right tabular-nums text-slate-500">
                                        {t.points.toLocaleString('en-IN')}
                                    </td>
                                    <td className={`px-6 py-2.5 text-right font-semibold tabular-nums ${top ? 'text-amber-700' : 'text-slate-900'}`}>
                                        {rupees(t.points)}
                                    </td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
            </div>
        </Reveal>
    );
}

function FaqItem({ question, answer, isOpen, onToggle, id }) {
    return (
        <div className="border-b border-slate-200 last:border-0">
            <h3>
                <button
                    id={`rw-q-${id}`}
                    type="button"
                    onClick={onToggle}
                    aria-expanded={isOpen}
                    aria-controls={`rw-a-${id}`}
                    className="group flex w-full items-center justify-between gap-4 py-5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500"
                >
                    <span className={`text-[15px] font-semibold ${isOpen ? 'text-red-600' : 'text-slate-800'}`}>
                        {question}
                    </span>
                    <ChevronDown className={`h-5 w-5 shrink-0 text-slate-400 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`} />
                </button>
            </h3>
            <div
                id={`rw-a-${id}`}
                aria-labelledby={`rw-q-${id}`}
                className={`grid transition-[grid-template-rows] duration-300 ease-out ${isOpen ? 'grid-rows-[1fr]' : 'grid-rows-[0fr]'}`}
            >
                <div className="overflow-hidden">
                    <p className="max-w-[65ch] pb-5 text-sm leading-relaxed text-slate-600">{answer}</p>
                </div>
            </div>
        </div>
    );
}

// ============================================
// MAIN
// ============================================
export default function RewardsContent() {
    const { isAuthenticated } = useAuth();
    const [openFaq, setOpenFaq] = useState(null);

    const startHref = isAuthenticated ? '/rewards/dashboard' : '/register';

    return (
        <div className="min-h-screen bg-white text-slate-900">

            {/* ===== HERO =====
                The one place a full saturated brand block earns its keep. The
                floating bouncing icons that used to sit here were pure motion
                noise; the number row carries the same energy and says something. */}
            <section className="relative overflow-hidden bg-gradient-to-br from-red-600 via-red-700 to-rose-800 px-4 py-20 sm:px-6 sm:py-28">
                <div className="pointer-events-none absolute inset-0">
                    <div className="absolute -left-24 top-0 h-80 w-80 rounded-full bg-white/5 blur-3xl" />
                    <div className="absolute -right-16 bottom-0 h-96 w-96 rounded-full bg-amber-400/10 blur-3xl" />
                </div>

                <div className="relative z-10 mx-auto max-w-3xl text-center">
                    <span className="inline-flex items-center gap-2 rounded-full border border-white/20 bg-white/10 px-4 py-1.5 text-sm font-medium text-white/90 backdrop-blur-md">
                        <Trophy className="h-4 w-4 text-amber-300" aria-hidden="true" />
                        DealDirect Property Hunt
                    </span>

                    <h1 className="mt-7 text-4xl font-extrabold leading-[1.08] tracking-tight text-white sm:text-5xl lg:text-6xl">
                        Every property hides
                        <br />
                        <span className="bg-gradient-to-r from-amber-300 to-yellow-200 bg-clip-text text-transparent">
                            a reward inside.
                        </span>
                    </h1>

                    <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-white/80">
                        Post a property, close a deal, or send an enquiry. Each one opens a door,
                        and behind every door is a reward worth real money.
                    </p>

                    <div className="mt-9 flex flex-wrap justify-center gap-3">
                        <Link
                            href={startHref}
                            className="inline-flex items-center gap-2 rounded-full bg-white px-8 py-3.5 text-base font-bold text-red-700 shadow-lg transition-transform duration-200 hover:scale-[1.03] focus:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-offset-2 focus-visible:ring-offset-red-700"
                        >
                            <Rocket className="h-4 w-4" aria-hidden="true" /> Start your Property Hunt
                        </Link>
                        <a
                            href="#prizes"
                            className="inline-flex items-center gap-2 rounded-full border border-white/25 bg-white/10 px-8 py-3.5 text-base font-semibold text-white backdrop-blur-md transition-colors hover:bg-white/20"
                        >
                            See the prizes <ChevronDown className="h-4 w-4" aria-hidden="true" />
                        </a>
                    </div>

                    <dl className="mx-auto mt-14 grid max-w-lg grid-cols-3 gap-6">
                        {[
                            { value: '₹5,000', label: 'Top posting prize' },
                            { value: '₹21,000', label: 'Top sale Shagun' },
                            { value: '₹100', label: 'Top enquiry prize' },
                        ].map((stat) => (
                            <div key={stat.label} className="text-center">
                                <dt className="sr-only">{stat.label}</dt>
                                <dd>
                                    <span className="block text-2xl font-extrabold tabular-nums text-white sm:text-3xl">
                                        {stat.value}
                                    </span>
                                    <span className="mt-1 block text-xs text-white/60 sm:text-sm">{stat.label}</span>
                                </dd>
                            </div>
                        ))}
                    </dl>
                </div>
            </section>

            {/* ===== HOW IT WORKS ===== */}
            <section className="border-b border-slate-100 px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto max-w-6xl">
                    <div className="max-w-2xl">
                        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                            How it works
                        </p>
                        <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl">
                            Three actions. One draw each.
                        </h2>
                        <p className="mt-4 text-[17px] leading-relaxed text-slate-600">
                            There is no points-per-rupee formula to work out. Do any of the three things
                            below and the system draws a reward from that pool at random. The more you
                            do, the more draws you get.
                        </p>
                    </div>

                    <ol className="mt-12 grid gap-5 sm:grid-cols-3">
                        {POOLS.map((pool, i) => {
                            const Icon = pool.icon;
                            return (
                                <Reveal key={pool.id} delay={i * 100} className="h-full">
                                    <li className="flex h-full list-none flex-col rounded-2xl border border-slate-200 bg-slate-50 p-6">
                                        <div className="flex items-center gap-3">
                                            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-white text-sm font-bold tabular-nums text-slate-400 ring-1 ring-slate-200">
                                                {i + 1}
                                            </span>
                                            <Icon className="h-5 w-5 text-red-600" aria-hidden="true" />
                                        </div>
                                        <h3 className="mt-4 text-lg font-bold tracking-tight text-slate-900">
                                            {pool.label}
                                        </h3>
                                        <p className="mt-1.5 text-sm leading-relaxed text-slate-600">{pool.blurb}</p>
                                        <p className="mt-auto pt-5 text-sm font-semibold text-slate-900">
                                            Win up to{' '}
                                            <span className="tabular-nums text-red-600">{rupees(pool.max)}</span>
                                        </p>
                                    </li>
                                </Reveal>
                            );
                        })}
                    </ol>
                </div>
            </section>

            {/* ===== PRIZES ===== */}
            <section id="prizes" className="scroll-mt-24 bg-slate-50 px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto max-w-6xl">
                    <div className="max-w-2xl">
                        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                            Prize pools
                        </p>
                        <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl">
                            Exactly what you can win.
                        </h2>
                        <p className="mt-4 text-[17px] leading-relaxed text-slate-600">
                            Every prize in every pool, with what it is worth in rupees.
                            Common prizes come up most often; the legendary row is genuinely rare.
                        </p>
                    </div>

                    <div className="mt-12 grid gap-5 lg:grid-cols-3">
                        {POOLS.map((pool, i) => (
                            <PrizePool key={pool.id} pool={pool} delay={i * 100} />
                        ))}
                    </div>

                    <p className="mt-6 text-sm text-slate-500">
                        1 point = ₹0.05.{' '}
                        <Link href="/rewards/terms" className="font-medium text-red-600 underline underline-offset-4 hover:text-red-700">
                            Full terms and conditions
                        </Link>
                    </p>
                </div>
            </section>

            {/* ===== TIERS + FIXED REWARDS ===== */}
            <section className="border-b border-slate-100 px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto max-w-6xl">
                    <div className="max-w-2xl">
                        <p className="inline-flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                            <TrendingUp className="h-3.5 w-3.5" aria-hidden="true" />
                            Tiers
                        </p>
                        <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl">
                            Higher tiers win bigger.
                        </h2>
                        <p className="mt-4 text-[17px] leading-relaxed text-slate-600">
                            Your tier comes from lifetime points and multiplies every reward you draw
                            after reaching it.
                        </p>
                    </div>

                    <div className="mt-10 grid grid-cols-2 gap-4 lg:grid-cols-4">
                        {TIERS.map((tier, i) => {
                            const Icon = tier.icon;
                            const isTop = tier.name === 'Diamond';
                            return (
                                <Reveal key={tier.name} delay={i * 80} className="h-full">
                                    <div className={`flex h-full flex-col rounded-2xl border p-5 ${isTop ? 'border-slate-900 bg-slate-900' : 'border-slate-200 bg-white'}`}>
                                        <Icon
                                            className={`h-5 w-5 ${isTop ? 'text-amber-300' : 'text-slate-400'}`}
                                            aria-hidden="true"
                                        />
                                        <h3 className={`mt-4 text-lg font-bold tracking-tight ${isTop ? 'text-white' : 'text-slate-900'}`}>
                                            {tier.name}
                                        </h3>
                                        <p className={`mt-1 text-sm tabular-nums ${isTop ? 'text-white/60' : 'text-slate-500'}`}>
                                            {tier.range}
                                        </p>
                                        <p className={`mt-auto pt-4 text-sm font-semibold ${isTop ? 'text-amber-300' : 'text-slate-900'}`}>
                                            {tier.bonus}
                                        </p>
                                    </div>
                                </Reveal>
                            );
                        })}
                    </div>

                    {/* Fixed rewards — no draw involved, so they sit apart from the pools */}
                    <div className="mt-12 grid gap-5 sm:grid-cols-2">
                        {[
                            { icon: Users, title: 'Refer a friend', desc: 'They sign up with your referral code, you both earn.', points: 100 },
                            { icon: Flag, title: 'Report a misleading listing', desc: 'Help keep the platform worth trusting.', points: 100 },
                        ].map((item, i) => {
                            const Icon = item.icon;
                            return (
                                <Reveal key={item.title} delay={i * 100} className="h-full">
                                    <div className="flex h-full items-start gap-4 rounded-2xl border border-slate-200 bg-white p-6">
                                        <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-red-50">
                                            <Icon className="h-5 w-5 text-red-600" aria-hidden="true" />
                                        </span>
                                        <div>
                                            <h3 className="text-base font-bold tracking-tight text-slate-900">{item.title}</h3>
                                            <p className="mt-1 text-sm text-slate-600">{item.desc}</p>
                                            <p className="mt-3 inline-flex items-center gap-1.5 text-sm font-semibold text-slate-900">
                                                <Check className="h-4 w-4 text-emerald-600" aria-hidden="true" />
                                                <span className="tabular-nums">+{item.points} pts</span>
                                                <span className="font-normal text-slate-500">({rupees(item.points)}), guaranteed</span>
                                            </p>
                                        </div>
                                    </div>
                                </Reveal>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* ===== FAQ ===== */}
            <section className="px-4 py-16 sm:px-6 sm:py-20">
                <div className="mx-auto grid max-w-6xl gap-10 lg:grid-cols-[1fr_1.4fr] lg:gap-16">
                    <div>
                        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                            Questions
                        </p>
                        <h2 className="mt-3 text-3xl font-extrabold tracking-tight text-slate-900 sm:text-4xl">
                            About rewards.
                        </h2>
                        <p className="mt-4 text-[17px] leading-relaxed text-slate-600">
                            Everything else — listings, safety, how DealDirect works — is in the
                            main help centre.
                        </p>
                        <Link
                            href="/faq"
                            className="mt-5 inline-flex items-center gap-2 text-sm font-semibold text-red-600 hover:text-red-700"
                        >
                            Go to the FAQs <ArrowRight className="h-4 w-4" aria-hidden="true" />
                        </Link>
                    </div>

                    <div className="rounded-2xl border border-slate-200 bg-white px-6">
                        {FAQS.map((faq, i) => (
                            <FaqItem
                                key={i}
                                id={i}
                                question={faq.q}
                                answer={faq.a}
                                isOpen={openFaq === i}
                                onToggle={() => setOpenFaq(openFaq === i ? null : i)}
                            />
                        ))}
                    </div>
                </div>
            </section>

            {/* ===== CLOSING CTA ===== */}
            <section className="relative overflow-hidden bg-slate-900 px-4 py-20 sm:px-6 sm:py-24">
                <div className="pointer-events-none absolute inset-0">
                    <div className="absolute right-0 top-0 h-96 w-96 rounded-full bg-red-600/10 blur-3xl" />
                    <div className="absolute bottom-0 left-0 h-72 w-72 rounded-full bg-amber-400/10 blur-3xl" />
                </div>
                <div className="relative z-10 mx-auto max-w-2xl text-center">
                    <Coins className="mx-auto h-8 w-8 text-amber-300" aria-hidden="true" />
                    <h2 className="mt-6 text-3xl font-extrabold leading-tight tracking-tight text-white sm:text-4xl">
                        Your next listing could be worth ₹21,000.
                    </h2>
                    <p className="mt-5 text-lg leading-relaxed text-slate-400">
                        Post, sell, enquire. Every action opens a door.
                    </p>
                    <Link
                        href={startHref}
                        className="mt-9 inline-flex items-center gap-2 rounded-full bg-red-600 px-8 py-3.5 text-base font-bold text-white shadow-lg transition-colors hover:bg-red-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-red-500 focus-visible:ring-offset-2 focus-visible:ring-offset-slate-900"
                    >
                        Start your Property Hunt <ArrowRight className="h-4 w-4" aria-hidden="true" />
                    </Link>
                </div>
            </section>
        </div>
    );
}
