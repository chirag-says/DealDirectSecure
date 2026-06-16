'use client';

import React, { useState, useEffect, useRef } from 'react';
import Link from 'next/link';
import { useAuth } from '../../context/AuthContext';
import {
    Home, Gift, TrendingUp, Award, Gem, BarChart3,
    ArrowRight, ChevronDown, Rocket, Star, Users, ShieldAlert,
    Sparkles, DoorOpen, Building2, Landmark, Castle, Hotel,
    Trophy, Coins,
} from 'lucide-react';

// ============================================
// ANIMATION HOOK
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

// ============================================
// PRIZE TIER ROW
// ============================================
function PrizeTierRow({ points, rarity, delay }) {
    const [ref, visible] = useRevealOnScroll(0.1);
    const rarityConfig = {
        common: { label: 'Common', color: 'bg-gray-100 text-gray-600', bar: 'bg-gray-300' },
        uncommon: { label: 'Uncommon', color: 'bg-green-100 text-green-700', bar: 'bg-green-400' },
        rare: { label: 'Rare', color: 'bg-blue-100 text-blue-700', bar: 'bg-blue-500' },
        epic: { label: 'Epic', color: 'bg-purple-100 text-purple-700', bar: 'bg-purple-500' },
        legendary: { label: 'Legendary', color: 'bg-amber-100 text-amber-700', bar: 'bg-gradient-to-r from-amber-400 to-yellow-500' },
    };
    const rc = rarityConfig[rarity] || rarityConfig.common;

    return (
        <div
            ref={ref}
            className={`flex items-center justify-between py-3 px-4 rounded-xl transition-all duration-700 ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'} hover:bg-white/60 group`}
            style={{ transitionDelay: `${delay}ms` }}
        >
            <span className={`text-xs font-bold px-2.5 py-1 rounded-full ${rc.color}`}>{rc.label}</span>
            <span className="text-gray-800 font-bold text-[15px] group-hover:text-red-600 transition-colors">
                {points.toLocaleString()} pts
            </span>
        </div>
    );
}

// ============================================
// TIER CARD (reused)
// ============================================
function TierCard({ icon: Icon, name, range, bonus, color, delay }) {
    const [ref, visible] = useRevealOnScroll(0.1);
    return (
        <div
            ref={ref}
            className={`relative overflow-hidden rounded-2xl p-6 border backdrop-blur-sm transition-all duration-700 hover:scale-105 hover:shadow-xl ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'}`}
            style={{ transitionDelay: `${delay}ms`, background: color.bg, borderColor: color.border }}
        >
            <div className="absolute top-0 right-0 w-24 h-24 rounded-full opacity-10 -mr-6 -mt-6" style={{ background: color.accent }}></div>
            <div className="w-12 h-12 rounded-xl flex items-center justify-center mb-3" style={{ backgroundColor: color.accent + '18' }}>
                <Icon className="w-6 h-6" style={{ color: color.accent }} />
            </div>
            <h4 className="font-bold text-lg text-gray-900">{name}</h4>
            <p className="text-sm text-gray-500 mt-1">{range}</p>
            <div className="mt-4 pt-3 border-t" style={{ borderColor: color.border }}>
                <span className="font-semibold text-sm" style={{ color: color.accent }}>{bonus}</span>
            </div>
        </div>
    );
}

// ============================================
// FAQ ACCORDION
// ============================================
function FaqItem({ question, answer, isOpen, onToggle }) {
    return (
        <div className="border-b border-gray-200 last:border-0">
            <button onClick={onToggle} className="flex items-center justify-between w-full py-5 px-1 text-left group">
                <span className="font-semibold text-gray-800 text-[15px] group-hover:text-red-600 transition-colors pr-4">{question}</span>
                <ChevronDown className={`w-5 h-5 text-gray-400 shrink-0 transition-transform duration-300 ${isOpen ? 'rotate-180' : ''}`} />
            </button>
            <div className={`overflow-hidden transition-all duration-300 ${isOpen ? 'max-h-40 pb-4' : 'max-h-0'}`}>
                <p className="text-gray-600 text-sm leading-relaxed px-1">{answer}</p>
            </div>
        </div>
    );
}

// ============================================
// PROPERTY HUNT DOOR CARD
// ============================================
function PropertyDoor({ icon: DoorIcon, label, maxPoints, delay }) {
    const [ref, visible] = useRevealOnScroll(0.1);
    return (
        <div
            ref={ref}
            className={`relative bg-white rounded-2xl border-2 border-gray-100 p-6 text-center transition-all duration-700 hover:shadow-xl hover:border-red-200 hover:scale-105 group cursor-pointer ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-6'}`}
            style={{ transitionDelay: `${delay}ms` }}
        >
            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-50 to-amber-50 flex items-center justify-center mx-auto mb-4 group-hover:scale-110 transition-transform">
                <DoorIcon className="w-8 h-8 text-red-500" />
            </div>
            <h4 className="font-bold text-gray-900 mb-1">{label}</h4>
            <p className="text-sm text-gray-500 mb-3">Tap to discover your reward</p>
            <div className="bg-gradient-to-r from-amber-500 to-orange-500 text-white text-sm font-bold px-4 py-2 rounded-full inline-block">
                Win up to {maxPoints.toLocaleString()} pts
            </div>
        </div>
    );
}

// ============================================
// MAIN COMPONENT
// ============================================
export default function RewardsContent() {
    const { isAuthenticated } = useAuth();
    const [openFaq, setOpenFaq] = useState(null);
    const [heroRef, heroVisible] = useRevealOnScroll(0.1);

    const faqCategories = [
        {
            category: "General Questions",
            items: [
                { q: 'What is Deal Direct?', a: 'Deal Direct is a specialized property portal designed to eliminate middlemen. We connect owners, buyers, and actual tenants directly to save you from paying heavy brokerage fees.' },
                { q: 'Is Deal Direct really free from brokers?', a: 'Yes. Our platform is built with strict filters and a "one post per user" policy to ensure that only genuine individuals—not agencies—are listing properties.' }
            ]
        },
        {
            category: "Posting & Listings",
            items: [
                { q: 'Why can I only post one property?', a: 'To maintain a spam-free environment and ensure high-quality listings, we restrict users to one active post. This prevents brokers from flooding the site with duplicate entries and ensures that every listing comes from a real person.' },
                { q: 'Can I edit or delete my post?', a: 'Absolutely. You can update your listing details or mark it as "Sold/Rented" at any time from your dashboard. Once a post is deleted, you are free to post a new one.' },
                { q: 'How do I make my listing stand out?', a: 'Since you only have one post, make it count! Use high-quality photos, provide a detailed description, and be transparent about the price and amenities.' }
            ]
        },
        {
            category: "Rewards & Referrals",
            items: [
                { q: 'How do I earn rewards on Deal Direct?', a: 'You earn rewards for being an active part of the community! This includes: Posting a verified property, making genuine enquiries on listings, closing a deal through the platform, and referring friends and family.' },
                { q: 'How do I refer someone?', a: 'Go to your "Rewards" tab to find your unique referral link. Share this link via WhatsApp, Email, or Social Media. When someone signs up using your link, you both get rewarded!' },
                { q: 'What can I do with my reward points?', a: 'Points can be redeemed for partner vouchers, premium listing boosts, or cashback.' },
                { q: 'How much is 1 point worth?', a: '1 point = ₹0.05. So 1,000 points = ₹50 in real value that you can redeem for vouchers and rewards.' },
                { q: 'How are rewards decided?', a: 'Every time you post a property, make an enquiry, or close a deal — you enter a Property Hunt. The system randomly picks your reward from a prize pool. Lower prizes are more common, but you could hit a jackpot!' },
                { q: 'Do my points expire?', a: 'No, as long as your account remains active your points stay with you.' },
                { q: 'Can I earn as both an owner and a buyer?', a: 'Yes. Your wallet is unified. Every action across both roles adds to the same balance.' },
                { q: 'How are redeemed vouchers delivered?', a: 'Digitally to your registered email within 24 hours of redemption.' }
            ]
        },
        {
            category: "Safety & Trust",
            items: [
                { q: 'Is my data safe?', a: 'We take privacy seriously. Your contact information is only shared with genuine users you choose to interact with. We never sell your data to third-party telemarketers.' },
                { q: 'How do I report a suspicious listing?', a: 'If you encounter a broker or a suspicious post, click the "Report" button on the listing page. Our team reviews every report within 24 hours to keep the platform clean.' }
            ]
        }
    ];

    // Prize data for the 3 categories (key tiers only)
    const postingPrizes = [
        { points: 40, cashValue: 2, rarity: 'common' },
        { points: 100, cashValue: 5, rarity: 'common' },
        { points: 200, cashValue: 10, rarity: 'common' },
        { points: 1000, cashValue: 50, rarity: 'uncommon' },
        { points: 5000, cashValue: 250, rarity: 'rare' },
        { points: 10000, cashValue: 500, rarity: 'rare' },
        { points: 40000, cashValue: 2000, rarity: 'epic' },
        { points: 100000, cashValue: 5000, rarity: 'legendary' },
    ];

    const salePrizes = [
        { points: 1000, cashValue: 50, rarity: 'common' },
        { points: 2000, cashValue: 100, rarity: 'common' },
        { points: 10000, cashValue: 500, rarity: 'uncommon' },
        { points: 30000, cashValue: 1500, rarity: 'rare' },
        { points: 50000, cashValue: 2500, rarity: 'rare' },
        { points: 102000, cashValue: 5100, rarity: 'epic' },
        { points: 300000, cashValue: 15000, rarity: 'epic' },
        { points: 420000, cashValue: 21000, rarity: 'legendary' },
    ];

    const enquiryPrizes = [
        { points: 20, cashValue: 1, rarity: 'common' },
        { points: 40, cashValue: 2, rarity: 'common' },
        { points: 100, cashValue: 5, rarity: 'uncommon' },
        { points: 400, cashValue: 20, rarity: 'rare' },
        { points: 1000, cashValue: 50, rarity: 'rare' },
        { points: 1600, cashValue: 80, rarity: 'epic' },
        { points: 2000, cashValue: 100, rarity: 'legendary' },
    ];

    return (
        <div className="min-h-screen bg-gradient-to-b from-gray-50 to-white">

            {/* ===== HERO SECTION ===== */}
            <section className="relative overflow-hidden pt-28 pb-20 sm:pt-36 sm:pb-28">
                <div className="absolute inset-0 bg-gradient-to-br from-red-600 via-red-700 to-rose-800"></div>

                {/* Decorative */}
                <div className="absolute inset-0 overflow-hidden">
                    <div className="absolute top-10 left-10 w-72 h-72 bg-white/5 rounded-full blur-3xl animate-pulse"></div>
                    <div className="absolute bottom-10 right-10 w-96 h-96 bg-amber-400/10 rounded-full blur-3xl animate-pulse" style={{ animationDelay: '1s' }}></div>
                    {/* Floating property icons */}
                    {[
                        { top: '15%', left: '8%', delay: '0s', Icon: Home },
                        { top: '25%', right: '12%', delay: '0.5s', Icon: Building2 },
                        { bottom: '20%', left: '15%', delay: '1s', Icon: Landmark },
                        { top: '40%', right: '20%', delay: '1.5s', Icon: Coins },
                        { bottom: '30%', right: '8%', delay: '2s', Icon: Trophy },
                    ].map((item, i) => (
                        <div key={i} className="absolute animate-bounce hidden lg:block" style={{ top: item.top, bottom: item.bottom, left: item.left, right: item.right, animationDelay: item.delay, animationDuration: '3s' }}>
                            <div className="w-10 h-10 rounded-full bg-white/10 backdrop-blur-sm flex items-center justify-center">
                                <item.Icon className="w-5 h-5 text-white/70" />
                            </div>
                        </div>
                    ))}
                </div>

                <div ref={heroRef} className={`relative z-10 max-w-4xl mx-auto text-center px-4 sm:px-6 transition-all duration-1000 ${heroVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}`}>
                    <div className="inline-flex items-center gap-2 bg-white/15 backdrop-blur-md rounded-full px-5 py-2 mb-8 border border-white/20">
                        <Trophy className="w-4 h-4 text-amber-300" />
                        <span className="text-white/90 text-sm font-medium">DealDirect Property Hunt</span>
                    </div>

                    <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-white leading-tight tracking-tight">
                        Every Property Hides
                        <br />
                        <span className="bg-clip-text text-transparent bg-gradient-to-r from-amber-300 to-yellow-200">
                            A Reward Inside.
                        </span>
                    </h1>

                    <p className="mt-6 text-lg sm:text-xl text-white/80 max-w-2xl mx-auto leading-relaxed">
                        Post a property? <strong className="text-white">Get up to ₹5,000.</strong>{' '}
                        Sell on DealDirect? <strong className="text-white">Get up to ₹21,000 as Shagun.</strong>{' '}
                        Send an enquiry? <strong className="text-white">Win rewards every time.</strong>
                    </p>



                    <div className="mt-8 flex flex-wrap justify-center gap-4">
                        <Link
                            href={isAuthenticated ? '/rewards/dashboard' : '/register'}
                            className="inline-flex items-center gap-2 bg-white text-red-700 px-8 py-3.5 rounded-full font-bold text-base shadow-xl hover:shadow-2xl hover:scale-105 transition-all duration-300"
                        >
                            <Rocket className="w-4 h-4" /> Start Your Property Hunt
                        </Link>
                        <a href="#property-hunt" className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-md text-white px-8 py-3.5 rounded-full font-semibold text-base border border-white/25 hover:bg-white/20 transition-all duration-300">
                            See How It Works <ChevronDown className="w-4 h-4" />
                        </a>
                    </div>

                    {/* Stats bar */}
                    <div className="mt-14 grid grid-cols-3 gap-6 max-w-lg mx-auto">
                        {[
                            { value: '100K', label: 'Max Posting Pts' },
                            { value: '500K', label: 'Max Sale Pts' },
                            { value: '2K', label: 'Max Enquiry Pts' },
                        ].map((stat, i) => (
                            <div key={i} className="text-center">
                                <div className="text-2xl sm:text-3xl font-extrabold text-white">{stat.value}</div>
                                <div className="text-xs sm:text-sm text-white/60 mt-1">{stat.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* ===== SECTION 1: PROPERTY HUNT CONCEPT ===== */}
            <section id="property-hunt" className="py-20 sm:py-24 px-4 sm:px-6">
                <div className="max-w-3xl mx-auto text-center">
                    <div className="w-16 h-16 rounded-2xl bg-red-100 flex items-center justify-center mx-auto mb-6">
                        <DoorOpen className="w-8 h-8 text-red-600" />
                    </div>
                    <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900 inline-flex items-center gap-3 justify-center w-full">
                        How Property Hunt Works
                    </h2>
                    <div className="mt-8 space-y-4 text-gray-600 text-base sm:text-lg leading-relaxed">
                        <p>
                            Every time you <strong className="text-gray-800">post a property, sell a property, or send an enquiry</strong> —
                            you open a random door in the Property Hunt. Behind each door is a reward, and you never know if you hit 
                            the jackpot. The more active you are, the more doors you open.
                        </p>
                        <p className="text-gray-800 font-medium">
                            <span className="text-red-600">Lower prizes are more common.</span> But every once in a while,
                            someone opens the golden door and wins big. <span className="text-red-600">Will it be you?</span>
                        </p>
                    </div>
                </div>

                {/* Property Hunt Doors */}
                <div className="max-w-4xl mx-auto mt-14 grid grid-cols-1 sm:grid-cols-3 gap-6">
                    <PropertyDoor icon={Home} label="Post Property" maxPoints={100000} delay={0} />
                    <PropertyDoor icon={Castle} label="Sell Property" maxPoints={500000} delay={150} />
                    <PropertyDoor icon={Hotel} label="Send Enquiry" maxPoints={2000} delay={300} />
                </div>
            </section>

            {/* ===== SECTION 2: POSTING PRIZES ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6 bg-gradient-to-br from-blue-50/50 to-indigo-50/50">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-10">
                        <div className="w-14 h-14 rounded-2xl bg-blue-100 flex items-center justify-center mx-auto mb-4">
                            <Home className="w-7 h-7 text-blue-600" />
                        </div>
                        <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900">Property Posting Rewards</h2>
                        <p className="text-gray-500 mt-3 text-base">
                            Post a property and open a door. Over <strong>1 Lac property postings</strong> get rewarded up to <strong className="text-red-600">₹5,000</strong> for the post.
                        </p>
                    </div>
                    <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-100 shadow-sm divide-y divide-gray-100">
                        {postingPrizes.map((item, i) => (
                            <PrizeTierRow key={i} points={item.points} cashValue={item.cashValue} rarity={item.rarity} delay={i * 60} />
                        ))}
                    </div>
                    <p className="text-center text-gray-500 text-sm mt-4 italic">Common rewards are most frequent. Legendary rewards are extremely rare.</p>
                </div>
            </section>

            {/* ===== SECTION 3: SALE PRIZES ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-10">
                        <div className="w-14 h-14 rounded-2xl bg-green-100 flex items-center justify-center mx-auto mb-4">
                            <Sparkles className="w-7 h-7 text-green-600" />
                        </div>
                        <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900 inline-flex items-center gap-3 justify-center w-full">
                            Property Sale Shagun <Gift className="w-8 h-8 text-green-500 inline" />
                        </h2>
                        <p className="text-gray-500 mt-3 text-base">
                            If your property gets sold on DealDirect, get up to <strong className="text-red-600">₹21,000 as Shagun</strong> from us. It&apos;s our way of celebrating your deal.
                        </p>
                    </div>
                    <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-100 shadow-sm divide-y divide-gray-100">
                        {salePrizes.map((item, i) => (
                            <PrizeTierRow key={i} points={item.points} cashValue={item.cashValue} rarity={item.rarity} delay={i * 60} />
                        ))}
                    </div>
                    <p className="text-center text-gray-500 text-sm mt-4 italic">The bigger the jackpot, the rarer it is. But someone always wins!</p>
                </div>
            </section>

            {/* ===== SECTION 4: ENQUIRY PRIZES ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6 bg-gradient-to-br from-amber-50/50 to-orange-50/50">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-10">
                        <div className="w-14 h-14 rounded-2xl bg-amber-100 flex items-center justify-center mx-auto mb-4">
                            <BarChart3 className="w-7 h-7 text-amber-600" />
                        </div>
                        <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900">Property Enquiry Rewards</h2>
                        <p className="text-gray-500 mt-3 text-base">
                            Every enquiry you send opens a door. Win up to <strong className="text-red-600">₹100</strong> in rewards.
                        </p>
                    </div>
                    <div className="bg-white/70 backdrop-blur-sm rounded-2xl border border-gray-100 shadow-sm divide-y divide-gray-100">
                        {enquiryPrizes.map((item, i) => (
                            <PrizeTierRow key={i} points={item.points} cashValue={item.cashValue} rarity={item.rarity} delay={i * 60} />
                        ))}
                    </div>
                </div>
            </section>

            {/* ===== SECTION 5: FIXED REWARDS ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-10">
                        <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900">More Ways to Earn</h2>
                        <p className="text-gray-500 mt-3 text-base">Fixed rewards — no luck required!</p>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-6 max-w-xl mx-auto">
                        {[
                            { icon: Users, title: 'Refer a Friend', desc: 'When your friend signs up using your referral code', points: 100, value: '₹5' },
                            { icon: ShieldAlert, title: 'Report Misleading Property', desc: 'Help keep DealDirect trustworthy', points: 100, value: '₹5' },
                        ].map((item, i) => {
                            const [ref, visible] = useRevealOnScroll(0.1);
                            return (
                                <div
                                    key={i}
                                    ref={ref}
                                    className={`bg-white rounded-2xl border border-gray-100 shadow-sm p-6 transition-all duration-700 hover:shadow-lg ${visible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-4'}`}
                                    style={{ transitionDelay: `${i * 100}ms` }}
                                >
                                    <div className="w-12 h-12 rounded-xl bg-red-50 flex items-center justify-center mb-4">
                                        <item.icon className="w-6 h-6 text-red-500" />
                                    </div>
                                    <h4 className="font-bold text-gray-900 text-lg">{item.title}</h4>
                                    <p className="text-gray-500 text-sm mt-1">{item.desc}</p>
                                    <div className="mt-4">
                                        <span className="bg-gradient-to-r from-amber-500 to-orange-500 text-white text-sm font-bold px-3 py-1 rounded-full">+{item.points} pts</span>
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                </div>
            </section>

            {/* ===== SECTION 6: TIERS ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6 bg-gradient-to-br from-gray-50 to-slate-50">
                <div className="max-w-4xl mx-auto">
                    <div className="text-center mb-12">
                        <div className="w-14 h-14 rounded-2xl bg-red-100 flex items-center justify-center mx-auto mb-4">
                            <TrendingUp className="w-7 h-7 text-red-600" />
                        </div>
                        <h2 className="text-3xl sm:text-4xl font-extrabold text-gray-900">
                            Earn More with Higher Tiers
                        </h2>
                        <p className="text-gray-500 mt-3 text-base max-w-2xl mx-auto">
                            Your tier is determined by your total lifetime points. Higher tiers give a bonus multiplier
                            on every reward — so Gold and Diamond members win bigger prizes.
                        </p>
                    </div>
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 sm:gap-6">
                        <TierCard icon={Award} name="Bronze" range="0 – 999 pts" bonus="Standard rewards" delay={0}
                            color={{ bg: 'linear-gradient(135deg, #fafaf5, #f5efe0)', border: '#e5dcc8', accent: '#a38b5e' }} />
                        <TierCard icon={Award} name="Silver" range="1,000 – 4,999 pts" bonus="+10% on all rewards" delay={100}
                            color={{ bg: 'linear-gradient(135deg, #f5f7fa, #e8ecf1)', border: '#c8ced8', accent: '#7b8a9e' }} />
                        <TierCard icon={Star} name="Gold" range="5,000 – 14,999 pts" bonus="+25% on all rewards" delay={200}
                            color={{ bg: 'linear-gradient(135deg, #fdf6e3, #fbecc0)', border: '#f0d78c', accent: '#c5940a' }} />
                        <TierCard icon={Gem} name="Diamond" range="15,000+ pts" bonus="+50% on all rewards" delay={300}
                            color={{ bg: 'linear-gradient(135deg, #ecf4ff, #d4e6ff)', border: '#a8c8f0', accent: '#3b82f6' }} />
                    </div>
                </div>
            </section>



            {/* ===== SECTION 8: FAQs ===== */}
            <section className="py-16 sm:py-20 px-4 sm:px-6 bg-gradient-to-br from-gray-50 to-slate-50">
                <div className="max-w-2xl mx-auto">
                    <div className="text-center mb-10">
                        <h2 className="text-3xl font-extrabold text-gray-900">Frequently Asked Questions</h2>
                    </div>
                    <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-6 sm:p-8 space-y-8">
                        {faqCategories.map((categoryGroup, catIdx) => (
                            <div key={catIdx}>
                                <h3 className="text-xl font-bold text-gray-800 mb-4 pb-2 border-b border-gray-100">
                                    {categoryGroup.category}
                                </h3>
                                <div>
                                    {categoryGroup.items.map((faq, itemIdx) => {
                                        const uniqueId = `${catIdx}-${itemIdx}`;
                                        return (
                                            <FaqItem 
                                                key={itemIdx} 
                                                question={faq.q} 
                                                answer={faq.a} 
                                                isOpen={openFaq === uniqueId} 
                                                onToggle={() => setOpenFaq(openFaq === uniqueId ? null : uniqueId)} 
                                            />
                                        );
                                    })}
                                </div>
                            </div>
                        ))}
                    </div>
                    <div className="text-center mt-6">
                        <Link href="/rewards/terms" className="text-red-600 hover:text-red-700 text-sm font-medium underline underline-offset-4">
                            Read full Terms &amp; Conditions →
                        </Link>
                    </div>
                </div>
            </section>

            {/* ===== CLOSING CTA ===== */}
            <section className="relative py-20 sm:py-24 px-4 sm:px-6 overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-gray-900 via-slate-900 to-gray-900"></div>
                <div className="absolute inset-0 overflow-hidden">
                    <div className="absolute top-0 right-0 w-96 h-96 bg-red-600/10 rounded-full blur-3xl"></div>
                    <div className="absolute bottom-0 left-0 w-72 h-72 bg-amber-400/10 rounded-full blur-3xl"></div>
                </div>
                <div className="relative z-10 max-w-2xl mx-auto text-center">
                    <h2 className="text-3xl sm:text-4xl font-extrabold text-white leading-tight">
                        Your next property could open a ₹21,000 door.
                    </h2>
                    <p className="mt-5 text-gray-400 text-base sm:text-lg leading-relaxed">
                        Start your Property Hunt today. Post, sell, enquire — every action opens a door. Your biggest reward is waiting.
                    </p>
                    <div className="mt-10 flex flex-wrap justify-center gap-4">
                        <Link
                            href={isAuthenticated ? '/rewards/dashboard' : '/register'}
                            className="inline-flex items-center gap-2 bg-red-600 text-white px-8 py-3.5 rounded-full font-bold text-base shadow-xl hover:bg-red-700 hover:scale-105 transition-all duration-300"
                        >
                            Start Your Property Hunt
                        </Link>
                        <a href="#property-hunt" className="inline-flex items-center gap-2 bg-white/10 backdrop-blur-md text-white px-8 py-3.5 rounded-full font-semibold text-base border border-white/20 hover:bg-white/20 transition-all duration-300">
                            See How It Works
                        </a>
                    </div>
                </div>
            </section>
        </div>
    );
}
