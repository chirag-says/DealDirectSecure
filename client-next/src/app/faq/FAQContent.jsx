'use client';

import React, { useState } from "react";
import {
    FaQuestionCircle,
    FaChevronDown,
    FaShieldAlt,
    FaClipboardList,
    FaGift,
    FaLock,
    FaBuilding,
    FaArrowRight,
    FaPlus,
    FaMinus
} from "react-icons/fa";
import { useRouter } from "next/navigation";

const faqCategories = [
    {
        title: "General Questions",
        icon: <FaBuilding />,
        gradient: "from-blue-500 to-indigo-600",
        accentColor: "text-blue-600",
        accentBg: "bg-blue-50",
        accentBorder: "border-blue-500",
        ringColor: "ring-blue-100",
        questions: [
            {
                q: "What is Deal Direct?",
                a: "Deal Direct is a specialized property portal designed to eliminate middlemen. We connect owners, buyers, and actual tenants directly to save you from paying heavy brokerage fees."
            },
            {
                q: "Is Deal Direct really free from brokers?",
                a: "Yes. Our platform is built with strict filters and a \"one post per user\" policy to ensure that only genuine individuals — not agencies — are listing properties."
            }
        ]
    },
    {
        title: "Posting & Listings",
        icon: <FaClipboardList />,
        gradient: "from-purple-500 to-violet-600",
        accentColor: "text-purple-600",
        accentBg: "bg-purple-50",
        accentBorder: "border-purple-500",
        ringColor: "ring-purple-100",
        questions: [
            {
                q: "Why can I only post one property?",
                a: "To maintain a spam-free environment and ensure high-quality listings, we restrict users to one active post. This prevents brokers from flooding the site with duplicate entries and ensures that every listing comes from a real person."
            },
            {
                q: "Can I edit or delete my post?",
                a: "Absolutely. You can update your listing details or mark it as \"Sold/Rented\" at any time from your dashboard. Once a post is deleted, you are free to post a new one."
            },
            {
                q: "How do I make my listing stand out?",
                a: "Since you only have one post, make it count! Use high-quality photos, provide a detailed description, and be transparent about the price and amenities."
            }
        ]
    },
    {
        title: "Rewards & Referrals",
        icon: <FaGift />,
        gradient: "from-emerald-500 to-green-600",
        accentColor: "text-emerald-600",
        accentBg: "bg-emerald-50",
        accentBorder: "border-emerald-500",
        ringColor: "ring-emerald-100",
        questions: [
            {
                q: "How do I earn rewards on Deal Direct?",
                a: "You earn rewards for being an active part of the community! This includes posting a verified property, making genuine enquiries on listings, closing a deal through the platform, and referring friends and family."
            },
            {
                q: "How do I refer someone?",
                a: "Go to your \"Rewards\" tab to find your unique referral link. Share this link via WhatsApp, Email, or Social Media. When someone signs up using your link, you both get rewarded!"
            },
            {
                q: "What can I do with my reward points?",
                a: "Points can be redeemed for partner vouchers, premium listing boosts, or cashback. Check the Rewards section in your dashboard for the latest redemption options."
            }
        ]
    },
    {
        title: "Safety & Trust",
        icon: <FaLock />,
        gradient: "from-amber-500 to-orange-600",
        accentColor: "text-orange-600",
        accentBg: "bg-orange-50",
        accentBorder: "border-orange-500",
        ringColor: "ring-orange-100",
        questions: [
            {
                q: "Is my data safe?",
                a: "We take privacy seriously. Your contact information is only shared with genuine users you choose to interact with. We never sell your data to third-party telemarketers."
            },
            {
                q: "How do I report a suspicious listing?",
                a: "If you encounter a broker or a suspicious post, click the \"Report\" button on the listing page. Our team reviews every report within 24 hours to keep the platform clean."
            }
        ]
    }
];

export default function FAQContent() {
    const router = useRouter();
    const [openItems, setOpenItems] = useState({});
    const [activeCategory, setActiveCategory] = useState(0);

    const toggleItem = (catIdx, qIdx) => {
        const key = `${catIdx}-${qIdx}`;
        setOpenItems(prev => ({ ...prev, [key]: !prev[key] }));
    };

    return (
        <div className="font-sans text-gray-900 bg-gradient-to-b from-white via-gray-50/50 to-white min-h-screen">

            {/* Hero Section */}
            <section className="relative py-20 md:py-28 overflow-hidden">
                {/* Background decoration */}
                <div className="absolute inset-0 overflow-hidden">
                    <div className="absolute -top-24 -right-24 w-96 h-96 bg-red-50 rounded-full blur-3xl opacity-60"></div>
                    <div className="absolute -bottom-24 -left-24 w-96 h-96 bg-blue-50 rounded-full blur-3xl opacity-60"></div>
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-gradient-to-r from-red-50 to-orange-50 rounded-full blur-3xl opacity-30"></div>
                </div>

                <div className="relative z-10 max-w-4xl mx-auto px-6 text-center">
                    <div className="inline-flex items-center gap-2 mb-8 px-5 py-2.5 rounded-full border border-red-200 bg-white/80 backdrop-blur-sm text-red-600 text-sm font-semibold tracking-wide shadow-sm">
                        <FaQuestionCircle className="text-red-500" />
                        <span>Help Center</span>
                    </div>

                    <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight leading-tight mb-6 text-gray-900">
                        Got <span className="bg-gradient-to-r from-red-600 to-red-500 bg-clip-text text-transparent">Questions?</span>
                        <br />
                        We&apos;ve Got Answers.
                    </h1>

                    <p className="text-lg md:text-xl text-gray-500 max-w-2xl mx-auto leading-relaxed">
                        Everything you need to know about Deal Direct — from listings and rewards to safety and trust.
                    </p>

                    {/* Quick stat pills */}
                    <div className="flex flex-wrap justify-center gap-3 mt-10">
                        {[
                            { label: "4 Categories", val: "📂" },
                            { label: "10+ Answers", val: "💡" },
                            { label: "24/7 Support", val: "🎧" },
                        ].map((s, i) => (
                            <div key={i} className="flex items-center gap-2 px-4 py-2 bg-white rounded-full border border-gray-100 shadow-sm text-sm text-gray-600">
                                <span>{s.val}</span>
                                <span className="font-medium">{s.label}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Category Navigation Tabs */}
            <section className="sticky top-[72px] z-30 bg-white/90 backdrop-blur-xl border-b border-gray-100 shadow-sm">
                <div className="max-w-4xl mx-auto px-6">
                    <div className="flex overflow-x-auto no-scrollbar gap-1 py-3">
                        {faqCategories.map((cat, idx) => (
                            <button
                                key={idx}
                                onClick={() => {
                                    setActiveCategory(idx);
                                    document.getElementById(`faq-cat-${idx}`)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                                }}
                                className={`flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold whitespace-nowrap transition-all duration-200 ${
                                    activeCategory === idx
                                        ? `bg-gradient-to-r ${cat.gradient} text-white shadow-md`
                                        : 'text-gray-500 hover:text-gray-800 hover:bg-gray-50'
                                }`}
                            >
                                {cat.icon}
                                {cat.title}
                            </button>
                        ))}
                    </div>
                </div>
            </section>

            {/* FAQ Content */}
            <section className="py-12 md:py-16 px-6">
                <div className="max-w-4xl mx-auto space-y-16">
                    {faqCategories.map((cat, catIdx) => (
                        <div key={catIdx} id={`faq-cat-${catIdx}`} className="scroll-mt-36">
                            {/* Category Header */}
                            <div className="flex items-center gap-4 mb-6">
                                <div className={`w-12 h-12 rounded-2xl bg-gradient-to-br ${cat.gradient} flex items-center justify-center text-white text-xl shadow-lg`}>
                                    {cat.icon}
                                </div>
                                <div>
                                    <h2 className="text-2xl md:text-3xl font-bold text-gray-900">{cat.title}</h2>
                                    <p className="text-sm text-gray-400 mt-0.5">{cat.questions.length} questions</p>
                                </div>
                            </div>

                            {/* Questions Accordion */}
                            <div className="space-y-3">
                                {cat.questions.map((item, qIdx) => {
                                    const isOpen = openItems[`${catIdx}-${qIdx}`];
                                    return (
                                        <div
                                            key={qIdx}
                                            className={`group rounded-2xl border-2 transition-all duration-300 overflow-hidden ${
                                                isOpen
                                                    ? `${cat.accentBorder} ${cat.accentBg} shadow-lg ring-4 ${cat.ringColor}`
                                                    : 'border-gray-100 bg-white hover:border-gray-200 hover:shadow-md'
                                            }`}
                                        >
                                            <button
                                                onClick={() => toggleItem(catIdx, qIdx)}
                                                className="w-full flex items-center justify-between px-6 py-5 text-left gap-4"
                                            >
                                                <div className="flex items-center gap-4">
                                                    <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-all duration-300 ${
                                                        isOpen
                                                            ? `bg-gradient-to-br ${cat.gradient} text-white shadow-md`
                                                            : 'bg-gray-100 text-gray-400 group-hover:bg-gray-200'
                                                    }`}>
                                                        <span className="text-xs font-bold">{String(qIdx + 1).padStart(2, '0')}</span>
                                                    </div>
                                                    <span className={`font-semibold text-[15px] md:text-base transition-colors ${isOpen ? cat.accentColor : 'text-gray-800'}`}>
                                                        {item.q}
                                                    </span>
                                                </div>
                                                <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 transition-all duration-300 ${
                                                    isOpen
                                                        ? `bg-gradient-to-br ${cat.gradient} text-white`
                                                        : 'bg-gray-100 text-gray-400'
                                                }`}>
                                                    {isOpen ? <FaMinus className="text-[10px]" /> : <FaPlus className="text-[10px]" />}
                                                </div>
                                            </button>
                                            <div className={`transition-all duration-500 ease-in-out ${isOpen ? 'max-h-96 opacity-100' : 'max-h-0 opacity-0'}`}>
                                                <div className="px-6 pb-6 pl-[4.5rem] text-gray-600 text-[15px] leading-relaxed">
                                                    {item.a}
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    ))}
                </div>
            </section>

            {/* CTA Section */}
            <section className="py-16 md:py-20 px-6">
                <div className="max-w-4xl mx-auto">
                    <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-10 md:p-16 text-center shadow-2xl">
                        {/* Decorative elements */}
                        <div className="absolute top-0 right-0 w-64 h-64 bg-red-500/10 rounded-full blur-3xl"></div>
                        <div className="absolute bottom-0 left-0 w-64 h-64 bg-blue-500/10 rounded-full blur-3xl"></div>
                        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-red-500/5 rounded-full blur-3xl"></div>

                        <div className="relative z-10">
                            <div className="w-16 h-16 rounded-2xl bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center text-white mx-auto mb-8 shadow-lg shadow-red-500/30">
                                <FaShieldAlt className="text-2xl" />
                            </div>
                            <h2 className="text-3xl md:text-4xl font-bold mb-4 text-white">
                                Still have questions?
                            </h2>
                            <p className="text-gray-400 mb-10 max-w-xl mx-auto text-lg">
                                Can&apos;t find the answer you&apos;re looking for? Our support team is always here to help.
                            </p>
                            <div className="flex flex-wrap justify-center gap-4">
                                <button
                                    onClick={() => router.push('/contact')}
                                    className="bg-gradient-to-r from-red-600 to-red-500 text-white px-8 py-4 rounded-full font-bold hover:from-red-700 hover:to-red-600 transition-all duration-300 shadow-lg shadow-red-500/30 hover:shadow-xl hover:shadow-red-500/40 hover:scale-105 inline-flex items-center gap-2"
                                >
                                    Contact Support <FaArrowRight className="text-sm" />
                                </button>
                                <button
                                    onClick={() => router.push('/about')}
                                    className="bg-white/10 backdrop-blur-sm text-white px-8 py-4 rounded-full font-bold border border-white/20 hover:bg-white/20 transition-all duration-300 hover:scale-105"
                                >
                                    Learn About Us
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

        </div>
    );
}
