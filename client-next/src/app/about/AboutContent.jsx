'use client';

import React, { useEffect } from "react";
import { useRouter } from "next/navigation";
import {
    FaBuilding,
    FaHandshake,
    FaUserShield,
    FaChartLine,
    FaUsers,
    FaCheckCircle,
    FaMapMarkerAlt,
    FaHeadset,
    FaSearch,
    FaRegCommentDots,
    FaKey,
    FaArrowRight,
    FaShieldAlt,
    FaMoneyBillWave,
    FaGift,
    FaUserFriends
} from "react-icons/fa";
import { BsGraphUpArrow, BsHouseDoor } from "react-icons/bs";
import { useAuth } from "../../context/AuthContext";

export default function AboutContent() {
    const router = useRouter();
    const { isAuthenticated, user, ownerHasProperty } = useAuth();

    const handleListProperty = () => {
        if (!isAuthenticated) {
            router.push('/login?from=/add-property');
        } else {
            router.push('/add-property');
        }
    };

    return (
        <div className="font-sans text-gray-900 bg-white min-h-screen">

            {/* --- HERO SECTION --- */}
            <section className="relative py-16 md:py-24 bg-white overflow-hidden">
                <div className="relative z-10 max-w-6xl mx-auto px-6 text-center">
                    <div className="inline-flex items-center gap-2 mb-6 px-5 py-2 rounded-full border border-red-200 bg-red-50 text-red-600 text-sm font-semibold tracking-wide uppercase">
                        <FaBuilding className="text-red-500" />
                        <span>India&apos;s Leading PropTech Platform</span>
                    </div>

                    <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight leading-tight mb-6 text-gray-900">
                        About <span className="text-red-600">Deal Direct</span>
                    </h1>

                    <p className="text-lg md:text-xl text-gray-500 max-w-3xl mx-auto leading-relaxed mb-12">
                        <strong className="text-gray-800">DealDirect</strong>, a venture by <strong className="text-gray-800">Agrawal Business Network LLP</strong>, is revolutionizing the way India buys, sells, and rents properties. By connecting you directly with verified property owners, we eliminate middlemen and save you lakhs in brokerage fees — making real estate transactions <strong className="text-gray-800">transparent, simple, and affordable</strong>.
                    </p>

                    {/* Key Metrics */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 max-w-4xl mx-auto">
                        {[
                            { label: "Brokerage Saved", val: "₹50Cr+", icon: <BsGraphUpArrow className="text-green-500" /> },
                            { label: "Happy Families", val: "10,000+", icon: <FaUsers className="text-blue-500" /> },
                            { label: "Cities Covered", val: "12+", icon: <FaMapMarkerAlt className="text-orange-500" /> },
                            { label: "Verified Listings", val: "100%", icon: <FaCheckCircle className="text-red-500" /> }
                        ].map((stat, i) => (
                            <div key={i} className="group bg-white border border-gray-100 p-5 rounded-2xl shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 cursor-default">
                                <div className="text-2xl mb-2">{stat.icon}</div>
                                <div className="text-2xl md:text-3xl font-bold text-gray-900">{stat.val}</div>
                                <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">{stat.label}</div>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* --- OUR STORY SECTION --- */}
            <section className="py-16 px-6 bg-gray-50 relative overflow-hidden">
                <div className="max-w-6xl mx-auto">
                    <div className="grid md:grid-cols-2 gap-12 md:gap-16 items-center">
                        <div>
                            <div className="inline-flex items-center gap-2 mb-4 px-4 py-1.5 rounded-full bg-orange-50 border border-orange-200 text-orange-600 text-sm font-medium">
                                <BsHouseDoor className="text-sm" />
                                Our Story
                            </div>
                            <h2 className="text-3xl md:text-4xl font-bold mb-6 leading-tight text-gray-900">
                                Born from a Simple Question: <br />
                                <span className="text-red-600">Why Pay Brokerage?</span>
                            </h2>
                            <div className="space-y-4 text-gray-600 leading-relaxed">
                                <p>
                                    <strong>Agrawal Business Network LLP</strong> founded Deal Direct with a clear mission — to disrupt the traditional real estate brokerage model that has burdened Indian homebuyers and sellers for decades.
                                </p>
                                <p>
                                    We realized that in an age of digital connectivity, paying 1-2% brokerage (often lakhs of rupees!) to a middleman was outdated. Property owners and buyers should be able to connect directly.
                                </p>
                                <p>
                                    Today, we&apos;re proud to be India&apos;s fastest-growing PropTech platform, having helped thousands of families find their dream homes while saving them crores in brokerage fees.
                                </p>
                            </div>
                        </div>

                        <div className="relative">
                            <div className="absolute -top-4 -left-4 w-full h-full bg-red-100 rounded-3xl"></div>
                            <div className="relative bg-white rounded-3xl p-8 md:p-10 border border-gray-100 shadow-xl">
                                <div className="flex items-center gap-4 mb-6">
                                    <div className="w-16 h-16 rounded-2xl bg-red-600 flex items-center justify-center">
                                        <BsHouseDoor className="text-3xl text-white" />
                                    </div>
                                    <div>
                                        <h4 className="text-xl font-bold text-gray-900">Our Mission</h4>
                                        <p className="text-gray-500 text-sm">What drives us every day</p>
                                    </div>
                                </div>
                                <p className="text-gray-600 leading-relaxed text-lg italic border-l-4 border-red-500 pl-4">
                                    &quot;To make property transactions in India completely brokerage-free, transparent, and accessible to everyone — regardless of where they are or how much they have.&quot;
                                </p>
                            </div>
                        </div>
                    </div>
                </div>
            </section>

            {/* --- WHY DEAL DIRECT (VALUES) --- */}
            <section className="py-16 px-6 relative bg-white">
                <div className="max-w-6xl mx-auto">
                    <div className="text-center mb-12">
                        <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
                            The Deal Direct <span className="text-red-600">Advantage</span>
                        </h2>
                        <p className="text-gray-500 text-lg max-w-2xl mx-auto">
                            We&apos;re not just another property listing site. Here&apos;s what makes us different.
                        </p>
                    </div>

                    <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
                        {[
                            { icon: <FaUserShield className="text-3xl" />, title: "100% Verified Owners", desc: "Every property listing is verified. We ensure you deal only with genuine owners — no brokers, no fraud.", color: "bg-blue-600" },
                            { icon: <FaHandshake className="text-3xl" />, title: "Zero Brokerage", desc: "Connect directly with owners and save lakhs in brokerage fees. Your money stays in your pocket.", color: "bg-purple-600" },
                            { icon: <FaChartLine className="text-3xl" />, title: "Smart Insights", desc: "Get market trends, price history, and locality data to make informed property decisions.", color: "bg-green-600" },
                            { icon: <FaHeadset className="text-3xl" />, title: "24/7 Support", desc: "Our dedicated support team is always ready to help you through your property journey.", color: "bg-orange-600" }
                        ].map((item, i) => (
                            <div key={i} className="group bg-white p-6 md:p-8 rounded-2xl border border-gray-100 shadow-md hover:shadow-xl hover:-translate-y-2 transition-all duration-300">
                                <div className={`w-14 h-14 rounded-2xl ${item.color} flex items-center justify-center text-white mb-5 group-hover:scale-110 transition-transform`}>
                                    {item.icon}
                                </div>
                                <h3 className="text-lg font-bold mb-3 text-gray-900">{item.title}</h3>
                                <p className="text-gray-500 text-sm leading-relaxed">{item.desc}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* --- HOW DEAL DIRECT WORKS: REAL ESTATE, REIMAGINED --- */}
            <section className="py-16 md:py-20 px-6 bg-gray-50 relative overflow-hidden">
                <div className="max-w-6xl mx-auto relative z-10">
                    <div className="text-center mb-14">
                        <div className="inline-flex items-center gap-2 mb-4 px-4 py-1.5 rounded-full bg-red-50 border border-red-200 text-red-600 text-sm font-medium">
                            <FaBuilding className="text-sm" />
                            Real Estate, Reimagined
                        </div>
                        <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
                            How <span className="text-red-600">Deal Direct</span> Works
                        </h2>
                        <p className="text-gray-500 text-lg max-w-3xl mx-auto leading-relaxed">
                            Most property portals are built for brokers. Deal Direct is built for <strong className="text-gray-700">you</strong>. We&apos;ve stripped away the noise, the spam, and the expensive commissions to create a marketplace based on <strong className="text-gray-700">transparency and rewards</strong>.
                        </p>
                    </div>

                    <div className="grid md:grid-cols-2 gap-6 md:gap-8">

                        {/* Card 1: Anti-Spam */}
                        <div className="group bg-white rounded-2xl p-8 shadow-md hover:shadow-xl transition-all duration-300 border border-gray-100 hover:-translate-y-1">
                            <div className="flex items-center gap-4 mb-5">
                                <div className="w-14 h-14 rounded-2xl bg-blue-600 flex items-center justify-center text-white group-hover:scale-110 transition-transform">
                                    <FaShieldAlt className="text-2xl" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-gray-900">The Power of &quot;One&quot;</h3>
                                    <span className="text-xs font-semibold text-blue-600 uppercase tracking-wider flex items-center gap-1"><FaShieldAlt className="text-[10px]" /> Anti-Spam Policy</span>
                                </div>
                            </div>
                            <p className="text-gray-600 leading-relaxed mb-4">
                                To ensure every listing is <strong>high-quality and genuine</strong>, we enforce a <strong className="text-blue-700">Strict 1-Post Per User</strong> rule.
                            </p>
                            <div className="space-y-3">
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Why?</strong> This prevents brokers from flooding the site with duplicate listings.</p>
                                </div>
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">The Result:</strong> Every property you see is from the actual owner or primary decision-maker. No clutter, just real options.</p>
                                </div>
                            </div>
                        </div>

                        {/* Card 2: Connect Directly */}
                        <div className="group bg-white rounded-2xl p-8 shadow-md hover:shadow-xl transition-all duration-300 border border-gray-100 hover:-translate-y-1">
                            <div className="flex items-center gap-4 mb-5">
                                <div className="w-14 h-14 rounded-2xl bg-purple-600 flex items-center justify-center text-white group-hover:scale-110 transition-transform">
                                    <FaMoneyBillWave className="text-2xl" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-gray-900">Connect Directly, Save Lacs</h3>
                                    <span className="text-xs font-semibold text-purple-600 uppercase tracking-wider flex items-center gap-1"><FaMoneyBillWave className="text-[10px]" /> Zero Brokerage</span>
                                </div>
                            </div>
                            <p className="text-gray-600 leading-relaxed mb-4">
                                We believe that finding a home shouldn&apos;t cost you a fortune in &quot;introduction fees.&quot;
                            </p>
                            <div className="space-y-3">
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Direct Communication:</strong> Browse, chat, and negotiate directly with owners, buyers, or actual tenants.</p>
                                </div>
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Zero Brokerage:</strong> Save anywhere from ₹50,000 to ₹5,00,000+ in brokerage fees depending on your deal size.</p>
                                </div>
                            </div>
                        </div>

                        {/* Card 3: Rewards */}
                        <div className="group bg-white rounded-2xl p-8 shadow-md hover:shadow-xl transition-all duration-300 border border-gray-100 hover:-translate-y-1">
                            <div className="flex items-center gap-4 mb-5">
                                <div className="w-14 h-14 rounded-2xl bg-green-600 flex items-center justify-center text-white group-hover:scale-110 transition-transform">
                                    <FaGift className="text-2xl" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-gray-900">Participate & Get Rewarded</h3>
                                    <span className="text-xs font-semibold text-green-600 uppercase tracking-wider flex items-center gap-1"><FaGift className="text-[10px]" /> Earn at Every Step</span>
                                </div>
                            </div>
                            <p className="text-gray-600 leading-relaxed mb-4">
                                Unlike other sites that just take your data, we <strong>value your engagement</strong>. Our ecosystem rewards you at every step:
                            </p>
                            <div className="space-y-3">
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Post a Property:</strong> Earn rewards just for listing your space.</p>
                                </div>
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Make Enquiries:</strong> Get credited for being an active seeker.</p>
                                </div>
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500"><strong className="text-gray-700">Close the Deal:</strong> We celebrate your success with special rewards once your transaction is complete.</p>
                                </div>
                            </div>
                        </div>

                        {/* Card 4: Referrals */}
                        <div className="group bg-white rounded-2xl p-8 shadow-md hover:shadow-xl transition-all duration-300 border border-gray-100 hover:-translate-y-1">
                            <div className="flex items-center gap-4 mb-5">
                                <div className="w-14 h-14 rounded-2xl bg-orange-500 flex items-center justify-center text-white group-hover:scale-110 transition-transform">
                                    <FaUserFriends className="text-2xl" />
                                </div>
                                <div>
                                    <h3 className="text-xl font-bold text-gray-900">Grow the Community</h3>
                                    <span className="text-xs font-semibold text-orange-600 uppercase tracking-wider flex items-center gap-1"><FaUserFriends className="text-[10px]" /> Referral Rewards</span>
                                </div>
                            </div>
                            <p className="text-gray-600 leading-relaxed mb-4">
                                Know someone looking to buy, sell, or rent? <strong>Refer them to Deal Direct!</strong>
                            </p>
                            <div className="space-y-3">
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500">When your friends join and use the platform, <strong className="text-gray-700">you get rewarded</strong>.</p>
                                </div>
                                <div className="flex items-start gap-3">
                                    <FaCheckCircle className="text-green-500 mt-1 shrink-0" />
                                    <p className="text-sm text-gray-500">It&apos;s our way of building a <strong className="text-gray-700">community of trust</strong> where everyone wins.</p>
                                </div>
                            </div>
                        </div>

                    </div>
                </div>
            </section>

            {/* --- VISION SECTION --- */}
            <section className="py-16 px-6 relative bg-white overflow-hidden">
                <div className="max-w-4xl mx-auto text-center relative z-10">
                    <h2 className="text-3xl md:text-4xl font-bold mb-6 leading-tight text-gray-900">
                        Building a <span className="text-red-600">Brokerage-Free India</span>
                    </h2>
                    <p className="text-lg text-gray-600 leading-relaxed max-w-3xl mx-auto mb-10">
                        We envision a future where every Indian can buy, sell, or rent property without paying a single rupee in brokerage. Through technology, transparency, and trust, we&apos;re making this vision a reality — one transaction at a time.
                    </p>

                    <div className="flex flex-wrap justify-center gap-3 text-sm">
                        {["Transparent Pricing", "No Hidden Fees", "Verified Listings", "Direct Connections", "Secure Platform"].map((tag, i) => (
                            <span key={i} className="px-4 py-2 bg-gray-50 border border-gray-200 rounded-full text-gray-600 hover:border-red-300 hover:text-red-600 transition-colors cursor-default">
                                {tag}
                            </span>
                        ))}
                    </div>
                </div>
            </section>

            {/* --- CTA SECTION --- */}
            <section className="py-16 px-6 relative overflow-hidden bg-gray-50">
                <div className="max-w-4xl mx-auto text-center relative z-10">
                    <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
                        Ready to Find Your <span className="text-red-600">Dream Home?</span>
                    </h2>
                    <p className="text-gray-500 text-lg mb-10 max-w-2xl mx-auto">
                        Join thousands of happy families who found their perfect property through Deal Direct — without paying any brokerage.
                    </p>
                    <div className="flex flex-wrap justify-center gap-4">
                        <button
                            onClick={() => router.push('/properties')}
                            className="bg-red-600 text-white px-8 py-4 rounded-full font-bold hover:bg-red-700 transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center gap-2"
                        >
                            Browse Properties <FaArrowRight className="text-sm" />
                        </button>
                        {!(user?.role === 'owner' && ownerHasProperty) && (
                            <button
                                onClick={handleListProperty}
                                className="bg-white text-gray-900 px-8 py-4 rounded-full font-bold border border-gray-200 hover:border-red-300 hover:text-red-600 transition-all duration-300 shadow-md hover:shadow-lg"
                            >
                                List Your Property
                            </button>
                        )}
                        <button
                            onClick={() => router.push('/contact')}
                            className="border border-gray-300 text-gray-600 px-8 py-4 rounded-full font-bold hover:bg-white hover:border-gray-400 transition-all duration-300"
                        >
                            Contact Us
                        </button>
                    </div>
                </div>
            </section>

        </div>
    );
}
