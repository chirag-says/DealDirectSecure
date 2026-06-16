'use client';

import React, { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import Image from "next/image";
import dynamic from "next/dynamic";
import api from "../utils/api";

import {
    AiOutlineDollarCircle,
    AiOutlineHeart
} from "react-icons/ai";
import {
    FaBuilding,
    FaMapMarkerAlt,
    FaChevronLeft,
    FaChevronRight,
    FaSearch,
    FaRegCommentDots,
    FaKey,
    FaShieldAlt,
    FaUserFriends,
    FaUsers,
    FaRegClock,
    FaArrowRight,
    FaCheckCircle
} from "react-icons/fa";
import HeroSection from "../components/HeroSection/HeroSection";
const TopLocalities = dynamic(
  () => import("../components/TopLocalities/TopLocalities"),
  { ssr: false, loading: () => <div style={{ minHeight: '200px' }} /> }
);
const PressMarquee = dynamic(
  () => import("../components/PressMarquee/PressMarquee"),
  { ssr: false, loading: () => <div style={{ minHeight: '80px' }} /> }
);
import { formatPrice } from "../utils/formatPrice";

import { FaRupeeSign } from "react-icons/fa";

// Asset Imports
import MumbaiIcon from "../assets/Mumbai.png";
import DelhiIcon from "../assets/Delhi.png";
import BangaloreIcon from "../assets/Bangalore.png";
import HyderabadIcon from "../assets/Hyderabad.png";
import PuneIcon from "../assets/Pune.png";
import ChennaiIcon from "../assets/chennai.png";
import KolkataIcon from "../assets/kolkata.png";
import AhmedabadIcon from "../assets/ahmedabad.png";
import GurgaonIcon from "../assets/Gurgaon.png";
import NoidaIcon from "../assets/noida.png";
import ChandigarhIcon from "../assets/chandigarh.png";
import JaipurIcon from "../assets/jaipur.png";

const API_BASE = process.env.NEXT_PUBLIC_API_BASE;

const parseBudgetValue = (label) => {
    if (!label) return null;
    const cleaned = label.replace(/₹|,/g, "").trim().toLowerCase();
    if (!cleaned) return null;

    if (cleaned.includes("crore")) {
        const amount = parseFloat(cleaned.replace("crore", "")) || 0;
        return amount * 10000000;
    }

    if (cleaned.includes("lakh")) {
        const amount = parseFloat(
            cleaned.replace("lakhs", "").replace("lakh", "")
        ) || 0;
        return amount * 100000;
    }

    const numeric = parseFloat(cleaned.replace(/[^0-9.]/g, ""));
    return Number.isNaN(numeric) ? null : Math.round(numeric);
};

const normalizePrice = (price, unit) => {
    const amount = Number(price) || 0;
    const normalizedUnit = (unit || "").toLowerCase();

    if (normalizedUnit.includes("crore")) return amount * 10000000;
    if (normalizedUnit.includes("lac") || normalizedUnit.includes("lakh")) return amount * 100000;
    return amount;
};

const formatCategoryDisplay = (name) => {
    const value = (name || "").toString();
    const lower = value.toLowerCase();
    if (lower.includes("commercial land")) return "Commercial Property";
    if (lower.includes("commercial property")) return "Commercial Property";
    if (lower.includes("residential land") || lower.includes("residential plot")) return "Residential Property";
    if (lower.includes("commercial plot")) return "Commercial Property";
    if (lower === "plot" || lower === "plots" || lower.includes("plot & land") || lower.includes("plots & land")) {
        return "Residential Property";
    }
    if (lower.includes("residential")) return "Residential Property";
    if (lower.includes("commercial")) return "Commercial Property";
    return value || "Property";
};

const HomeContent = ({ initialProperties = [], initialCategories = [], initialPropertyTypes = [], initialLatestPosts = [], initialBuilderProperties = [] }) => {
    const [properties] = useState(initialProperties);
    const [builderProperties] = useState(initialBuilderProperties);
    const [categories] = useState(initialCategories);
    const [subcategories, setSubcategories] = useState([]);
    const [propertyTypeOptions] = useState(initialPropertyTypes);
    const [filters, setFilters] = useState({
        search: "",
        category: "",
        subcategory: "",
        city: "",
        state: "",
        minBudget: "",
        maxBudget: "",
        propertyTypes: [],
    });
    const router = useRouter();
    const scrollRef = useRef(null);
    const builderScrollRef = useRef(null);
    const propertiesSectionRef = useRef(null);

    const handleCityClick = (cityName) => {
        router.push(`/properties?city=${encodeURIComponent(cityName)}`);
    };

    const scroll = (direction, ref) => {
        if (ref.current) {
            const { current } = ref;
            const scrollAmount = 320;
            if (direction === 'left') {
                current.scrollBy({ left: -scrollAmount, behavior: 'smooth' });
            } else {
                current.scrollBy({ left: scrollAmount, behavior: 'smooth' });
            }
        }
    };

    const resolveImageSrc = (img) => {
        if (!img) return "";
        const lower = img.toLowerCase();
        if (lower.startsWith("data:")) return img;
        if (lower.startsWith("http://") || lower.startsWith("https://")) return img;
        if (img.startsWith("/uploads")) return `${API_BASE}${img}`;
        return `${API_BASE}/uploads/${img}`;
    };

    // Properties, categories, and property types are now pre-fetched on the server
    // and passed via props. Only subcategories are fetched client-side on filter change.

    useEffect(() => {
        const fetchSubcategories = async () => {
            if (!filters.category) {
                setSubcategories([]);
                return;
            }
            try {
                const res = await api.get(
                    `/subcategories/byCategory/${filters.category}`
                );
                setSubcategories(res.data.data || res.data || []);
            } catch (error) {
                console.error("Error fetching subcategories:", error);
            }
        };
        fetchSubcategories();
    }, [filters.category]);

    const handleViewDetails = (property) => {
        router.push(`/properties/${property._id}`);
    };

    return (
        <div className="font-sans text-gray-900 bg-white min-h-screen">

            <HeroSection
                filters={filters}
                setFilters={setFilters}
                categories={categories}
                subcategories={subcategories}
                propertyTypes={propertyTypeOptions}
            />

            {/* 🏙 Featured Properties */}
            <section ref={propertiesSectionRef} className="relative py-10 bg-white">
                <div className="max-w-7xl mx-auto px-6">
                    <div className="flex flex-col sm:justify-between sm:flex-row  justify-center items-center sm:items-end mb-3">
                        <div>
                            <h2 className="text-[1.65rem] sm:text-3xl text-center sm:text-left font-bold text-gray-900">
                                Popular <span className="text-red-600">Properties</span>
                            </h2>
                            <p className="text-gray-500 mt-2 text-sm sm:text-base text-center sm:text-left max-w-lg">
                                Handpicked premium homes and investments across India&apos;s top cities.
                            </p>
                        </div>

                        <button
                            onClick={() => router.push('/properties')}
                            className="text-red-600 py-2 text-sm sm:text-base font-semibold hover:text-red-700 transition flex items-center gap-1.5 sm:gap-2 pb-1 border-b-2 border-transparent hover:border-red-600"
                        >
                            View All <FaArrowRight className="text-xs sm:text-sm" />
                        </button>
                    </div>

                    {properties.length === 0 ? (
                        <p className="text-gray-500 text-lg text-center py-12 bg-gray-50 rounded-xl border border-dashed border-gray-200">No popular properties available right now.</p>
                    ) : (
                        <div className="relative group">
                            <button onClick={() => scroll('left', scrollRef)} className="absolute -left-2 sm:-left-4 top-1/2 -translate-y-1/2 z-10 w-8 h-8 sm:w-10 sm:h-10 bg-white backdrop-blur-sm rounded-full shadow-xl flex items-center justify-center text-gray-800 hover:text-red-600 transition-all border border-gray-100 opacity-0 group-hover:opacity-100">
                                <FaChevronLeft className="text-xs sm:text-sm" />
                            </button>

                            <button onClick={() => scroll('right', scrollRef)} className="absolute -right-2 sm:-right-4 top-1/2 -translate-y-1/2 z-10 w-8 h-8 sm:w-10 sm:h-10 bg-white backdrop-blur-sm rounded-full shadow-xl flex items-center justify-center text-gray-800 hover:text-red-600 transition-all border border-gray-100 opacity-0 group-hover:opacity-100">
                                <FaChevronRight className="text-xs sm:text-sm" />
                            </button>

                            <div ref={scrollRef} className="flex gap-6 overflow-x-auto pb-8 pt-2 snap-x snap-mandatory scrollbar-hide px-2" style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}>
                                {[...properties]
                                    .sort((a, b) => normalizePrice(b.price, b.priceUnit) - normalizePrice(a.price, a.priceUnit))
                                    .slice(0, 8)
                                    .map((property) => (
                                        <div
                                            key={property._id}
                                            onClick={() => handleViewDetails(property)}
                                            className="group relative bg-white rounded-2xl shadow-md hover:shadow-2xl hover:-translate-y-1 transition-all duration-300 border border-gray-100 overflow-hidden cursor-pointer min-w-[300px] w-[300px] flex-shrink-0 snap-start"
                                        >
                                            <div className="relative h-48 overflow-hidden">
                                                <div className="absolute top-3 left-3 z-10 bg-white/90 backdrop-blur text-slate-800 text-xs font-bold px-2 py-1 rounded shadow-sm">
                                                    {formatCategoryDisplay(property.category?.name || property.categoryName || property.category || property.propertyCategory)}
                                                </div>
                                                <div className="relative h-full w-full">
                                                    <Image
                                                        src={resolveImageSrc(property.images?.[0])}
                                                        alt={property.title}
                                                        fill
                                                        sizes="300px"
                                                        className="object-cover group-hover:scale-110 transition-transform duration-700"
                                                        onError={(e) => (e.currentTarget.src = 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800')}
                                                    />
                                                </div>
                                                <div className="absolute inset-0 bg-gradient-to-t from-black/50 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                                            </div>

                                            <div className="p-4">
                                                <h3 className="text-lg font-bold text-gray-900 mb-1 truncate">{property.title}</h3>
                                                <p className="text-sm text-gray-500 mb-3 flex items-center gap-1">
                                                    <FaMapMarkerAlt className="text-red-500" /> {property.address?.city}, {property.address?.state}
                                                </p>
                                                <div className="flex items-center justify-between border-t border-gray-100 pt-3 mt-3">
                                                    <p className="text-xl font-bold text-red-600">
                                                        {formatPrice(property.price)}
                                                    </p>
                                                    <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded-md">
                                                        {property.propertyTypeName || property.propertyType?.name}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                            </div>
                        </div>
                    )}
                </div>
            </section>

            {/* 🏗 Builder Projects Section */}
            {builderProperties.length > 0 && (
                <section className="relative py-10 bg-gradient-to-b from-indigo-50/60 to-white">
                    <div className="max-w-7xl mx-auto px-6">
                        <div className="flex flex-col sm:justify-between sm:flex-row justify-center items-center sm:items-end mb-3">
                            <div>
                                <h2 className="text-[1.65rem] sm:text-3xl text-center sm:text-left font-bold text-gray-900">
                                    Builder <span className="text-indigo-600">Projects</span>
                                </h2>
                                <p className="text-gray-500 mt-2 text-sm sm:text-base text-center sm:text-left max-w-lg">
                                    Premium developer projects — buy directly from verified builders.
                                </p>
                            </div>
                            <button
                                onClick={() => router.push('/projects')}
                                className="text-indigo-600 py-2 text-sm sm:text-base font-semibold hover:text-indigo-700 transition flex items-center gap-1.5 sm:gap-2 pb-1 border-b-2 border-transparent hover:border-indigo-600"
                            >
                                View All <FaArrowRight className="text-xs sm:text-sm" />
                            </button>
                        </div>

                        <div className="relative group">
                            <button onClick={() => scroll('left', builderScrollRef)} className="absolute -left-2 sm:-left-4 top-1/2 -translate-y-1/2 z-10 w-8 h-8 sm:w-10 sm:h-10 bg-white backdrop-blur-sm rounded-full shadow-xl flex items-center justify-center text-gray-800 hover:text-indigo-600 transition-all border border-gray-100 opacity-0 group-hover:opacity-100">
                                <FaChevronLeft className="text-xs sm:text-sm" />
                            </button>
                            <button onClick={() => scroll('right', builderScrollRef)} className="absolute -right-2 sm:-right-4 top-1/2 -translate-y-1/2 z-10 w-8 h-8 sm:w-10 sm:h-10 bg-white backdrop-blur-sm rounded-full shadow-xl flex items-center justify-center text-gray-800 hover:text-indigo-600 transition-all border border-gray-100 opacity-0 group-hover:opacity-100">
                                <FaChevronRight className="text-xs sm:text-sm" />
                            </button>

                            <div ref={builderScrollRef} className="flex gap-6 overflow-x-auto pb-8 pt-2 snap-x snap-mandatory scrollbar-hide px-2" style={{ scrollbarWidth: 'none', msOverflowStyle: 'none' }}>
                                {builderProperties.slice(0, 8).map((property) => {
                                    const builderName = property.builder?.company || property.builder?.name;
                                    const price = property.price;
                                    const normalizedPrice = normalizePrice(price, property.priceUnit);
                                    return (
                                        <div
                                            key={property._id}
                                            onClick={() => handleViewDetails(property)}
                                            className="group relative bg-white rounded-2xl shadow-md hover:shadow-2xl hover:-translate-y-1 transition-all duration-300 border border-indigo-100 overflow-hidden cursor-pointer min-w-[300px] w-[300px] flex-shrink-0 snap-start"
                                        >
                                            <div className="relative h-48 overflow-hidden">
                                                {/* Builder Project badge — top left (unchanged) */}
                                                <div className="absolute top-3 left-3 z-10">
                                                    <span className="bg-indigo-600 text-white text-[11px] font-bold px-2.5 py-1 rounded-full shadow-sm flex items-center gap-1">
                                                        <FaBuilding className="text-[10px]" /> Builder Project
                                                    </span>
                                                </div>

                                                {/* GROUP BUY — two-string hanging shop sign */}
                                                {property.groupBuyEnabled && (
                                                    <div style={{
                                                        position: 'absolute',
                                                        top: 0,
                                                        right: '16px',
                                                        zIndex: 20,
                                                        paddingTop: '18px',
                                                        filter: 'drop-shadow(0 3px 8px rgba(0,0,0,0.28))',
                                                    }}>
                                                        {/* Left string */}
                                                        <div style={{
                                                            position: 'absolute',
                                                            top: 0,
                                                            left: '18px',
                                                            width: '2px',
                                                            height: '18px',
                                                            background: '#92400e',
                                                            borderRadius: '1px',
                                                        }} />
                                                        {/* Right string */}
                                                        <div style={{
                                                            position: 'absolute',
                                                            top: 0,
                                                            right: '18px',
                                                            width: '2px',
                                                            height: '18px',
                                                            background: '#92400e',
                                                            borderRadius: '1px',
                                                        }} />
                                                        {/* Sign body — flat rectangle */}
                                                        <div style={{
                                                            position: 'relative',
                                                            display: 'flex',
                                                            alignItems: 'center',
                                                            gap: '7px',
                                                            background: 'linear-gradient(to right, #fdba74, #fed7aa)',
                                                            color: '#1e293b',
                                                            padding: '9px 18px',
                                                            border: '1.5px dashed rgba(30,41,59,0.45)',
                                                            boxShadow: '0 3px 8px rgba(0,0,0,0.22), inset 0 1px 0 rgba(255,255,255,0.4)',
                                                            whiteSpace: 'nowrap',
                                                        }}>
                                                            <FaUsers style={{ fontSize: '12px', flexShrink: 0 }} />
                                                            <span style={{ fontWeight: 900, fontSize: '12px', letterSpacing: '0.06em', textTransform: 'uppercase', lineHeight: 1 }}>GROUP BUY</span>
                                                        </div>
                                                    </div>
                                                )}


                                                <div className="relative h-full w-full">
                                                    <Image
                                                        src={resolveImageSrc(property.images?.[0])}
                                                        alt={property.title}
                                                        fill
                                                        sizes="300px"
                                                        className="object-cover group-hover:scale-110 transition-transform duration-700"
                                                        onError={(e) => (e.currentTarget.src = 'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800')}
                                                    />
                                                </div>
                                                <div className="absolute inset-0 bg-gradient-to-t from-black/60 to-transparent" />
                                                {builderName && (
                                                    <p className="absolute bottom-3 left-3 text-white text-[11px] font-semibold bg-black/40 backdrop-blur-sm px-2 py-0.5 rounded-lg">
                                                        🏗 {builderName}
                                                    </p>
                                                )}
                                            </div>

                                            <div className="p-4">
                                                <h3 className="text-base font-bold text-gray-900 mb-1 truncate">{property.title}</h3>
                                                <p className="text-sm text-gray-500 mb-3 flex items-center gap-1">
                                                    <FaMapMarkerAlt className="text-red-500" /> {property.address?.city}, {property.address?.state}
                                                </p>
                                                <div className="flex items-center justify-between border-t border-gray-100 pt-3 mt-3">
                                                    <p className="text-xl font-bold text-indigo-700">
                                                        {formatPrice(normalizedPrice || price)}
                                                    </p>
                                                    <span className="text-xs bg-indigo-50 text-indigo-700 px-2 py-1 rounded-md font-medium">
                                                        {property.propertyTypeName || property.propertyType?.name}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    );
                                })}
                            </div>
                        </div>
                    </div>
                </section>
            )}

            {/* 🛠 How Deal Direct Works Section */}
            <section className="py-8 sm:py-16 bg-white relative overflow-hidden">
                <div className="absolute top-0 left-0 w-96 h-96 bg-blue-100/50 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2"></div>
                <div className="absolute bottom-0 right-0 w-96 h-96 bg-purple-100/50 rounded-full blur-3xl translate-x-1/2 translate-y-1/2"></div>

                <div className="max-w-5xl mx-auto text-center px-4 sm:px-6 relative z-10">
                    <h2 className="text-2xl sm:text-4xl font-extrabold text-gray-900 mb-2 sm:mb-3 tracking-tight">
                        How Deal Direct Works
                    </h2>
                    <p className="text-gray-500 text-sm sm:text-lg mb-6 sm:mb-12 max-w-2xl mx-auto leading-relaxed">
                        Three simple steps to find your perfect property or sell directly to buyers
                    </p>
                </div>

                <div className="max-w-6xl mx-auto grid grid-cols-1 md:grid-cols-3 gap-6 sm:gap-10 px-4 sm:px-6 pt-6 sm:pt-12 pb-4 relative z-10">
                    <div className="group relative bg-white rounded-xl sm:rounded-2xl p-5 sm:p-8 shadow-lg hover:shadow-2xl transition-all duration-300 border border-gray-100 hover:border-blue-200 hover:-translate-y-2">
                        <div className="absolute -top-3 sm:-top-4 left-1/2 -translate-x-1/2 w-14 h-14 sm:w-20 sm:h-20 flex items-center justify-center bg-gradient-to-br from-blue-500 to-blue-600 rounded-xl sm:rounded-2xl shadow-xl text-2xl sm:text-4xl text-white group-hover:scale-110 transition-transform duration-300">
                            <FaSearch />
                        </div>
                        <div className="mt-6 sm:mt-10 text-center">
                            <h3 className="text-lg sm:text-2xl font-bold text-gray-900 mb-2 sm:mb-3">Search Properties</h3>
                            <p className="text-gray-500 text-sm sm:text-base leading-relaxed">
                                Browse thousands of listings directly from property owners.
                            </p>
                        </div>
                    </div>

                    <div className="group relative bg-white rounded-xl sm:rounded-2xl p-5 sm:p-8 shadow-lg hover:shadow-2xl transition-all duration-300 border border-gray-100 hover:border-purple-200 hover:-translate-y-2">
                        <div className="absolute -top-3 sm:-top-4 left-1/2 -translate-x-1/2 w-14 h-14 sm:w-20 sm:h-20 flex items-center justify-center bg-gradient-to-br from-purple-500 to-purple-600 rounded-xl sm:rounded-2xl shadow-xl text-2xl sm:text-4xl text-white group-hover:scale-110 transition-transform duration-300">
                            <FaRegCommentDots />
                        </div>
                        <div className="mt-6 sm:mt-10 text-center">
                            <h3 className="text-lg sm:text-2xl font-bold text-gray-900 mb-2 sm:mb-3">Connect Directly</h3>
                            <p className="text-gray-500 text-sm sm:text-base leading-relaxed">
                                Message property owners instantly. No intermediaries.
                            </p>
                        </div>
                    </div>

                    <div className="group relative bg-white rounded-xl sm:rounded-2xl p-5 sm:p-8 shadow-lg hover:shadow-2xl transition-all duration-300 border border-gray-100 hover:border-green-200 hover:-translate-y-2">
                        <div className="absolute -top-3 sm:-top-4 left-1/2 -translate-x-1/2 w-14 h-14 sm:w-20 sm:h-20 flex items-center justify-center bg-gradient-to-br from-green-500 to-green-600 rounded-xl sm:rounded-2xl shadow-xl text-2xl sm:text-4xl text-white group-hover:scale-110 transition-transform duration-300">
                            <FaKey />
                        </div>
                        <div className="mt-6 sm:mt-10 text-center">
                            <h3 className="text-lg sm:text-2xl font-bold text-gray-900 mb-2 sm:mb-3">Close the Deal</h3>
                            <p className="text-gray-500 text-sm sm:text-base leading-relaxed">
                                Negotiate directly and complete your deal confidently.
                            </p>
                        </div>
                    </div>
                </div>
            </section>

            {/* Why Choose Deal Direct Section */}
            <section className="py-8 sm:py-12 bg-white relative overflow-hidden">
                <div className="absolute inset-0 opacity-[0.4]" style={{
                    backgroundImage: 'radial-gradient(circle at 1px 1px, rgb(200 200 200) 1px, transparent 0)',
                    backgroundSize: '40px 40px'
                }}></div>

                <div className="max-w-6xl mx-auto text-center px-4 sm:px-6 relative z-10">
                    <h2 className="text-2xl sm:text-4xl font-extrabold text-gray-900 mb-2 sm:mb-4 tracking-tight">
                        Why Choose Deal Direct?
                    </h2>
                    <p className="text-gray-500 text-sm sm:text-lg mb-6 sm:mb-16 max-w-2xl mx-auto leading-relaxed">
                        Experience the benefits of direct property transactions
                    </p>
                </div>

                <div className="max-w-7xl mx-auto grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-6 sm:gap-12 px-4 sm:px-8 relative z-10">
                    {[
                        { icon: <FaRupeeSign className="w-7 h-7 sm:w-12 sm:h-12" />, title: "Zero Commission", desc: "Save thousands by connecting directly with owners." },
                        { icon: <FaRegClock className="w-7 h-7 sm:w-11 sm:h-11" />, title: "Faster Deals", desc: "Close deals quicker with direct communication." },
                        { icon: <FaShieldAlt className="w-7 h-7 sm:w-11 sm:h-11" />, title: "Secure Transactions", desc: "Safe and transparent property transactions." },
                        { icon: <FaUserFriends className="w-7 h-7 sm:w-11 sm:h-11" />, title: "Direct Communication", desc: "Chat directly with owners and get instant replies." },
                    ].map((item, i) => (
                        <div key={i} className="group text-center flex flex-col items-center transition-all duration-300 hover:-translate-y-2">
                            <div className="w-14 h-14 sm:w-24 sm:h-24 flex items-center justify-center bg-gradient-to-br from-orange-500 to-orange-600 rounded-2xl sm:rounded-3xl mb-3 sm:mb-6 text-2xl sm:text-4xl text-white shadow-lg group-hover:shadow-2xl group-hover:scale-105 transition-all duration-300">
                                {item.icon}
                            </div>
                            <h3 className="text-sm sm:text-xl font-bold text-gray-900 mb-1 sm:mb-3 tracking-tight">{item.title}</h3>
                            <p className="text-gray-500 text-xs sm:text-[15px] leading-relaxed max-w-[220px]">{item.desc}</p>
                        </div>
                    ))}
                </div>
            </section>

            <TopLocalities />

            {/* 🏙 Explore Popular Cities */}
            <section className="py-12 bg-white">
                <div className="max-w-7xl mx-auto px-6">
                    <h2 className="text-3xl font-bold text-gray-900 mb-4">
                        Explore by City
                    </h2>
                    <p className="text-gray-500 mb-10 max-w-3xl text-base leading-relaxed">
                        Discover city-wise insights and properties in India&apos;s most active real estate markets.
                    </p>

                    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-4">
                        {[
                            { name: "Mumbai", icon: MumbaiIcon },
                            { name: "Delhi", icon: DelhiIcon },
                            { name: "Bangalore", icon: BangaloreIcon },
                            { name: "Hyderabad", icon: HyderabadIcon },
                            { name: "Pune", icon: PuneIcon },
                            { name: "Chennai", icon: ChennaiIcon },
                            { name: "Kolkata", icon: KolkataIcon },
                            { name: "Ahmedabad", icon: AhmedabadIcon },
                            { name: "Gurgaon", icon: GurgaonIcon },
                            { name: "Noida", icon: NoidaIcon },
                            { name: "Chandigarh", icon: ChandigarhIcon },
                            { name: "Jaipur", icon: JaipurIcon },
                        ].map((city, index) => (
                            <div
                                key={index}
                                onClick={() => handleCityClick(city.name)}
                                className="flex flex-col items-center justify-center p-6 border border-gray-200 rounded-2xl bg-white hover:shadow-xl hover:-translate-y-1 transition-all cursor-pointer group"
                            >
                                <div className="w-14 h-14 flex items-center justify-center bg-gray-50 rounded-full mb-3 group-hover:bg-gray-100 transition-colors">
                                    <Image src={city.icon.src} alt={city.name} width={32} height={32} className="object-contain opacity-80 group-hover:opacity-100 transition-all" />
                                </div>
                                <span className="font-semibold text-gray-700 text-sm group-hover:text-red-600 transition-colors">{city.name}</span>
                            </div>
                        ))}
                    </div>
                </div>
            </section>

            {/* Latest from Blog */}
            <LatestBlogSection initialPosts={initialLatestPosts} />

            {/* Press Coverage Marquee */}
            <PressMarquee />
        </div>
    );
};


// ============================================
// LATEST BLOG SECTION
// ============================================

function LatestBlogSection({ initialPosts = [] }) {
    const posts = initialPosts;
    const loading = false;

    if (!loading && posts.length === 0) return null;

    return (
        <section className="py-16 bg-gray-50">
            <div className="max-w-6xl mx-auto px-6">
                <div className="flex items-center justify-between mb-10">
                    <div>
                        <span className="text-blue-600 text-sm font-semibold uppercase tracking-widest">Knowledge Base</span>
                        <h2 className="text-3xl font-extrabold text-gray-900 mt-1">Latest from Our Blog</h2>
                    </div>
                    <Link
                        href="/blog"
                        className="hidden sm:inline-flex items-center gap-2 text-blue-600 hover:text-blue-800 font-semibold text-sm transition-colors"
                    >
                        View all posts →
                    </Link>
                </div>

                {loading ? (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                        {[...Array(3)].map((_, i) => (
                            <div key={i} className="bg-white rounded-2xl overflow-hidden shadow-md animate-pulse">
                                <div className="h-44 bg-gray-200" />
                                <div className="p-5 space-y-3">
                                    <div className="h-4 bg-gray-200 rounded w-3/4" />
                                    <div className="h-3 bg-gray-200 rounded w-full" />
                                    <div className="h-3 bg-gray-200 rounded w-5/6" />
                                </div>
                            </div>
                        ))}
                    </div>
                ) : (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
                        {posts.map((post) => {
                            const date = post.publishedAt
                                ? new Date(post.publishedAt).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })
                                : '';
                            return (
                                <Link key={post._id} href={`/blog/${post.slug}`} className="group block">
                                    <article className="bg-white rounded-2xl overflow-hidden shadow-md border border-gray-100 hover:shadow-xl hover:-translate-y-1 transition-all duration-300">
                                        <div className="relative h-44 bg-gradient-to-br from-slate-700 to-blue-800 overflow-hidden">
                                            {post.coverImage ? (
                                                <Image
                                                    src={post.coverImage}
                                                    alt={post.title}
                                                    fill
                                                    sizes="(max-width: 768px) 100vw, 33vw"
                                                    className="object-cover group-hover:scale-105 transition-transform duration-500 opacity-90"
                                                />
                                            ) : (
                                                <div className="w-full h-full flex items-center justify-center">
                                                    <span className="text-5xl opacity-20">📝</span>
                                                </div>
                                            )}
                                            <div className="absolute top-3 left-3">
                                                <span className="bg-blue-100 text-blue-700 text-xs font-semibold px-2.5 py-1 rounded-full">{post.category}</span>
                                            </div>
                                        </div>
                                        <div className="p-5">
                                            <h3 className="font-bold text-gray-900 text-sm group-hover:text-blue-600 transition-colors mb-2 line-clamp-2 leading-snug">
                                                {post.title}
                                            </h3>
                                            <p className="text-gray-500 text-xs line-clamp-2 mb-3">{post.excerpt}</p>
                                            <div className="flex items-center gap-3 text-xs text-gray-400">
                                                <span>{date}</span>
                                                <span>·</span>
                                                <span>{post.readTime} min read</span>
                                            </div>
                                        </div>
                                    </article>
                                </Link>
                            );
                        })}
                    </div>
                )}

                <div className="text-center mt-8 sm:hidden">
                    <Link href="/blog" className="inline-flex items-center gap-2 text-blue-600 hover:text-blue-800 font-semibold text-sm">
                        View all posts →
                    </Link>
                </div>
            </div>
        </section>
    );
}

export default HomeContent;
