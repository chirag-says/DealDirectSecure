'use client';

import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import Link from "next/link";
import Image from "next/image";
import dynamic from "next/dynamic";
import { useRouter, usePathname, useSearchParams } from "next/navigation";
import { toast } from "react-toastify";
import { AiOutlineUser, AiOutlineMenu, AiOutlineClose, AiOutlineSearch, AiOutlineHome, AiOutlineInfoCircle, AiOutlinePhone, AiOutlineFileText, AiOutlinePlusCircle, AiOutlineLogin, AiOutlineLogout, AiOutlineSetting, AiOutlineHeart, AiOutlineBell, AiOutlineGift } from "react-icons/ai";

import { FaMapMarkerAlt, FaMicrophone } from "react-icons/fa";
// Inline SVGs to avoid importing entire react-icons/bs (~2.9MB) and react-icons/hi (~424KB) bundles
const BsBuilding = (props) => (
  <svg stroke="currentColor" fill="currentColor" strokeWidth="0" viewBox="0 0 16 16" height={props.size || "1em"} width={props.size || "1em"} className={props.className}>
    <path d="M4 2.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1Zm3 0a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1Zm3.5-.5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-1ZM4 5.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1ZM7.5 5a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-1Zm2.5.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1ZM4.5 8a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-1Zm2.5.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1ZM10.5 8a.5.5 0 0 0-.5.5v1a.5.5 0 0 0 .5.5h1a.5.5 0 0 0 .5-.5v-1a.5.5 0 0 0-.5-.5h-1Zm-2.5 3.5a.5.5 0 0 1 .5-.5h1a.5.5 0 0 1 .5.5v1a.5.5 0 0 1-.5.5h-1a.5.5 0 0 1-.5-.5v-1Z"/>
    <path d="M2 1a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v14a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1V1Zm11 0H3v14h3v-2.5a.5.5 0 0 1 .5-.5h3a.5.5 0 0 1 .5.5V15h3V1Z"/>
  </svg>
);
const BsHouseDoor = (props) => (
  <svg stroke="currentColor" fill="currentColor" strokeWidth="0" viewBox="0 0 16 16" height={props.size || "1em"} width={props.size || "1em"} className={props.className}>
    <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 1.5 7.5v7a.5.5 0 0 0 .5.5h4.5a.5.5 0 0 0 .5-.5v-4h2v4a.5.5 0 0 0 .5.5H14a.5.5 0 0 0 .5-.5v-7a.5.5 0 0 0-.146-.354L13 5.793V2.5a.5.5 0 0 0-.5-.5h-1a.5.5 0 0 0-.5.5v1.293L8.354 1.146ZM2.5 14V7.707l5.5-5.5 5.5 5.5V14H10v-4a.5.5 0 0 0-.5-.5h-3a.5.5 0 0 0-.5.5v4H2.5Z"/>
  </svg>
);
const HiOutlineDocumentText = (props) => (
  <svg stroke="currentColor" fill="none" strokeWidth="2" viewBox="0 0 24 24" height={props.size || "1em"} width={props.size || "1em"} className={props.className}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/>
  </svg>
);
const CalendarCheck = (props) => (
  <svg xmlns="http://www.w3.org/2000/svg" width={props.size || "1em"} height={props.size || "1em"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={props.className}>
    <path d="M8 2v4"/><path d="M16 2v4"/><rect width="18" height="18" x="3" y="4" rx="2"/><path d="M3 10h18"/><path d="m9 16 2 2 4-4"/>
  </svg>
);
import logo from "../../assets/dealdirect_logo.png";

const EmailVerificationModal = dynamic(
  () => import("../EmailVerificationModal/EmailVerificationModal"),
  { ssr: false }
);
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";

// Omnibox-style relevance scoring (Same as HeroSection)
const calculateRelevanceScore = (query, text) => {
  if (!text) return 0;

  const queryLower = query.toLowerCase();
  const textLower = text.toLowerCase();

  if (textLower === queryLower) return 100;
  if (textLower.startsWith(queryLower)) return 90;

  const words = textLower.split(/\s+/);
  if (words.some(word => word.startsWith(queryLower))) return 80;
  if (textLower.includes(queryLower)) return 70;

  // Fuzzy match
  let queryIndex = 0;
  for (let i = 0; i < textLower.length && queryIndex < queryLower.length; i++) {
    if (textLower[i] === queryLower[queryIndex]) queryIndex++;
  }
  return queryIndex === queryLower.length ? 50 : 0;
};

function Navbar() {
  const [menuOpen, setMenuOpen] = useState(false);
  const [isScrolled, setIsScrolled] = useState(false);
  const [activeMenu, setActiveMenu] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [navCity, setNavCity] = useState("");
  const [isDetectingCity, setIsDetectingCity] = useState(false);
  const [mounted, setMounted] = useState(false);

  const [isVerificationModalOpen, setIsVerificationModalOpen] = useState(false);
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const userDropdownRef = useRef(null);

  // Use AuthContext for user state
  const { user, loading: authLoading, isAuthenticated, logout: authLogout, canAddProperty, ownerHasProperty, refreshOwnerPropertyStatus } = useAuth();

  // Search Suggestions State
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const searchInputRef = useRef(null);
  const suggestionsRef = useRef(null);

  const router = useRouter();
  const pathname = usePathname() || "";
  const searchParams = useSearchParams();

  // Compute login URL to redirect back
  const queryString = searchParams?.toString();
  const currentUrl = pathname + (queryString ? '?' + queryString : '');
  
  const loginUrl = pathname === '/login' || pathname === '/register'
    ? '/login' 
    : `/login?from=${encodeURIComponent(currentUrl)}`;

  const toggleMenu = () => setMenuOpen((s) => !s);

  useEffect(() => {
    const handleScroll = () => {
      // Detect if we've scrolled past the hero section (approximately 600-700px)
      setIsScrolled(window.scrollY > 500);
    };
    window.addEventListener("scroll", handleScroll);

    // Auto-detect city on page load (triggers browser popup)
    detectCity();

    return () => {
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

  // Detect city via browser geolocation — triggered only by user click on city pill
  const detectCity = async () => {
    if (!navigator.geolocation) return;
    setIsDetectingCity(true);
    navigator.geolocation.getCurrentPosition(
      async (position) => {
        try {
          const { latitude, longitude } = position.coords;
          const res = await fetch(
            `https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&addressdetails=1&zoom=10`
          );
          const data = await res.json();
          const detected =
            data.address?.city ||
            data.address?.town ||
            data.address?.state_district ||
            "Mumbai";
          setNavCity(detected);
        } catch {
          setNavCity("Mumbai");
        } finally {
          setIsDetectingCity(false);
        }
      },
      () => {
        // User denied or error
        setIsDetectingCity(false);
      },
      { timeout: 8000, maximumAge: 300000 }
    );
  };

  useEffect(() => {
    setMounted(true);
  }, []);

  // Fetch unread notification count when user logs in
  useEffect(() => {
    const fetchUnread = async () => {
      if (!isAuthenticated) {
        setUnreadNotifications(0);
        return;
      }
      try {
        const res = await api.get('/notifications');
        if (res.data.success) {
          const list = res.data.notifications || [];
          const count = list.filter((n) => !n.isRead).length;
          setUnreadNotifications(count);
        }
      } catch (err) {
        // Silently fail - 401 handled by interceptor
        console.error("Failed to fetch notifications", err);
      }
    };

    fetchUnread();

    // Re-fetch when notifications are marked as read from the notifications page
    const handleNotificationsUpdated = () => fetchUnread();
    window.addEventListener('notifications-updated', handleNotificationsUpdated);

    return () => {
      window.removeEventListener('notifications-updated', handleNotificationsUpdated);
    };
  }, [isAuthenticated]);

  // Search Suggestions Logic
  useEffect(() => {
    const fetchSuggestions = async () => {
      if (!searchQuery || searchQuery.trim().length < 2) {
        setSuggestions([]);
        setShowSuggestions(false);
        return;
      }

      setIsLoadingSuggestions(true);
      try {
        const response = await api.get('/properties/property-list');
        const properties = response.data.data || [];

        const searchTerm = searchQuery.toLowerCase().trim();
        const scoredSuggestions = [];

        properties.forEach(property => {
          if (property.title) {
            const score = calculateRelevanceScore(searchTerm, property.title);
            if (score > 0) {
              scoredSuggestions.push({
                type: 'project',
                value: property.title,
                subtitle: `${property.city || ''} ${property.locality ? '• ' + property.locality : ''}`.trim(),
                score,
              });
            }
          }

          if (property.locality) {
            const score = calculateRelevanceScore(searchTerm, property.locality);
            if (score > 0) {
              scoredSuggestions.push({
                type: 'locality',
                value: property.locality,
                subtitle: property.city || '',
                score: score * 0.9,
              });
            }
          }

          if (property.city) {
            const score = calculateRelevanceScore(searchTerm, property.city);
            if (score > 0) {
              scoredSuggestions.push({
                type: 'city',
                value: property.city,
                subtitle: 'City',
                score: score * 0.8,
              });
            }
          }
        });

        const uniqueSuggestions = Array.from(
          new Map(scoredSuggestions.map(item => [`${item.type}-${item.value}`, item])).values()
        ).sort((a, b) => b.score - a.score).slice(0, 8);

        setSuggestions(uniqueSuggestions);
        setShowSuggestions(uniqueSuggestions.length > 0);
        setSelectedIndex(-1);
      } catch (error) {
        console.error('Error fetching suggestions:', error);
        setSuggestions([]);
      } finally {
        setIsLoadingSuggestions(false);
      }
    };

    const debounceTimer = setTimeout(fetchSuggestions, 200);
    return () => clearTimeout(debounceTimer);
  }, [searchQuery]);

  // Handle Click Outside for Suggestions
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        suggestionsRef.current &&
        !suggestionsRef.current.contains(event.target) &&
        searchInputRef.current &&
        !searchInputRef.current.contains(event.target)
      ) {
        setShowSuggestions(false);
      }
      // Close user dropdown when clicking outside
      if (
        userDropdownRef.current &&
        !userDropdownRef.current.contains(event.target)
      ) {
        setIsUserDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSuggestionClick = (suggestion) => {
    setSearchQuery(suggestion.value);
    setShowSuggestions(false);
    setSelectedIndex(-1);
    router.push(`/properties?search=${encodeURIComponent(suggestion.value)}`);
  };

  const handleMapClick = () => {
    const searchParams = new URLSearchParams();
    searchParams.set('view', 'map');
    if (searchQuery) {
      searchParams.set('search', searchQuery);
    }
    router.push(`/properties?${searchParams.toString()}`);
  };

  const handleSearch = () => {
    if (searchQuery.trim()) {
      router.push(`/properties?search=${encodeURIComponent(searchQuery)}`);
      setShowSuggestions(false);
    }
  };

  const handleKeyDown = (e) => {
    if (!showSuggestions || suggestions.length === 0) {
      if (e.key === 'Enter') {
        handleSearch();
      }
      return;
    }

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev < suggestions.length - 1 ? prev + 1 : prev));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev > 0 ? prev - 1 : -1));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (selectedIndex >= 0) {
        handleSuggestionClick(suggestions[selectedIndex]);
      } else {
        handleSearch();
      }
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  const highlightMatch = (text, query) => {
    if (!query || !text) return text;
    const index = text.toLowerCase().indexOf(query.toLowerCase());
    if (index === -1) return text;

    return (
      <>
        {text.substring(0, index)}
        <span className="font-semibold">{text.substring(index, index + query.length)}</span>
        {text.substring(index + query.length)}
      </>
    );
  };

  const handleLogout = async () => {
    await authLogout();
    // authLogout handles navigation and state clearing
  };

  const derivedRole = useMemo(() => {
    if (!user) return "user";
    const fallbacks = user.role || user.accountType || user.userType || user.type;
    if (typeof fallbacks === "string") return fallbacks.toLowerCase();
    if (user.isAgent) return "agent";
    return "user";
  }, [user]);

  const isAgent = derivedRole === "agent";
  const agentUploadUrl = process.env.NEXT_PUBLIC_AGENT_UPLOAD_URL || "/admin/add-property";
  const isExternalAgentUrl = /^https?:\/\//i.test(agentUploadUrl || "");
  const showAgentUpload = isAgent && Boolean(agentUploadUrl);

  const handleAgentUploadNavigation = useCallback(() => {
    if (!showAgentUpload) return;
    if (isExternalAgentUrl) {
      window.location.href = agentUploadUrl;
      return;
    }
    router.push(agentUploadUrl);
  }, [agentUploadUrl, isExternalAgentUrl, router, showAgentUpload]);

  const handleRegisterProperty = async () => {
    if (!isAuthenticated) {
      router.push('/login?from=/add-property');
      return;
    }

    // Check if user is a buyer (user role) - needs email verification to list property
    const userRole = (user.role || "user").toLowerCase();

    if (userRole === "user" || userRole === "buyer") {
      // Buyer needs to verify email first
      setIsVerificationModalOpen(true);
      return;
    }

    // For agents, keep existing behaviour
    if (userRole === "agent") {
      router.push("/add-property");
      return;
    }

    // For owners - canAddProperty from context already checks if they have a property
    if (userRole === "owner") {
      if (ownerHasProperty) {
        toast.info(
          "You can list only one property as an owner. Please edit your existing listing from My Properties.",
        );
        router.push("/my-properties");
        return;
      }
      router.push("/add-property");
    }
  };

  const handleVerificationSuccess = () => {
    // After successful verification, navigate to add property
    router.push("/add-property");
  };

  // Classes that adapt: white background always
  const navWrapperClass = `fixed top-0 left-0 w-full z-[9999] transition-all duration-300 ${isScrolled
    ? "bg-white shadow-lg py-2"
    : "bg-white py-3"
    }`;

  const navTextClass = "text-gray-800"; // Dark text for white background

  // Mobile accordion state
  const [mobileAccordion, setMobileAccordion] = useState(null);
  const toggleMobileAccordion = (key) => setMobileAccordion(prev => prev === key ? null : key);

  return (
    <>

      {isVerificationModalOpen && (
        <EmailVerificationModal
          isOpen={isVerificationModalOpen}
          onClose={() => setIsVerificationModalOpen(false)}
          user={user}
          onVerified={handleVerificationSuccess}
        />
      )}
      <nav className={navWrapperClass}>
        <div className="mx-auto flex items-center justify-between px-4 sm:px-6 lg:px-8 max-w-[1400px] gap-4">
          {/* Logo & Global City */}
          <div className="flex items-center gap-4 shrink-0">
            <Link href="/" className="flex items-center shrink-0">
              <Image
                src={logo}
                alt="DealDirect"
                height={36}
                width={160}
                className="h-9 w-auto object-contain hover:scale-105 transition-transform duration-300"
                priority
              />
            </Link>
            {navCity && (
              <button
                onClick={detectCity}
                title="Click to detect your city"
                className="hidden md:flex items-center gap-1.5 px-3 py-1.5 bg-gray-50 border border-gray-200 rounded-full cursor-pointer select-none transition-all hover:bg-gray-100 hover:border-gray-300 hover:shadow-sm active:scale-95"
              >
                {isDetectingCity ? (
                  <div className="w-3.5 h-3.5 border-2 border-red-500 border-t-transparent rounded-full animate-spin" />
                ) : (
                  <FaMapMarkerAlt className="text-red-500 text-sm" />
                )}
                <span className="text-sm font-semibold text-gray-700 tracking-wide">{navCity}</span>
              </button>
            )}
          </div>

          {/* Desktop Center: Search Bar (only when scrolled) */}
          {isScrolled && (
            <div className="hidden lg:flex items-center flex-1 max-w-lg relative" ref={searchInputRef}>
              <div className="relative flex-1 flex items-center">
                <AiOutlineSearch className="absolute left-3 text-gray-400 text-lg" />
                <input
                  type="text"
                  placeholder="Enter Locality / Project / S..."
                  value={searchQuery}
                  onChange={(e) => {
                    setSearchQuery(e.target.value);
                    setShowSuggestions(true);
                  }}
                  onKeyDown={handleKeyDown}
                  onFocus={() => {
                    if (suggestions.length > 0) setShowSuggestions(true);
                  }}
                  className="w-full border border-gray-200 rounded-full pl-10 pr-16 py-2 text-sm text-gray-700 focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none bg-gray-50"
                />
                <div className="absolute right-3 flex items-center gap-2">
                  <FaMapMarkerAlt
                    className="text-red-500 cursor-pointer hover:text-red-600 transition-transform hover:scale-110 text-sm"
                    onClick={handleMapClick}
                    title="Search on Map"
                  />
                  <FaMicrophone className="text-red-500 cursor-pointer hover:text-red-600 text-sm" />
                </div>
              </div>

              {/* Search Suggestions Dropdown */}
              {showSuggestions && (suggestions.length > 0 || isLoadingSuggestions) && (
                <div
                  ref={suggestionsRef}
                  className="absolute top-full left-0 right-0 mt-2 bg-white border border-gray-200 rounded-xl shadow-2xl max-h-96 overflow-y-auto z-50"
                >
                  {isLoadingSuggestions ? (
                    <div className="p-4 text-center text-gray-500">
                      <div className="animate-spin inline-block w-5 h-5 border-2 border-red-600 border-t-transparent rounded-full"></div>
                      <p className="mt-2 text-sm">Searching...</p>
                    </div>
                  ) : (
                    <ul className="py-1">
                      {suggestions.map((suggestion, index) => (
                        <li
                          key={index}
                          onClick={() => handleSuggestionClick(suggestion)}
                          onMouseEnter={() => setSelectedIndex(index)}
                          className={`px-4 py-3 cursor-pointer transition-colors flex items-start gap-3 ${selectedIndex === index ? 'bg-gray-100' : 'hover:bg-gray-50'
                            }`}
                        >
                          <AiOutlineSearch className="text-gray-400 flex-shrink-0 mt-0.5" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-gray-900">
                              {highlightMatch(suggestion.value, searchQuery)}
                            </p>
                            {suggestion.subtitle && (
                              <p className="text-xs text-gray-500 truncate">{suggestion.subtitle}</p>
                            )}
                          </div>
                          <span className="text-xs text-gray-400 capitalize flex-shrink-0">{suggestion.type}</span>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {/* Search Button */}
              <button
                onClick={handleSearch}
                className="ml-2 bg-red-600 text-white px-5 py-2 rounded-full font-semibold text-sm hover:bg-red-700 transition flex items-center gap-1.5 shrink-0"
              >
                <AiOutlineSearch className="text-sm" />
                Search
              </button>
            </div>
          )}

          {/* Desktop Left Nav (non-scrolled: Buy, Rent, Services) */}
          {!isScrolled && (
            <div className="hidden lg:flex items-center gap-5 ml-4">

              {/* Buy Dropdown */}
              <div
                className="relative"
                onMouseEnter={() => setActiveMenu('buy')}
                onMouseLeave={() => setActiveMenu(null)}
              >
                <button className={`${navTextClass} hover:text-red-600 font-medium text-[15px] flex items-center gap-1 transition-colors duration-200`}>
                  Buy
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {activeMenu === 'buy' && (
                  <div className="absolute top-full left-0 pt-2 bg-white shadow-2xl rounded-lg p-6 w-[600px] z-50">
                    <div className="grid grid-cols-3 gap-6">
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Residential</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=Apartment&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Apartment / Flat</Link></li>
                          <li><Link href="/properties?search=Independent House&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Independent House</Link></li>
                          <li><Link href="/properties?search=Villa&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Villa</Link></li>
                          <li><Link href="/properties?search=Builder Floor&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Builder Floor</Link></li>
                          <li><Link href="/properties?search=Penthouse&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Penthouse</Link></li>
                        </ul>
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Commercial</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=Office Space&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Office Space</Link></li>
                          <li><Link href="/properties?search=Shop&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Shop / Showroom</Link></li>
                          <li><Link href="/properties?search=Warehouse&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Warehouse / Godown</Link></li>
                          <li><Link href="/properties?search=Industrial&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Industrial Building</Link></li>
                        </ul>
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">By BHK</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=1 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">1 BHK</Link></li>
                          <li><Link href="/properties?search=2 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">2 BHK</Link></li>
                          <li><Link href="/properties?search=3 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">3 BHK</Link></li>
                          <li><Link href="/properties?search=4 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">4 BHK</Link></li>
                          <li><Link href="/properties?search=5%2B BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">5+ BHK</Link></li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Rent Dropdown */}
              <div
                className="relative"
                onMouseEnter={() => setActiveMenu('rent')}
                onMouseLeave={() => setActiveMenu(null)}
              >
                <button className={`${navTextClass} hover:text-red-600 font-medium text-[15px] flex items-center gap-1 transition-colors duration-200`}>
                  Rent
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {activeMenu === 'rent' && (
                  <div className="absolute top-full left-0 pt-2 bg-white shadow-2xl rounded-lg p-6 w-[600px] z-50">
                    <div className="grid grid-cols-3 gap-6">
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Residential</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=Apartment&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Apartment / Flat</Link></li>
                          <li><Link href="/properties?search=Independent House&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Independent House</Link></li>
                          <li><Link href="/properties?search=Villa&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Villa</Link></li>
                          <li><Link href="/properties?search=Builder Floor&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Builder Floor</Link></li>
                          <li><Link href="/properties?search=PG&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">PG / Hostel</Link></li>
                        </ul>
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Commercial</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=Office Space&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Office Space</Link></li>
                          <li><Link href="/properties?search=Shop&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Shop / Showroom</Link></li>
                          <li><Link href="/properties?search=Coworking&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Coworking Space</Link></li>
                          <li><Link href="/properties?search=Warehouse&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Warehouse / Godown</Link></li>
                        </ul>
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">By BHK</h3>
                        <ul className="space-y-2">
                          <li><Link href="/properties?search=1 RK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">1 RK</Link></li>
                          <li><Link href="/properties?search=1 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">1 BHK</Link></li>
                          <li><Link href="/properties?search=2 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">2 BHK</Link></li>
                          <li><Link href="/properties?search=3 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">3 BHK</Link></li>
                          <li><Link href="/properties?search=4 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">4 BHK</Link></li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Services Dropdown */}
              <div
                className="relative"
                onMouseEnter={() => setActiveMenu('services')}
                onMouseLeave={() => setActiveMenu(null)}
              >
                <button className={`${navTextClass} hover:text-red-600 font-medium text-[15px] flex items-center gap-1 transition-colors duration-200`}>
                  Services
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {activeMenu === 'services' && (
                  <div className="absolute top-full left-0 pt-2 bg-white shadow-2xl rounded-lg p-6 w-[400px] z-50">
                    <div className="grid grid-cols-2 gap-6">
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Property Services</h3>
                        <ul className="space-y-2">
                          <li><button onClick={handleRegisterProperty} className="text-gray-700 hover:text-red-600 text-sm text-left w-full">Post Property Free</button></li>
                          <li><Link href="/properties" className="text-gray-700 hover:text-red-600 text-sm">Browse Properties</Link></li>
                          <li><Link href="/projects" className="text-gray-700 hover:text-indigo-600 text-sm font-medium">🏗 Builder Projects</Link></li>
                          <li><Link href="/coming-soon" className="text-gray-700 hover:text-red-600 text-sm">On the horizon</Link></li>
                        </ul>
                      </div>
                      <div>
                        <h3 className="font-bold text-gray-900 mb-3 text-sm">Company</h3>
                        <ul className="space-y-2">
                          <li><Link href="/about" className="text-gray-700 hover:text-red-600 text-sm">About Us</Link></li>
                          <li><Link href="/contact" className="text-gray-700 hover:text-red-600 text-sm">Contact Us</Link></li>
                          <li><Link href="/blog" className="text-gray-700 hover:text-red-600 text-sm">Blog</Link></li>
                        </ul>
                      </div>
                    </div>
                  </div>
                )}
              </div>

            </div>
          )}

          {/* Desktop Right Side — fixed min-width prevents CLS when buttons change */}
          <div className="hidden lg:flex items-center justify-end gap-3 shrink-0 min-w-[240px]">

            {isScrolled && (
              <>
                <Link href="/properties" className={`${navTextClass} hover:text-red-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  Properties
                </Link>
                <Link href="/projects" className={`${navTextClass} hover:text-indigo-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  Projects
                </Link>
                <Link href="/agreements" className={`${navTextClass} hover:text-red-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  Agreements
                </Link>
                <Link href="/blog" className={`${navTextClass} hover:text-red-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  Blog
                </Link>
                <Link href="/about" className={`${navTextClass} hover:text-red-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  About Us
                </Link>
                <Link href="/contact" className={`${navTextClass} hover:text-red-600 font-medium text-sm transition-colors whitespace-nowrap`}>
                  Contact
                </Link>
                <div className="w-px h-5 bg-gray-200 mx-1"></div>
              </>
            )}

            {showAgentUpload && (
              <button
                type="button"
                onClick={handleAgentUploadNavigation}
                className="bg-gradient-to-r from-red-600 to-rose-700 text-white px-4 py-2 rounded-lg text-sm font-semibold shadow-md hover:opacity-95 transition"
              >
                Upload Property
              </button>
            )}

            {/* Register Property Button */}
            {!(user?.role === 'owner' && ownerHasProperty) && (
              <button
                type="button"
                onClick={handleRegisterProperty}
                className="bg-red-600 text-white px-5 py-2 rounded-lg text-sm font-bold hover:bg-red-700 transition shadow-sm whitespace-nowrap"
              >
                Register Property
              </button>
            )}

            {/* Layer 3: Show skeleton while auth is loading or not yet mounted */}
            {(!mounted || authLoading) ? (
              <div className="flex items-center gap-1.5 p-1">
                <div className="w-9 h-9 rounded-full bg-gray-200 animate-pulse"></div>
                <div className="w-3.5 h-3.5 bg-gray-200 rounded animate-pulse"></div>
              </div>
            ) : user ? (
              <div className="relative" ref={userDropdownRef}>
                <button
                  onClick={() => setIsUserDropdownOpen(!isUserDropdownOpen)}
                  className="flex items-center gap-1.5 p-1 rounded-full hover:bg-gray-100 transition-colors"
                >
                  {user.profileImage ? (
                    <img
                      src={user.profileImage}
                      alt={user.name}
                      className="w-9 h-9 rounded-full object-cover border-2 border-gray-200"
                    />
                  ) : (
                    <div className="w-9 h-9 rounded-full bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center text-white font-bold text-sm">
                      {user.name?.charAt(0).toUpperCase() || "U"}
                    </div>
                  )}
                  <svg className={`w-3.5 h-3.5 text-gray-600 transition-transform ${isUserDropdownOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>

                {/* User Dropdown Menu */}
                {isUserDropdownOpen && (
                  <div className="absolute right-0 top-full mt-2 w-64 bg-white rounded-xl shadow-2xl border border-gray-100 py-2 z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                    {/* User Info Header */}
                    <div className="px-4 py-3 border-b border-gray-100">
                      <div className="flex items-center gap-3">
                        {user.profileImage ? (
                          <img
                            src={user.profileImage}
                            alt={user.name}
                            className="w-11 h-11 rounded-full object-cover border-2 border-gray-200"
                          />
                        ) : (
                          <div className="w-11 h-11 rounded-full bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center text-white font-bold text-lg">
                            {user.name?.charAt(0).toUpperCase() || "U"}
                          </div>
                        )}
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold text-gray-900 truncate">{user.name}</p>
                          <p className="text-xs text-gray-500 truncate">{user.email}</p>
                          <span className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium ${user.role === 'owner' ? 'bg-blue-100 text-blue-700' :
                            user.role === 'agent' ? 'bg-purple-100 text-purple-700' :
                              'bg-gray-100 text-gray-600'
                            }`}>
                            {user.role === 'owner' ? 'Property Owner' : user.role === 'agent' ? 'Agent' : user.role === 'admin' ? 'Administrator' : 'Buyer'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Menu Items */}
                    <div className="py-2">
                      <Link href="/notifications" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <div className="relative">
                          <AiOutlineBell className="w-5 h-5 text-gray-500" />
                          {unreadNotifications > 0 && <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-red-500"></span>}
                        </div>
                        <span className="font-medium">Notifications</span>
                      </Link>
                      <Link href="/profile" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <AiOutlineUser className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">My Profile</span>
                      </Link>
                      {(user.role === 'owner' || user.role === 'agent') && (
                        <Link href="/my-properties" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                          <BsHouseDoor className="w-5 h-5 text-gray-500" />
                          <span className="font-medium">My Properties</span>
                        </Link>
                      )}
                      <Link href="/saved-properties" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <AiOutlineHeart className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">Saved Properties</span>
                      </Link>
                      <Link href="/my-bookings" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <CalendarCheck className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">My Bookings</span>
                      </Link>
                      <Link href="/agreements" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <HiOutlineDocumentText className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">My Agreements</span>
                      </Link>
                      <Link href="/rewards/dashboard" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <AiOutlineGift className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">Rewards</span>
                      </Link>

                    </div>

                    <div className="border-t border-gray-100 my-1"></div>

                    <div className="py-1">
                      <Link href="/profile?tab=settings" onClick={() => setIsUserDropdownOpen(false)} className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors">
                        <AiOutlineSetting className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">Settings</span>
                      </Link>
                      <button
                        onClick={() => { handleLogout(); setIsUserDropdownOpen(false); }}
                        className="w-full flex items-center gap-3 px-4 py-2.5 text-red-600 hover:bg-red-50 transition-colors"
                      >
                        <AiOutlineLogout className="w-5 h-5" />
                        <span className="font-medium">Logout</span>
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <Link href={loginUrl} className={`flex items-center space-x-1 ${navTextClass} hover:text-red-600 transition-colors duration-200`}>
                <AiOutlineUser className="text-lg" />
                <span className="font-medium text-sm">Login</span>
              </Link>
            )}
          </div>

          {/* Mobile Right: Quick Actions + Hamburger */}
          <div className="flex lg:hidden items-center gap-2">
            {/* Layer 3: Mobile skeleton while loading */}
            {(!mounted || authLoading) ? (
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-full bg-gray-200 animate-pulse"></div>
              </div>
            ) : user ? (
              <>
                <Link href="/notifications" className="relative p-2 rounded-full hover:bg-gray-100 transition">
                  <AiOutlineBell className="text-xl text-gray-700" />
                  {unreadNotifications > 0 && <span className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-red-500"></span>}
                </Link>
                <Link href="/profile" className="p-0.5">
                  {user.profileImage ? (
                    <img src={user.profileImage} alt={user.name} className="w-8 h-8 rounded-full object-cover border-2 border-gray-200" />
                  ) : (
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-red-500 to-red-600 flex items-center justify-center text-white font-bold text-xs">
                      {user.name?.charAt(0).toUpperCase() || "U"}
                    </div>
                  )}
                </Link>
              </>
            ) : (
              <Link href={loginUrl} className="text-sm font-semibold text-red-600 hover:text-red-700 transition mr-1">
                Login
              </Link>
            )}
            <button
              onClick={toggleMenu}
              className="p-2 text-gray-700 hover:bg-gray-100 rounded-lg transition"
              aria-label={menuOpen ? "Close menu" : "Open menu"}
            >
              {menuOpen ? <AiOutlineClose size={22} /> : <AiOutlineMenu size={22} />}
            </button>
          </div>
        </div>

        {/* Mobile Menu Overlay */}
        <div
          className={`lg:hidden fixed inset-0 z-[5000] bg-black/50 backdrop-blur-sm transition-opacity duration-300 ${menuOpen ? "opacity-100 visible" : "opacity-0 invisible"
            }`}
          onClick={toggleMenu}
        />

        {/* Mobile Menu Drawer */}
        <div
          className={`lg:hidden fixed top-0 right-0 h-full w-[85%] max-w-sm bg-white shadow-2xl z-[5001] transform transition-transform duration-300 ease-out ${menuOpen ? "translate-x-0" : "translate-x-full"
            }`}
        >
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
              <span className="text-lg font-bold text-slate-800">Menu</span>
              <button
                onClick={toggleMenu}
                className="p-2 text-slate-500 hover:bg-slate-100 rounded-full transition"
              >
                <AiOutlineClose size={22} />
              </button>
            </div>

            {/* Scrollable Links */}
            <div className="flex-1 overflow-y-auto py-2 pb-4 px-3">

              <Link href="/" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <AiOutlineHome size={18} />
                Home
              </Link>

              <Link href="/properties" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <BsBuilding size={18} />
                Properties
              </Link>

              <Link href="/rewards/dashboard" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <AiOutlineGift size={18} />
                Rewards
              </Link>

              <Link href="/blog" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <HiOutlineDocumentText size={18} />
                Blog
              </Link>

              {/* My Properties — only for owners/agents */}
              {(user?.role === 'owner' || user?.role === 'agent') && (
                <Link href="/my-properties" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                  <BsHouseDoor size={18} />
                  My Properties
                </Link>
              )}

              {/* User-specific links — only shown when logged in */}
              {user && (
                <>
                  <Link href="/saved-properties" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                    <AiOutlineHeart size={18} />
                    Saved Properties
                  </Link>
                  <Link href="/my-bookings" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                    <CalendarCheck size={18} />
                    My Bookings
                  </Link>
                </>
              )}

              {/* Buy Accordion */}
              <div>
                <button
                  onClick={() => toggleMobileAccordion('buy')}
                  className="w-full flex items-center justify-between px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
                >
                  <span className="flex items-center gap-3">
                    <AiOutlineHome size={18} />
                    Buy
                  </span>
                  <svg className={`w-4 h-4 transition-transform duration-200 ${mobileAccordion === 'buy' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {mobileAccordion === 'buy' && (
                  <div className="ml-8 mr-2 mb-2 space-y-1 border-l-2 border-red-100 pl-4">
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-1 mb-1">Residential</p>
                    <Link href="/properties?search=Apartment&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Apartment / Flat</Link>
                    <Link href="/properties?search=Villa&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Villa</Link>
                    <Link href="/properties?search=Independent House&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Independent House</Link>
                    <Link href="/properties?search=Builder Floor&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Builder Floor</Link>
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-3 mb-1">Commercial</p>
                    <Link href="/properties?search=Office Space&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Office Space</Link>
                    <Link href="/properties?search=Shop&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Shop / Showroom</Link>
                    <Link href="/properties?search=Warehouse&availableFor=Sell" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Warehouse</Link>
                  </div>
                )}
              </div>

              {/* Rent Accordion */}
              <div>
                <button
                  onClick={() => toggleMobileAccordion('rent')}
                  className="w-full flex items-center justify-between px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
                >
                  <span className="flex items-center gap-3">
                    <BsHouseDoor size={18} />
                    Rent
                  </span>
                  <svg className={`w-4 h-4 transition-transform duration-200 ${mobileAccordion === 'rent' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {mobileAccordion === 'rent' && (
                  <div className="ml-8 mr-2 mb-2 space-y-1 border-l-2 border-red-100 pl-4">
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-1 mb-1">Residential</p>
                    <Link href="/properties?search=Apartment&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Apartment / Flat</Link>
                    <Link href="/properties?search=Villa&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Villa</Link>
                    <Link href="/properties?search=PG&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">PG / Hostel</Link>
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-3 mb-1">Commercial</p>
                    <Link href="/properties?search=Office Space&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Office Space</Link>
                    <Link href="/properties?search=Shop&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Shop / Showroom</Link>
                    <Link href="/properties?search=Coworking&availableFor=Rent" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Coworking Space</Link>
                  </div>
                )}
              </div>

              {/* Services Accordion */}
              <div>
                <button
                  onClick={() => toggleMobileAccordion('services')}
                  className="w-full flex items-center justify-between px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
                >
                  <span className="flex items-center gap-3">
                    <AiOutlineSetting size={18} />
                    Services
                  </span>
                  <svg className={`w-4 h-4 transition-transform duration-200 ${mobileAccordion === 'services' ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                {mobileAccordion === 'services' && (
                  <div className="ml-8 mr-2 mb-2 space-y-1 border-l-2 border-red-100 pl-4">
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-1 mb-1">Property Services</p>
                    <button onClick={() => { handleRegisterProperty(); toggleMenu(); }} className="block py-1.5 text-sm text-gray-600 hover:text-red-600 text-left w-full">Post Property Free</button>
                    <Link href="/properties" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Browse Properties</Link>
                    <Link href="/coming-soon" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">On the Horizon</Link>
                    <p className="text-xs font-bold text-gray-400 uppercase tracking-wider mt-3 mb-1">Company</p>
                    <Link href="/about" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">About Us</Link>
                    <Link href="/contact" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Contact Us</Link>
                    <Link href="/blog" onClick={toggleMenu} className="block py-1.5 text-sm text-gray-600 hover:text-red-600">Blog</Link>
                  </div>
                )}
              </div>

              {/* Register Property */}
              {!(user?.role === 'owner' && ownerHasProperty) && (
                <button
                  onClick={() => { handleRegisterProperty(); toggleMenu(); }}
                  className="w-full flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition text-left"
                >
                  <AiOutlinePlusCircle size={18} />
                  Register Property
                </button>
              )}

              {showAgentUpload && (
                <button
                  type="button"
                  className="w-full flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition text-left"
                  onClick={() => { handleAgentUploadNavigation(); if (!isExternalAgentUrl) toggleMenu(); }}
                >
                  <AiOutlinePlusCircle size={18} />
                  Upload Property
                </button>
              )}

              <Link href="/agreements" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <AiOutlineFileText size={18} />
                Agreements
              </Link>



              <Link href="/about" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <AiOutlineInfoCircle size={18} />
                About Us
              </Link>

              <Link href="/contact" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <AiOutlinePhone size={18} />
                Contact
              </Link>

              <Link href="/blog" onClick={toggleMenu} className="flex items-center gap-3 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition">
                <HiOutlineDocumentText size={18} />
                Knowledge Base
              </Link>


            </div>

            {/* Mobile Footer: User Section */}
            <div className="p-4 border-t bg-slate-50">
              {user ? (
                <div className="space-y-2">
                  <div className="flex items-center gap-3 px-2 py-1">
                    {user.profileImage ? (
                      <img src={user.profileImage} alt={user.name} className="w-10 h-10 rounded-full object-cover border-2 border-gray-200" />
                    ) : (
                      <div className="w-10 h-10 bg-gradient-to-br from-red-500 to-red-600 rounded-full flex items-center justify-center text-white font-bold text-sm">
                        {user.name?.charAt(0).toUpperCase() || "U"}
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-slate-800 text-sm truncate">{user.name || "User"}</p>
                      <span className={`inline-block px-2 py-0.5 rounded-full text-[10px] font-medium ${user.role === 'owner' ? 'bg-blue-100 text-blue-700' : user.role === 'agent' ? 'bg-purple-100 text-purple-700' : 'bg-gray-100 text-gray-600'}`}>
                        {user.role === 'owner' ? 'Owner' : user.role === 'agent' ? 'Agent' : 'Buyer'}
                      </span>
                    </div>
                  </div>

                  <div className="flex gap-2">
                    <Link href="/profile" onClick={toggleMenu} className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white rounded-lg border border-gray-200 hover:bg-gray-50 transition">
                      <AiOutlineUser size={14} /> Profile
                    </Link>
                    <Link href="/saved-properties" onClick={toggleMenu} className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white rounded-lg border border-gray-200 hover:bg-gray-50 transition">
                      <AiOutlineHeart size={14} /> Saved
                    </Link>
                    <Link href="/my-bookings" onClick={toggleMenu} className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 text-xs font-medium text-slate-700 bg-white rounded-lg border border-gray-200 hover:bg-gray-50 transition">
                      <CalendarCheck size={14} /> Bookings
                    </Link>
                  </div>

                  <button
                    onClick={() => { handleLogout(); toggleMenu(); }}
                    className="w-full flex items-center justify-center gap-2 bg-white border border-red-200 text-red-600 py-2 rounded-lg text-sm font-medium hover:bg-red-50 transition"
                  >
                    <AiOutlineLogout size={16} />
                    Logout
                  </button>
                </div>
              ) : (
                <Link
                  href={loginUrl}
                  onClick={toggleMenu}
                  className="w-full flex items-center justify-center gap-2 bg-slate-900 text-white py-3 rounded-lg font-semibold hover:bg-slate-800 transition"
                >
                  <AiOutlineLogin size={20} />
                  Login / Sign Up
                </Link>
              )}
            </div>
          </div>
        </div>
      </nav>
    </>
  );
}

export default Navbar;
