import React, { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { Link, useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import { AiOutlineUser, AiOutlineMenu, AiOutlineClose, AiOutlineSearch, AiOutlineHome, AiOutlineInfoCircle, AiOutlinePhone, AiOutlineFileText, AiOutlinePlusCircle, AiOutlineLogin, AiOutlineLogout, AiOutlineSetting, AiOutlineHeart, AiOutlineBell } from "react-icons/ai";
import { FaMapMarkerAlt, FaMicrophone } from "react-icons/fa";
import { BsBuilding, BsHouseDoor } from "react-icons/bs";
import { HiOutlineDocumentText } from "react-icons/hi";
import logo from "../../assets/dealdirect_logo.png";

import EmailVerificationModal from "../EmailVerificationModal/EmailVerificationModal";
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

  const [isVerificationModalOpen, setIsVerificationModalOpen] = useState(false);
  const [isUserDropdownOpen, setIsUserDropdownOpen] = useState(false);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const userDropdownRef = useRef(null);

  // Use AuthContext for user state
  const { user, isAuthenticated, logout: authLogout } = useAuth();

  // Search Suggestions State
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const searchInputRef = useRef(null);
  const suggestionsRef = useRef(null);

  const navigate = useNavigate();

  const toggleMenu = () => setMenuOpen((s) => !s);

  useEffect(() => {
    const handleScroll = () => {
      // Detect if we've scrolled past the hero section (approximately 600-700px)
      setIsScrolled(window.scrollY > 500);
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
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
    navigate(`/properties?search=${encodeURIComponent(suggestion.value)}`);
  };

  const handleMapClick = () => {
    const searchParams = new URLSearchParams();
    searchParams.set('view', 'map');
    if (searchQuery) {
      searchParams.set('search', searchQuery);
    }
    navigate(`/properties?${searchParams.toString()}`);
  };

  const handleSearch = () => {
    if (searchQuery.trim()) {
      navigate(`/properties?search=${encodeURIComponent(searchQuery)}`);
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
  const agentUploadUrl = import.meta.env.VITE_AGENT_UPLOAD_URL || "/admin/add-property";
  const isExternalAgentUrl = /^https?:\/\//i.test(agentUploadUrl || "");
  const showAgentUpload = isAgent && Boolean(agentUploadUrl);

  const handleAgentUploadNavigation = useCallback(() => {
    if (!showAgentUpload) return;
    if (isExternalAgentUrl) {
      window.location.href = agentUploadUrl;
      return;
    }
    navigate(agentUploadUrl);
  }, [agentUploadUrl, isExternalAgentUrl, navigate, showAgentUpload]);

  const handleRegisterProperty = async () => {
    if (!isAuthenticated) {
      navigate('/login', { state: { from: '/add-property' } });
      return;
    }

    // Check if user is a buyer (user role) - needs email verification to list property
    const userRole = (user.role || "user").toLowerCase();

    if (userRole === "user") {
      // Buyer needs to verify email first
      setIsVerificationModalOpen(true);
      return;
    }

    // For agents, keep existing behaviour
    if (userRole === "agent") {
      navigate("/add-property");
      return;
    }

    // For owners, enforce: only one property can be listed
    if (userRole === "owner") {
      try {
        const res = await api.get('/properties/my-properties');

        const count =
          typeof res.data?.count === "number"
            ? res.data.count
            : Array.isArray(res.data?.data)
              ? res.data.data.length
              : 0;

        if (count >= 1) {
          toast.info(
            "You can list only one property as an owner. Please edit your existing listing from My Properties.",
          );
          navigate("/my-properties");
          return;
        }
      } catch (error) {
        console.error("Error checking existing properties:", error);
        // If the check fails, fall back to allowing navigation so user isn't blocked unexpectedly
      }

      navigate("/add-property");
    }
  };

  const handleVerificationSuccess = () => {
    // After successful verification, navigate to add property
    navigate("/add-property");
  };

  // Classes that adapt: white background always
  const navWrapperClass = `fixed top-0 left-0 w-full z-[9999] transition-all duration-300 ${isScrolled
    ? "bg-white shadow-lg py-3"
    : "bg-white py-4"
    }`;

  const navTextClass = "text-gray-800"; // Dark text for white background

  return (
    <>

      <EmailVerificationModal
        isOpen={isVerificationModalOpen}
        onClose={() => setIsVerificationModalOpen(false)}
        user={user}
        onVerified={handleVerificationSuccess}
      />
      <nav className={navWrapperClass}>
        <div className="mx-auto flex items-center justify-between px-6 lg:px-8 max-w-[1400px]">
          {/* Left Side: Logo + Navigation */}
          <div className="flex items-center gap-6">
            {/* Logo */}
            <Link to="/" className="flex items-center">
              <img
                src={logo}
                alt="DealDirect"
                className="h-10 w-auto object-contain hover:scale-105 transition-transform duration-300"
              />
            </Link>

            {/* Scrolled State: Search Bar */}
            {isScrolled && (
              <div className="hidden lg:flex items-center flex-1 max-w-2xl mx-6 gap-3 relative" ref={searchInputRef}>

                {/* Search Bar */}
                <div className="relative flex-1 flex items-center">
                  <AiOutlineSearch className="absolute left-3 text-gray-400 text-lg" />
                  <input
                    type="text"
                    placeholder="Enter Locality / Project / Society / Landmark"
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value);
                      setShowSuggestions(true);
                    }}
                    onKeyDown={handleKeyDown}
                    onFocus={() => {
                      if (suggestions.length > 0) setShowSuggestions(true);
                    }}
                    className="w-full border border-gray-300 rounded-lg pl-10 pr-16 py-2 text-sm text-gray-700 focus:ring-2 focus:ring-red-500 outline-none"
                  />
                  <div className="absolute right-3 flex items-center gap-2">
                    <FaMapMarkerAlt
                      className="text-red-600 cursor-pointer hover:text-red-700 transition-transform hover:scale-110"
                      onClick={handleMapClick}
                      title="Search on Map"
                    />
                    <FaMicrophone className="text-red-600 cursor-pointer hover:text-red-700" />
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
                  className="bg-red-600 text-white px-6 py-2 rounded-lg font-semibold text-sm hover:bg-red-700 transition flex items-center gap-2"
                >
                  <AiOutlineSearch />
                  Search
                </button>
              </div>
            )}

            {/* Desktop Navigation Items - Only in non-scrolled state */}
            {!isScrolled && (
              <div className="hidden lg:flex items-center gap-6">

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
                            <li><Link to="/properties?search=Apartment&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Apartment / Flat</Link></li>
                            <li><Link to="/properties?search=Independent House&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Independent House</Link></li>
                            <li><Link to="/properties?search=Villa&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Villa</Link></li>
                            <li><Link to="/properties?search=Builder Floor&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Builder Floor</Link></li>
                            <li><Link to="/properties?search=Penthouse&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Penthouse</Link></li>
                          </ul>
                        </div>
                        <div>
                          <h3 className="font-bold text-gray-900 mb-3 text-sm">Commercial</h3>
                          <ul className="space-y-2">
                            <li><Link to="/properties?search=Office Space&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Office Space</Link></li>
                            <li><Link to="/properties?search=Shop&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Shop / Showroom</Link></li>
                            <li><Link to="/properties?search=Warehouse&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Warehouse / Godown</Link></li>
                            <li><Link to="/properties?search=Industrial&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">Industrial Building</Link></li>
                          </ul>
                        </div>
                        <div>
                          <h3 className="font-bold text-gray-900 mb-3 text-sm">By BHK</h3>
                          <ul className="space-y-2">
                            <li><Link to="/properties?search=1 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">1 BHK</Link></li>
                            <li><Link to="/properties?search=2 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">2 BHK</Link></li>
                            <li><Link to="/properties?search=3 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">3 BHK</Link></li>
                            <li><Link to="/properties?search=4 BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">4 BHK</Link></li>
                            <li><Link to="/properties?search=5%2B BHK&availableFor=Sell" className="text-gray-700 hover:text-red-600 text-sm">5+ BHK</Link></li>
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
                            <li><Link to="/properties?search=Apartment&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Apartment / Flat</Link></li>
                            <li><Link to="/properties?search=Independent House&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Independent House</Link></li>
                            <li><Link to="/properties?search=Villa&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Villa</Link></li>
                            <li><Link to="/properties?search=Builder Floor&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Builder Floor</Link></li>
                            <li><Link to="/properties?search=PG&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">PG / Hostel</Link></li>
                          </ul>
                        </div>
                        <div>
                          <h3 className="font-bold text-gray-900 mb-3 text-sm">Commercial</h3>
                          <ul className="space-y-2">
                            <li><Link to="/properties?search=Office Space&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Office Space</Link></li>
                            <li><Link to="/properties?search=Shop&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Shop / Showroom</Link></li>
                            <li><Link to="/properties?search=Coworking&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Coworking Space</Link></li>
                            <li><Link to="/properties?search=Warehouse&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">Warehouse / Godown</Link></li>
                          </ul>
                        </div>
                        <div>
                          <h3 className="font-bold text-gray-900 mb-3 text-sm">By BHK</h3>
                          <ul className="space-y-2">
                            <li><Link to="/properties?search=1 RK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">1 RK</Link></li>
                            <li><Link to="/properties?search=1 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">1 BHK</Link></li>
                            <li><Link to="/properties?search=2 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">2 BHK</Link></li>
                            <li><Link to="/properties?search=3 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">3 BHK</Link></li>
                            <li><Link to="/properties?search=4 BHK&availableFor=Rent" className="text-gray-700 hover:text-red-600 text-sm">4 BHK</Link></li>
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
                            <li><Link to="/properties" className="text-gray-700 hover:text-red-600 text-sm">Browse Properties</Link></li>
                          </ul>
                        </div>
                        <div>
                          <h3 className="font-bold text-gray-900 mb-3 text-sm">Company</h3>
                          <ul className="space-y-2">
                            <li><Link to="/pricing" className="text-gray-700 hover:text-red-600 text-sm">Pricing & Plans</Link></li>
                            <li><Link to="/about" className="text-gray-700 hover:text-red-600 text-sm">About Us</Link></li>
                            <li><Link to="/contact" className="text-gray-700 hover:text-red-600 text-sm">Contact Us</Link></li>
                          </ul>
                        </div>
                      </div>
                    </div>
                  )}
                </div>


              </div>
            )}
          </div>

          {/* Right Side: Sell Property + Login */}
          <div className="hidden lg:flex items-center gap-6 ml-auto">

            <div className="flex items-center gap-6">
              {isScrolled && (
                <>
                  <Link to="/properties" className={`${navTextClass} hover:text-red-600 font-medium text-[15px] transition-colors duration-200`}>
                    Properties
                  </Link>
                  <Link
                    to="/pricing"
                    className={`${navTextClass} hover:text-red-600 font-medium text-[15px] transition-colors duration-200`}
                  >
                    Pricing
                  </Link>
                  <Link
                    to="/agreements"
                    className={`${navTextClass} hover:text-red-600 font-medium text-[15px] transition-colors duration-200`}
                  >
                    Agreements
                  </Link>
                  <Link to="/about" className={`${navTextClass} hover:text-red-600 font-medium text-[15px] transition-colors duration-200`}>
                    About
                  </Link>
                  <Link to="/contact" className={`${navTextClass} hover:text-red-600 font-medium text-[15px] transition-colors duration-200`}>
                    Contact
                  </Link>
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

              {/* Register Property Button - always visible */}
              <button
                type="button"
                onClick={handleRegisterProperty}
                className="bg-red-600 text-white px-6 py-2.5 rounded-lg text-base font-bold hover:bg-red-700 transition shadow-md"
              >
                Register Property
              </button>
            </div>

            {user ? (
              <div className="relative" ref={userDropdownRef}>
                <button
                  onClick={() => setIsUserDropdownOpen(!isUserDropdownOpen)}
                  className="flex items-center gap-2 p-1 rounded-full hover:bg-gray-100 transition-colors"
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
                  <svg className={`w-4 h-4 text-gray-600 transition-transform ${isUserDropdownOpen ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
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
                            {user.role === 'owner' ? '🏠 Property Owner' : user.role === 'agent' ? '👔 Agent' : '👤 Buyer'}
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* Menu Items */}
                    <div className="py-2">
                      <Link
                        to="/notifications"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <div className="relative">
                          <AiOutlineBell className="w-5 h-5 text-gray-500" />
                          {unreadNotifications > 0 && (
                            <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-red-500"></span>
                          )}
                        </div>
                        <span className="font-medium">Notifications</span>
                      </Link>
                      <Link
                        to="/profile"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <AiOutlineUser className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">My Profile</span>
                      </Link>

                      {(user.role === 'owner' || user.role === 'agent') && (
                        <Link
                          to="/my-properties"
                          onClick={() => setIsUserDropdownOpen(false)}
                          className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                        >
                          <BsHouseDoor className="w-5 h-5 text-gray-500" />
                          <span className="font-medium">My Properties</span>
                        </Link>
                      )}

                      <Link
                        to="/saved-properties"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <AiOutlineHeart className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">Saved Properties</span>
                      </Link>

                      <Link
                        to="/agreements"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <HiOutlineDocumentText className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">My Agreements</span>
                      </Link>
                    </div>

                    {/* Divider */}
                    <div className="border-t border-gray-100 my-1"></div>

                    {/* Settings & Logout */}
                    <div className="py-1">
                      <Link
                        to="/profile?tab=settings"
                        onClick={() => setIsUserDropdownOpen(false)}
                        className="flex items-center gap-3 px-4 py-2.5 text-gray-700 hover:bg-gray-50 transition-colors"
                      >
                        <AiOutlineSetting className="w-5 h-5 text-gray-500" />
                        <span className="font-medium">Settings</span>
                      </Link>

                      <button
                        onClick={() => {
                          handleLogout();
                          setIsUserDropdownOpen(false);
                        }}
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
              <Link to="/login" className={`flex items-center space-x-1 ${navTextClass} hover:text-red-600 transition-colors duration-200`}>
                <AiOutlineUser className="text-lg" />
                <span className="font-medium text-sm">Login</span>
              </Link>
            )}
          </div>

          {/* Mobile Menu Toggle */}
          <button
            onClick={toggleMenu}
            className={`lg:hidden text-2xl transition text-gray-700`}
            aria-label={menuOpen ? "Close menu" : "Open menu"}
          >
            {menuOpen ? <AiOutlineClose /> : <AiOutlineMenu />}
          </button>
        </div>

        {/* Mobile Menu Overlay */}
        <div
          className={`lg:hidden fixed inset-0 z-[5000] bg-black/50 backdrop-blur-sm transition-opacity duration-300 ${menuOpen ? "opacity-100 visible" : "opacity-0 invisible"
            }`}
          onClick={toggleMenu}
        />

        {/* Mobile Menu Drawer */}
        <div
          className={`lg:hidden fixed top-0 right-0 h-full w-[80%] max-w-sm bg-white shadow-2xl z-[5001] transform transition-transform duration-300 ease-out ${menuOpen ? "translate-x-0" : "translate-x-full"
            }`}
        >
          <div className="flex flex-col h-full">
            {/* Header */}
            <div className="flex items-center justify-between p-5 border-b">
              <span className="text-xl font-bold text-slate-800">Menu</span>
              <button
                onClick={toggleMenu}
                className="p-2 text-slate-500 hover:bg-slate-100 rounded-full transition"
              >
                <AiOutlineClose size={24} />
              </button>
            </div>

            {/* Links */}
            <div className="flex-1 overflow-y-auto py-4 px-3 space-y-2">
              <Link
                to="/"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <AiOutlineHome size={20} />
                Home
              </Link>

              <Link
                to="/properties"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <BsBuilding size={20} />
                Properties
              </Link>

              <Link
                to="/pricing"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <AiOutlineFileText size={20} />
                Pricing & Plans
              </Link>

              <button
                onClick={() => {
                  handleRegisterProperty();
                  toggleMenu();
                }}
                className="w-full flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition text-left"
              >
                <AiOutlinePlusCircle size={20} />
                Register Property
              </button>

              {showAgentUpload && (
                <button
                  type="button"
                  className="w-full flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition text-left"
                  onClick={() => {
                    handleAgentUploadNavigation();
                    if (!isExternalAgentUrl) toggleMenu();
                  }}
                >
                  <AiOutlinePlusCircle size={20} />
                  Upload Property
                </button>
              )}

              <Link
                to="/agreements"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <AiOutlineFileText size={20} />
                Agreements
              </Link>

              <Link
                to="/about"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <AiOutlineInfoCircle size={20} />
                About
              </Link>

              <Link
                to="/contact"
                onClick={toggleMenu}
                className="flex items-center gap-4 px-4 py-3 text-slate-700 font-medium rounded-xl hover:bg-red-50 hover:text-red-600 transition"
              >
                <AiOutlinePhone size={20} />
                Contact
              </Link>
            </div>

            {/* Footer / User Section */}
            <div className="p-5 border-t bg-slate-50">
              {user ? (
                <div className="flex flex-col gap-3">
                  {/* User Info */}
                  <div className="flex items-center gap-3 p-2">
                    {user.profileImage ? (
                      <img
                        src={user.profileImage}
                        alt={user.name}
                        className="w-12 h-12 rounded-full object-cover border-2 border-gray-200"
                      />
                    ) : (
                      <div className="w-12 h-12 bg-gradient-to-br from-red-500 to-red-600 rounded-full flex items-center justify-center text-white font-bold text-lg">
                        {user.name?.charAt(0).toUpperCase() || "U"}
                      </div>
                    )}
                    <div className="flex-1">
                      <p className="font-semibold text-slate-800">{user.name || "User"}</p>
                      <p className="text-xs text-slate-500 truncate">{user.email}</p>
                      <span className={`inline-block mt-1 px-2 py-0.5 rounded-full text-xs font-medium ${user.role === 'owner' ? 'bg-blue-100 text-blue-700' :
                        user.role === 'agent' ? 'bg-purple-100 text-purple-700' :
                          'bg-gray-100 text-gray-600'
                        }`}>
                        {user.role === 'owner' ? 'Owner' : user.role === 'agent' ? 'Agent' : 'Buyer'}
                      </span>
                    </div>
                  </div>

                  {/* Quick Links */}
                  <div className="space-y-1">
                    <Link
                      to="/profile"
                      onClick={toggleMenu}
                      className="flex items-center gap-3 px-3 py-2.5 text-slate-700 font-medium rounded-lg hover:bg-white transition"
                    >
                      <AiOutlineUser size={18} />
                      My Profile
                    </Link>
                    {(user.role === 'owner' || user.role === 'agent') && (
                      <Link
                        to="/my-properties"
                        onClick={toggleMenu}
                        className="flex items-center gap-3 px-3 py-2.5 text-slate-700 font-medium rounded-lg hover:bg-white transition"
                      >
                        <BsHouseDoor size={18} />
                        My Properties
                      </Link>
                    )}
                    <Link
                      to="/saved-properties"
                      onClick={toggleMenu}
                      className="flex items-center gap-3 px-3 py-2.5 text-slate-700 font-medium rounded-lg hover:bg-white transition"
                    >
                      <AiOutlineHeart size={18} />
                      Saved Properties
                    </Link>
                  </div>

                  {/* Logout Button */}
                  <button
                    onClick={() => { handleLogout(); toggleMenu(); }}
                    className="w-full flex items-center justify-center gap-2 bg-white border border-red-200 text-red-600 py-2.5 rounded-lg font-medium hover:bg-red-50 transition mt-2"
                  >
                    <AiOutlineLogout size={18} />
                    Logout
                  </button>
                </div>
              ) : (
                <Link
                  to="/login"
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

