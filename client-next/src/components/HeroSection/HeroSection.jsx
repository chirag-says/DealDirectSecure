'use client';

// src/Components/HeroSection/HeroSection.jsx - Omnibox Style
import React, { useState, useRef, useEffect } from "react";
import { useRouter } from "next/navigation";
import Image from "next/image";
import api from "../../utils/api";
import { AiOutlineSearch } from "react-icons/ai";
import { FaMapMarkerAlt, FaMicrophone, FaBuilding, FaHistory, FaHome, FaKey, FaTags, FaBed, FaTree, FaStore, FaChevronDown, FaCrosshairs } from "react-icons/fa";
import herokaback from "../../assets/herokaback.png";



// Simple in-memory cache for suggestions
const suggestionsCache = new Map();
const CACHE_TTL = 60000; // 1 minute cache

// Filter Options Constants
const RESIDENTIAL_TYPES = ["Apartment / Flat", "Independent House", "Villa", "Builder Floor", "Row House", "Studio Apartment", "Penthouse", "Farm House"];
const COMMERCIAL_TYPES = ["Office Space", "Shop / Retail", "Showroom", "Restaurant / Cafe", "Co-Working Space", "Warehouse / Godown", "Industrial Shed", "Commercial Building / Floor"];
const BHK_OPTIONS = ["1 RK", "1 BHK", "2 BHK", "3 BHK", "4 BHK", "5+ BHK", "Studio"];
const COMMERCIAL_SUB_TYPES = ["Bare Shell", "Warm Shell", "Fully Furnished"];
const PROJECT_STATUSES = ["New Launch", "Under Construction", "Ready to Move"];
const POSSESSION_STATUSES = ["Ready to Move", "Under Construction"];
const FURNISHING_STATUSES = ["Fully Furnished", "Semi-Furnished", "Unfurnished"];
const TRANSACTION_TYPES = ["Buy", "Rent"];
const BUY_BUDGET_OPTIONS = ["Under ₹50 Lac", "₹50 Lac - ₹1 Cr", "₹1 Cr - ₹2 Cr", "₹2 Cr - ₹5 Cr", "Above ₹5 Cr"];
const RENT_BUDGET_OPTIONS = ["Under ₹10,000", "₹10,000 - ₹25,000", "₹25,000 - ₹50,000", "₹50,000 - ₹1 Lac", "Above ₹1 Lac"];

const HeroSection = ({ filters, setFilters }) => {
  const router = useRouter();
  const [openDropdown, setOpenDropdown] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
  const [isListening, setIsListening] = useState(false);
  const [activeIntent, setActiveIntent] = useState('');

  // New detailed sub-filters
  const [subFilters, setSubFilters] = useState({
    budget: '',
    projectStatus: '',
    possessionStatus: '',
    furnishingStatus: '',
    transactionType: '',
    propertyTypes: [],
    bhk: [],
    commercialSubTypes: []
  });

  const TOP_CITIES = [
    "Agra", "Ahmedabad", "Ajmer", "Aligarh", "Amritsar", "Asansol", 
    "Aurangabad", "Bangalore", "Bareilly", "Belagavi", "Bhavnagar", 
    "Bhilai", "Bhiwandi", "Bhopal", "Bhubaneswar", "Bikaner", "Chandigarh",
    "Chennai", "Coimbatore", "Cuttack", "Dehradun", "Delhi", "Dhanbad",
    "Durgapur", "Erode", "Faridabad", "Firozabad", "Ghaziabad", "Gorakhpur",
    "Gulbarga", "Guntur", "Guwahati", "Gwalior", "Hubli", "Hyderabad",
    "Indore", "Jabalpur", "Jaipur", "Jalandhar", "Jalgaon", "Jamshedpur",
    "Jhansi", "Jodhpur", "Kakinada", "Kannur", "Kanpur", "Kochi", "Kolhapur",
    "Kolkata", "Kollam", "Kozhikode", "Lucknow", "Ludhiana", "Madurai",
    "Malappuram", "Mathura", "Mangalore", "Meerut", "Moradabad", "Mumbai",
    "Mysore", "Nagpur", "Nashik", "Nellore", "Noida", "Patna", "Pondicherry",
    "Prayagraj", "Pune", "Raipur", "Rajkot", "Ranchi", "Rourkela", "Salem",
    "Sangli", "Siliguri", "Solapur", "Srinagar", "Surat", "Thiruvananthapuram",
    "Thrissur", "Tiruchirappalli", "Tiruppur", "Udaipur", "Ujjain",
    "Vadodara", "Varanasi", "Vasai-Virar", "Vijayawada", "Visakhapatnam",
    "Warangal"
  ];
  const [selectedCity, setSelectedCity] = useState("Bangalore");
  const [isLocating, setIsLocating] = useState(false);
  const cityDropdownRef = useRef(null);

  useEffect(() => {
    // Attempt to load from localStorage first
    const savedCity = localStorage.getItem("dd_user_city");
    if (savedCity && TOP_CITIES.includes(savedCity)) {
      setSelectedCity(savedCity);
      // Give the Navbar a quick heartbeat bump
      setTimeout(() => window.dispatchEvent(new Event("city_changed")), 100);
      return;
    }

    // Otherwise, auto-detect location quietly
    if ("geolocation" in navigator) {
      navigator.geolocation.getCurrentPosition(
        async (position) => {
          try {
            const { latitude, longitude } = position.coords;
            const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&addressdetails=1&zoom=14`);
            const data = await res.json();
            
            // Try to extract city name from various OSMap address fields
            const detectedCityRaw = data.address?.city || data.address?.town || data.address?.state_district || "";
            const detectedLocality = data.address?.suburb || data.address?.neighbourhood || data.address?.road || "";
            
            if (detectedLocality && (!filters || !filters.search)) {
              setFilters(prev => ({ ...prev, search: detectedLocality }));
            }
            
            if (!detectedCityRaw) return;

            // Optional: match against our database/list of cities
            // If it's a major city in our array, select it.
            const matchedCity = TOP_CITIES.find(c => detectedCityRaw.toLowerCase().includes(c.toLowerCase()));
            if (matchedCity) {
              setSelectedCity(matchedCity);
              localStorage.setItem("dd_user_city", matchedCity);
              window.dispatchEvent(new Event("city_changed"));
            }
          } catch (err) {
            console.warn("Auto-location failed", err);
            localStorage.setItem("dd_user_city", "Bangalore");
          setSelectedCity("Bangalore");
          if (!filters || !filters.search) {
             setFilters(prev => ({ ...prev, search: "Bangalore" }));
          }
          window.dispatchEvent(new Event("city_changed"));
          }
        },
        (err) => {
          console.warn("Geolocation permission denied or failed", err);
          localStorage.setItem("dd_user_city", "Bangalore");
          setSelectedCity("Bangalore");
          if (!filters || !filters.search) {
             setFilters(prev => ({ ...prev, search: "Bangalore" }));
          }
          window.dispatchEvent(new Event("city_changed"));
        },
        { timeout: 5000 }
      );
    } else {
      localStorage.setItem("dd_user_city", "Bangalore");
          setSelectedCity("Bangalore");
          if (!filters || !filters.search) {
             setFilters(prev => ({ ...prev, search: "Bangalore" }));
          }
          window.dispatchEvent(new Event("city_changed"));
    }
  }, []);

  const toggleArrayFilter = (filterKey, value) => {
    setSubFilters(prev => {
      const current = prev[filterKey];
      if (current.includes(value)) {
        return { ...prev, [filterKey]: current.filter(item => item !== value) };
      }
      return { ...prev, [filterKey]: [...current, value] };
    });
  };

  const handleSubFilterSelect = (filterKey, value) => {
    setSubFilters(prev => {
      // If switching between Buy/Rent, clear incompatible fields
      if (filterKey === 'transactionType' && prev.transactionType !== value) {
        return {
          ...prev,
          [filterKey]: value,
          budget: '',
          possessionStatus: '',
          furnishingStatus: ''
        };
      }
      return { ...prev, [filterKey]: value };
    });
    setOpenDropdown(null);
  };

  const [selectedIndex, setSelectedIndex] = useState(-1);
  const searchInputRef = useRef(null);
  const suggestionsRef = useRef(null);
  const abortControllerRef = useRef(null);
  const recognitionRef = useRef(null);

  const [recentSearches, setRecentSearches] = useState([]);

  useEffect(() => {
    const saved = localStorage.getItem("dealDirectRecentSearches");
    if (saved) {
      try {
        setRecentSearches(JSON.parse(saved));
      } catch {
        console.error("Failed to parse recent searches");
      }
    }
  }, []);

  const addToRecentSearches = (item) => {
    setRecentSearches(prev => {
      const filtered = prev.filter(p => p.value !== item.value);
      const newRecent = [{ ...item, timestamp: Date.now() }, ...filtered].slice(0, 5);
      localStorage.setItem("dealDirectRecentSearches", JSON.stringify(newRecent));
      return newRecent;
    });
  };

  const dropdownRefs = {
    budget: useRef(null),
    projectStatus: useRef(null),
    possessionStatus: useRef(null),
    furnishingStatus: useRef(null),
    transactionType: useRef(null),
    propertyType: useRef(null),
    bhk: useRef(null),
    commercialSubType: useRef(null),
  };

  // Optimized autocomplete with dedicated endpoint, caching, and request cancellation
  useEffect(() => {
    const searchTerm = filters.search?.trim() || '';

    if (searchTerm.length < 2) {
      setSuggestions([]);
      setShowSuggestions(false);
      return;
    }

    // Check cache first
    const cacheKey = searchTerm.toLowerCase();
    const cached = suggestionsCache.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      setSuggestions(cached.data);
      setShowSuggestions(cached.data.length > 0);
      setSelectedIndex(-1);
      return;
    }

    const fetchSuggestions = async () => {
      // Cancel previous request
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
      abortControllerRef.current = new AbortController();

      setIsLoadingSuggestions(true);
      try {
        const response = await api.get(
          '/properties/suggestions',
          {
            params: { q: searchTerm },
            signal: abortControllerRef.current.signal,
            timeout: 3000 // 3 second timeout
          }
        );

        const data = response.data.suggestions || [];

        // Cache the result
        suggestionsCache.set(cacheKey, {
          data,
          timestamp: Date.now()
        });

        setSuggestions(data);
        setShowSuggestions(data.length > 0);
        setSelectedIndex(-1);
      } catch (error) {
        // Only log error if not an abort (user typing too fast)
        if (error?.name !== 'AbortError' && error?.name !== 'CanceledError') {
          console.error('Error fetching suggestions:', error);
          setSuggestions([]);
        }
      } finally {
        setIsLoadingSuggestions(false);
      }
    };

    // Debounce: 150ms for fast response
    const debounceTimer = setTimeout(fetchSuggestions, 150);
    return () => {
      clearTimeout(debounceTimer);
      if (abortControllerRef.current) {
        abortControllerRef.current.abort();
      }
    };
  }, [filters.search]);

  // Handle keyboard navigation
  const handleKeyDown = (e) => {
    // Handle Enter key - either select suggestion or trigger search
    if (e.key === 'Enter') {
      e.preventDefault();
      if (showSuggestions && selectedIndex >= 0 && suggestions[selectedIndex]) {
        handleSuggestionClick(suggestions[selectedIndex]);
      } else {
        handleSearchClick();
      }
      return;
    }

    if (!showSuggestions || suggestions.length === 0) return;

    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex(prev => (prev < suggestions.length - 1 ? prev + 1 : prev));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex(prev => (prev > 0 ? prev - 1 : -1));
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        openDropdown &&
        dropdownRefs[openDropdown]?.current &&
        !dropdownRefs[openDropdown].current.contains(event.target)
      ) {
        setOpenDropdown(null);
      }
      if (
        openDropdown === 'city' &&
        cityDropdownRef.current &&
        !cityDropdownRef.current.contains(event.target)
      ) {
        setOpenDropdown(null);
      }
      if (
        suggestionsRef.current &&
        !suggestionsRef.current.contains(event.target) &&
        searchInputRef.current &&
        !searchInputRef.current.contains(event.target)
      ) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [openDropdown]);

  const buildSearchParams = (queryOverride = null) => {
    const searchParams = new URLSearchParams();
    const queryTerm = queryOverride !== null ? queryOverride : filters.search;

    const isQueryingSpecificCity = TOP_CITIES.some(c =>
      queryTerm && queryTerm.toLowerCase().includes(c.toLowerCase())
    );

    if (queryTerm) searchParams.set("search", queryTerm);

    if (selectedCity && selectedCity !== 'All Cities' && !isQueryingSpecificCity) {
      searchParams.set("city", selectedCity);
    }

    if (activeIntent) searchParams.set("intent", activeIntent);
    if (subFilters.budget) searchParams.set("budget", subFilters.budget);
    if (subFilters.projectStatus) searchParams.set("status", subFilters.projectStatus);
    if (subFilters.possessionStatus) searchParams.set("possession", subFilters.possessionStatus);
    if (subFilters.furnishingStatus) searchParams.set("furnishing", subFilters.furnishingStatus);
    if (subFilters.transactionType) searchParams.set("transaction", subFilters.transactionType);
    if (subFilters.propertyTypes.length > 0) {
      searchParams.set("types", subFilters.propertyTypes.join(','));
    }

    return searchParams;
  };

  const handleSuggestionClick = (suggestion) => {
    setFilters({ ...filters, search: suggestion.value });
    setShowSuggestions(false);
    setSelectedIndex(-1);
    const searchParams = buildSearchParams(suggestion.value);
    router.push(`/properties?${searchParams.toString()}`);
  };

  const handleMapClick = () => {
    const searchParams = buildSearchParams();
    searchParams.set('view', 'map');
    router.push(`/properties?${searchParams.toString()}`);
  };

  const handleSearchClick = () => {
    const searchParams = buildSearchParams();
    router.push(`/properties?${searchParams.toString()}`);
  };

  const startVoiceInput = () => {
    if (isListening) {
      if (recognitionRef.current) {
        recognitionRef.current.stop();
      }
      return;
    }

    if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
      alert("Voice input is not supported in this browser.");
      return;
    }

    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    const recognition = new SpeechRecognition();
    recognitionRef.current = recognition;
    recognition.continuous = false;
    recognition.interimResults = false;
    recognition.lang = 'en-US';

    recognition.onstart = () => { setIsListening(true); };
    recognition.onresult = (event) => {
      const transcript = event.results[0][0].transcript;
      if (transcript) {
        setFilters(prev => ({ ...prev, search: transcript }));
        setShowSuggestions(true);
      }
    };
    recognition.onerror = (event) => {
      console.error("Speech recognition error", event.error);
      setIsListening(false);
    };
    recognition.onend = () => { setIsListening(false); };
    recognition.start();
  };

  // Highlight matching text
  const highlightMatch = (text, query) => {
    if (!query || !text) return text;
    const index = text.toLowerCase().indexOf(query.toLowerCase());
    if (index === -1) return text;

    return (
      <>
        {text.substring(0, index)}
        <span className="text-red-500 font-bold">{text.substring(index, index + query.length)}</span>
        {text.substring(index + query.length)}
      </>
    );
  };

  return (
    <section className="relative flex flex-col justify-center items-center px-4 sm:px-8 lg:px-16 text-center z-20">
      {/* Background image — rendered as next/image with priority for LCP */}
      <Image
        src={herokaback}
        alt=""
        fill
        priority
        className="object-cover object-left md:object-center"
        sizes="100vw"
      />

      {/* Dark overlay for better text readability */}
      <div className="absolute inset-0 bg-black/40"></div>

      <div className="relative pt-24 sm:pt-32 pb-8 sm:pb-16 z-10 flex flex-col items-center max-w-7xl w-full space-y-1 sm:space-y-2">
        <h1 className="text-xl sm:text-4xl lg:text-5xl font-[700] text-white leading-tight max-w-4xl">
          Buy, Rent & Sell Properties
          <br />
          <span className="bg-gradient-to-r from-blue-400 to-cyan-300 bg-clip-text text-transparent">
            Directly from Owners
          </span>
        </h1>

        <p className="font-bold text-sm sm:text-xl lg:text-2xl text-gray-200 max-w-3xl">
          No middleman. No commission fees.
          <br />
          <span className="font-bold text-white">
            Deal directly with property owners
          </span>
        </p>

        {/* Hero Section Search Bar Layout */}
        <div className="mt-4 sm:mt-8 w-full max-w-5xl relative z-50 px-2 sm:px-0">
          
          {/* Intent Tabs Row (mobile: above, desktop: inline) */}
          <div className="flex w-full overflow-hidden rounded-t-xl relative z-10 bottom-0 ml-0 sm:hidden">
            {[
              { label: 'Residential', value: 'Residential' },
              { label: 'Commercial', value: 'Commercial' },
            ].map((intent) => (
              <button
                key={intent.label}
                onClick={() => {
                  setActiveIntent(prev => prev === intent.value ? '' : intent.value);
                  setSubFilters(prev => ({ ...prev, propertyTypes: [] }));
                }}
                className={`flex-1 px-5 py-2 text-[11px] font-bold transition-all ${
                  activeIntent === intent.value
                    ? 'bg-white text-blue-500'
                    : 'bg-black/40 text-white hover:bg-black/60'
                }`}
              >
                {intent.label}
              </button>
            ))}
          </div>

          {/* Transaction Tabs Row + Intent (desktop only inline) */}
          <div className="flex w-full sm:w-fit overflow-hidden sm:rounded-t-xl relative z-10 bottom-[-1px] ml-0">
            {/* Transaction Type Tabs */}
            {[
              { label: 'All Status', type: '' },
              { label: 'For Rent', type: 'Rent' },
              { label: 'For Sale', type: 'Buy' },
            ].map((tab) => {
              const isActive = (tab.label === 'All Status' && subFilters.transactionType === '') || 
                               (tab.type !== '' && subFilters.transactionType === tab.type);
              return (
                <button
                  key={tab.label}
                  onClick={() => {
                    setSubFilters(prev => ({
                      ...prev,
                      transactionType: tab.type,
                      propertyTypes: [],
                      bhk: [],
                      commercialSubTypes: [],
                      projectStatus: '',
                      possessionStatus: '',
                      furnishingStatus: '',
                      budget: ''
                    }));
                  }}
                  className={`flex-1 sm:flex-none px-4 sm:px-6 py-2.5 sm:py-3 text-[11px] sm:text-sm font-bold transition-all ${
                    isActive
                      ? 'bg-white text-blue-500'
                      : 'bg-black/40 text-white hover:bg-black/60'
                  }`}
                >
                  {tab.label}
                </button>
              );
            })}

            {/* Divider - desktop only */}
            <div className="hidden sm:flex items-center px-0.5 bg-black/40">
              <div className="w-px h-5 bg-white/30"></div>
            </div>

            {/* Intent Tabs - desktop only (inline with transaction) */}
            {[
              { label: 'Residential', value: 'Residential' },
              { label: 'Commercial', value: 'Commercial' },
            ].map((intent) => (
              <button
                key={`desktop-${intent.label}`}
                onClick={() => {
                  setActiveIntent(prev => prev === intent.value ? '' : intent.value);
                  setSubFilters(prev => ({ ...prev, propertyTypes: [] }));
                }}
                className={`hidden sm:block px-6 py-3 text-sm font-bold transition-all ${
                  activeIntent === intent.value
                    ? 'bg-white text-blue-500'
                    : 'bg-black/40 text-white hover:bg-black/60'
                }`}
              >
                {intent.label}
              </button>
            ))}
          </div>

          {/* Main Search Container */}
          <div className="bg-white rounded-b-xl rounded-tr-xl shadow-2xl p-3 sm:p-4 relative w-full text-left">
          <div className="grid grid-cols-2 md:flex md:flex-row md:items-center gap-2 md:gap-4">
            
            {/* LOOKING FOR */}
            <div className="col-span-2 md:flex-1 w-full md:border-r border-gray-200 border border-gray-100 md:border-0 rounded-lg md:rounded-none px-2 py-2 md:py-0 md:pb-0 relative" ref={dropdownRefs.propertyType}>
              <label className="text-[10px] font-extrabold text-gray-800 uppercase tracking-widest hidden md:block mb-1">Looking For</label>
              <div 
                onClick={() => setOpenDropdown(openDropdown === 'propertyType' ? null : 'propertyType')}
                className="flex justify-between items-center cursor-pointer text-gray-400 text-sm md:text-base hover:text-gray-600 transition-colors"
              >
                <span className={`truncate pr-2 ${subFilters.propertyTypes.length > 0 ? 'text-gray-800 font-medium' : ''}`}>
                  {subFilters.propertyTypes.length > 0 ? subFilters.propertyTypes.join(', ') : 'Property Type'}
                </span>
                <FaChevronDown className="text-[10px] md:text-xs shrink-0" />
              </div>
              
              {openDropdown === 'propertyType' && (
                <div className="absolute left-0 right-0 sm:right-auto top-full mt-2 bg-white rounded-xl shadow-xl border border-gray-100 p-4 sm:w-80 z-[9999] text-left">
                  <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">
                    {activeIntent === 'Commercial' ? 'Commercial Types' : activeIntent === 'Residential' ? 'Residential Types' : 'Property Types'}
                  </h4>
                  <div className="flex flex-wrap gap-2 max-h-[300px] overflow-y-auto">
                    {(activeIntent === 'Commercial' ? COMMERCIAL_TYPES : activeIntent === 'Residential' ? RESIDENTIAL_TYPES : [...RESIDENTIAL_TYPES, ...COMMERCIAL_TYPES]).map(opt => (
                      <button
                        key={opt}
                        onClick={() => toggleArrayFilter('propertyTypes', opt)}
                        className={`px-3 py-1.5 rounded-full border text-xs sm:text-sm transition-colors ${
                          subFilters.propertyTypes.includes(opt)
                            ? 'bg-blue-600 text-white border-blue-600'
                            : 'bg-white text-gray-600 border-gray-200 hover:border-blue-400'
                        }`}
                      >
                        {opt}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* LOCATION */}
            <div className="col-span-2 md:flex-[1.5] w-full md:border-r border-gray-200 border border-gray-100 md:border-0 rounded-lg md:rounded-none px-2 py-2 md:py-0 md:pb-0 relative" ref={searchInputRef}>
              <label className="text-[10px] font-extrabold text-gray-800 uppercase tracking-widest hidden md:block mb-1">Location</label>
              <div className="flex items-center gap-2 w-full">
                
                {/* City Selector */}
                <div className="relative flex items-center h-full shrink-0" ref={cityDropdownRef}>
                  <div 
                    className="cursor-pointer text-sm md:text-base font-medium text-gray-800 flex items-center gap-1.5 border-r border-gray-200 pr-2 shrink-0 hover:text-blue-500 transition-colors h-full" 
                    onClick={(e) => { e.stopPropagation(); setOpenDropdown(openDropdown === 'city' ? null : 'city'); }}
                  >
                    <span className="truncate max-w-[80px] md:max-w-[120px]">All Cities</span>
                    <FaChevronDown className="text-[10px] text-gray-400" />
                  </div>
                  
                  {/* City Dropdown Box (Same as before) */}
                  {openDropdown === 'city' && (
                    <div className="fixed inset-0 sm:absolute sm:inset-auto sm:top-full sm:left-0 sm:mt-2 bg-white sm:rounded-xl sm:shadow-xl sm:border sm:border-gray-100 sm:py-3 sm:w-64 z-[9999] text-left sm:overflow-hidden">
                      <div className="px-4 pb-2 mb-2 border-b border-gray-100 flex flex-col gap-1">
                        <h4 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest">Select City</h4>
                        <button 
                          onClick={() => {
                            setIsLocating(true);
                            navigator.geolocation.getCurrentPosition(
                              async (position) => {
                                try {
                                  const { latitude, longitude } = position.coords;
                                  const res = await fetch(`https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&addressdetails=1&zoom=14`);
                                  const data = await res.json();
                                  const detected = data.address?.city || data.address?.town || data.address?.state_district || "Bangalore";
                                  const locality = data.address?.suburb || data.address?.neighbourhood || data.address?.road || detected;
                                  const matched = TOP_CITIES.find(c => detected.toLowerCase().includes(c.toLowerCase())) || detected;
                                  setSelectedCity(matched);
                                  localStorage.setItem("dd_user_city", matched);
                                  window.dispatchEvent(new Event("city_changed"));
                                  if (locality && (!filters || !filters.search)) {
                                    setFilters(prev => ({ ...prev, search: locality }));
                                  }
                                } catch (e) {
                                  // fallback
                                } finally {
                                  setIsLocating(false);
                                  setOpenDropdown(null);
                                }
                              },
                              () => {
                                setIsLocating(false);
                                alert("Location access denied or unavailable.");
                              }
                            );
                          }}
                          className="flex items-center gap-2 text-xs font-semibold text-blue-600 hover:text-blue-700 hover:bg-blue-50 py-1.5 px-2 -mx-2 rounded-md transition-colors"
                        >
                          <FaCrosshairs className={isLocating ? "animate-spin" : ""} />
                          {isLocating ? "Locating..." : "Auto-detect my City"}
                        </button>
                      </div>
                      {/* Mobile close bar */}
                      <div className="sm:hidden flex items-center justify-between px-4 pt-4 pb-3 border-b border-gray-200">
                        <h3 className="text-base font-bold text-gray-800">Select City</h3>
                        <button onClick={() => setOpenDropdown(null)} className="text-gray-400 hover:text-gray-600 text-2xl leading-none">&times;</button>
                      </div>
                      <div className="max-h-[60vh] sm:max-h-60 overflow-y-auto">
                        <div 
                          onClick={() => {
                            setSelectedCity("All Cities");
                            setFilters(prev => ({ ...prev, search: '' }));
                            setOpenDropdown(null);
                          }}
                          className={`px-4 py-2 text-sm cursor-pointer transition-colors ${selectedCity === 'All Cities' ? 'bg-red-50 text-red-600 font-bold' : 'text-gray-700 hover:bg-gray-50'}`}
                        >
                          All Cities
                        </div>
                        {TOP_CITIES.map(city => (
                          <div 
                            key={city}
                            onClick={() => {
                              setSelectedCity(city);
                              localStorage.setItem("dd_user_city", city);
                              window.dispatchEvent(new Event("city_changed"));
                              setFilters(prev => ({ ...prev, search: city }));
                              setOpenDropdown(null);
                            }}
                            className={`px-4 py-2 text-sm cursor-pointer transition-colors ${selectedCity === city ? 'bg-red-50 text-red-600 font-bold' : 'text-gray-700 hover:bg-gray-50'}`}
                          >
                            {city}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                {/* Autocomplete Input */}
                <input
                  type="text"
                  value={filters.search}
                  onChange={(e) => {
                    setFilters({ ...filters, search: e.target.value });
                    setShowSuggestions(true);
                  }}
                  onKeyDown={handleKeyDown}
                  onFocus={() => setShowSuggestions(true)}
                  placeholder={isListening ? "Listening..." : "Search Locality..."}
                  className="flex-1 text-sm md:text-base bg-transparent outline-none text-gray-800 font-medium placeholder-gray-400 min-w-0"
                />
              </div>

              {/* Suggestions Box */}
              {showSuggestions && ((suggestions.length > 0) || isLoadingSuggestions || (recentSearches.length > 0 && (!filters.search || filters.search.length < 2))) && (
                <div
                  ref={suggestionsRef}
                  className="absolute top-full left-0 mt-3 bg-white border border-gray-100 rounded-2xl shadow-2xl max-h-[400px] sm:max-h-[500px] overflow-y-auto z-[9999] text-left py-2 w-full sm:w-[500px]"
                >
                  {isLoadingSuggestions ? (
                    <div className="p-6 text-center text-gray-500">
                      <div className="animate-spin inline-block w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full mb-2"></div>
                      <p className="text-sm font-medium">Finding best matches...</p>
                    </div>
                  ) : (
                    <div className="flex flex-col">
                      {/* Recent Searches Section */}
                      {(!filters.search || filters.search.length < 2) && recentSearches.length > 0 && (
                        <div className="mb-2">
                          <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2 px-5 mt-2">Recent Searches</h3>
                          <div className="px-3 space-y-1">
                            {recentSearches.map((suggestion, index) => (
                              <div
                                key={`recent-${index}`}
                                onClick={() => handleSuggestionClick(suggestion)}
                                className="rounded-lg p-2.5 hover:bg-gray-50 cursor-pointer transition-colors group flex items-center gap-3"
                              >
                                <div className="text-gray-400 group-hover:text-blue-500 transition-colors">
                                  <FaHistory size={12} className="transform rotate-12" />
                                </div>
                                <div className="flex-1">
                                  <p className="text-[13px] font-medium text-gray-700 group-hover:text-gray-900">{suggestion.value}</p>
                                  {suggestion.subtitle && <p className="text-[11px] text-gray-400">{suggestion.subtitle}</p>}
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* API Results */}
                      {suggestions.length > 0 && (
                        <>
                          {suggestions.filter(s => s.type === 'city' || s.type === 'locality').length > 0 && (
                            <div className="mt-1">
                              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 px-5 pt-2">Location</h3>
                              <ul>
                                {suggestions.filter(s => s.type === 'city' || s.type === 'locality').map((suggestion, index) => (
                                  <li
                                    key={`loc-${index}`}
                                    onClick={() => handleSuggestionClick(suggestion)}
                                    className="px-5 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-3 group"
                                  >
                                    <div className="text-gray-400 group-hover:text-blue-500 transition-colors">
                                      <FaMapMarkerAlt size={14} />
                                    </div>
                                    <div className="flex-1">
                                      <p className="text-[13px] font-medium text-gray-700 group-hover:text-gray-900">
                                        {highlightMatch(suggestion.value, filters.search)}
                                      </p>
                                      {suggestion.subtitle && (
                                        <p className="text-[11px] text-gray-400">{suggestion.subtitle}</p>
                                      )}
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {suggestions.filter(s => s.type === 'project').length > 0 && (
                            <div className="mt-1">
                              <h3 className="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-1 px-5 pt-2">Project</h3>
                              <ul>
                                {suggestions.filter(s => s.type === 'project').map((suggestion, index) => (
                                  <li
                                    key={`proj-${index}`}
                                    onClick={() => handleSuggestionClick(suggestion)}
                                    className="px-5 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-3 group"
                                  >
                                    <div className="text-gray-400 group-hover:text-blue-500 transition-colors">
                                      <FaBuilding size={14} />
                                    </div>
                                    <div className="flex-1">
                                      <p className="text-[13px] font-medium text-gray-700 group-hover:text-gray-900">
                                        {highlightMatch(suggestion.value, filters.search)}
                                      </p>
                                      {suggestion.subtitle && (
                                        <p className="text-[11px] text-gray-400">{suggestion.subtitle}</p>
                                      )}
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* PROPERTY SIZE */}
            <div className="col-span-1 md:flex-1 w-full md:border-r border-gray-200 border border-gray-100 md:border-0 rounded-lg md:rounded-none px-2 py-2 md:py-0 md:pb-0 relative" ref={dropdownRefs.bhk}>
              <label className="text-[10px] font-extrabold text-gray-800 uppercase tracking-widest hidden md:block mb-1">Property Size</label>
              <div 
                onClick={() => setOpenDropdown(openDropdown === 'bhk' ? null : 'bhk')}
                className="flex justify-between items-center cursor-pointer text-gray-400 text-sm md:text-base hover:text-gray-600 transition-colors"
              >
                <span className={`truncate pr-2 ${subFilters.bhk.length > 0 ? 'text-gray-800 font-medium' : ''}`}>
                  {subFilters.bhk.length > 0 ? subFilters.bhk.join(', ') : 'Bedrooms'}
                </span>
                <FaChevronDown className="text-[10px] md:text-xs shrink-0" />
              </div>
              
              {openDropdown === 'bhk' && (
                <div className="absolute left-0 right-0 sm:right-auto top-full mt-2 bg-white rounded-xl shadow-xl border border-gray-100 p-4 sm:w-64 z-[9999] text-left">
                  <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">BHK Configuration</h4>
                  <div className="flex flex-wrap gap-2">
                    {BHK_OPTIONS.map(opt => (
                      <button
                        key={opt}
                        onClick={() => toggleArrayFilter('bhk', opt)}
                        className={`px-3 py-1.5 rounded-full border text-xs sm:text-sm transition-colors ${
                          subFilters.bhk.includes(opt)
                            ? 'bg-blue-600 text-white border-blue-600'
                            : 'bg-white text-gray-600 border-gray-200 hover:border-blue-400'
                        }`}
                      >
                        {opt}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* YOUR BUDGET */}
            <div className="col-span-1 md:flex-1 w-full border border-gray-100 md:border-0 rounded-lg md:rounded-none px-2 py-2 md:py-0 md:pb-0 relative" ref={dropdownRefs.budget}>
              <label className="text-[10px] font-extrabold text-gray-800 uppercase tracking-widest hidden md:block mb-1">Your Budget</label>
              <div 
                onClick={() => setOpenDropdown(openDropdown === 'budget' ? null : 'budget')}
                className="flex justify-between items-center cursor-pointer text-gray-400 text-sm md:text-base hover:text-gray-600 transition-colors"
              >
                <span className={`truncate pr-2 ${subFilters.budget ? 'text-gray-800 font-medium' : ''}`}>
                  {subFilters.budget || 'Max. Price'}
                </span>
                <FaChevronDown className="text-[10px] md:text-xs shrink-0" />
              </div>
              
              {openDropdown === 'budget' && (
                <div className="absolute left-0 right-0 sm:right-auto top-full mt-2 bg-white rounded-xl shadow-xl border border-gray-100 p-4 sm:w-64 z-[9999] text-left">
                  <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-3">Select Budget</h4>
                  <div className="flex flex-col gap-2">
                    {(subFilters.transactionType === 'Rent' ? RENT_BUDGET_OPTIONS : BUY_BUDGET_OPTIONS).map(opt => (
                      <label key={opt} className="flex items-center gap-3 cursor-pointer group">
                        <div className={`w-4 h-4 rounded-full border flex items-center justify-center ${subFilters.budget === opt ? 'border-blue-500' : 'border-gray-300 group-hover:border-blue-400'}`}>
                          {subFilters.budget === opt && <div className="w-2 h-2 bg-blue-500 rounded-full" />}
                        </div>
                        <span className="text-sm text-gray-600 select-none group-hover:text-gray-900 font-medium">{opt}</span>
                        <input type="radio" className="hidden" checked={subFilters.budget === opt} onChange={() => handleSubFilterSelect('budget', opt)} />
                      </label>
                    ))}
                    <button onClick={() => handleSubFilterSelect('budget', '')} className="text-[11px] font-bold text-red-500 mt-2 hover:underline text-left uppercase tracking-wider">Clear Selection</button>
                  </div>
                </div>
              )}
            </div>

            {/* SEARCH BUTTON */}
            <button
              onClick={handleSearchClick}
              className="col-span-2 md:col-span-1 bg-[#00b2ff] text-white rounded-lg px-6 py-3 md:py-4 font-bold text-sm md:text-base hover:bg-[#0099db] transition-colors flex-shrink-0 shadow-md hover:shadow-lg"
            >
              Search
            </button>
            
          </div>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;