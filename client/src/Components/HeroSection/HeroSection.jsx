// src/Components/HeroSection/HeroSection.jsx - Omnibox Style
import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../utils/api";
import { AiOutlineSearch } from "react-icons/ai";
import { FaMapMarkerAlt, FaMicrophone, FaBuilding, FaHistory } from "react-icons/fa";
import herokaback from "../../assets/herokaback.png";



// Simple in-memory cache for suggestions
const suggestionsCache = new Map();
const CACHE_TTL = 60000; // 1 minute cache

const HeroSection = ({ filters, setFilters }) => {
  const navigate = useNavigate();
  const [openDropdown, setOpenDropdown] = useState(null);
  const [suggestions, setSuggestions] = useState([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
  const [isListening, setIsListening] = useState(false);

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
    propertyType: useRef(null),
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
        // If a suggestion is selected, click it
        handleSuggestionClick(suggestions[selectedIndex]);
      } else {
        // Otherwise, trigger normal search
        handleSearchClick();
      }
      return;
    }

    // Arrow navigation only works when suggestions are visible
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

  const handleSuggestionClick = (suggestion) => {
    addToRecentSearches(suggestion);
    setFilters({ ...filters, search: suggestion.value });
    setShowSuggestions(false);
    setSelectedIndex(-1);
    // Navigate to properties page with the selected suggestion
    navigate(`/properties?search=${encodeURIComponent(suggestion.value)}&intent=Buy`);
  };

  const handleMapClick = () => {
    // Navigate to PropertyList with map view enabled
    // Preserve current search query if any
    const searchParams = new URLSearchParams();
    searchParams.set('view', 'map');
    if (filters.search) {
      searchParams.set('search', filters.search);
    }
    navigate(`/properties?${searchParams.toString()}`);
  };

  const handleSearchClick = () => {
    const searchParams = new URLSearchParams();

    if (filters.search) {
      searchParams.set("search", filters.search);
    }

    // Default intent since tabs are not shown in this simplified version
    searchParams.set("intent", "Buy");

    navigate(`/properties?${searchParams.toString()}`);
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

    recognition.onstart = () => {
      setIsListening(true);
    };

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

    recognition.onend = () => {
      setIsListening(false);
    };

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
      {/* Background image */}
      <div
        className="absolute inset-0 bg-cover bg-left md:bg-center bg-no-repeat"
        style={{ backgroundImage: `url(${herokaback})` }}
      ></div>

      {/* Dark overlay for better text readability */}
      <div className="absolute inset-0 bg-black/40"></div>

      <div className="relative pt-32 pb-16 z-10 flex flex-col items-center max-w-7xl w-full space-y-2">
        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-[700] text-white leading-tight max-w-4xl">
          Buy, Rent & Sell Properties
          <br />
          <span className="text-red-600">Directly from Owners</span>
        </h1>

        <p className="font-bold text-lg sm:text-xl lg:text-2xl text-gray-200 max-w-3xl">
          No middleman. No commission fees.
          <br />
          <span className="font-bold text-white">
            Deal directly with property owners
          </span>
        </p>

        <div className="bg-white/95 backdrop-blur-md shadow-2xl rounded-full p-1.5 sm:p-3 mt-8 w-full max-w-5xl relative z-50">
          <div className="flex flex-row gap-2 items-center">
            <div className="relative flex-1 w-full z-50" ref={searchInputRef}>
              <div className="relative flex items-center">
                <AiOutlineSearch className="absolute left-3 sm:left-4 text-gray-400 text-lg sm:text-2xl" />
                <input
                  type="text"
                  placeholder="Search by Project, Locality, or City"
                  value={filters.search}
                  onChange={(e) => {
                    setFilters({ ...filters, search: e.target.value });
                    setShowSuggestions(true);
                  }}
                  onKeyDown={handleKeyDown}
                  onFocus={() => {
                    setShowSuggestions(true);
                  }}
                  className="w-full bg-transparent rounded-full pl-9 sm:pl-12 pr-16 sm:pr-20 py-2 sm:py-4 text-sm sm:text-lg text-gray-900 placeholder-gray-400 focus:outline-none placeholder:text-ellipsis"
                />
                {/* Responsive placeholder text using CSS */}
                {/* Re-setting placeholder to long text, but relying on CSS to handle overflow gracefully if needed. 
                     Actually, a short placeholder "Search by Project..." works better. 
                     Let's use the full text but rely on text-overflow (already added placeholder:text-ellipsis). */}
                <div className="absolute right-2 sm:right-4 flex items-center gap-2 sm:gap-4">
                  <FaMapMarkerAlt
                    className="text-gray-600 cursor-pointer hover:text-blue-800 text-base sm:text-blue-600-2xl transition-colors hover:scale-110 animate-pulse"
                    onClick={handleMapClick}
                    title="Search on Map"
                  />
                  <FaMicrophone
                    className={`cursor-pointer text-base sm:text-xl transition-all hover:scale-110 ${isListening ? 'text-red-600 animate-pulse scale-110' : 'text-red-600 hover:text-red-700'}`}
                    onClick={startVoiceInput}
                    title="Search by Voice"
                  />
                </div>
              </div>

              {/* Omnibox Suggestions */}
              {showSuggestions && (
                <div
                  ref={suggestionsRef}
                  className="absolute top-full left-0 right-0 mt-3 bg-white border border-gray-100 rounded-2xl shadow-2xl max-h-[500px] overflow-y-auto z-50 text-left py-2"
                >
                  {isLoadingSuggestions ? (
                    <div className="p-6 text-center text-gray-500">
                      <div className="animate-spin inline-block w-6 h-6 border-2 border-red-600 border-t-transparent rounded-full"></div>
                      <p className="mt-2 text-sm font-medium">Finding best matches...</p>
                    </div>
                  ) : (
                    <div className="flex flex-col">
                      {/* Recent Searches Section - Show if query is empty or matches found */}
                      {(!filters.search || filters.search.length < 2) && recentSearches.length > 0 && (
                        <div className="mb-2">
                          <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-2 px-6 mt-2">Recent Searches</h3>
                          <div className="px-4 space-y-2">
                            {recentSearches.map((suggestion, index) => (
                              <div
                                key={`recent-${index}`}
                                onClick={() => handleSuggestionClick(suggestion)}
                                className="border border-gray-200 rounded-xl p-3 hover:bg-red-50 cursor-pointer transition-colors group"
                              >
                                <div className="flex items-center gap-3">
                                  <div className="w-8 h-8 rounded-full bg-gray-100 flex items-center justify-center text-gray-400 group-hover:bg-white group-hover:text-red-500 transition-colors">
                                    <FaHistory size={12} className="transform rotate-12" /> {/* Using generic icon for recent */}
                                  </div>
                                  <div>
                                    <p className="text-sm font-semibold text-gray-800">{suggestion.value}</p>
                                    {suggestion.subtitle && <p className="text-xs text-gray-500">{suggestion.subtitle}</p>}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Grouped API Results */}
                      {suggestions.length > 0 && (
                        <>
                          {/* Locations Group */}
                          {suggestions.filter(s => s.type === 'city' || s.type === 'locality').length > 0 && (
                            <div className="mt-2">
                              <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1 px-6 pt-2">Location</h3>
                              <ul>
                                {suggestions.filter(s => s.type === 'city' || s.type === 'locality').map((suggestion, index) => (
                                  <li
                                    key={`loc-${index}`}
                                    onClick={() => handleSuggestionClick(suggestion)}
                                    className="px-6 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-3 group"
                                  >
                                    <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-gray-50 text-gray-400 group-hover:bg-red-50 group-hover:text-red-500 transition-colors">
                                      <FaMapMarkerAlt />
                                    </div>
                                    <div className="flex-1">
                                      <p className="text-sm text-gray-700">
                                        {highlightMatch(suggestion.value, filters.search)}
                                      </p>
                                      {suggestion.subtitle && (
                                        <p className="text-xs text-gray-400">{suggestion.subtitle}</p>
                                      )}
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Projects Group */}
                          {suggestions.filter(s => s.type === 'project').length > 0 && (
                            <div className="mt-2 text-gray-800">
                              <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1 px-6 pt-2">Project</h3>
                              <ul>
                                {suggestions.filter(s => s.type === 'project').map((suggestion, index) => (
                                  <li
                                    key={`proj-${index}`}
                                    onClick={() => handleSuggestionClick(suggestion)}
                                    className="px-6 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-3 group"
                                  >
                                    <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-gray-50 text-gray-400 group-hover:bg-blue-50 group-hover:text-blue-500 transition-colors">
                                      <FaBuilding />
                                    </div>
                                    <div className="flex-1">
                                      <p className="text-sm text-gray-700">
                                        {highlightMatch(suggestion.value, filters.search)}
                                      </p>
                                      {suggestion.subtitle && (
                                        <p className="text-xs text-gray-400">{suggestion.subtitle}</p>
                                      )}
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {/* Other Group (if any) */}
                          {suggestions.filter(s => !['city', 'locality', 'project'].includes(s.type)).length > 0 && (
                            <div className="mt-2 text-gray-800">
                              <h3 className="text-xs font-bold text-gray-500 uppercase tracking-wider mb-1 px-6 pt-2">Other Matches</h3>
                              <ul>
                                {suggestions.filter(s => !['city', 'locality', 'project'].includes(s.type)).map((suggestion, index) => (
                                  <li
                                    key={`other-${index}`}
                                    onClick={() => handleSuggestionClick(suggestion)}
                                    className="px-6 py-2.5 cursor-pointer hover:bg-gray-50 transition-colors flex items-center gap-3 group"
                                  >
                                    <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-gray-50 text-gray-400">
                                      <AiOutlineSearch />
                                    </div>
                                    <div className="flex-1">
                                      <p className="text-sm text-gray-700">
                                        {highlightMatch(suggestion.value, filters.search)}
                                      </p>
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </>
                      )}

                      {suggestions.length === 0 && (!filters.search || filters.search.length < 2) && recentSearches.length === 0 && (
                        <div className="p-8 text-center text-gray-400">
                          <p>Start typing to search properties...</p>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>

            <button
              onClick={handleSearchClick}
              className="bg-red-600 text-white p-3 sm:px-8 sm:py-4 rounded-full font-semibold text-sm sm:text-lg hover:bg-red-700 transition-all shadow-lg flex items-center justify-center gap-2 whitespace-nowrap flex-shrink-0 aspect-square sm:aspect-auto"
            >
              <AiOutlineSearch className="text-xl sm:text-xl" />
              <span className="hidden sm:inline">Search</span>
            </button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default HeroSection;