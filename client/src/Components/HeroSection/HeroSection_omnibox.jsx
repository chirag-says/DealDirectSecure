// src/Components/HeroSection/HeroSection.jsx - Omnibox Style
import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import api from "../../utils/api";
import { AiOutlineSearch } from "react-icons/ai";
import { FaMapMarkerAlt, FaMicrophone, FaHome, FaKey, FaBuilding, FaBed, FaTree } from "react-icons/fa";
import { tabConfig } from "./filterConfig";
import PropertyTypeFilter from "./PropertyTypeFilter";
import SKYBACKGROUND from "../../assets/SKYBACKGROUND.png";

const API_BASE = import.meta.env.VITE_API_BASE;

const defaultTabs = [
    { label: "Buy", intent: "buy", icon: FaHome },
    { label: "Rental", intent: "rent", icon: FaKey },
    { label: "Projects", intent: "project", icon: FaBuilding },
    { label: "PG / Hostels", intent: "pg", icon: FaBed },
    { label: "Plot & Land", intent: "plot", icon: FaTree },
];

// Omnibox-style relevance scoring
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

const HeroSection = ({ filters, setFilters, propertyTypes = [] }) => {
    const navigate = useNavigate();
    const [activeTab, setActiveTab] = useState("Buy");
    const [openDropdown, setOpenDropdown] = useState(null);
    const [suggestions, setSuggestions] = useState([]);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const [isLoadingSuggestions, setIsLoadingSuggestions] = useState(false);
    const [selectedIndex, setSelectedIndex] = useState(-1);
    const searchInputRef = useRef(null);
    const suggestionsRef = useRef(null);

    const dropdownRefs = {
        budget: useRef(null),
        propertyType: useRef(null),
    };

    // Omnibox-style search with debouncing
    useEffect(() => {
        const fetchSuggestions = async () => {
            if (!filters.search || filters.search.trim().length < 2) {
                setSuggestions([]);
                setShowSuggestions(false);
                return;
            }

            setIsLoadingSuggestions(true);
            try {
                const response = await api.get('/properties/property-list');
                const properties = response.data.data || [];

                const searchTerm = filters.search.toLowerCase().trim();
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
    }, [filters.search]);

    // Handle keyboard navigation
    const handleKeyDown = (e) => {
        if (!showSuggestions || suggestions.length === 0) return;

        if (e.key === 'ArrowDown') {
            e.preventDefault();
            setSelectedIndex(prev => (prev < suggestions.length - 1 ? prev + 1 : prev));
        } else if (e.key === 'ArrowUp') {
            e.preventDefault();
            setSelectedIndex(prev => (prev > 0 ? prev - 1 : -1));
        } else if (e.key === 'Enter' && selectedIndex >= 0) {
            e.preventDefault();
            handleSuggestionClick(suggestions[selectedIndex]);
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

    const tabs = defaultTabs;
    const configKey = tabConfig[activeTab] ? activeTab : "Buy";
    const currentConfig = tabConfig[configKey];

    const updateFilter = (field, value) => {
        setFilters((prev) => ({ ...prev, [field]: value }));
    };

    const updatePropertyTypes = (updater) => {
        setFilters((prev) => {
            const previous = prev.propertyTypes || [];
            const nextValue = typeof updater === "function" ? updater(previous) : updater;
            return { ...prev, propertyTypes: nextValue };
        });
    };

    const renderFilters = () =>
        currentConfig.filters.map((filterType) => {
            if (filterType === "propertyType") {
                return (
                    <PropertyTypeFilter
                        key="propertyType"
                        selectedPropertyTypes={filters.propertyTypes || []}
                        setSelectedPropertyTypes={updatePropertyTypes}
                        openDropdown={openDropdown}
                        setOpenDropdown={setOpenDropdown}
                        dropdownRef={dropdownRefs.propertyType}
                    />
                );
            }
            return null;
        });

    const handleSuggestionClick = (suggestion) => {
        setFilters({ ...filters, search: suggestion.value });
        setShowSuggestions(false);
        setSelectedIndex(-1);
    };

    const handleTabSelect = (tab) => {
        setActiveTab(tab.label);
    };

    // Highlight matching text
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

    return (
        <section className="relative flex flex-col justify-center items-center px-4 sm:px-8 lg:px-16 text-center overflow-visible">
            <div
                className="absolute inset-0 bg-cover bg-center bg-no-repeat"
                style={{ backgroundImage: `url(${SKYBACKGROUND})` }}
            ></div>

            <div
                className="absolute inset-0 opacity-[0.03]"
                style={{
                    backgroundImage:
                        "url('data:image/svg+xml,%3Csvg xmlns=%22http://www.w3.org/2000/svg%22 width=%22100%22 height=%22100%22 viewBox=%220 0 100 100%22%3E%3Ccircle cx=%2250%22 cy=%2250%22 r=%2250%22 fill=%22%23ffffff10%22/%3E%3C/svg%3E')",
                }}
            ></div>

            <div className="relative pt-20 py-15 z-10 flex flex-col items-center max-w-7xl w-full space-y-2">
                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-[700] text-white leading-tight max-w-4xl">
                    Buy, Sell & Rent Properties
                    <br />
                    <span className="text-red-500">Directly from Owners</span>
                </h1>

                <p className="text-lg sm:text-xl lg:text-2xl text-gray-200 max-w-3xl">
                    No middleman. No commission fees.
                    <br />
                    <span className="font-semibold text-white">
                        Deal directly with property owners
                    </span>
                </p>

                <div className="flex flex-wrap justify-center gap-3 mt-5">
                    {tabs.map((tab, i) => {
                        const Icon = tab.icon;
                        return (
                            <button
                                key={`${tab.label}-${i}`}
                                onClick={() => handleTabSelect(tab)}
                                className={`flex items-center gap-2 px-5 py-2.5 rounded-full font-semibold text-sm border-2 transition-all duration-300 ${activeTab === tab.label
                                    ? "bg-red-600 text-white border-transparent shadow-lg shadow-red-500/50 scale-105"
                                    : "bg-white/10 backdrop-blur-sm text-white border-white/30 hover:border-white/50 hover:bg-white/20"
                                    }`}
                            >
                                {Icon && <Icon className="text-base" />}
                                {tab.label}
                            </button>
                        );
                    })}
                </div>

                <div className="bg-white/95 backdrop-blur-md shadow-2xl rounded-3xl p-6 sm:p-8 mt-6 w-full max-w-5xl border border-gray-100">
                    <div className="flex flex-col sm:flex-row gap-3">
                        <div className="relative flex-1" ref={searchInputRef}>
                            <div className="relative flex items-center">
                                <AiOutlineSearch className="absolute left-4 text-gray-500 text-lg" />
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
                                        if (suggestions.length > 0) setShowSuggestions(true);
                                    }}
                                    className="w-full border border-gray-300 rounded-xl pl-11 pr-20 py-3 text-sm text-gray-900 placeholder-gray-500 focus:ring-2 focus:ring-red-500 outline-none"
                                />
                                <div className="absolute right-4 flex items-center gap-3">
                                    <FaMapMarkerAlt className="text-gray-600 cursor-pointer hover:text-gray-800" />
                                    <FaMicrophone className="text-red-600 cursor-pointer hover:text-red-700" />
                                </div>
                            </div>

                            {/* Omnibox Suggestions */}
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
                                                            {highlightMatch(suggestion.value, filters.search)}
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
                        </div>

                        <button className="bg-red-600 text-white px-8 py-3 rounded-xl font-semibold text-sm hover:bg-red-700 transition-all shadow-lg flex items-center gap-2 whitespace-nowrap">
                            <AiOutlineSearch />
                            Search
                        </button>
                    </div>
                </div>
            </div>
        </section>
    );
};

export default HeroSection;
