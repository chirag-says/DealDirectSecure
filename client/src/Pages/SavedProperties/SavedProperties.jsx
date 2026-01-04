import React, { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { toast } from "react-toastify";
import {
  Heart,
  MapPin,
  Home,
  Building2,
  ExternalLink,
  Search,
  RefreshCw,
  HeartOff,
  Clock,
} from "lucide-react";
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from "framer-motion";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";

// Property Card Component
const PropertyCard = ({ property, onRemove, onViewDetails }) => {
  const [removing, setRemoving] = useState(false);

  const formatPrice = (price) => {
    if (!price) return "Price on Request";
    if (price >= 10000000) return `₹${(price / 10000000).toFixed(2)} Cr`;
    if (price >= 100000) return `₹${(price / 100000).toFixed(2)} Lac`;
    return `₹${price.toLocaleString()}`;
  };

  const getMainImage = () => {
    // Check categorized images first (residential or commercial)
    if (property.categorizedImages) {
      if (property.categorizedImages.residential) {
        const residentialCategories = ['exterior', 'livingRoom', 'bedroom', 'hall', 'balcony', 'kitchen'];
        for (const cat of residentialCategories) {
          if (property.categorizedImages.residential[cat]?.length > 0) {
            return property.categorizedImages.residential[cat][0];
          }
        }
      }
      if (property.categorizedImages.commercial) {
        const commercialCategories = ['facade', 'reception', 'workArea', 'cabin', 'shopFloor'];
        for (const cat of commercialCategories) {
          if (property.categorizedImages.commercial[cat]?.length > 0) {
            return property.categorizedImages.commercial[cat][0];
          }
        }
      }
    }
    if (property.images?.length > 0) {
      return property.images[0];
    }
    return "https://images.unsplash.com/photo-1560518883-ce09059eeffa?w=400";
  };

  const handleRemove = async () => {
    setRemoving(true);
    await onRemove(property._id);
    setRemoving(false);
  };

  const getPropertyType = () => {
    if (typeof property.propertyType === 'object') {
      return property.propertyType?.name;
    }
    return property.propertyType || property.propertyTypeName || "Property";
  };

  const getLocation = () => {
    const locality = property.locality || property.address?.locality || property.address?.area || "";
    const city = property.city || property.address?.city || "";
    return `${locality}${locality && city ? ", " : ""}${city}`;
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -20 }}
      className="bg-white rounded-2xl border border-gray-200 overflow-hidden hover:shadow-xl transition-all group"
    >
      {/* Image Section */}
      <div className="relative h-52 overflow-hidden">
        <img
          src={getMainImage()}
          alt={property.title}
          className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-500"
        />

        {/* Overlay Gradient */}
        <div className="absolute inset-0 bg-gradient-to-t from-black/60 via-transparent to-transparent" />

        {/* Top Badges */}
        <div className="absolute top-3 left-3 flex gap-2">
          <span className="px-3 py-1 bg-red-600 text-white text-xs font-bold rounded-full shadow-lg">
            {property.listingType || "Rent"}
          </span>
          <span className="px-3 py-1 bg-white/95 text-gray-800 text-xs font-medium rounded-full shadow">
            {getPropertyType()}
          </span>
        </div>

        {/* Remove Button */}
        <button
          onClick={handleRemove}
          disabled={removing}
          className="absolute top-3 right-3 p-2.5 bg-white/90 backdrop-blur rounded-full hover:bg-red-50 transition shadow-lg group/btn disabled:opacity-50"
          title="Remove from saved"
        >
          {removing ? (
            <RefreshCw className="w-4 h-4 text-red-500 animate-spin" />
          ) : (
            <HeartOff className="w-4 h-4 text-red-500 group-hover/btn:scale-110 transition-transform" />
          )}
        </button>

        {/* Price Badge */}
        <div className="absolute bottom-3 left-3">
          <div className="bg-white/95 backdrop-blur px-4 py-2 rounded-xl shadow-lg">
            <p className="text-lg font-bold text-gray-900">{formatPrice(property.expectedPrice || property.price)}</p>
            {property.listingType === "Rent" && (
              <p className="text-xs text-gray-500">per month</p>
            )}
          </div>
        </div>

        {/* Interested Badge */}
        <div className="absolute bottom-3 right-3">
          <div className="flex items-center gap-1.5 bg-pink-500 text-white px-3 py-1.5 rounded-full text-xs font-medium shadow-lg">
            <Heart className="w-3.5 h-3.5 fill-current" />
            Interested
          </div>
        </div>
      </div>

      {/* Content Section */}
      <div className="p-5">
        <h3 className="font-bold text-gray-900 text-lg line-clamp-1 mb-2 group-hover:text-red-600 transition">
          {property.title}
        </h3>

        <p className="text-sm text-gray-500 flex items-center gap-1.5 mb-4">
          <MapPin className="w-4 h-4 text-red-500 flex-shrink-0" />
          <span className="line-clamp-1">{getLocation() || "Location not specified"}</span>
        </p>

        {/* Property Details */}
        <div className="flex items-center gap-4 mb-4 text-sm text-gray-600">
          {property.bhk && (
            <div className="flex items-center gap-1">
              <Home className="w-4 h-4 text-gray-400" />
              <span>{property.bhk}</span>
            </div>
          )}
          {(property.area?.builtUpSqft || property.builtUpArea) && (
            <div className="flex items-center gap-1">
              <Building2 className="w-4 h-4 text-gray-400" />
              <span>{property.area?.builtUpSqft || property.builtUpArea} sq.ft</span>
            </div>
          )}
          {property.furnishing && (
            <span className="text-xs bg-gray-100 px-2 py-1 rounded-full">
              {property.furnishing}
            </span>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-100">
          <div className="flex items-center gap-1.5 text-xs text-gray-400">
            <Clock className="w-3.5 h-3.5" />
            <span>
              Saved {property.interestedAt ? new Date(property.interestedAt).toLocaleDateString('en-IN', {
                day: 'numeric',
                month: 'short',
                year: 'numeric'
              }) : 'recently'}
            </span>
          </div>

          <button
            onClick={() => onViewDetails(property)}
            className="flex items-center gap-1.5 text-red-600 hover:text-red-700 font-medium text-sm transition"
          >
            View Details
            <ExternalLink className="w-4 h-4" />
          </button>
        </div>
      </div>
    </motion.div>
  );
};

export default function SavedProperties() {
  const navigate = useNavigate();
  const { user, isAuthenticated, loading: authLoading } = useAuth();
  const [properties, setProperties] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [filterType, setFilterType] = useState("all"); // all, rent, sell
  const [sortBy, setSortBy] = useState("newest");

  // Auth check & fetch saved properties
  useEffect(() => {
    if (!authLoading) {
      if (!isAuthenticated) {
        toast.error("Please login to view saved properties");
        navigate("/login");
        return;
      }
      fetchSavedProperties();
    }
  }, [authLoading, isAuthenticated, navigate]);

  const fetchSavedProperties = async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }

      const res = await api.get('/properties/saved');

      if (res.data.success) {
        setProperties(res.data.data || []);
      }
    } catch (err) {
      console.error("Error fetching saved properties:", err);
      // 401 errors handled by interceptor
      if (err.response?.status !== 404 && err.response?.status !== 401) {
        toast.error("Failed to load saved properties");
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRemove = async (propertyId) => {
    try {
      await api.delete(`/properties/saved/${propertyId}`);

      setProperties(prev => prev.filter(p => p._id !== propertyId));
      toast.success("Property removed from saved");
    } catch (err) {
      console.error("Error removing property:", err);
      toast.error("Failed to remove property");
    }
  };

  const handleViewDetails = (property) => {
    navigate(`/properties/${property._id}`);
  };

  const handleRefresh = () => {
    fetchSavedProperties(true);
  };

  // Filter and sort properties
  const filteredProperties = properties
    .filter((p) => {
      if (filterType === "all") return true;
      return (p.listingType?.toLowerCase() || "rent") === filterType;
    })
    .filter((p) => {
      if (!searchQuery) return true;
      const query = searchQuery.toLowerCase();
      const locality = p.locality || p.address?.locality || p.address?.area || "";
      const city = p.city || p.address?.city || "";
      return (
        p.title?.toLowerCase().includes(query) ||
        locality.toLowerCase().includes(query) ||
        city.toLowerCase().includes(query)
      );
    })
    .sort((a, b) => {
      switch (sortBy) {
        case "newest":
          return new Date(b.interestedAt || b.createdAt) - new Date(a.interestedAt || a.createdAt);
        case "oldest":
          return new Date(a.interestedAt || a.createdAt) - new Date(b.interestedAt || b.createdAt);
        case "price-high":
          return (b.expectedPrice || b.price || 0) - (a.expectedPrice || a.price || 0);
        case "price-low":
          return (a.expectedPrice || a.price || 0) - (b.expectedPrice || b.price || 0);
        default:
          return 0;
      }
    });

  if (loading || authLoading) {
    return (
      <div className="min-h-screen bg-gray-50 pt-24 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 text-red-600 animate-spin mx-auto mb-4" />
          <p className="text-gray-600">Loading saved properties...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <div className="bg-white border-b border-gray-200">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
                <Heart className="w-7 h-7 text-red-500 fill-red-500" />
                Saved Properties
              </h1>
              <p className="text-gray-500 mt-1">
                Properties you've expressed interest in ({properties.length} saved)
              </p>
            </div>

            <div className="flex items-center gap-3">
              <button
                onClick={handleRefresh}
                disabled={refreshing}
                className="inline-flex items-center gap-2 bg-gray-100 text-gray-700 px-4 py-2.5 rounded-xl font-medium hover:bg-gray-200 transition border border-gray-200 disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
                {refreshing ? 'Refreshing...' : 'Refresh'}
              </button>
              <Link
                to="/properties"
                className="inline-flex items-center gap-2 bg-red-600 text-white px-5 py-2.5 rounded-xl font-semibold hover:bg-red-700 transition shadow-md"
              >
                <Search className="w-5 h-5" />
                Browse Properties
              </Link>
            </div>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Filters */}
        {properties.length > 0 && (
          <div className="bg-white rounded-xl border border-gray-200 p-4 mb-6">
            <div className="flex flex-col md:flex-row gap-4">
              {/* Search */}
              <div className="flex-1 relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-400" />
                <input
                  type="text"
                  placeholder="Search saved properties..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 border border-gray-200 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-red-500 outline-none"
                />
              </div>

              {/* Filter Tabs */}
              <div className="flex items-center gap-2 flex-wrap">
                {[
                  { key: "all", label: "All" },
                  { key: "rent", label: "For Rent" },
                  { key: "sell", label: "For Sale" },
                ].map((tab) => (
                  <button
                    key={tab.key}
                    onClick={() => setFilterType(tab.key)}
                    className={`px-4 py-2 rounded-lg text-sm font-medium whitespace-nowrap transition ${filterType === tab.key
                      ? "bg-red-600 text-white"
                      : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                      }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>

              {/* Sort */}
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="px-4 py-2.5 border border-gray-200 rounded-lg text-sm font-medium text-gray-700 focus:ring-2 focus:ring-red-500 outline-none"
              >
                <option value="newest">Recently Saved</option>
                <option value="oldest">Oldest First</option>
                <option value="price-high">Price: High to Low</option>
                <option value="price-low">Price: Low to High</option>
              </select>
            </div>
          </div>
        )}

        {/* Properties Grid */}
        {filteredProperties.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <AnimatePresence>
              {filteredProperties.map((property) => (
                <PropertyCard
                  key={property._id}
                  property={property}
                  onRemove={handleRemove}
                  onViewDetails={handleViewDetails}
                />
              ))}
            </AnimatePresence>
          </div>
        ) : (
          <div className="bg-white rounded-2xl border border-gray-200 p-12 text-center">
            <div className="w-24 h-24 bg-red-50 rounded-full flex items-center justify-center mx-auto mb-6">
              <Heart className="w-12 h-12 text-red-300" />
            </div>
            <h3 className="text-xl font-semibold text-gray-900 mb-2">
              {searchQuery || filterType !== "all"
                ? "No properties found"
                : "No saved properties yet"}
            </h3>
            <p className="text-gray-500 mb-6 max-w-md mx-auto">
              {searchQuery || filterType !== "all"
                ? "Try adjusting your search or filter criteria"
                : "When you find a property you like, click 'I'm Interested' to save it here for easy access."}
            </p>
            <Link
              to="/properties"
              className="inline-flex items-center gap-2 bg-red-600 text-white px-6 py-3 rounded-xl font-semibold hover:bg-red-700 transition"
            >
              <Search className="w-5 h-5" />
              Browse Properties
            </Link>
          </div>
        )}
      </div>
    </div>
  );
}
