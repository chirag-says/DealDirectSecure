import React, { useState, useEffect, useRef } from "react";
import {
    Home, MapPin, IndianRupee, Layers, Image as ImageIcon, Calendar,
    ChevronLeft, Upload, Check, X, Building2, Users, Utensils, Car, Zap,
    Shield, Store, ArrowRight, FileText, Tag, Wifi, LandPlot, Plus, AlertTriangle, Navigation, Loader2
} from "lucide-react";
import { toast } from "react-toastify";
import { useNavigate, useParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { MapContainer, TileLayer, Marker, useMapEvents, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";

// Fix for default marker icon in react-leaflet
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
    iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
    iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
    shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
});

// Custom marker icon
const customIcon = new L.Icon({
    iconUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png",
    iconRetinaUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png",
    shadowUrl: "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png",
    iconSize: [25, 41],
    iconAnchor: [12, 41],
    popupAnchor: [1, -34],
    shadowSize: [41, 41]
});

// Map click handler component
function LocationMarker({ position, setPosition, setFormData }) {
    useMapEvents({
        click(e) {
            const { lat, lng } = e.latlng;
            setPosition([lat, lng]);
            setFormData(prev => ({
                ...prev,
                latitude: lat.toFixed(6),
                longitude: lng.toFixed(6)
            }));
        },
    });

    return position ? <Marker position={position} icon={customIcon} /> : null;
}

// Component to recenter map
function RecenterMap({ position }) {
    const map = useMap();
    useEffect(() => {
        if (position) {
            map.setView(position, 15);
        }
    }, [position, map]);
    return null;
}

const API_BASE = import.meta.env.VITE_API_BASE;

// Steps
const STEPS = [
    { id: 1, label: "Basic Info", icon: <Home size={18} />, description: "Property basics" },
    { id: 2, label: "Location", icon: <MapPin size={18} />, description: "Address details" },
    { id: 3, label: "Pricing & Area", icon: <IndianRupee size={18} />, description: "Value & size" },
    { id: 4, label: "Property Details", icon: <Layers size={18} />, description: "Specific features" },
    { id: 5, label: "Photos", icon: <ImageIcon size={18} />, description: "Property images" },
    { id: 6, label: "Review", icon: <Calendar size={18} />, description: "Final check" },
];

const PROPERTY_CATEGORIES = {
    Residential: {
        icon: <Home size={28} />,
        types: ["Apartment / Flat", "Independent House", "Villa", "Builder Floor", "Row House", "Studio Apartment", "Penthouse", "Farm House"],
        amenities: ["Lift", "Gym", "Swimming Pool", "Club House", "Power Backup", "CCTV", "Parking Covered", "Parking Open", "Modular Kitchen", "Wardrobes", "Geyser", "AC", "Fans", "Water Purifier", "Intercom", "Garden", "Jogging Track", "Kids Play Area", "Community Hall", "RO Water", "Store Room", "Servant Room"]
    },
    Commercial: {
        icon: <Store size={28} />,
        types: ["Office Space", "Shop / Retail", "Showroom", "Restaurant / Cafe", "Co-Working Space", "Warehouse / Godown", "Industrial Shed", "Commercial Building / Floor"],
        amenities: ["Lift", "Power Backup", "CCTV", "Fire Safety", "Reserved Parking", "Visitor Parking", "Internet", "Loading Dock", "Goods Lift", "Sprinkler System", "Water Storage", "Security", "Washrooms", "AC"]
    }
};

// Image categories based on property type (same as AddProperty)
const IMAGE_CATEGORIES = {
    Residential: {
        "Apartment / Flat": [
            { key: "exterior", label: "Building Exterior", maxImages: 3 },
            { key: "livingRoom", label: "Living Room", maxImages: 4 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "balcony", label: "Balcony / Terrace", maxImages: 2 },
            { key: "hall", label: "Hall / Lobby", maxImages: 2 },
            { key: "parking", label: "Parking Area", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Independent House": [
            { key: "exterior", label: "House Exterior", maxImages: 4 },
            { key: "livingRoom", label: "Living Room", maxImages: 3 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "garden", label: "Garden/Lawn", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Villa": [
            { key: "exterior", label: "Villa Exterior", maxImages: 5 },
            { key: "livingRoom", label: "Living Room", maxImages: 4 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 5 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "pool", label: "Swimming Pool", maxImages: 3 },
            { key: "garden", label: "Garden", maxImages: 3 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Builder Floor": [{ key: "exterior", label: "Building Exterior", maxImages: 2 }, { key: "livingRoom", label: "Living Room", maxImages: 3 }, { key: "bedroom", label: "Bedrooms", maxImages: 4 }, { key: "other", label: "Other", maxImages: 5 }],
        "Studio Apartment": [{ key: "livingRoom", label: "Studio Space", maxImages: 4 }, { key: "kitchen", label: "Kitchen", maxImages: 2 }, { key: "bathroom", label: "Bathroom", maxImages: 2 }, { key: "other", label: "Other", maxImages: 3 }],
        "Penthouse": [{ key: "exterior", label: "Building & Terrace", maxImages: 4 }, { key: "livingRoom", label: "Living Area", maxImages: 4 }, { key: "terrace", label: "Terrace", maxImages: 4 }, { key: "other", label: "Other", maxImages: 5 }],
        "Row House": [{ key: "exterior", label: "House Exterior", maxImages: 3 }, { key: "livingRoom", label: "Living Room", maxImages: 3 }, { key: "bedroom", label: "Bedrooms", maxImages: 4 }, { key: "other", label: "Other", maxImages: 5 }],
        "Farm House": [{ key: "exterior", label: "Property Exterior", maxImages: 5 }, { key: "livingRoom", label: "Living Space", maxImages: 3 }, { key: "land", label: "Farm Land", maxImages: 5 }, { key: "other", label: "Other", maxImages: 5 }]
    },
    Commercial: {
        // Mirror AddProperty commercial categories and align with backend keys
        "Office Space": [
            { key: "facade", label: "Building Exterior", maxImages: 4 },
            { key: "reception", label: "Reception / Lobby", maxImages: 3 },
            { key: "workArea", label: "Open Work Area", maxImages: 6 },
            { key: "cabin", label: "Cabins / Rooms", maxImages: 4 },
            { key: "conferenceRoom", label: "Conference Rooms", maxImages: 3 },
            { key: "pantry", label: "Pantry", maxImages: 3 },
            { key: "washroom", label: "Washrooms", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Shop / Retail": [
            { key: "facade", label: "Shop Front / Facade", maxImages: 4 },
            { key: "shopFloor", label: "Shop Floor", maxImages: 6 },
            { key: "displayArea", label: "Display Area", maxImages: 4 },
            { key: "storageArea", label: "Storage / Back Area", maxImages: 4 },
            { key: "washroom", label: "Washrooms", maxImages: 2 },
            { key: "parking", label: "Customer Parking", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Showroom": [
            { key: "facade", label: "Showroom Exterior", maxImages: 4 },
            { key: "reception", label: "Reception / Front Desk", maxImages: 3 },
            { key: "displayArea", label: "Display Area", maxImages: 6 },
            { key: "seatingArea", label: "Customer Seating", maxImages: 3 },
            { key: "storageArea", label: "Back Office / Storage", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Restaurant / Cafe": [
            { key: "facade", label: "Exterior / Entrance", maxImages: 4 },
            { key: "seatingArea", label: "Dining / Seating", maxImages: 6 },
            { key: "kitchenCommercial", label: "Commercial Kitchen", maxImages: 4 },
            { key: "washroom", label: "Washrooms", maxImages: 3 },
            { key: "storageArea", label: "Storage / Prep Area", maxImages: 3 },
            { key: "parking", label: "Parking / Valet", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Co-Working Space": [
            { key: "facade", label: "Exterior", maxImages: 3 },
            { key: "reception", label: "Reception / Entry", maxImages: 3 },
            { key: "workArea", label: "Open Desk Area", maxImages: 6 },
            { key: "cabin", label: "Private Cabins", maxImages: 4 },
            { key: "conferenceRoom", label: "Meeting Rooms", maxImages: 3 },
            { key: "seatingArea", label: "Lounge / Breakout", maxImages: 3 },
            { key: "pantry", label: "Pantry / Cafe", maxImages: 3 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Warehouse / Godown": [
            { key: "facade", label: "Warehouse Exterior", maxImages: 3 },
            { key: "warehouse", label: "Main Storage Area", maxImages: 8 },
            { key: "loadingArea", label: "Loading / Unloading", maxImages: 4 },
            { key: "storageArea", label: "Racks / Internal Storage", maxImages: 4 },
            { key: "parking", label: "Truck / Vehicle Parking", maxImages: 3 },
            { key: "floorPlan", label: "Site / Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Industrial Shed": [
            { key: "facade", label: "Shed Exterior", maxImages: 3 },
            { key: "warehouse", label: "Main Production Floor", maxImages: 8 },
            { key: "loadingArea", label: "Loading Area", maxImages: 4 },
            { key: "storageArea", label: "Storage / Raw Material", maxImages: 4 },
            { key: "parking", label: "Parking / Yard", maxImages: 3 },
            { key: "floorPlan", label: "Layout / Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Commercial Building / Floor": [
            { key: "facade", label: "Building Exterior", maxImages: 4 },
            { key: "reception", label: "Main Lobby / Reception", maxImages: 3 },
            { key: "workArea", label: "Typical Floor / Work Area", maxImages: 6 },
            { key: "cabin", label: "Cabins / Offices", maxImages: 4 },
            { key: "conferenceRoom", label: "Conference Rooms", maxImages: 3 },
            { key: "parking", label: "Parking Levels", maxImages: 4 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 2 },
            { key: "other", label: "Other", maxImages: 5 }
        ]
    }
};

export default function EditProperty() {
    const navigate = useNavigate();
    const { id } = useParams();

    // Loading states
    const [isLoading, setIsLoading] = useState(true);
    const [isSaving, setIsSaving] = useState(false);
    const [property, setProperty] = useState(null);

    // UI state
    const [currentStep, setCurrentStep] = useState(1);
    const [direction, setDirection] = useState(0);
    const [existingImages, setExistingImages] = useState([]);
    const [existingCategorizedImages, setExistingCategorizedImages] = useState({});
    const [categorizedImages, setCategorizedImages] = useState({});
    const [expandedCategories, setExpandedCategories] = useState({});
    const [imagesToRemove, setImagesToRemove] = useState([]);

    const [formData, setFormData] = useState({
        listingType: "Rent",
        propertyCategory: "Residential",
        propertyType: "Apartment / Flat",
        bhkType: "",
        bedrooms: "",
        bathrooms: 1,
        balconies: 0,
        builtUpArea: "",
        carpetArea: "",
        superBuiltUpArea: "",
        plotArea: "",
        expectedPrice: "",
        maintenanceIncluded: true,
        maintenance: "",
        expectedDeposit: "",
        bookingAmount: "",
        priceNegotiable: false,
        furnishing: "Unfurnished",
        floorNo: "",
        totalFloors: "",
        propertyAge: "New",
        facing: "",
        constructionStatus: "Ready to Move",
        parkingCovered: 0,
        parkingOpen: 0,
        selectedAmenities: [],
        servantRoom: false,
        poojaRoom: false,
        studyRoom: false,
        storeRoom: false,
        reraId: "",
        availableFrom: new Date().toISOString().split('T')[0],
        petFriendly: "No",
        allowedFor: "Family",
        city: "",
        locality: "",
        landmark: "",
        address: "",
        latitude: "",
        longitude: "",
        description: "",
        title: ""
    });

    // Map state
    const [mapPosition, setMapPosition] = useState(null);
    const [isLocating, setIsLocating] = useState(false);
    const defaultCenter = [20.5937, 78.9629];

    // Location autocomplete state
    const [locationSuggestions, setLocationSuggestions] = useState([]);
    const [isSearchingLocation, setIsSearchingLocation] = useState(false);
    const [activeLocationField, setActiveLocationField] = useState(null);
    const [showSuggestions, setShowSuggestions] = useState(false);
    const searchTimeoutRef = useRef(null);
    const suggestionsRef = useRef(null);

    // Auth using AuthContext
    const { user: authUser, isAuthenticated, loading: authLoading } = useAuth();

    // Auth check and fetch property
    useEffect(() => {
        if (authLoading) return;

        if (!isAuthenticated || !authUser) {
            toast.error("Please login to edit your property");
            navigate("/login");
            return;
        }

        if (authUser.role !== "owner" && authUser.role !== "agent") {
            toast.error("Only property owners can edit properties");
            navigate("/");
            return;
        }

        fetchProperty();
    }, [id, authLoading, isAuthenticated, authUser, navigate]);

    const fetchProperty = async () => {
        try {
            setIsLoading(true);
            // Use api client - it handles auth via cookies
            const res = await api.get(`/properties/${id}`);

            if (res.data) {
                const prop = res.data;
                setProperty(prop);

                // Populate form data from property
                setFormData({
                    listingType: prop.listingType || "Rent",
                    propertyCategory: prop.categoryName || "Residential",
                    propertyType: prop.propertyTypeName || "Apartment / Flat",
                    bhkType: prop.bhk || prop.bhkType || "",
                    bedrooms: prop.bedrooms || "",
                    bathrooms: prop.bathrooms || 1,
                    balconies: prop.balconies || 0,
                    builtUpArea: prop.builtUpArea || prop.area?.builtUpSqft || "",
                    carpetArea: prop.carpetArea || prop.area?.carpetSqft || "",
                    superBuiltUpArea: prop.superBuiltUpArea || prop.area?.superBuiltUpSqft || "",
                    plotArea: prop.plotArea || prop.area?.plotSqft || "",
                    expectedPrice: prop.price || prop.expectedPrice || "",
                    maintenanceIncluded: prop.maintenanceIncluded ?? true,
                    maintenance: prop.maintenance || "",
                    expectedDeposit: prop.deposit || prop.expectedDeposit || "",
                    bookingAmount: prop.bookingAmount || "",
                    priceNegotiable: prop.negotiable || prop.priceNegotiable || false,
                    furnishing: prop.furnishing || "Unfurnished",
                    floorNo: prop.floorNo || prop.floor || "",
                    totalFloors: prop.totalFloors || "",
                    propertyAge: prop.propertyAge || "New",
                    facing: prop.facing || "",
                    constructionStatus: prop.constructionStatus || "Ready to Move",
                    parkingCovered: prop.parking?.covered || 0,
                    parkingOpen: prop.parking?.open || 0,
                    selectedAmenities: prop.amenities || [],
                    servantRoom: prop.extras?.servantRoom || prop.servantRoom || false,
                    poojaRoom: prop.extras?.poojaRoom || prop.poojaRoom || false,
                    studyRoom: prop.extras?.studyRoom || prop.studyRoom || false,
                    storeRoom: prop.extras?.storeRoom || prop.storeRoom || false,
                    reraId: prop.legal?.reraId || prop.reraId || "",
                    availableFrom: prop.availableFrom ? new Date(prop.availableFrom).toISOString().split('T')[0] : new Date().toISOString().split('T')[0],
                    petFriendly: prop.petFriendly || "No",
                    allowedFor: prop.allowedFor || "Family",
                    city: prop.city || prop.address?.city || "",
                    locality: prop.locality || prop.address?.area || "",
                    landmark: prop.landmark || prop.address?.landmark || "",
                    address: prop.address?.full || prop.fullAddress || "",
                    latitude: prop.latitude || prop.address?.latitude || prop.location?.coordinates?.[1] || "",
                    longitude: prop.longitude || prop.address?.longitude || prop.location?.coordinates?.[0] || "",
                    description: prop.description || "",
                    title: prop.title || ""
                });

                // Set existing categorized images
                const existingCatImages = {};
                const categoryType = prop.categoryName?.toLowerCase() || "residential";

                if (prop.categorizedImages) {
                    const catImages = prop.categorizedImages[categoryType] || prop.categorizedImages.residential || prop.categorizedImages.commercial;
                    if (catImages) {
                        Object.keys(catImages).forEach(key => {
                            if (Array.isArray(catImages[key]) && catImages[key].length > 0) {
                                existingCatImages[key] = catImages[key];
                            }
                        });
                    }
                }

                // If no categorized images, put all images in "other" category
                if (Object.keys(existingCatImages).length === 0 && prop.images?.length > 0) {
                    existingCatImages.other = prop.images;
                }

                setExistingCategorizedImages(existingCatImages);

                // Flatten for display purposes
                const allImages = [];
                Object.values(existingCatImages).forEach(imgs => {
                    if (Array.isArray(imgs)) allImages.push(...imgs);
                });
                setExistingImages(allImages);

                // Set map position if coordinates exist
                if (prop.latitude && prop.longitude) {
                    setMapPosition([parseFloat(prop.latitude), parseFloat(prop.longitude)]);
                } else if (prop.location?.coordinates?.length === 2) {
                    setMapPosition([prop.location.coordinates[1], prop.location.coordinates[0]]);
                }
            }
        } catch (error) {
            console.error("Error fetching property:", error);
            toast.error("Failed to load property");
            navigate("/my-properties");
        } finally {
            setIsLoading(false);
        }
    };

    // Get image categories based on property type
    const getImageCategories = () => {
        const category = formData.propertyCategory;
        const type = formData.propertyType;

        if (IMAGE_CATEGORIES[category] && IMAGE_CATEGORIES[category][type]) {
            return IMAGE_CATEGORIES[category][type];
        }

        // Default categories
        return [
            { key: "exterior", label: "Exterior", maxImages: 3 },
            { key: "interior", label: "Interior", maxImages: 5 },
            { key: "other", label: "Other", maxImages: 5 }
        ];
    };

    // Handle categorized image upload
    const handleCategorizedImageUpload = (categoryKey, e) => {
        const files = Array.from(e.target.files);
        const categories = getImageCategories();
        const categoryConfig = categories.find(c => c.key === categoryKey);
        const maxImages = categoryConfig?.maxImages || 5;

        const existingCount = (existingCategorizedImages[categoryKey]?.length || 0) + (categorizedImages[categoryKey]?.files?.length || 0);
        const remainingSlots = maxImages - existingCount;

        if (files.length > remainingSlots) {
            toast.error(`You can only add ${remainingSlots} more image(s) to this category (max: ${maxImages})`);
            return;
        }

        const previews = files.map(file => URL.createObjectURL(file));

        setCategorizedImages(prev => ({
            ...prev,
            [categoryKey]: {
                files: [...(prev[categoryKey]?.files || []), ...files],
                previews: [...(prev[categoryKey]?.previews || []), ...previews]
            }
        }));
    };

    // Remove image from category
    const removeCategorizedImage = (categoryKey, index, isExisting = false) => {
        if (isExisting) {
            // Mark existing image for removal
            const imageUrl = existingCategorizedImages[categoryKey][index];
            setImagesToRemove(prev => [...prev, imageUrl]);

            setExistingCategorizedImages(prev => ({
                ...prev,
                [categoryKey]: prev[categoryKey].filter((_, i) => i !== index)
            }));
        } else {
            // Remove new image preview
            setCategorizedImages(prev => {
                const newCat = { ...prev[categoryKey] };
                URL.revokeObjectURL(newCat.previews[index]);
                newCat.files = newCat.files.filter((_, i) => i !== index);
                newCat.previews = newCat.previews.filter((_, i) => i !== index);
                return { ...prev, [categoryKey]: newCat };
            });
        }
    };

    // Get total count of categorized images
    const getTotalCategorizedImages = () => {
        let count = 0;
        Object.values(existingCategorizedImages).forEach(imgs => {
            count += imgs?.length || 0;
        });
        Object.values(categorizedImages).forEach(cat => {
            count += cat.files?.length || 0;
        });
        return count;
    };

    // Toggle category expansion
    const toggleCategory = (categoryKey) => {
        setExpandedCategories(prev => ({
            ...prev,
            [categoryKey]: !prev[categoryKey]
        }));
    };

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({ ...prev, [name]: type === "checkbox" ? checked : value }));
    };

    const handleAmenityToggle = (amenity) => {
        setFormData(prev => ({
            ...prev,
            selectedAmenities: prev.selectedAmenities.includes(amenity)
                ? prev.selectedAmenities.filter(a => a !== amenity)
                : [...prev.selectedAmenities, amenity]
        }));
    };

    // Location search
    const searchLocations = async (query, field) => {
        if (!query || query.length < 3) {
            setLocationSuggestions([]);
            return;
        }

        setIsSearchingLocation(true);
        try {
            const response = await fetch(
                `https://nominatim.openstreetmap.org/search?format=json&q=${encodeURIComponent(query)}, India&limit=5&addressdetails=1`,
                { headers: { 'User-Agent': 'DealDirect Property App' } }
            );
            const data = await response.json();
            setLocationSuggestions(data);
            setShowSuggestions(true);
        } catch (error) {
            console.error("Error searching locations:", error);
        } finally {
            setIsSearchingLocation(false);
        }
    };

    const handleLocationInputChange = (e, field) => {
        const value = e.target.value;
        setFormData(prev => ({ ...prev, [field]: value }));
        setActiveLocationField(field);

        if (searchTimeoutRef.current) clearTimeout(searchTimeoutRef.current);
        searchTimeoutRef.current = setTimeout(() => searchLocations(value, field), 300);
    };

    const handleLocationSelect = (suggestion) => {
        const address = suggestion.address || {};
        setFormData(prev => ({
            ...prev,
            city: address.city || address.town || address.village || address.state_district || prev.city,
            locality: address.suburb || address.neighbourhood || address.hamlet || prev.locality,
            address: suggestion.display_name,
            latitude: suggestion.lat,
            longitude: suggestion.lon
        }));
        setMapPosition([parseFloat(suggestion.lat), parseFloat(suggestion.lon)]);
        setShowSuggestions(false);
        setLocationSuggestions([]);
    };

    const getCurrentLocation = () => {
        if (!navigator.geolocation) {
            toast.error("Geolocation not supported");
            return;
        }

        setIsLocating(true);
        navigator.geolocation.getCurrentPosition(
            async (position) => {
                const { latitude, longitude } = position.coords;
                setMapPosition([latitude, longitude]);
                setFormData(prev => ({
                    ...prev,
                    latitude: latitude.toFixed(6),
                    longitude: longitude.toFixed(6)
                }));

                // Reverse geocode
                try {
                    const response = await fetch(
                        `https://nominatim.openstreetmap.org/reverse?format=json&lat=${latitude}&lon=${longitude}&addressdetails=1`,
                        { headers: { 'User-Agent': 'DealDirect Property App' } }
                    );
                    const data = await response.json();
                    if (data.address) {
                        setFormData(prev => ({
                            ...prev,
                            city: data.address.city || data.address.town || data.address.village || data.address.state_district || "",
                            locality: data.address.suburb || data.address.neighbourhood || data.address.hamlet || "",
                            landmark: data.address.road || "",
                            address: data.display_name || ""
                        }));
                    }
                } catch (error) {
                    console.error("Error reverse geocoding:", error);
                }
                setIsLocating(false);
            },
            (error) => {
                toast.error("Could not get your location");
                setIsLocating(false);
            },
            { enableHighAccuracy: true }
        );
    };

    const handleNext = () => {
        setDirection(1);
        setCurrentStep(prev => Math.min(prev + 1, 6));
    };

    const handlePrev = () => {
        setDirection(-1);
        setCurrentStep(prev => Math.max(prev - 1, 1));
    };

    const handleSubmit = async () => {
        setIsSaving(true);
        try {
            const formDataToSend = new FormData();

            // Add all form fields
            Object.entries(formData).forEach(([key, value]) => {
                if (key === 'selectedAmenities') {
                    formDataToSend.append('amenities', JSON.stringify(value));
                } else if (typeof value === 'object') {
                    formDataToSend.append(key, JSON.stringify(value));
                } else {
                    formDataToSend.append(key, value);
                }
            });

            // Add parking data
            formDataToSend.append('parking', JSON.stringify({
                covered: formData.parkingCovered,
                open: formData.parkingOpen
            }));

            // Add price field
            formDataToSend.append('price', formData.expectedPrice);

            // Add categorized new images and build category map
            const imageCategoryMap = [];
            let imageIndex = 0;

            Object.entries(categorizedImages).forEach(([categoryKey, categoryData]) => {
                if (categoryData.files && categoryData.files.length > 0) {
                    categoryData.files.forEach(file => {
                        formDataToSend.append('images', file);
                        imageCategoryMap.push({
                            index: imageIndex,
                            category: categoryKey
                        });
                        imageIndex++;
                    });
                }
            });

            // Add category map
            formDataToSend.append('imageCategoryMap', JSON.stringify(imageCategoryMap));

            // Add images to remove
            if (imagesToRemove.length > 0) {
                formDataToSend.append('imagesToRemove', JSON.stringify(imagesToRemove));
            }

            // Add existing categorized images
            formDataToSend.append('existingCategorizedImages', JSON.stringify(existingCategorizedImages));

            // Use api client - handles auth via cookies
            const res = await api.put(
                `/properties/my-properties/${id}`,
                formDataToSend,
                {
                    headers: {
                        'Content-Type': 'multipart/form-data'
                    }
                }
            );

            if (res.data.success) {
                toast.success("Property updated successfully!");
                navigate("/my-properties");
            } else {
                toast.error(res.data.message || "Failed to update property");
            }
        } catch (error) {
            console.error("Error updating property:", error);
            toast.error(error.response?.data?.message || "Failed to update property");
        } finally {
            setIsSaving(false);
        }
    };

    const isResidential = formData.propertyCategory === "Residential";

    // Animation variants
    const variants = {
        enter: (direction) => ({ x: direction > 0 ? 20 : -20, opacity: 0 }),
        center: { x: 0, opacity: 1 },
        exit: (direction) => ({ x: direction < 0 ? 20 : -20, opacity: 0 }),
    };

    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-50 pt-24 flex items-center justify-center">
                <div className="text-center">
                    <Loader2 className="w-10 h-10 text-blue-600 animate-spin mx-auto mb-4" />
                    <p className="text-gray-600">Loading property details...</p>
                </div>
            </div>
        );
    }

    // Render Steps
    const renderStep1 = () => (
        <div className="space-y-8">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Edit Property</h2>
                <p className="text-gray-500 mt-2">Update your property listing information</p>
            </div>

            {/* Listing Type */}
            <div className="grid grid-cols-2 gap-4">
                {["Rent", "Sell"].map(type => (
                    <button
                        key={type}
                        type="button"
                        onClick={() => setFormData(p => ({ ...p, listingType: type }))}
                        className={`p-6 rounded-2xl border-2 transition-all ${formData.listingType === type
                            ? "border-blue-600 bg-blue-50 ring-4 ring-blue-100"
                            : "border-gray-200 hover:border-gray-300 bg-white"
                            }`}
                    >
                        <div className={`text-xl font-bold ${formData.listingType === type ? "text-blue-600" : "text-gray-700"}`}>
                            {type === "Rent" ? "For Rent" : "For Sale"}
                        </div>
                    </button>
                ))}
            </div>

            {/* Property Category */}
            <div>
                <label className="block text-sm font-semibold text-gray-700 mb-3">Property Category</label>
                <div className="grid grid-cols-2 gap-4">
                    {Object.entries(PROPERTY_CATEGORIES).map(([cat, config]) => (
                        <button
                            key={cat}
                            type="button"
                            onClick={() => setFormData(p => ({ ...p, propertyCategory: cat, propertyType: config.types[0] }))}
                            className={`p-6 rounded-2xl border-2 transition-all flex flex-col items-center gap-3 ${formData.propertyCategory === cat
                                ? "border-blue-600 bg-blue-50 ring-4 ring-blue-100"
                                : "border-gray-200 hover:border-gray-300 bg-white"
                                }`}
                        >
                            <div className={formData.propertyCategory === cat ? "text-blue-600" : "text-gray-400"}>
                                {config.icon}
                            </div>
                            <span className={`font-bold ${formData.propertyCategory === cat ? "text-blue-600" : "text-gray-700"}`}>
                                {cat}
                            </span>
                        </button>
                    ))}
                </div>
            </div>

            {/* Property Type */}
            <div>
                <label className="block text-sm font-semibold text-gray-700 mb-3">Property Type</label>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {PROPERTY_CATEGORIES[formData.propertyCategory].types.map(type => (
                        <button
                            key={type}
                            type="button"
                            onClick={() => setFormData(p => ({ ...p, propertyType: type }))}
                            className={`p-4 rounded-xl border-2 text-sm font-medium transition-all ${formData.propertyType === type
                                ? "border-blue-600 bg-blue-50 text-blue-600"
                                : "border-gray-200 text-gray-600 hover:border-gray-300"
                                }`}
                        >
                            {type}
                        </button>
                    ))}
                </div>
            </div>

            {/* BHK for Residential */}
            {isResidential && (
                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">BHK Type</label>
                    <div className="grid grid-cols-5 gap-3">
                        {["1 BHK", "2 BHK", "3 BHK", "4 BHK", "5+ BHK"].map(bhk => (
                            <button
                                key={bhk}
                                type="button"
                                onClick={() => setFormData(p => ({ ...p, bhkType: bhk, bedrooms: bhk.split(" ")[0] }))}
                                className={`p-4 rounded-xl border-2 font-medium transition-all ${formData.bhkType === bhk
                                    ? "border-blue-600 bg-blue-50 text-blue-600"
                                    : "border-gray-200 text-gray-600 hover:border-gray-300"
                                    }`}
                            >
                                {bhk}
                            </button>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );

    const renderStep2 = () => (
        <div className="space-y-6">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Location Details</h2>
                <p className="text-gray-500 mt-2">Update property location information</p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
                <div className="relative">
                    <label className="block text-sm font-semibold text-gray-700 mb-2">City *</label>
                    <input
                        type="text"
                        name="city"
                        value={formData.city}
                        onChange={(e) => handleLocationInputChange(e, 'city')}
                        placeholder="Enter city"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                    {showSuggestions && activeLocationField === 'city' && locationSuggestions.length > 0 && (
                        <div className="absolute z-50 w-full mt-1 bg-white border border-gray-200 rounded-xl shadow-lg max-h-60 overflow-auto">
                            {locationSuggestions.map((suggestion, idx) => (
                                <button
                                    key={idx}
                                    type="button"
                                    onClick={() => handleLocationSelect(suggestion)}
                                    className="w-full px-4 py-3 text-left hover:bg-gray-50 border-b border-gray-100 last:border-0"
                                >
                                    <p className="font-medium text-gray-900 text-sm">{suggestion.display_name}</p>
                                </button>
                            ))}
                        </div>
                    )}
                </div>

                <div className="relative">
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Locality / Area *</label>
                    <input
                        type="text"
                        name="locality"
                        value={formData.locality}
                        onChange={(e) => handleLocationInputChange(e, 'locality')}
                        placeholder="Enter locality"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Landmark</label>
                    <input
                        type="text"
                        name="landmark"
                        value={formData.landmark}
                        onChange={handleChange}
                        placeholder="Nearby landmark"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Full Address</label>
                    <input
                        type="text"
                        name="address"
                        value={formData.address}
                        onChange={(e) => handleLocationInputChange(e, 'address')}
                        placeholder="Complete address"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>
            </div>

            {/* Map Section */}
            <div className="bg-gray-50 rounded-2xl p-6 border border-gray-200">
                <div className="flex items-center justify-between mb-4">
                    <div>
                        <h3 className="font-semibold text-gray-900">Pin Location on Map</h3>
                        <p className="text-sm text-gray-500">Click on the map or use current location</p>
                    </div>
                    <button
                        type="button"
                        onClick={getCurrentLocation}
                        disabled={isLocating}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-xl text-sm font-medium hover:bg-blue-700 transition disabled:opacity-50"
                    >
                        {isLocating ? <Loader2 className="w-4 h-4 animate-spin" /> : <Navigation className="w-4 h-4" />}
                        {isLocating ? "Locating..." : "Use My Location"}
                    </button>
                </div>

                <div className="h-[300px] rounded-xl overflow-hidden border border-gray-200">
                    <MapContainer
                        center={mapPosition || defaultCenter}
                        zoom={mapPosition ? 15 : 5}
                        style={{ height: "100%", width: "100%" }}
                    >
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a>'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        <LocationMarker position={mapPosition} setPosition={setMapPosition} setFormData={setFormData} />
                        {mapPosition && <RecenterMap position={mapPosition} />}
                    </MapContainer>
                </div>

                {formData.latitude && formData.longitude && (
                    <div className="mt-3 flex gap-4 text-sm text-gray-600">
                        <span>Lat: {formData.latitude}</span>
                        <span>Lng: {formData.longitude}</span>
                    </div>
                )}
            </div>
        </div>
    );

    const renderStep3 = () => (
        <div className="space-y-6">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Pricing & Area</h2>
                <p className="text-gray-500 mt-2">Update price and property dimensions</p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">
                        {formData.listingType === "Rent" ? "Monthly Rent" : "Expected Price"} (₹) *
                    </label>
                    <input
                        type="number"
                        name="expectedPrice"
                        value={formData.expectedPrice}
                        onChange={handleChange}
                        placeholder="Enter amount"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                {formData.listingType === "Rent" && (
                    <div>
                        <label className="block text-sm font-semibold text-gray-700 mb-2">Security Deposit (₹)</label>
                        <input
                            type="number"
                            name="expectedDeposit"
                            value={formData.expectedDeposit}
                            onChange={handleChange}
                            placeholder="Deposit amount"
                            className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                        />
                    </div>
                )}

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Built-up Area (sq.ft) *</label>
                    <input
                        type="number"
                        name="builtUpArea"
                        value={formData.builtUpArea}
                        onChange={handleChange}
                        placeholder="Enter area"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Carpet Area (sq.ft)</label>
                    <input
                        type="number"
                        name="carpetArea"
                        value={formData.carpetArea}
                        onChange={handleChange}
                        placeholder="Enter carpet area"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div className="flex items-center gap-3">
                    <input
                        type="checkbox"
                        id="priceNegotiable"
                        name="priceNegotiable"
                        checked={formData.priceNegotiable}
                        onChange={handleChange}
                        className="w-5 h-5 rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                    />
                    <label htmlFor="priceNegotiable" className="text-sm font-medium text-gray-700">Price is Negotiable</label>
                </div>
            </div>
        </div>
    );

    const renderStep4 = () => (
        <div className="space-y-6">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Property Details</h2>
                <p className="text-gray-500 mt-2">Update additional property information</p>
            </div>

            <div className="grid md:grid-cols-2 gap-6">
                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Furnishing Status</label>
                    <select
                        name="furnishing"
                        value={formData.furnishing}
                        onChange={handleChange}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    >
                        <option value="Unfurnished">Unfurnished</option>
                        <option value="Semi-Furnished">Semi-Furnished</option>
                        <option value="Fully Furnished">Fully Furnished</option>
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Construction Status</label>
                    <select
                        name="constructionStatus"
                        value={formData.constructionStatus}
                        onChange={handleChange}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    >
                        <option value="Ready to Move">Ready to Move</option>
                        <option value="Under Construction">Under Construction</option>
                        <option value="New Launch">New Launch</option>
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Floor Number</label>
                    <input
                        type="number"
                        name="floorNo"
                        value={formData.floorNo}
                        onChange={handleChange}
                        placeholder="Floor number"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Total Floors</label>
                    <input
                        type="number"
                        name="totalFloors"
                        value={formData.totalFloors}
                        onChange={handleChange}
                        placeholder="Total floors in building"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Bathrooms</label>
                    <input
                        type="number"
                        name="bathrooms"
                        value={formData.bathrooms}
                        onChange={handleChange}
                        min="1"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Balconies</label>
                    <input
                        type="number"
                        name="balconies"
                        value={formData.balconies}
                        onChange={handleChange}
                        min="0"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Facing</label>
                    <select
                        name="facing"
                        value={formData.facing}
                        onChange={handleChange}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    >
                        <option value="">Select Facing</option>
                        <option value="North">North</option>
                        <option value="South">South</option>
                        <option value="East">East</option>
                        <option value="West">West</option>
                        <option value="North-East">North-East</option>
                        <option value="North-West">North-West</option>
                        <option value="South-East">South-East</option>
                        <option value="South-West">South-West</option>
                    </select>
                </div>

                <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-2">Available From</label>
                    <input
                        type="date"
                        name="availableFrom"
                        value={formData.availableFrom}
                        onChange={handleChange}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none"
                    />
                </div>
            </div>

            {/* Amenities */}
            <div>
                <label className="block text-sm font-semibold text-gray-700 mb-3">Amenities</label>
                <div className="flex flex-wrap gap-2">
                    {PROPERTY_CATEGORIES[formData.propertyCategory].amenities.map(amenity => (
                        <button
                            key={amenity}
                            type="button"
                            onClick={() => handleAmenityToggle(amenity)}
                            className={`px-4 py-2 rounded-full text-sm font-medium transition-all ${formData.selectedAmenities.includes(amenity)
                                ? "bg-blue-600 text-white"
                                : "bg-gray-100 text-gray-600 hover:bg-gray-200"
                                }`}
                        >
                            {amenity}
                        </button>
                    ))}
                </div>
            </div>

            {/* Description */}
            <div>
                <label className="block text-sm font-semibold text-gray-700 mb-2">Description</label>
                <textarea
                    name="description"
                    value={formData.description}
                    onChange={handleChange}
                    rows={4}
                    placeholder="Describe your property..."
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 outline-none resize-none"
                />
            </div>
        </div>
    );

    const renderStep5 = () => {
        const categories = getImageCategories();
        const totalImages = getTotalCategorizedImages();

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Property Photos</h2>
                    <p className="text-gray-500 mt-2">
                        Organize your property images by category • {totalImages} image{totalImages !== 1 ? 's' : ''} total
                    </p>
                </div>

                <div className="space-y-4">
                    {categories.map((category) => {
                        const existingCount = existingCategorizedImages[category.key]?.length || 0;
                        const newCount = categorizedImages[category.key]?.files?.length || 0;
                        const totalCatImages = existingCount + newCount;
                        const isExpanded = expandedCategories[category.key] !== false;

                        return (
                            <div key={category.key} className="border border-gray-200 rounded-xl overflow-hidden">
                                {/* Category Header */}
                                <button
                                    type="button"
                                    onClick={() => toggleCategory(category.key)}
                                    className="w-full px-4 py-3 bg-gray-50 flex items-center justify-between hover:bg-gray-100 transition-colors"
                                >
                                    <div className="flex items-center gap-3">
                                        <ImageIcon size={20} className="text-blue-500" />
                                        <span className="font-medium text-gray-800">{category.label}</span>
                                        <span className="text-sm text-gray-500">
                                            ({totalCatImages}/{category.maxImages})
                                        </span>
                                    </div>
                                    <motion.div
                                        animate={{ rotate: isExpanded ? 180 : 0 }}
                                        transition={{ duration: 0.2 }}
                                    >
                                        <ChevronLeft className="transform -rotate-90" size={20} />
                                    </motion.div>
                                </button>

                                {/* Category Content */}
                                <AnimatePresence>
                                    {isExpanded && (
                                        <motion.div
                                            initial={{ height: 0, opacity: 0 }}
                                            animate={{ height: "auto", opacity: 1 }}
                                            exit={{ height: 0, opacity: 0 }}
                                            transition={{ duration: 0.2 }}
                                            className="overflow-hidden"
                                        >
                                            <div className="p-4">
                                                {/* Existing Images */}
                                                <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
                                                    {existingCategorizedImages[category.key]?.map((img, idx) => (
                                                        <div key={`existing-${idx}`} className="relative group aspect-square rounded-lg overflow-hidden border border-gray-200">
                                                            <img src={img} alt={`${category.label} ${idx + 1}`} className="w-full h-full object-cover" />
                                                            <button
                                                                type="button"
                                                                onClick={() => removeCategorizedImage(category.key, idx, true)}
                                                                className="absolute top-2 right-2 p-1.5 bg-red-500 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                                                            >
                                                                <X size={12} />
                                                            </button>
                                                            <span className="absolute bottom-2 left-2 text-xs bg-black/50 text-white px-2 py-0.5 rounded">
                                                                Current
                                                            </span>
                                                        </div>
                                                    ))}

                                                    {/* New Image Previews */}
                                                    {categorizedImages[category.key]?.previews?.map((preview, idx) => (
                                                        <div key={`new-${idx}`} className="relative group aspect-square rounded-lg overflow-hidden border-2 border-green-400">
                                                            <img src={preview} alt={`New ${idx + 1}`} className="w-full h-full object-cover" />
                                                            <button
                                                                type="button"
                                                                onClick={() => removeCategorizedImage(category.key, idx, false)}
                                                                className="absolute top-2 right-2 p-1.5 bg-red-500 text-white rounded-full opacity-0 group-hover:opacity-100 transition-opacity"
                                                            >
                                                                <X size={12} />
                                                            </button>
                                                            <span className="absolute bottom-2 left-2 text-xs bg-green-500 text-white px-2 py-0.5 rounded">
                                                                New
                                                            </span>
                                                        </div>
                                                    ))}

                                                    {/* Upload Button */}
                                                    {totalCatImages < category.maxImages && (
                                                        <label className="aspect-square rounded-lg border-2 border-dashed border-gray-300 flex flex-col items-center justify-center cursor-pointer hover:border-blue-500 hover:bg-blue-50 transition-colors">
                                                            <input
                                                                type="file"
                                                                accept="image/*"
                                                                multiple
                                                                onChange={(e) => handleCategorizedImageUpload(category.key, e)}
                                                                className="hidden"
                                                            />
                                                            <Plus size={24} className="text-gray-400" />
                                                            <span className="text-xs text-gray-500 mt-1">Add</span>
                                                        </label>
                                                    )}
                                                </div>

                                                {totalCatImages === 0 && (
                                                    <p className="text-sm text-gray-400 text-center py-2">
                                                        No images in this category
                                                    </p>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>
                            </div>
                        );
                    })}
                </div>

                {totalImages < 3 && (
                    <div className="flex items-center gap-2 p-3 bg-amber-50 border border-amber-200 rounded-lg">
                        <AlertTriangle size={18} className="text-amber-500" />
                        <span className="text-sm text-amber-700">
                            Add at least 3 images for better visibility
                        </span>
                    </div>
                )}
            </div>
        );
    };

    const renderStep6 = () => {
        // Get first available image for preview
        const getPreviewImage = () => {
            for (const catKey of Object.keys(existingCategorizedImages)) {
                if (existingCategorizedImages[catKey]?.length > 0) {
                    return existingCategorizedImages[catKey][0];
                }
            }
            for (const catKey of Object.keys(categorizedImages)) {
                if (categorizedImages[catKey]?.previews?.length > 0) {
                    return categorizedImages[catKey].previews[0];
                }
            }
            return null;
        };

        const previewImage = getPreviewImage();
        const totalImages = getTotalCategorizedImages();

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Review Changes</h2>
                    <p className="text-gray-500 mt-2">Confirm your property updates</p>
                </div>

                <div className="max-w-3xl mx-auto bg-white rounded-2xl shadow-lg p-6 border border-gray-200">
                    {/* Preview Image */}
                    <div className="h-56 bg-gray-100 rounded-2xl overflow-hidden relative mb-4 border border-gray-200">
                        {previewImage ? (
                            <img src={previewImage} className="w-full h-full object-cover" alt="Property Preview" />
                        ) : (
                            <div className="w-full h-full flex items-center justify-center text-gray-300">
                                <ImageIcon size={48} />
                            </div>
                        )}
                        <div className="absolute top-4 left-4 bg-white text-blue-600 px-3 py-1 rounded-full text-xs font-bold shadow-md uppercase">
                            {formData.listingType}
                        </div>
                        <div className="absolute bottom-4 right-4 bg-black/70 text-white px-3 py-1 rounded-full text-xs font-semibold">
                            {totalImages} photos
                        </div>
                    </div>

                    <div className="space-y-4">
                        <div className="flex justify-between items-start">
                            <div>
                                <h3 className="font-bold text-xl text-gray-900">
                                    {formData.title || `${formData.bhkType || formData.propertyType} for ${formData.listingType}`}
                                </h3>
                                <p className="text-sm text-gray-500 flex items-center gap-1 mt-1">
                                    <MapPin size={14} /> {formData.locality}, {formData.city}
                                </p>
                            </div>
                            <div className="text-right">
                                <div className="font-bold text-2xl text-blue-600">
                                    ₹ {formData.expectedPrice ? Number(formData.expectedPrice).toLocaleString() : "-"}
                                </div>
                                <div className="text-xs text-gray-500">
                                    {formData.priceNegotiable ? "Negotiable" : "Fixed Price"}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-4 border-t border-gray-100">
                            <div>
                                <div className="text-xs text-gray-400 uppercase">Area</div>
                                <div className="font-semibold text-gray-800">{formData.builtUpArea || "-"} sq.ft</div>
                            </div>
                            <div>
                                <div className="text-xs text-gray-400 uppercase">Furnishing</div>
                                <div className="font-semibold text-gray-800">{formData.furnishing}</div>
                            </div>
                            {isResidential && (
                                <div>
                                    <div className="text-xs text-gray-400 uppercase">Config</div>
                                    <div className="font-semibold text-gray-800">{formData.bhkType || "-"}</div>
                                </div>
                            )}
                            <div>
                                <div className="text-xs text-gray-400 uppercase">Available</div>
                                <div className="font-semibold text-gray-800">{formData.availableFrom || "Immediate"}</div>
                            </div>
                        </div>

                        {formData.selectedAmenities.length > 0 && (
                            <div>
                                <div className="text-xs text-gray-400 uppercase mb-2">Amenities</div>
                                <div className="flex flex-wrap gap-2">
                                    {formData.selectedAmenities.map(a => (
                                        <span key={a} className="bg-gray-100 text-gray-600 border border-gray-200 px-2 py-1 rounded text-xs">
                                            {a}
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}

                        {formData.description && (
                            <div>
                                <div className="text-xs text-gray-400 uppercase">Description</div>
                                <p className="mt-1 text-sm text-gray-600 bg-gray-50 p-3 rounded-lg">{formData.description}</p>
                            </div>
                        )}

                        <div className="pt-4">
                            <button
                                onClick={handleSubmit}
                                disabled={isSaving}
                                className="w-full bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-xl font-bold flex items-center justify-center gap-2 transition-colors shadow-lg disabled:opacity-50"
                            >
                                {isSaving ? (
                                    <>
                                        <Loader2 className="w-5 h-5 animate-spin" />
                                        Saving Changes...
                                    </>
                                ) : (
                                    <>
                                        Save Changes <Check size={18} />
                                    </>
                                )}
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    return (
        <div className="min-h-screen bg-gray-50 flex flex-col md:flex-row font-sans text-gray-900">
            {/* Sidebar */}
            <aside className="hidden md:flex flex-col w-80 bg-blue-600 h-[calc(100vh-5rem)] sticky top-20 p-6 pt-8 z-20 shadow-xl overflow-y-auto">
                <div className="mb-6">
                    <h2 className="text-white text-xl font-bold">Edit Property</h2>
                    <p className="text-blue-200 text-sm mt-1">Update your listing</p>
                </div>
                <nav className="space-y-2 flex-1">
                    {STEPS.map(step => {
                        const isActive = currentStep === step.id;
                        const isCompleted = currentStep > step.id;
                        return (
                            <button
                                key={step.id}
                                onClick={() => { setDirection(step.id > currentStep ? 1 : -1); setCurrentStep(step.id); }}
                                className={`w-full group flex items-center gap-4 p-4 rounded-2xl transition-all relative overflow-hidden ${isActive ? "bg-white text-blue-600 shadow-md" : "text-blue-100 hover:bg-white/10 hover:text-white"
                                    }`}
                            >
                                <div className={`relative z-10 transition-colors ${isActive ? "text-blue-600" : isCompleted ? "text-white" : "text-blue-200 group-hover:text-white"}`}>
                                    {isCompleted ? <Check size={18} strokeWidth={3} /> : step.icon}
                                </div>
                                <div className="flex flex-col relative z-10 text-left">
                                    <span className={`font-bold text-sm ${isActive ? "text-blue-600" : "text-white"}`}>{step.label}</span>
                                    <span className={`text-xs font-medium ${isActive ? "text-blue-400" : "text-blue-200/80"}`}>{step.description}</span>
                                </div>
                            </button>
                        );
                    })}
                </nav>
                <div className="mt-auto pt-6">
                    <button
                        onClick={() => navigate("/my-properties")}
                        className="w-full flex items-center justify-center gap-2 bg-white/10 hover:bg-white/20 text-white px-4 py-3 rounded-xl font-medium transition"
                    >
                        <ChevronLeft size={18} />
                        Back to My Properties
                    </button>
                </div>
            </aside>

            {/* Mobile Header */}
            <div className="md:hidden bg-blue-600 p-4 sticky top-20 z-30 shadow-md flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <button onClick={() => navigate("/my-properties")} className="p-1.5 bg-white/20 rounded-lg">
                        <ChevronLeft className="text-white" size={16} />
                    </button>
                    <span className="font-bold text-white">Step {currentStep} of 6</span>
                </div>
                <div className="flex gap-1.5">
                    {STEPS.map(s => (
                        <div key={s.id} className={`h-1.5 w-6 rounded-full ${s.id <= currentStep ? "bg-white" : "bg-blue-400/50"}`} />
                    ))}
                </div>
            </div>

            {/* Main Content */}
            <main className="flex-1 p-6 md:p-12 max-w-5xl mx-auto w-full flex flex-col h-full">
                <div className="flex-1 mb-20 md:mb-0 relative">
                    <AnimatePresence mode="wait" custom={direction}>
                        <motion.div
                            key={currentStep}
                            custom={direction}
                            variants={variants}
                            initial="enter"
                            animate="center"
                            exit="exit"
                            transition={{ x: { type: "spring", stiffness: 300, damping: 30 }, opacity: { duration: 0.2 } }}
                            className="min-h-[520px]"
                        >
                            {currentStep === 1 && renderStep1()}
                            {currentStep === 2 && renderStep2()}
                            {currentStep === 3 && renderStep3()}
                            {currentStep === 4 && renderStep4()}
                            {currentStep === 5 && renderStep5()}
                            {currentStep === 6 && renderStep6()}
                        </motion.div>
                    </AnimatePresence>

                    {/* Navigation Buttons */}
                    <div className="flex justify-between items-center mt-12 pt-8 border-t border-gray-200">
                        <button
                            onClick={handlePrev}
                            disabled={currentStep === 1}
                            className={`flex items-center gap-2 px-8 py-3 rounded-xl font-bold transition-all ${currentStep === 1 ? "text-gray-300 cursor-not-allowed" : "text-gray-600 hover:bg-gray-100"
                                }`}
                        >
                            <ChevronLeft size={18} /> Back
                        </button>

                        <div className="flex items-center gap-3">
                            {currentStep < 6 && (
                                <button
                                    onClick={handleNext}
                                    className="bg-blue-600 text-white px-10 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg flex items-center gap-2"
                                >
                                    Next Step <ArrowRight size={18} />
                                </button>
                            )}
                            {currentStep === 6 && (
                                <button
                                    onClick={handleSubmit}
                                    disabled={isSaving}
                                    className="bg-blue-600 text-white px-10 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg flex items-center gap-2 disabled:opacity-50"
                                >
                                    {isSaving ? (
                                        <>
                                            <Loader2 className="w-5 h-5 animate-spin" />
                                            Saving...
                                        </>
                                    ) : (
                                        <>
                                            Save Changes <Check size={18} />
                                        </>
                                    )}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}
