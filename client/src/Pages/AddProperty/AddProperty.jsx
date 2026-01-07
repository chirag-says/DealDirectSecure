import React, { useState, useEffect, useRef, useMemo } from "react";
import {
    Home, MapPin, IndianRupee, Layers, Image as ImageIcon, Calendar,
    ChevronLeft, Upload, Check, X, Building2, Users, Utensils, Car, Zap,
    Shield, Store, ArrowRight, FileText, Tag, Wifi, LandPlot, Plus, AlertTriangle, Navigation
} from "lucide-react";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import EmailVerificationModal from "../../Components/EmailVerificationModal/EmailVerificationModal";
import locationData from "../../data/real-estate-locations.json";
import { MapContainer, TileLayer, Marker, useMapEvents, useMap } from "react-leaflet";
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import axios from "axios"; // Keep for metadata fetching (public endpoints)

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

// API Base URL
const API_BASE = import.meta.env.VITE_API_BASE;

// Steps
const STEPS = [
    { id: 1, label: "Category & Type", icon: <Home size={18} />, description: "Property basics" },
    { id: 2, label: "Location", icon: <MapPin size={18} />, description: "Address details" },
    { id: 3, label: "Pricing & Area", icon: <IndianRupee size={18} />, description: "Value & size" },
    { id: 4, label: "Property Details", icon: <Layers size={18} />, description: "Specific features" },
    { id: 5, label: "Photos & Docs", icon: <ImageIcon size={18} />, description: "Images & documents" },
    { id: 6, label: "Review", icon: <Calendar size={18} />, description: "Final check" },
];

// Categories & types (customized & professional)
const PROPERTY_CATEGORIES = {
    Residential: {
        icon: <Home size={28} />,
        types: [
            "Apartment / Flat",
            "Independent House",
            "Villa",
            "Builder Floor",
            "Row House",
            "Studio Apartment",
            "Penthouse",
            "Farm House"
        ],
        desc: "Homes for living",
        amenities: [
            "Lift", "Gym", "Swimming Pool", "Club House", "Power Backup", "CCTV", "Parking Covered", "Parking Open",
            "Modular Kitchen", "Wardrobes", "Geyser", "AC", "Fans", "Water Purifier", "Intercom", "Garden", "Jogging Track",
            "Kids Play Area", "Community Hall", "RO Water", "Store Room", "Servant Room"
        ]
    },
    Commercial: {
        icon: <Store size={28} />,
        types: [
            "Office Space",
            "Shop / Retail",
            "Showroom",
            "Restaurant / Cafe",
            "Co-Working Space",
            "Warehouse / Godown",
            "Industrial Shed",
            "Commercial Building / Floor"
        ],
        desc: "Business spaces",
        amenities: [
            "Lift", "Power Backup", "CCTV", "Fire Safety", "Reserved Parking", "Visitor Parking", "Internet",
            "Loading Dock", "Goods Lift", "Sprinkler System", "Water Storage", "Security", "Washrooms", "AC"
        ]
    }
};

// Commercial property specific configurations
const COMMERCIAL_CONFIGS = {
    "Office Space": {
        icon: <Building2 size={16} />,
        fields: ["workstations", "conferenceRooms", "cabins", "washrooms", "pantry"],
        label: "Office Configuration"
    },
    "Shop / Retail": {
        icon: <Store size={16} />,
        fields: ["frontage", "washrooms", "storage", "displayWindows"],
        label: "Shop Configuration"
    },
    "Showroom": {
        icon: <Store size={16} />,
        fields: ["frontage", "washrooms", "storage", "displayArea", "parking"],
        label: "Showroom Configuration"
    },
    "Restaurant / Cafe": {
        icon: <Utensils size={16} />,
        fields: ["seatingCapacity", "kitchenArea", "washrooms", "barArea", "outdoorSeating"],
        label: "Restaurant Configuration"
    },
    "Co-Working Space": {
        icon: <Users size={16} />,
        fields: ["workstations", "meetingRooms", "privateCabins", "phoneBooths", "loungeArea"],
        label: "Co-Working Configuration"
    },
    "Warehouse / Godown": {
        icon: <LandPlot size={16} />,
        fields: ["loadingDocks", "ceilingHeight", "floorLoadCapacity", "officeSpace", "washrooms"],
        label: "Warehouse Configuration"
    },
    "Industrial Shed": {
        icon: <Building2 size={16} />,
        fields: ["ceilingHeight", "floorLoadCapacity", "powerConnection", "overheadCrane", "officeSpace"],
        label: "Industrial Shed Configuration"
    },
    "Commercial Building / Floor": {
        icon: <Building2 size={16} />,
        fields: ["washrooms", "pantry", "centralAC", "powerBackup", "parking"],
        label: "Building Configuration"
    }
};

// Amenity mapping for icons
const AMENITY_ICONS = {
    Lift: <Building2 size={16} />,
    Gym: <Zap size={16} />,
    "Swimming Pool": <Zap size={16} />,
    "Power Backup": <Zap size={16} />,
    CCTV: <Shield size={16} />,
    "Parking Covered": <Car size={16} />,
    "Parking Open": <Car size={16} />,
    Internet: <Wifi size={16} />,
    "Modular Kitchen": <Utensils size={16} />,
    Security: <Shield size={16} />,
    "Fire Safety": <Shield size={16} />,
    "Loading Dock": <Car size={16} />
};

// Image categories based on property type
const IMAGE_CATEGORIES = {
    Residential: {
        "Apartment / Flat": [
            { key: "exterior", label: "Building Exterior", maxImages: 3, tip: "Show the building facade and entrance" },
            { key: "livingRoom", label: "Living Room", maxImages: 4, tip: "Main living area with natural lighting" },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 4, tip: "All bedrooms - master and other rooms" },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3, tip: "Attached and common bathrooms" },
            { key: "kitchen", label: "Kitchen", maxImages: 2, tip: "Kitchen with appliances visible" },
            { key: "balcony", label: "Balcony / Terrace", maxImages: 2, tip: "Balcony view and space" },
            { key: "hall", label: "Hall / Lobby", maxImages: 2, tip: "Building lobby or common areas" },
            { key: "parking", label: "Parking Area", maxImages: 2, tip: "Covered or open parking space" },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1, tip: "2D layout if available" },
            { key: "other", label: "Other Areas", maxImages: 5, tip: "Amenities, garden, pool, etc." }
        ],
        "Independent House": [
            { key: "exterior", label: "House Exterior", maxImages: 4 },
            { key: "livingRoom", label: "Living Room", maxImages: 3 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "garden", label: "Garden/Lawn", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Villa": [
            { key: "exterior", label: "Villa Exterior", maxImages: 5 },
            { key: "livingRoom", label: "Living Room", maxImages: 4 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 5 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "garden", label: "Garden", maxImages: 3 },
            { key: "balcony", label: "Balcony / Terrace", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Builder Floor": [
            { key: "exterior", label: "Building Exterior", maxImages: 2 },
            { key: "livingRoom", label: "Living Room", maxImages: 3 },
            { key: "bedroom", label: "Bedrooms", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "balcony", label: "Balcony", maxImages: 2 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Studio Apartment": [
            { key: "livingRoom", label: "Studio Space", maxImages: 4 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "bathroom", label: "Bathroom", maxImages: 2 },
            { key: "balcony", label: "Balcony / Sit-out", maxImages: 2 },
            { key: "other", label: "Other", maxImages: 3 }
        ],
        "Penthouse": [
            { key: "exterior", label: "Building & Terrace", maxImages: 4 },
            { key: "livingRoom", label: "Living Area", maxImages: 4 },
            { key: "bedroom", label: "Bedroom(s)", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "balcony", label: "Balcony", maxImages: 2 },
            { key: "hall", label: "Lobby / Passage", maxImages: 2 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Row House": [
            { key: "exterior", label: "House Exterior", maxImages: 3 },
            { key: "livingRoom", label: "Living Room", maxImages: 3 },
            { key: "bedroom", label: "Bedrooms", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "garden", label: "Garden / Front Yard", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 2 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ],
        "Farm House": [
            { key: "exterior", label: "Property Exterior", maxImages: 5 },
            { key: "livingRoom", label: "Living Space", maxImages: 3 },
            { key: "bedroom", label: "Bedrooms / Guest Rooms", maxImages: 4 },
            { key: "bathroom", label: "Bathroom(s)", maxImages: 3 },
            { key: "kitchen", label: "Kitchen", maxImages: 2 },
            { key: "garden", label: "Garden / Lawn", maxImages: 5 },
            { key: "parking", label: "Parking / Driveway", maxImages: 3 },
            { key: "floorPlan", label: "Floor / Site Plan", maxImages: 1 },
            { key: "other", label: "Other", maxImages: 5 }
        ]
    },
    Commercial: {
        // These keys are aligned with Property.categorizedImages.commercial
        "Office Space": [
            { key: "facade", label: "Building Exterior", maxImages: 4, tip: "Building facade and entrance" },
            { key: "reception", label: "Reception / Lobby", maxImages: 3, tip: "Front desk and waiting area" },
            { key: "workArea", label: "Open Work Area", maxImages: 6, tip: "Main working floor, desks and cubicles" },
            { key: "cabin", label: "Cabins / Private Rooms", maxImages: 4, tip: "Manager and private cabins" },
            { key: "conferenceRoom", label: "Conference / Meeting Rooms", maxImages: 3, tip: "Conference and huddle rooms" },
            { key: "pantry", label: "Pantry / Cafeteria", maxImages: 3, tip: "Pantry, tea/coffee area" },
            { key: "washroom", label: "Washrooms", maxImages: 3, tip: "Restrooms for staff and visitors" },
            { key: "parking", label: "Parking Area", maxImages: 3, tip: "Covered / open parking" },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1, tip: "2D layout if available" },
            { key: "other", label: "Other Areas", maxImages: 5, tip: "Server room, terrace, utilities, etc." }
        ],
        "Shop / Retail": [
            { key: "facade", label: "Shop Front / Facade", maxImages: 4, tip: "Street view and entrance" },
            { key: "shopFloor", label: "Shop Floor", maxImages: 6, tip: "Main retail floor and aisles" },
            { key: "displayArea", label: "Display / Window Area", maxImages: 4, tip: "Display racks and windows" },
            { key: "storageArea", label: "Back Storage / Inventory", maxImages: 4, tip: "Stock room and storage" },
            { key: "washroom", label: "Washrooms", maxImages: 2 },
            { key: "parking", label: "Customer Parking", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Showroom": [
            { key: "facade", label: "Showroom Exterior", maxImages: 4 },
            { key: "reception", label: "Reception / Front Desk", maxImages: 3 },
            { key: "displayArea", label: "Display Area", maxImages: 6 },
            { key: "seatingArea", label: "Customer Seating / Lounge", maxImages: 3 },
            { key: "storageArea", label: "Back Office / Storage", maxImages: 3 },
            { key: "parking", label: "Parking", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Restaurant / Cafe": [
            { key: "facade", label: "Exterior / Entrance", maxImages: 4 },
            { key: "seatingArea", label: "Dining / Seating Area", maxImages: 6 },
            { key: "kitchenCommercial", label: "Commercial Kitchen", maxImages: 4 },
            { key: "washroom", label: "Washrooms", maxImages: 3 },
            { key: "storageArea", label: "Storage / Prep Area", maxImages: 3 },
            { key: "parking", label: "Parking / Valet Area", maxImages: 3 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Co-Working Space": [
            { key: "facade", label: "Exterior", maxImages: 3 },
            { key: "reception", label: "Reception / Entry", maxImages: 3 },
            { key: "workArea", label: "Open Desk Area", maxImages: 6 },
            { key: "cabin", label: "Private Cabins", maxImages: 4 },
            { key: "conferenceRoom", label: "Meeting / Conference Rooms", maxImages: 3 },
            { key: "seatingArea", label: "Lounge / Breakout", maxImages: 3 },
            { key: "pantry", label: "Pantry / Cafe", maxImages: 3 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Warehouse / Godown": [
            { key: "facade", label: "Warehouse Exterior", maxImages: 3 },
            { key: "warehouse", label: "Main Storage Area", maxImages: 8 },
            { key: "loadingArea", label: "Loading / Unloading Area", maxImages: 4 },
            { key: "storageArea", label: "Racks / Internal Storage", maxImages: 4 },
            { key: "parking", label: "Truck / Vehicle Parking", maxImages: 3 },
            { key: "floorPlan", label: "Site / Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Industrial Shed": [
            { key: "facade", label: "Shed Exterior", maxImages: 3 },
            { key: "warehouse", label: "Main Production Floor", maxImages: 8 },
            { key: "loadingArea", label: "Loading / Dock Area", maxImages: 4 },
            { key: "storageArea", label: "Storage / Raw Material", maxImages: 4 },
            { key: "parking", label: "Parking / Yard", maxImages: 3 },
            { key: "floorPlan", label: "Layout / Floor Plan", maxImages: 1 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ],
        "Commercial Building / Floor": [
            { key: "facade", label: "Building Exterior", maxImages: 4 },
            { key: "reception", label: "Main Lobby / Reception", maxImages: 3 },
            { key: "workArea", label: "Typical Floor / Work Area", maxImages: 6 },
            { key: "cabin", label: "Cabins / Offices", maxImages: 4 },
            { key: "conferenceRoom", label: "Conference Rooms", maxImages: 3 },
            { key: "parking", label: "Parking Levels", maxImages: 4 },
            { key: "floorPlan", label: "Floor Plan", maxImages: 2 },
            { key: "other", label: "Other Areas", maxImages: 5 }
        ]
    }
};

// Animation variants
const variants = {
    enter: (direction) => ({
        x: direction > 0 ? 20 : -20,
        opacity: 0,
    }),
    center: {
        x: 0,
        opacity: 1,
    },
    exit: (direction) => ({
        x: direction < 0 ? 20 : -20,
        opacity: 0,
    }),
};

export default function AddProperty() {
    const navigate = useNavigate();

    // Auth state using AuthContext
    const { user: authUser, isAuthenticated, loading: authLoading } = useAuth();
    const [user, setUser] = useState(null);
    const [showVerificationModal, setShowVerificationModal] = useState(false);
    const [isAuthorized, setIsAuthorized] = useState(false);

    // Check user authorization on mount using AuthContext
    useEffect(() => {
        if (authLoading) return;

        if (!isAuthenticated || !authUser) {
            toast.error("Please login to list your property");
            navigate("/login");
            return;
        }

        setUser(authUser);
        const role = (authUser.role || "user").toLowerCase();

        if (role === "agent") {
            // Agents can list unlimited properties
            setIsAuthorized(true);
        } else if (role === "owner") {
            // Owners can only list ONE property - check if they already have one
            const checkOwnerLimit = async () => {
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
                            "You can list only one property as an owner. Please edit your existing listing.",
                        );
                        navigate("/my-properties");
                        return;
                    }
                    setIsAuthorized(true);
                } catch (error) {
                    console.error("Error checking existing properties:", error);
                    // If check fails, allow access to not block the user
                    setIsAuthorized(true);
                }
            };
            checkOwnerLimit();
        } else {
            // Buyer/User needs to verify email to become owner
            setShowVerificationModal(true);
        }
    }, [authLoading, isAuthenticated, authUser, navigate]);

    const handleVerificationSuccess = () => {
        // User state will be automatically updated via AuthContext's checkAuth
        // which runs after successful verification completes
        setIsAuthorized(true);
        setShowVerificationModal(false);
        toast.success("You can now list your property!");
    };

    // UI state
    const [currentStep, setCurrentStep] = useState(1);
    const [direction, setDirection] = useState(0);
    const [isLoading, setIsLoading] = useState(false);
    const [images, setImages] = useState([]);
    const [previewImages, setPreviewImages] = useState([]);
    const [categorizedImages, setCategorizedImages] = useState({});
    const [expandedCategories, setExpandedCategories] = useState([]);

    const [metadata, setMetadata] = useState({
        categories: [],
        subcategories: [],
        propertyTypes: []
    });

    const [formData, setFormData] = useState({
        listingType: "Rent", propertyCategory: "Residential", propertyType: "Apartment / Flat",
        bhkType: "", bedrooms: "", bathrooms: 1, balconies: 0,
        builtUpArea: "", carpetArea: "", superBuiltUpArea: "", plotArea: "",
        expectedPrice: "", maintenanceIncluded: true, maintenance: "", expectedDeposit: "", bookingAmount: "", priceNegotiable: false, gstApplicable: false,
        furnishing: "Unfurnished", floorNo: "", totalFloors: "", propertyAge: "New", facing: "", constructionStatus: "Ready to Move",
        commercialSubType: "", washrooms: 1, loadingArea: "", dockAvailable: false, shutters: "", floorHeight: "",
        workstations: "", conferenceRooms: "", cabins: "", pantry: "", frontage: "", storage: "", displayWindows: "", displayArea: "",
        seatingCapacity: "", kitchenArea: "", barArea: "", outdoorSeating: "", meetingRooms: "", privateCabins: "", phoneBooths: "", loungeArea: "",
        loadingDocks: "", ceilingHeight: "", floorLoadCapacity: "", powerConnection: "", overheadCrane: "", centralAC: "", powerBackup: "",
        parkingCovered: 0, parkingOpen: 0, selectedAmenities: [],
        servantRoom: false, poojaRoom: false, studyRoom: false, storeRoom: false,
        reraId: "", occupancyCertificate: false, tradeLicense: false, fireNoc: false,
        availableFrom: new Date().toISOString().split('T')[0], petFriendly: "No", allowedFor: "Family", ageOfProperty: "",
        city: "", locality: "", landmark: "", address: "", nearby: [],
        latitude: "", longitude: "",
        description: "", videoUrl: "", showHelpTips: true
    });

    // Map state
    const [mapPosition, setMapPosition] = useState(null);
    const [isLocating, setIsLocating] = useState(false);
    const defaultCenter = [20.5937, 78.9629]; // Center of India

    // Location autocomplete state
    const [locationSuggestions, setLocationSuggestions] = useState([]);
    const [isSearchingLocation, setIsSearchingLocation] = useState(false);
    const [activeLocationField, setActiveLocationField] = useState(null); // 'city', 'locality', or 'address'
    const [showSuggestions, setShowSuggestions] = useState(false);
    const searchTimeoutRef = useRef(null);
    const geocodeTimeoutRef = useRef(null);
    const suggestionsRef = useRef(null);

    // Fetch metadata
    useEffect(() => {
        const fetchMetadata = async () => {
            try {
                const [cats, subs, types] = await Promise.all([
                    api.get('/categories/list-category'),
                    api.get('/subcategories/list'),
                    api.get('/propertyTypes/list-propertytype')
                ]);
                setMetadata({
                    categories: cats.data.data || cats.data || [],
                    subcategories: subs.data.data || subs.data || [],
                    propertyTypes: types.data.data || types.data || []
                });
            } catch (error) {
                console.error("Failed to fetch metadata", error);
            }
        };
        fetchMetadata();
    }, []);

    const isResidential = formData.propertyCategory === "Residential";
    const isCommercial = formData.propertyCategory === "Commercial";
    const commercialConfig = isCommercial ? COMMERCIAL_CONFIGS[formData.propertyType] : null;

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData(prev => ({ ...prev, [name]: type === "checkbox" ? checked : value }));
    };

    const handleAmenityToggle = (amenity) => {
        setFormData(prev => {
            const list = prev.selectedAmenities || [];
            return {
                ...prev,
                selectedAmenities: list.includes(amenity) ? list.filter(a => a !== amenity) : [...list, amenity]
            };
        });
    };

    const handleCategoryChange = (category) => {
        const defaultType = PROPERTY_CATEGORIES[category].types[0];
        setFormData(prev => ({
            ...prev,
            propertyCategory: category,
            propertyType: defaultType,
            bhkType: category === "Residential" ? prev.bhkType : "",
            furnishing: category === "Residential" ? prev.furnishing : "Bare Shell",
            commercialSubType: category === "Commercial" ? prev.commercialSubType : "",
        }));
    };

    const handlePropertyTypeChange = (type) => {
        setFormData(prev => ({
            ...prev,
            propertyType: type,
            bhkType: type.includes("Studio") ? "Studio" : prev.bhkType
        }));
    };

    const getImageCategories = () => {
        if (isResidential) return IMAGE_CATEGORIES.Residential[formData.propertyType] || IMAGE_CATEGORIES.Residential["Apartment / Flat"];
        else if (isCommercial) return IMAGE_CATEGORIES.Commercial[formData.propertyType] || IMAGE_CATEGORIES.Commercial["Office Space"];
        return [];
    };

    const handleCategorizedImageUpload = (categoryKey, e) => {
        const files = Array.from(e.target.files || []);
        if (!files.length) return;
        const category = getImageCategories().find(c => c.key === categoryKey);
        const maxImages = category?.maxImages || 5;
        const currentImages = categorizedImages[categoryKey]?.files || [];
        if (files.length + currentImages.length > maxImages) return toast.error(`Maximum ${maxImages} images allowed`);
        const newPreviews = files.map(file => URL.createObjectURL(file));
        setCategorizedImages(prev => ({
            ...prev,
            [categoryKey]: {
                files: [...(prev[categoryKey]?.files || []), ...files],
                previews: [...(prev[categoryKey]?.previews || []), ...newPreviews]
            }
        }));
    };

    const removeCategorizedImage = (categoryKey, index) => {
        setCategorizedImages(prev => ({
            ...prev,
            [categoryKey]: {
                files: prev[categoryKey]?.files?.filter((_, i) => i !== index) || [],
                previews: prev[categoryKey]?.previews?.filter((_, i) => i !== index) || []
            }
        }));
    };

    const getTotalCategorizedImages = () => {
        return Object.values(categorizedImages).reduce((total, cat) => total + (cat.files?.length || 0), 0);
    };

    const toggleCategory = (categoryKey) => {
        setExpandedCategories(prev =>
            prev.includes(categoryKey) ? prev.filter(k => k !== categoryKey) : [...prev, categoryKey]
        );
    };

    // Validation
    const validateStep = (step) => {
        const f = formData;
        switch (step) {
            case 1:
                if (!f.propertyCategory || !f.propertyType) return "Please choose category and type.";
                if (isResidential && !f.bhkType && !f.propertyType.toLowerCase().includes("studio")) return "Please choose BHK.";
                break;
            case 2:
                if (!f.city || !f.locality) return "City and Locality are required.";
                break;
            case 3:
                if (!f.expectedPrice) return "Please enter expected price.";
                if (!f.builtUpArea && !(isCommercial && f.propertyType.toLowerCase().includes("warehouse"))) return "Built-up area is required.";
                break;
            case 4:
                if (isResidential && !f.bedrooms && !f.bhkType.includes("Studio")) return "Please confirm bedrooms.";
                break;
            case 5:
                const categories = getImageCategories();
                const exteriorCategory = categories.find(c => ['exterior', 'facade'].includes(c.key));

                if (exteriorCategory) {
                    const hasExteriorImage = categorizedImages[exteriorCategory.key]?.files?.length > 0;
                    if (!hasExteriorImage) return `Please upload at least one ${exteriorCategory.label} photo.`;
                }
                break;
            default: break;
        }
        return null;
    };

    const handleNext = () => {
        const error = validateStep(currentStep);
        if (error) return toast.error(error);
        setDirection(1);
        setCurrentStep(prev => Math.min(prev + 1, 6));
    };

    const handlePrev = () => {
        setDirection(-1);
        setCurrentStep(prev => Math.max(prev - 1, 1));
    };

    const findObjectId = (name, type) => {
        if (!metadata[type] || !metadata[type].length) return null;
        let match = metadata[type].find(item => item.name === name) ||
            metadata[type].find(item => item.name.toLowerCase() === name.toLowerCase()) ||
            metadata[type].find(item => item.name.toLowerCase().includes(name.toLowerCase()));
        return match ? match._id : null;
    };

    // Lightweight number helpers to keep payload clean
    const toNumber = (val) => {
        const num = Number(val);
        return Number.isFinite(num) ? num : undefined;
    };

    const roundTo = (val, digits = 2) => {
        if (!Number.isFinite(val)) return undefined;
        const factor = 10 ** digits;
        return Math.round(val * factor) / factor;
    };

    const handleSubmit = async () => {
        setIsLoading(true);
        try {
            const priceValue = toNumber(formData.expectedPrice);
            if (priceValue === undefined) {
                toast.error("Please enter a valid price amount.");
                setIsLoading(false);
                return;
            }

            const submitData = new FormData();
            const categoryId = findObjectId(formData.propertyCategory, 'categories');
            const propertyTypeId = findObjectId(formData.propertyType, 'propertyTypes');

            if (!categoryId && !metadata.categories.length) {
                toast.error("Categories not loaded. Please retry in a moment.");
                setIsLoading(false);
                return;
            }

            if (!propertyTypeId && !metadata.propertyTypes.length) {
                toast.error("Property types not loaded. Please retry in a moment.");
                setIsLoading(false);
                return;
            }

            submitData.append("propertyType", propertyTypeId || (metadata.propertyTypes[0]?._id));
            submitData.append("propertyTypeName", formData.propertyType);
            submitData.append("category", categoryId || (metadata.categories[0]?._id));
            submitData.append("categoryName", formData.propertyCategory);
            submitData.append("title", generateTitle());
            submitData.append("description", formData.description || generateShortDescription());
            submitData.append("price", priceValue);
            submitData.append("listingType", formData.listingType);
            submitData.append("priceUnit", formData.listingType === "Rent" ? "Monthly" : "Total");
            submitData.append("negotiable", formData.priceNegotiable ? "true" : "false");
            submitData.append("gstApplicable", formData.gstApplicable ? "Yes" : "No");
            submitData.append("city", formData.city);
            submitData.append("locality", formData.locality);
            if (formData.bookingAmount) submitData.append("bookingAmount", toNumber(formData.bookingAmount) ?? formData.bookingAmount);
            if (formData.videoUrl) submitData.append("videoUrl", formData.videoUrl.trim());
            if (formData.ageOfProperty || formData.propertyAge) submitData.append("ageOfProperty", formData.ageOfProperty || formData.propertyAge);

            const builtUp = toNumber(formData.builtUpArea);
            const carpet = toNumber(formData.carpetArea);
            const superBuilt = toNumber(formData.superBuiltUpArea);
            const plot = toNumber(formData.plotArea);
            const totalSqft = builtUp || carpet || superBuilt || plot;
            const pricePerSqft = totalSqft ? roundTo(priceValue / totalSqft) : undefined;
            const areaData = {
                builtUpSqft: builtUp,
                carpetSqft: carpet,
                superBuiltUpSqft: superBuilt,
                plotSqft: plot,
                totalSqft,
                pricePerSqft
            };
            submitData.append("area", JSON.stringify(areaData));

            const addressData = {
                city: formData.city,
                area: formData.locality,
                line: formData.address,
                landmark: formData.landmark,
                nearby: Array.isArray(formData.nearby)
                    ? formData.nearby
                    : (formData.nearby ? formData.nearby.split(',').map(item => item.trim()).filter(Boolean) : []),
                latitude: formData.latitude ? parseFloat(formData.latitude) : null,
                longitude: formData.longitude ? parseFloat(formData.longitude) : null
            };
            submitData.append("address", JSON.stringify(addressData));

            // Add coordinates separately for easy access
            if (formData.latitude && formData.longitude) {
                submitData.append("latitude", formData.latitude);
                submitData.append("longitude", formData.longitude);
            }

            let featuresData = {
                listingType: formData.listingType,
                parking: {
                    covered: toNumber(formData.parkingCovered) ?? 0,
                    open: toNumber(formData.parkingOpen) ?? 0
                },
                amenities: formData.selectedAmenities || [],
                availableFrom: formData.availableFrom ? new Date(formData.availableFrom).toISOString() : undefined,
                deposit: toNumber(formData.expectedDeposit) ?? formData.expectedDeposit,
                securityDeposit: toNumber(formData.expectedDeposit) ?? formData.expectedDeposit,
                maintenance: formData.maintenanceIncluded ? "Included" : (toNumber(formData.maintenance) ?? formData.maintenance),
                maintenanceIncluded: formData.maintenanceIncluded,
            };

            if (isResidential) {
                featuresData = { ...featuresData, bhk: formData.bhkType, bedrooms: formData.bedrooms, bathrooms: formData.bathrooms, balconies: formData.balconies, furnishing: formData.furnishing, floorNo: formData.floorNo, totalFloors: formData.totalFloors, facing: formData.facing, constructionStatus: formData.constructionStatus, propertyAge: formData.propertyAge, extras: { servantRoom: formData.servantRoom, poojaRoom: formData.poojaRoom, studyRoom: formData.studyRoom, storeRoom: formData.storeRoom }, allowedFor: formData.allowedFor, petFriendly: formData.petFriendly };
            } else {
                featuresData = { ...featuresData, commercialSubType: formData.commercialSubType, washrooms: formData.washrooms, loadingArea: formData.loadingArea, dockAvailable: formData.dockAvailable, shutters: formData.shutters, floorHeight: formData.floorHeight, powerLoad: formData.powerLoad };
                if (commercialConfig) commercialConfig.fields.forEach(field => { if (formData[field]) featuresData[field] = formData[field]; });
            }

            submitData.append("features", JSON.stringify(featuresData));

            const legalData = { reraId: formData.reraId, occupancyCertificate: !!formData.occupancyCertificate, tradeLicense: !!formData.tradeLicense, fireNoc: !!formData.fireNoc };
            submitData.append("legal", JSON.stringify(legalData));

            images.forEach(file => submitData.append("images", file));

            const imageCategoryMap = {};
            Object.entries(categorizedImages).forEach(([categoryKey, data]) => {
                if (data.files && data.files.length > 0) {
                    data.files.forEach((file, index) => {
                        submitData.append(`categorizedImages`, file);
                        if (!imageCategoryMap[categoryKey]) imageCategoryMap[categoryKey] = [];
                        imageCategoryMap[categoryKey].push(index);
                    });
                }
            });
            submitData.append("imageCategoryMap", JSON.stringify(imageCategoryMap));

            // Use api.js for authenticated request
            await api.post('/properties/add', submitData, {
                headers: { "Content-Type": "multipart/form-data" }
            });

            toast.success("Property published successfully!");
            navigate("/");
        } catch (error) {
            console.error("Submission failed", error);
            toast.error(error.response?.data?.message || "Failed to publish property");
        } finally {
            setIsLoading(false);
        }
    };

    const generateTitle = () => {
        const parts = [];
        if (isResidential) { if (formData.bhkType) parts.push(formData.bhkType); }
        parts.push(formData.propertyType);
        parts.push(formData.listingType === "Rent" ? "for Rent" : "for Sale");
        if (formData.locality) parts.push(`in ${formData.locality}`);
        return parts.filter(Boolean).join(" ");
    };

    const generateShortDescription = () => formData.description || `${generateTitle()} | ${formData.builtUpArea || "Area not specified"} sq.ft`;

    // Common Styles (UPDATED: Blue focus ring instead of red)
    const inputStyle = "w-full px-4 py-3 rounded-xl border border-gray-300 bg-white text-gray-900 placeholder:text-gray-400 focus:border-blue-600 focus:ring-1 focus:ring-blue-600 outline-none transition-all";
    const labelStyle = "text-sm font-semibold text-gray-700 mb-1 block";
    const cardStyle = "bg-white p-6 rounded-2xl border border-gray-200 shadow-sm";

    // Render Steps
    const renderStep1 = () => (
        <div className="space-y-6">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Basics</h2>
                <p className="text-gray-500 mt-2">Choose category and type. We'll show only relevant fields next.</p>
            </div>

            <div className="text-sm font-semibold text-gray-900 uppercase tracking-wider">Property Category</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {Object.entries(PROPERTY_CATEGORIES).map(([key, value]) => (
                    <div key={key}
                        // UPDATED: Blue theme for selected category
                        className={`cursor-pointer rounded-2xl p-4 flex gap-4 items-center transition-all ${formData.propertyCategory === key ? "bg-blue-50 border-2 border-blue-200 text-blue-700 shadow-sm" : "bg-white border border-gray-200 hover:bg-gray-50 text-gray-700"}`}
                        onClick={() => handleCategoryChange(key)}
                    >
                        {/* UPDATED: Blue icon background */}
                        <div className={`p-3 rounded-full ${formData.propertyCategory === key ? "bg-blue-100 text-blue-600" : "bg-gray-100 text-gray-600"}`}>
                            {value.icon}
                        </div>
                        <div>
                            <div className="font-bold">{key}</div>
                            {/* UPDATED: Blue subtitle text */}
                            <div className={`text-xs ${formData.propertyCategory === key ? "text-blue-500" : "text-gray-500"}`}>{value.desc}</div>
                        </div>
                        {/* UPDATED: Blue Checkmark */}
                        {formData.propertyCategory === key && <div className="ml-auto text-blue-600"><Check size={18} /></div>}
                    </div>
                ))}
            </div>

            <div>
                <label className="text-sm font-semibold text-gray-900 uppercase tracking-wider">Property Type</label>
                <div className="flex flex-wrap gap-3 mt-2">
                    {PROPERTY_CATEGORIES[formData.propertyCategory].types.map(type => (
                        <button key={type} onClick={() => handlePropertyTypeChange(type)}
                            // UPDATED: Blue background for active button, Blue hover for inactive
                            className={`px-4 py-2 rounded-xl border text-sm font-medium transition-all ${formData.propertyType === type ? "bg-blue-600 text-white border-blue-600 shadow-md" : "bg-white text-gray-600 border-gray-300 hover:bg-blue-50 hover:border-blue-200"}`}>
                            {type}
                        </button>
                    ))}
                </div>
            </div>

            {isResidential && (
                <div>
                    <label className="text-sm font-semibold text-gray-900 uppercase tracking-wider">BHK Configuration</label>
                    <div className="flex flex-wrap gap-3 mt-2">
                        {["1 RK", "1 BHK", "2 BHK", "3 BHK", "4 BHK", "5+ BHK", "Studio"].map(bhk => (
                            <button key={bhk} onClick={() => setFormData(p => ({ ...p, bhkType: bhk, bedrooms: bhk === "Studio" ? 0 : (bhk.split(" ")[0]) }))}
                                // UPDATED: Blue background for active button
                                className={`px-4 py-2 rounded-xl border text-sm font-medium transition-all ${formData.bhkType === bhk ? "bg-blue-600 text-white border-blue-600 shadow-md" : "bg-white text-gray-600 border-gray-300 hover:bg-blue-50 hover:border-blue-200"}`}>
                                {bhk}
                            </button>
                        ))}
                    </div>
                </div>
            )}

            {isCommercial && (
                <div>
                    <label className="text-sm font-semibold text-gray-900 uppercase tracking-wider">Commercial Sub-type</label>
                    <div className="flex flex-wrap gap-3 mt-2">
                        {["Bare Shell", "Warm Shell", "Fully Furnished"].map(subType => (
                            <button key={subType} onClick={() => setFormData(p => ({ ...p, commercialSubType: subType }))}
                                // UPDATED: Blue background for active button
                                className={`px-4 py-2 rounded-xl border text-sm font-medium transition-all ${formData.commercialSubType === subType ? "bg-blue-600 text-white border-blue-600 shadow-md" : "bg-white text-gray-600 border-gray-300 hover:bg-blue-50 hover:border-blue-200"}`}>
                                {subType}
                            </button>
                        ))}
                    </div>
                </div>
            )}
        </div>
    );

    // Get current location using Geolocation API
    const getCurrentLocation = () => {
        if (!navigator.geolocation) {
            toast.error("Geolocation is not supported by your browser");
            return;
        }

        setIsLocating(true);

        // First try with high accuracy (GPS)
        const tryGetLocation = (highAccuracy, timeout) => {
            return new Promise((resolve, reject) => {
                navigator.geolocation.getCurrentPosition(resolve, reject, {
                    enableHighAccuracy: highAccuracy,
                    timeout: timeout,
                    maximumAge: 60000 // Allow cached position up to 1 minute old
                });
            });
        };

        // Try high accuracy first, then fall back to low accuracy
        tryGetLocation(true, 15000)
            .catch(() => {
                console.log("High accuracy failed, trying low accuracy...");
                return tryGetLocation(false, 20000);
            })
            .then((position) => {
                const { latitude, longitude } = position.coords;
                setMapPosition([latitude, longitude]);
                setFormData(prev => ({
                    ...prev,
                    latitude: latitude.toFixed(6),
                    longitude: longitude.toFixed(6)
                }));
                setIsLocating(false);
                toast.success("Location detected successfully!");

                // Reverse geocode to get address details
                reverseGeocode(latitude, longitude);
            })
            .catch((error) => {
                setIsLocating(false);
                console.error("Geolocation error:", error);
                switch (error.code) {
                    case 1: // PERMISSION_DENIED
                        toast.error("Location permission denied. Please enable it in your browser settings.");
                        break;
                    case 2: // POSITION_UNAVAILABLE
                        toast.error("Location unavailable. Please check your GPS/network settings.");
                        break;
                    case 3: // TIMEOUT
                        toast.error("Location request timed out. Please try again or enter location manually.");
                        break;
                    default:
                        toast.error("Could not get your location. Please enter it manually.");
                }
            });
    };

    // Reverse geocode to get address from coordinates
    const reverseGeocode = async (lat, lng) => {
        try {
            const response = await axios.get(
                `https://nominatim.openstreetmap.org/reverse?format=json&lat=${lat}&lon=${lng}&addressdetails=1&zoom=18`,
                { headers: { 'Accept-Language': 'en' } }
            );
            if (response.data && response.data.address) {
                const addr = response.data.address;

                // Extract city (try multiple fields)
                const city = addr.city || addr.town || addr.village || addr.state_district || addr.county || '';

                // Extract locality/area
                const locality = addr.suburb || addr.neighbourhood || addr.hamlet || addr.residential || addr.quarter || '';

                // Extract landmark (nearby point of interest)
                const landmark = addr.amenity || addr.building || addr.shop || addr.tourism || addr.leisure || '';

                // Build a cleaner address line
                const addressParts = [];
                if (addr.house_number) addressParts.push(addr.house_number);
                if (addr.road || addr.street) addressParts.push(addr.road || addr.street);
                if (locality) addressParts.push(locality);
                if (city) addressParts.push(city);
                if (addr.state) addressParts.push(addr.state);
                if (addr.postcode) addressParts.push(addr.postcode);

                const formattedAddress = addressParts.length > 0
                    ? addressParts.join(', ')
                    : response.data.display_name;

                setFormData(prev => ({
                    ...prev,
                    city: city || prev.city,
                    locality: locality || prev.locality,
                    address: formattedAddress || prev.address,
                    landmark: landmark || prev.landmark
                }));

                toast.success("Address details filled from your location!");
            }
        } catch (error) {
            console.error("Reverse geocoding failed:", error);
            toast.error("Could not fetch address details. Please enter manually.");
        }
    };

    // Forward geocode when user types address/locality/city manually
    const forwardGeocode = async (query) => {
        if (!query || query.length < 3) return;
        try {
            const response = await axios.get("https://nominatim.openstreetmap.org/search", {
                params: { format: "json", q: query, addressdetails: 1, limit: 1 },
                headers: { "Accept-Language": "en" }
            });

            const best = response.data?.[0];
            if (!best) return;

            const lat = parseFloat(best.lat);
            const lon = parseFloat(best.lon);

            if (Number.isFinite(lat) && Number.isFinite(lon)) {
                const latFixed = lat.toFixed(6);
                const lonFixed = lon.toFixed(6);

                setFormData(prev => {
                    if (prev.latitude === latFixed && prev.longitude === lonFixed) return prev;
                    return { ...prev, latitude: latFixed, longitude: lonFixed };
                });

                setMapPosition([lat, lon]);
            }
        } catch (error) {
            console.error("Forward geocoding failed:", error);
        }
    };

    // Search locations using local JSON data
    const searchLocations = (query, fieldType) => {
        setActiveLocationField(fieldType);
        setShowSuggestions(true);

        const suggestions = [];
        const searchTerm = (query || '').toLowerCase().trim();

        if (fieldType === 'city') {
            // Search cities
            locationData.cities.forEach(city => {
                if (!searchTerm || city.name.toLowerCase().includes(searchTerm)) {
                    suggestions.push({
                        type: 'city',
                        city: city.name,
                        locality: '',
                        project: '',
                        display_name: city.name,
                        shortName: city.name
                    });
                }
            });
        } else if (fieldType === 'locality') {
            // Search areas/localities within selected city or all cities
            const selectedCity = formData.city?.toLowerCase();

            locationData.cities.forEach(city => {
                // If city is selected, only search within that city
                if (selectedCity && city.name.toLowerCase() !== selectedCity) return;

                city.areas.forEach(area => {
                    if (!searchTerm || area.name.toLowerCase().includes(searchTerm)) {
                        suggestions.push({
                            type: 'locality',
                            city: city.name,
                            locality: area.name,
                            project: '',
                            display_name: `${area.name}, ${city.name}`,
                            shortName: `${area.name}, ${city.name}`,
                            projects: area.projects
                        });
                    }
                });
            });
        } else if (fieldType === 'address' || fieldType === 'project') {
            // Search ALL - cities, areas, and projects for comprehensive suggestions
            const selectedCity = formData.city?.toLowerCase();
            const selectedLocality = formData.locality?.toLowerCase();

            locationData.cities.forEach(city => {
                // If no city selected, also show matching cities
                if (!selectedCity && (!searchTerm || city.name.toLowerCase().includes(searchTerm))) {
                    suggestions.push({
                        type: 'city',
                        city: city.name,
                        locality: '',
                        project: '',
                        display_name: city.name,
                        shortName: city.name
                    });
                }

                if (selectedCity && city.name.toLowerCase() !== selectedCity) return;

                city.areas.forEach(area => {
                    // If no locality selected, also show matching areas
                    if (!selectedLocality && (!searchTerm || area.name.toLowerCase().includes(searchTerm))) {
                        suggestions.push({
                            type: 'locality',
                            city: city.name,
                            locality: area.name,
                            project: '',
                            display_name: `${area.name}, ${city.name}`,
                            shortName: `${area.name}, ${city.name}`
                        });
                    }

                    if (selectedLocality && area.name.toLowerCase() !== selectedLocality) return;

                    // Always search projects
                    area.projects.forEach(project => {
                        if (!searchTerm || project.toLowerCase().includes(searchTerm)) {
                            suggestions.push({
                                type: 'project',
                                city: city.name,
                                locality: area.name,
                                project: project,
                                display_name: `${project}, ${area.name}, ${city.name}`,
                                shortName: `${project}, ${area.name}`
                            });
                        }
                    });
                });
            });
        }

        // Limit suggestions
        setLocationSuggestions(suggestions.slice(0, 15));
        setShowSuggestions(suggestions.length > 0);
    };

    // Get a shorter display name for suggestions
    const getShortDisplayName = (item) => {
        const parts = [];
        const addr = item.address;

        if (addr?.suburb || addr?.neighbourhood) parts.push(addr.suburb || addr.neighbourhood);
        if (addr?.city || addr?.town || addr?.village) parts.push(addr.city || addr.town || addr.village);
        if (addr?.state) parts.push(addr.state);

        return parts.length > 0 ? parts.join(', ') : item.display_name?.split(',').slice(0, 3).join(',');
    };

    // Handle location input change
    const handleLocationInputChange = (e, fieldType) => {
        const { name, value } = e.target;
        setFormData(prev => ({ ...prev, [name]: value }));
        setActiveLocationField(fieldType);

        // Clear previous timeout
        if (searchTimeoutRef.current) {
            clearTimeout(searchTimeoutRef.current);
        }

        // Debounce the search - search immediately for local data
        searchTimeoutRef.current = setTimeout(() => {
            searchLocations(value, fieldType);
        }, 100);
    };

    // Handle input focus - show suggestions immediately on focus
    const handleLocationFocus = (fieldType, value) => {
        setActiveLocationField(fieldType);
        // Show suggestions immediately when focused, even without typing
        searchLocations(value || '', fieldType);
    };

    // Handle input blur - delay to allow click on suggestions
    const handleLocationBlur = () => {
        setTimeout(() => {
            setShowSuggestions(false);
        }, 200);
    };

    // Handle suggestion selection
    const handleSuggestionSelect = (suggestion) => {
        const updates = {};

        // Update fields based on suggestion type and active field
        if (suggestion.type === 'city' || activeLocationField === 'city') {
            updates.city = suggestion.city;
            // Clear locality when city changes
            if (formData.city !== suggestion.city) {
                updates.locality = '';
                updates.address = '';
            }
        }

        if (suggestion.type === 'locality' || activeLocationField === 'locality') {
            updates.locality = suggestion.locality;
            if (suggestion.city) updates.city = suggestion.city;
        }

        if (suggestion.type === 'project' || activeLocationField === 'address') {
            updates.address = suggestion.project || suggestion.display_name;
            if (suggestion.city) updates.city = suggestion.city;
            if (suggestion.locality) updates.locality = suggestion.locality;
        }

        setFormData(prev => ({ ...prev, ...updates }));
        setLocationSuggestions([]);
        setShowSuggestions(false);
        setActiveLocationField(null);
    };

    // Debounce forward geocoding as user types address/locality/city
    useEffect(() => {
        const query = [formData.address, formData.locality, formData.city]
            .filter(Boolean)
            .join(", ");

        if (geocodeTimeoutRef.current) clearTimeout(geocodeTimeoutRef.current);

        if (!query || query.length < 3) return;

        geocodeTimeoutRef.current = setTimeout(() => {
            forwardGeocode(query);
        }, 800);

        return () => {
            if (geocodeTimeoutRef.current) clearTimeout(geocodeTimeoutRef.current);
        };
    }, [formData.address, formData.locality, formData.city]);

    // Close suggestions when clicking outside
    useEffect(() => {
        const handleClickOutside = (event) => {
            if (suggestionsRef.current && !suggestionsRef.current.contains(event.target)) {
                setShowSuggestions(false);
            }
        };

        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const renderStep2 = () => (
        <div className="space-y-6">
            <div className="text-center">
                <h2 className="text-3xl font-bold text-gray-900">Location</h2>
                <p className="text-gray-500 mt-2">Accurate location increases trust and discoverability.</p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* City Field with Autocomplete */}
                <div className="relative">
                    <label className={labelStyle}>City</label>
                    <div className="relative">
                        <input
                            name="city"
                            value={formData.city}
                            onChange={(e) => handleLocationInputChange(e, 'city')}
                            onFocus={() => handleLocationFocus('city', formData.city)}
                            onBlur={handleLocationBlur}
                            placeholder="Click to select city..."
                            className={inputStyle}
                            autoComplete="off"
                        />
                    </div>
                    {/* City Suggestions Dropdown */}
                    {showSuggestions && activeLocationField === 'city' && locationSuggestions.length > 0 && (
                        <div ref={suggestionsRef} className="absolute z-50 w-full mt-1 bg-white border border-gray-200 rounded-xl shadow-lg max-h-60 overflow-y-auto">
                            {locationSuggestions.map((suggestion, index) => (
                                <div
                                    key={index}
                                    onMouseDown={(e) => e.preventDefault()}
                                    onClick={() => handleSuggestionSelect(suggestion)}
                                    className="px-4 py-3 hover:bg-blue-50 cursor-pointer border-b border-gray-100 last:border-b-0 transition-colors"
                                >
                                    <div className="flex items-center gap-2">
                                        <MapPin size={16} className="text-blue-600 flex-shrink-0" />
                                        <span className="font-medium text-gray-900 text-sm">{suggestion.city}</span>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>

                {/* Locality Field with Autocomplete */}
                <div className="relative">
                    <label className={labelStyle}>Locality / Area</label>
                    <div className="relative">
                        <input
                            name="locality"
                            value={formData.locality}
                            onChange={(e) => handleLocationInputChange(e, 'locality')}
                            onFocus={() => handleLocationFocus('locality', formData.locality)}
                            onBlur={handleLocationBlur}
                            placeholder={formData.city ? `Select area in ${formData.city}...` : "Select city first..."}
                            className={inputStyle}
                            autoComplete="off"
                        />
                    </div>
                    {/* Locality Suggestions Dropdown */}
                    {showSuggestions && activeLocationField === 'locality' && locationSuggestions.length > 0 && (
                        <div ref={suggestionsRef} className="absolute z-50 w-full mt-1 bg-white border border-gray-200 rounded-xl shadow-lg max-h-60 overflow-y-auto">
                            {locationSuggestions.map((suggestion, index) => (
                                <div
                                    key={index}
                                    onMouseDown={(e) => e.preventDefault()}
                                    onClick={() => handleSuggestionSelect(suggestion)}
                                    className="px-4 py-3 hover:bg-blue-50 cursor-pointer border-b border-gray-100 last:border-b-0 transition-colors"
                                >
                                    <div className="flex items-center gap-2">
                                        <Building2 size={16} className="text-green-600 flex-shrink-0" />
                                        <div>
                                            <span className="font-medium text-gray-900 text-sm">{suggestion.locality}</span>
                                            {suggestion.city && <span className="text-xs text-gray-500 ml-1">({suggestion.city})</span>}
                                        </div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>

            {/* Project/Society Name Field with Autocomplete */}
            <div className="relative z-40">
                <label className={labelStyle}>Project / Society Name</label>
                <div className="relative">
                    <input
                        name="address"
                        value={formData.address}
                        onChange={(e) => handleLocationInputChange(e, 'address')}
                        onFocus={() => handleLocationFocus('address', formData.address)}
                        onBlur={handleLocationBlur}
                        placeholder="Search city, area or project name..."
                        className={inputStyle}
                        autoComplete="off"
                    />
                </div>
                {/* Project Suggestions Dropdown */}
                {showSuggestions && activeLocationField === 'address' && locationSuggestions.length > 0 && (
                    <div ref={suggestionsRef} className="absolute z-[100] w-full mt-1 bg-white border border-gray-200 rounded-xl shadow-2xl max-h-64 overflow-y-auto">
                        {locationSuggestions.map((suggestion, index) => (
                            <div
                                key={index}
                                onMouseDown={(e) => e.preventDefault()}
                                onClick={() => handleSuggestionSelect(suggestion)}
                                className="px-4 py-2.5 hover:bg-blue-50 cursor-pointer border-b border-gray-100 last:border-b-0 transition-colors"
                            >
                                <div className="flex items-center gap-3">
                                    {suggestion.type === 'city' && (
                                        <MapPin size={16} className="text-blue-600 flex-shrink-0" />
                                    )}
                                    {suggestion.type === 'locality' && (
                                        <Building2 size={16} className="text-green-600 flex-shrink-0" />
                                    )}
                                    {suggestion.type === 'project' && (
                                        <Home size={16} className="text-orange-600 flex-shrink-0" />
                                    )}
                                    <div className="flex-1 min-w-0">
                                        <div className="font-medium text-gray-900 text-sm truncate">
                                            {suggestion.type === 'city' && suggestion.city}
                                            {suggestion.type === 'locality' && suggestion.locality}
                                            {suggestion.type === 'project' && suggestion.project}
                                        </div>
                                        <div className="text-xs text-gray-500 truncate">
                                            {suggestion.type === 'city' && 'City'}
                                            {suggestion.type === 'locality' && `Area in ${suggestion.city}`}
                                            {suggestion.type === 'project' && `${suggestion.locality}, ${suggestion.city}`}
                                        </div>
                                    </div>
                                    <span className={`text-xs px-2 py-0.5 rounded-full flex-shrink-0 ${suggestion.type === 'city' ? 'bg-blue-100 text-blue-700' :
                                        suggestion.type === 'locality' ? 'bg-green-100 text-green-700' :
                                            'bg-orange-100 text-orange-700'
                                        }`}>
                                        {suggestion.type === 'city' ? 'City' : suggestion.type === 'locality' ? 'Area' : 'Project'}
                                    </span>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <label className={labelStyle}>Landmark</label>
                    <input name="landmark" value={formData.landmark} onChange={handleChange} placeholder="e.g. Near City Mall" className={inputStyle} />
                </div>
                <div>
                    <label className={labelStyle}>Nearby (tags)</label>
                    <input name="nearby" value={(formData.nearby || []).join(", ")} onChange={(e) => setFormData(p => ({ ...p, nearby: e.target.value.split(",").map(s => s.trim()).filter(Boolean) }))} placeholder="Metro, School, Hospital (comma separated)" className={inputStyle} />
                </div>
            </div>

            {/* Leaflet Map Section */}
            <div className={`${cardStyle} relative z-0`}>
                <div className="flex items-center justify-between mb-4">
                    <h3 className="font-bold text-gray-900 flex items-center gap-2">
                        <MapPin size={18} className="text-blue-600" />
                        Pin Property Location on Map
                    </h3>
                    <button
                        type="button"
                        onClick={getCurrentLocation}
                        disabled={isLocating}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        <Navigation size={16} className={isLocating ? "animate-pulse" : ""} />
                        {isLocating ? "Detecting..." : "Use My Location"}
                    </button>
                </div>

                <p className="text-sm text-gray-500 mb-3">Click on the map to set your property's exact location, or use the "Use My Location" button.</p>

                <div className="rounded-xl overflow-hidden border border-gray-200 relative z-0" style={{ height: "350px" }}>
                    <MapContainer
                        center={mapPosition || defaultCenter}
                        zoom={mapPosition ? 15 : 5}
                        style={{ height: "100%", width: "100%" }}
                        scrollWheelZoom={true}
                    >
                        <TileLayer
                            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
                            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
                        />
                        <LocationMarker
                            position={mapPosition}
                            setPosition={setMapPosition}
                            setFormData={setFormData}
                        />
                        {mapPosition && <RecenterMap position={mapPosition} />}
                    </MapContainer>
                </div>

                {/* Coordinates Display (always editable) */}
                <div className="mt-4 grid grid-cols-2 gap-4">
                    <div>
                        <label className={labelStyle}>Latitude</label>
                        <input
                            name="latitude"
                            value={formData.latitude}
                            onChange={(e) => {
                                const lat = parseFloat(e.target.value);
                                handleChange(e);
                                if (!isNaN(lat) && formData.longitude) {
                                    setMapPosition([lat, parseFloat(formData.longitude)]);
                                }
                            }}
                            placeholder="e.g. 19.0760"
                            className={inputStyle}
                        />
                    </div>
                    <div>
                        <label className={labelStyle}>Longitude</label>
                        <input
                            name="longitude"
                            value={formData.longitude}
                            onChange={(e) => {
                                const lng = parseFloat(e.target.value);
                                handleChange(e);
                                if (!isNaN(lng) && formData.latitude) {
                                    setMapPosition([parseFloat(formData.latitude), lng]);
                                }
                            }}
                            placeholder="e.g. 72.8777"
                            className={inputStyle}
                        />
                    </div>
                </div>

                {mapPosition && (
                    <div className="mt-3 flex items-center gap-2 text-sm text-green-600 bg-green-50 px-3 py-2 rounded-lg border border-green-200">
                        <Check size={16} />
                        <span>Location pinned: {mapPosition[0].toFixed(4)}, {mapPosition[1].toFixed(4)}</span>
                    </div>
                )}
            </div>
        </div>
    );

    const renderStep3 = () => {
        const isRent = formData.listingType === "Rent";
        const isSell = formData.listingType === "Sell";

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Pricing & Area</h2>
                    <p className="text-gray-500 mt-2">Provide accurate area & pricing to attract quality leads.</p>
                </div>

                <div className={cardStyle}>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className={labelStyle}>Listing Type</label>
                            <div className="flex gap-2 mt-2">
                                {["Rent", "Sell"].map(t => (
                                    <button key={t} onClick={() => setFormData(p => ({ ...p, listingType: t }))}
                                        // UPDATED: Blue theme for listing type
                                        className={`px-4 py-2 rounded-xl text-sm font-medium ${formData.listingType === t ? "bg-blue-600 text-white" : "bg-white text-gray-600 border border-gray-300 hover:bg-gray-50"}`}>{t}</button>
                                ))}
                            </div>
                        </div>
                        <div>
                            <label className={labelStyle}>Expected {isRent ? "Monthly Rent" : "Sale Price"}</label>
                            <div className="relative">
                                <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">₹</div>
                                <input name="expectedPrice" value={formData.expectedPrice} onChange={handleChange} type="number" className={`${inputStyle} pl-10`} placeholder="0" />
                            </div>
                        </div>
                    </div>

                    {isRent && (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                            <div>
                                <label className={labelStyle}>Security Deposit</label>
                                <div className="relative">
                                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">₹</div>
                                    <input name="expectedDeposit" value={formData.expectedDeposit} onChange={handleChange} type="number" className={`${inputStyle} pl-10`} placeholder="0" />
                                </div>
                            </div>
                            <div className="md:col-span-2">
                                <label className={labelStyle}>Monthly Maintenance</label>
                                <div className="flex items-center gap-3 mt-2">
                                    <label className="flex items-center gap-2 cursor-pointer">
                                        {/* UPDATED: Blue checkbox */}
                                        <input type="checkbox" checked={formData.maintenanceIncluded} onChange={(e) => setFormData(p => ({ ...p, maintenanceIncluded: e.target.checked, maintenance: e.target.checked ? "" : p.maintenance }))} className="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-600" />
                                        <span className="text-sm text-gray-700">Included in rent</span>
                                    </label>
                                    {!formData.maintenanceIncluded && (
                                        <div className="relative flex-1">
                                            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-gray-500">₹</div>
                                            <input name="maintenance" value={formData.maintenance} onChange={handleChange} type="number" className={`${inputStyle} pl-8 py-2`} placeholder="Monthly amount" />
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>
                    )}

                    {isSell && (
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                            <div>
                                <label className={labelStyle}>Booking Amount</label>
                                <div className="relative">
                                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">₹</div>
                                    <input name="bookingAmount" value={formData.bookingAmount} onChange={handleChange} type="number" className={`${inputStyle} pl-10`} placeholder="0" />
                                </div>
                            </div>
                            <div>
                                <label className={labelStyle}>Monthly Maintenance</label>
                                <div className="relative">
                                    <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">₹</div>
                                    <input name="maintenance" value={formData.maintenance} onChange={handleChange} type="number" className={`${inputStyle} pl-10`} placeholder="Society maintenance" />
                                </div>
                            </div>
                            <div>
                                <label className={labelStyle}>GST Applicable?</label>
                                <select name="gstApplicable" value={formData.gstApplicable ? "Yes" : "No"} onChange={(e) => setFormData(p => ({ ...p, gstApplicable: e.target.value === "Yes" }))} className={inputStyle}>
                                    <option>No</option>
                                    <option>Yes</option>
                                </select>
                            </div>
                        </div>
                    )}

                    <div className="flex items-center gap-4 mt-4">
                        <label className={labelStyle}>Price Negotiable?</label>
                        <div className="flex gap-2">
                            {["No", "Yes"].map(opt => (
                                <button key={opt} type="button" onClick={() => setFormData(p => ({ ...p, priceNegotiable: opt === "Yes" }))}
                                    // UPDATED: Blue theme for negotiation toggle
                                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${formData.priceNegotiable === (opt === "Yes") ? "bg-blue-600 text-white shadow-md" : "bg-white text-gray-600 border border-gray-300 hover:bg-gray-50"}`}>
                                    {opt}
                                </button>
                            ))}
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label className={labelStyle}>{isResidential ? "Built-up Area" : "Built-up / Carpet Area"}</label>
                        <div className="relative">
                            <input name="builtUpArea" value={formData.builtUpArea} onChange={handleChange} type="number" className={inputStyle} placeholder="eg. 1200" />
                            <div className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-500 text-sm">sq.ft</div>
                        </div>
                    </div>
                    <div>
                        <label className={labelStyle}>Carpet Area</label>
                        <div className="relative">
                            <input name="carpetArea" value={formData.carpetArea} onChange={handleChange} type="number" className={inputStyle} placeholder="eg. 900" />
                            <div className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-500 text-sm">sq.ft</div>
                        </div>
                    </div>
                    <div>
                        <label className={labelStyle}>Super Built-up (optional)</label>
                        <div className="relative">
                            <input name="superBuiltUpArea" value={formData.superBuiltUpArea} onChange={handleChange} type="number" className={inputStyle} placeholder="eg. 1400" />
                            <div className="absolute inset-y-0 right-0 pr-4 flex items-center text-gray-500 text-sm">sq.ft</div>
                        </div>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                    {isResidential && (
                        <>
                            <div>
                                <label className={labelStyle}>Floor No</label>
                                <input name="floorNo" value={formData.floorNo} onChange={handleChange} type="number" min="0" className={inputStyle} placeholder="eg. 3" />
                            </div>
                            <div>
                                <label className={labelStyle}>Total Floors</label>
                                <input name="totalFloors" value={formData.totalFloors} onChange={handleChange} type="number" min="1" className={inputStyle} placeholder="eg. 10" />
                            </div>
                            <div>
                                <label className={labelStyle}>Facing</label>
                                <select name="facing" value={formData.facing} onChange={handleChange} className={inputStyle}>
                                    <option value="">Select</option>
                                    {["East", "West", "North", "South", "North-East", "North-West", "South-East", "South-West"].map(d => <option key={d}>{d}</option>)}
                                </select>
                            </div>
                        </>
                    )}
                    {isCommercial && (
                        <>
                            <div>
                                <label className={labelStyle}>Washrooms</label>
                                <input name="washrooms" value={formData.washrooms} onChange={handleChange} type="number" min="0" className={inputStyle} />
                            </div>
                            <div>
                                <label className={labelStyle}>Floor Height (ft)</label>
                                <input name="floorHeight" value={formData.floorHeight} onChange={handleChange} type="number" className={inputStyle} />
                            </div>
                            <div>
                                <label className={labelStyle}>Power Load (kW)</label>
                                <input name="powerLoad" value={formData.powerLoad} onChange={handleChange} type="number" className={inputStyle} />
                            </div>
                        </>
                    )}
                </div>
            </div>
        );
    };

    const renderStep4 = () => {
        const isRent = formData.listingType === "Rent";
        const isSell = formData.listingType === "Sell";

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Property Details</h2>
                    <p className="text-gray-500 mt-2">Add specific features to make your listing stand out.</p>
                </div>

                {isResidential && (
                    <>
                        <div className={cardStyle}>
                            <h3 className="font-bold mb-4 flex items-center gap-2 text-gray-900">
                                {/* UPDATED: Blue icon */}
                                <Home size={18} className="text-blue-600" />
                                Residential Configuration
                            </h3>
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                <div><label className={labelStyle}>Bedrooms</label><input name="bedrooms" value={formData.bedrooms} onChange={handleChange} type="number" className={inputStyle} /></div>
                                <div><label className={labelStyle}>Bathrooms</label><input name="bathrooms" value={formData.bathrooms} onChange={handleChange} type="number" className={inputStyle} /></div>
                                <div><label className={labelStyle}>Balconies</label><input name="balconies" value={formData.balconies} onChange={handleChange} type="number" className={inputStyle} /></div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                                <div>
                                    <label className={labelStyle}>Furnishing</label>
                                    <select name="furnishing" value={formData.furnishing} onChange={handleChange} className={inputStyle}>
                                        <option>Unfurnished</option>
                                        <option>Semi-Furnished</option>
                                        <option>Fully Furnished</option>
                                    </select>
                                </div>
                                <div>
                                    <label className={labelStyle}>Property Age</label>
                                    <select name="propertyAge" value={formData.propertyAge} onChange={handleChange} className={inputStyle}>
                                        <option>New</option>
                                        <option>1-5 Years</option>
                                        <option>5-10 Years</option>
                                        <option>10+ Years</option>
                                    </select>
                                </div>
                            </div>

                            {isSell && (
                                <div className="mt-4">
                                    <label className={labelStyle}>Construction Status</label>
                                    <div className="flex flex-wrap gap-2 mt-2">
                                        {["Ready to Move", "Under Construction", "New Launch"].map(status => (
                                            <button key={status} type="button" onClick={() => setFormData(p => ({ ...p, constructionStatus: status }))}
                                                // UPDATED: Blue theme for status toggle
                                                className={`px-4 py-2 rounded-xl text-sm transition-all ${formData.constructionStatus === status ? "bg-blue-600 text-white shadow-md" : "bg-white text-gray-600 border border-gray-300 hover:bg-gray-50"}`}>
                                                {status}
                                            </button>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mt-4 text-gray-700">
                                {["servantRoom", "poojaRoom", "studyRoom", "storeRoom"].map(room => (
                                    <label key={room} className="flex items-center gap-2 cursor-pointer">
                                        {/* UPDATED: Blue checkbox */}
                                        <input type="checkbox" name={room} checked={formData[room]} onChange={handleChange} className="w-4 h-4 text-blue-600 rounded border-gray-300 focus:ring-blue-600" />
                                        <span className="text-sm capitalize">{room.replace(/([A-Z])/g, ' $1').trim()}</span>
                                    </label>
                                ))}
                            </div>
                        </div>

                        {isRent && (
                            <div className={cardStyle}>
                                <h3 className="font-bold mb-4 flex items-center gap-2 text-gray-900"><Users size={18} className="text-blue-600" /> Tenant Preferences</h3>
                                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                                    <div>
                                        <label className={labelStyle}>Preferred Tenants</label>
                                        <select name="allowedFor" value={formData.allowedFor} onChange={handleChange} className={inputStyle}>
                                            <option value="Family">Family</option>
                                            <option value="Bachelor Male">Bachelor Male</option>
                                            <option value="Bachelor Female">Bachelor Female</option>
                                            <option value="Company Lease">Company Lease</option>
                                            <option value="Any">Any</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className={labelStyle}>Pet Friendly?</label>
                                        <select name="petFriendly" value={formData.petFriendly} onChange={handleChange} className={inputStyle}>
                                            <option value="No">No</option>
                                            <option value="Yes">Yes</option>
                                        </select>
                                    </div>
                                    <div>
                                        <label className={labelStyle}>Available From</label>
                                        <input type="date" name="availableFrom" value={formData.availableFrom} onChange={handleChange} min={new Date().toISOString().split('T')[0]} className={inputStyle} />
                                    </div>
                                </div>
                            </div>
                        )}
                    </>
                )}

                {isCommercial && commercialConfig && (
                    <div className={cardStyle}>
                        <h3 className="font-bold mb-4 flex items-center gap-2 text-gray-900">{commercialConfig.icon} {commercialConfig.label}</h3>
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                            {commercialConfig.fields.map(field => (
                                <div key={field}>
                                    <label className={labelStyle}>{field.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}</label>
                                    <input name={field} value={formData[field]} onChange={handleChange} type="number" className={inputStyle} />
                                </div>
                            ))}
                        </div>
                    </div>
                )}

                <div className={cardStyle}>
                    <h3 className="font-bold mb-4 text-gray-900">Parking & Amenities</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div><label className={labelStyle}>Parking (Covered)</label><input name="parkingCovered" value={formData.parkingCovered} onChange={handleChange} type="number" className={inputStyle} /></div>
                        <div><label className={labelStyle}>Parking (Open)</label><input name="parkingOpen" value={formData.parkingOpen} onChange={handleChange} type="number" className={inputStyle} /></div>
                    </div>

                    <div className="mt-4">
                        <label className="text-sm font-semibold text-gray-900 uppercase tracking-wider">Amenities</label>
                        <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3 mt-2">
                            {PROPERTY_CATEGORIES[formData.propertyCategory].amenities.map(am => (
                                // UPDATED: Blue theme for selected amenity
                                <div key={am} onClick={() => handleAmenityToggle(am)} className={`p-3 rounded-xl border cursor-pointer ${formData.selectedAmenities.includes(am) ? "bg-blue-50 border-blue-200 text-blue-700" : "bg-white border-gray-200 hover:bg-gray-50 text-gray-600"}`}>
                                    <div className="flex items-center gap-2">
                                        <div className={formData.selectedAmenities.includes(am) ? "text-blue-600" : "text-gray-400"}>{AMENITY_ICONS[am] || <Tag size={14} />}</div>
                                        <div className="text-sm">{am}</div>
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                </div>
            </div>
        );
    };

    const renderStep5 = () => {
        const categories = getImageCategories();
        const totalImages = getTotalCategorizedImages();

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Photos & Documents</h2>
                    <p className="text-gray-500 mt-2">Click on any category to add photos. All images are optional.</p>
                </div>

                <div className="flex justify-center">
                    <div className="bg-white border border-gray-200 px-4 py-2 rounded-full text-sm flex items-center gap-2 shadow-sm text-gray-700">
                        {/* UPDATED: Blue icon */}
                        <ImageIcon size={16} className="text-blue-600" />
                        <span>{totalImages} photos uploaded</span>
                    </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
                    {categories.map((category) => {
                        const catImages = categorizedImages[category.key] || { files: [], previews: [] };
                        const imageCount = catImages.files?.length || 0;
                        const isExpanded = expandedCategories.includes(category.key);
                        const hasImages = imageCount > 0;

                        return (
                            <div key={category.key} onClick={() => toggleCategory(category.key)}
                                // UPDATED: Blue theme for active selection
                                className={`rounded-xl p-3 border cursor-pointer transition-all ${isExpanded ? 'border-blue-500 ring-1 ring-blue-500 bg-blue-50' : hasImages ? 'border-green-500 bg-green-50' : 'border-gray-200 bg-white hover:bg-gray-50'}`}
                            >
                                <div className="flex items-center justify-between">
                                    <span className={`font-medium text-sm truncate ${isExpanded ? 'text-blue-700' : 'text-gray-700'}`}>{category.label}</span>
                                    <div className="flex items-center gap-1.5">
                                        {hasImages && <span className="bg-green-100 text-green-700 border border-green-200 text-xs px-1.5 py-0.5 rounded-full font-medium">{imageCount}</span>}
                                        {/* UPDATED: Blue icon color */}
                                        <Plus size={14} className={`transition-transform ${isExpanded ? 'rotate-45 text-blue-600' : 'text-gray-400'}`} />
                                    </div>
                                </div>
                            </div>
                        );
                    })}
                </div>

                {expandedCategories.length > 0 && (
                    <div className="space-y-4 mt-6">
                        {categories.filter(cat => expandedCategories.includes(cat.key)).map((category) => {
                            const catImages = categorizedImages[category.key] || { files: [], previews: [] };
                            const imageCount = catImages.files?.length || 0;

                            return (
                                <div key={category.key} className="rounded-2xl p-4 border border-gray-200 bg-white shadow-sm">
                                    <div className="flex items-center justify-between mb-3">
                                        <div className="flex items-center gap-2">
                                            <span className="text-gray-900 font-semibold">{category.label}</span>
                                            <span className="text-gray-400 text-xs">({imageCount}/{category.maxImages})</span>
                                        </div>
                                        <button onClick={(e) => { e.stopPropagation(); toggleCategory(category.key); }} className="text-gray-400 hover:text-gray-600 p-1"><X size={16} /></button>
                                    </div>

                                    {/* UPDATED: Blue hover effects for upload area */}
                                    <div className="border-2 border-dashed border-gray-300 rounded-xl p-6 text-center relative hover:border-blue-400 hover:bg-blue-50 transition-all cursor-pointer mb-3">
                                        <input type="file" multiple accept="image/*" onChange={(e) => handleCategorizedImageUpload(category.key, e)} className="absolute inset-0 w-full h-full opacity-0 cursor-pointer" disabled={imageCount >= category.maxImages} />
                                        <Upload size={24} className="mx-auto text-gray-400 mb-2" />
                                        <div className="text-gray-700 font-medium">{imageCount >= category.maxImages ? 'Maximum images reached' : 'Click to upload'}</div>
                                    </div>

                                    {catImages.previews?.length > 0 && (
                                        <div className="grid grid-cols-4 sm:grid-cols-5 gap-2">
                                            {catImages.previews.map((src, idx) => (
                                                <div key={idx} className="relative rounded-lg overflow-hidden aspect-square border border-gray-200">
                                                    <img src={src} className="w-full h-full object-cover" alt="preview" />
                                                    <button onClick={(e) => { e.stopPropagation(); removeCategorizedImage(category.key, idx); }} className="absolute top-1 right-1 bg-red-600 rounded-full p-1 shadow hover:bg-red-700"><X size={10} className="text-white" /></button>
                                                </div>
                                            ))}
                                        </div>
                                    )}
                                </div>
                            );
                        })}
                    </div>
                )}

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-gray-200">
                    <div>
                        <label className={labelStyle}>Video Walkthrough (optional)</label>
                        <input name="videoUrl" value={formData.videoUrl} onChange={handleChange} placeholder="YouTube / Google Drive link" className={inputStyle} />
                    </div>
                    <div>
                        <label className={labelStyle}>Upload Documents</label>
                        <input type="file" accept=".pdf" className={inputStyle} />
                    </div>
                </div>
            </div>
        );
    };

    const getFirstPreviewImage = () => {
        const categories = getImageCategories();
        for (const cat of categories) {
            if (categorizedImages[cat.key]?.previews?.length > 0) return categorizedImages[cat.key].previews[0];
        }
        return previewImages[0] || null;
    };

    const renderStep6 = () => {
        const firstImage = getFirstPreviewImage();
        const totalImages = getTotalCategorizedImages() + (images?.length || 0);

        return (
            <div className="space-y-6">
                <div className="text-center">
                    <h2 className="text-3xl font-bold text-gray-900">Review & Publish</h2>
                    <p className="text-gray-500 mt-2">Double-check everything — buyers prefer complete listings.</p>
                </div>

                <div className="max-w-3xl mx-auto bg-white rounded-2xl shadow-lg p-6 border border-gray-200">
                    <div className="h-56 bg-gray-100 rounded-2xl overflow-hidden relative mb-4 border border-gray-200">
                        {firstImage ? <img src={firstImage} className="w-full h-full object-cover" alt="Property Preview" /> : <div className="w-full h-full flex items-center justify-center text-gray-300"><ImageIcon size={48} /></div>}
                        {/* UPDATED: Blue theme badge */}
                        <div className="absolute top-4 left-4 bg-white text-blue-600 px-3 py-1 rounded-full text-xs font-bold shadow-md uppercase tracking-wide border border-blue-100">{formData.listingType}</div>
                        <div className="absolute bottom-4 right-4 bg-black/70 text-white px-3 py-1 rounded-full text-xs font-semibold backdrop-blur-sm">{totalImages} photos</div>
                    </div>

                    <div className="space-y-3">
                        <div className="flex justify-between items-start">
                            <div>
                                <h3 className="font-bold text-xl text-gray-900">{generateTitle()}</h3>
                                <p className="text-sm text-gray-500 flex items-center gap-1 mt-1"><MapPin size={14} /> {formData.locality}, {formData.city}</p>
                            </div>
                            <div className="text-right">
                                {/* UPDATED: Blue price text */}
                                <div className="font-bold text-2xl text-blue-600">₹ {formData.expectedPrice ? Number(formData.expectedPrice).toLocaleString() : "-"}</div>
                                <div className="text-xs text-gray-500">{formData.priceNegotiable ? "Negotiable" : "Fixed Price"}</div>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 py-4 border-t border-gray-100 mt-2">
                            <div><div className="text-xs text-gray-400 uppercase">Area</div><div className="font-semibold text-gray-800">{formData.builtUpArea || formData.carpetArea || "-"} sq.ft</div></div>
                            <div><div className="text-xs text-gray-400 uppercase">Furnishing</div><div className="font-semibold text-gray-800">{formData.furnishing}</div></div>
                            {isResidential && <div><div className="text-xs text-gray-400 uppercase">Config</div><div className="font-semibold text-gray-800">{formData.bedrooms || formData.bhkType || "-"}</div></div>}
                            <div><div className="text-xs text-gray-400 uppercase">Available</div><div className="font-semibold text-gray-800">{formData.availableFrom || "Immediate"}</div></div>
                        </div>

                        {formData.selectedAmenities.length > 0 && (
                            <div>
                                <div className="text-xs text-gray-400 uppercase mb-2">Amenities</div>
                                <div className="flex flex-wrap gap-2">
                                    {formData.selectedAmenities.map(a => <span key={a} className="bg-gray-100 text-gray-600 border border-gray-200 px-2 py-1 rounded text-xs">{a}</span>)}
                                </div>
                            </div>
                        )}

                        <div className="pt-2">
                            <div className="text-xs text-gray-400 uppercase">Description</div>
                            <div className="mt-1 text-sm text-gray-600 leading-relaxed bg-gray-50 p-3 rounded-lg border border-gray-100">{formData.description || generateShortDescription()}</div>
                        </div>

                        <div className="pt-4">
                            {/* UPDATED: Blue primary button */}
                            <button onClick={handleSubmit} disabled={isLoading} className="w-full bg-blue-600 hover:bg-blue-700 text-white py-4 rounded-xl font-bold flex items-center justify-center gap-2 transition-colors shadow-lg shadow-blue-200">
                                {isLoading ? "Publishing..." : <>Confirm & Publish <Check size={18} /></>}
                            </button>
                        </div>
                    </div>
                </div>

                <div className="max-w-3xl mx-auto text-xs sm:text-sm text-gray-500 flex flex-wrap items-center justify-between gap-2">
                    <p>
                        Want higher visibility or more active listings over time? Explore our owner Pricing & Plans.
                    </p>
                    <a
                        href="/pricing"
                        className="inline-flex items-center px-3 py-1.5 rounded-full border border-blue-200 text-blue-700 font-semibold hover:bg-blue-50 text-[11px] sm:text-xs"
                    >
                        View Pricing & Plans
                        <span className="ml-1 text-[13px]">→</span>
                    </a>
                </div>
            </div>
        );
    };

    if (!isAuthorized) return <div className="min-h-screen bg-gray-50 flex items-center justify-center"><EmailVerificationModal isOpen={showVerificationModal} onClose={() => navigate("/")} user={user} onVerified={handleVerificationSuccess} /></div>;

    return (
        <div className="min-h-screen bg-gray-50 flex flex-col md:flex-row font-sans text-gray-900">
            {/* Sidebar (Kept Red as per previous instruction/layout, but main content is now Blue theme) */}
            <aside className="hidden md:flex flex-col w-80 bg-red-600 h-[calc(100vh-5rem)] sticky top-20 p-6 pt-8 z-20 shadow-xl overflow-y-auto">
                <nav className="space-y-2 flex-1">
                    {STEPS.map(step => {
                        const isActive = currentStep === step.id;
                        const isCompleted = currentStep > step.id;
                        return (
                            <div key={step.id} className={`group flex items-center gap-4 p-4 rounded-2xl transition-all duration-300 relative overflow-hidden ${isActive ? "bg-white text-red-600 shadow-md" : "text-red-100 hover:bg-white/10 hover:text-white"}`}>
                                <div className={`relative z-10 transition-colors ${isActive ? "text-red-600" : isCompleted ? "text-white" : "text-red-200 group-hover:text-white"}`}>
                                    {isCompleted ? <Check size={18} strokeWidth={3} /> : step.icon}
                                </div>
                                <div className="flex flex-col relative z-10">
                                    <span className={`font-bold text-sm ${isActive ? "text-red-600" : "text-white"}`}>{step.label}</span>
                                    <span className={`text-xs font-medium ${isActive ? "text-red-400" : "text-red-200/80"}`}>{step.description}</span>
                                </div>
                                {isActive && <motion.div layoutId="activeStep" className="absolute inset-0 bg-white rounded-2xl" transition={{ type: "spring", stiffness: 300, damping: 30 }} />}
                            </div>
                        );
                    })}
                </nav>
                <div className="mt-auto pt-8 border-t border-white/20">
                    <div className="bg-white/10 backdrop-blur rounded-2xl p-5 text-white">
                        <h4 className="font-bold">Seller Assistance</h4>
                        <p className="text-xs text-red-100 mt-2">Need help? Toggle tips in the form fields.</p>
                        <button onClick={() => setFormData(p => ({ ...p, showHelpTips: !p.showHelpTips }))} className="mt-3 w-full bg-white/20 hover:bg-white/30 px-3 py-2 rounded-lg text-xs transition-colors">Toggle Tips</button>
                    </div>
                </div>
            </aside>

            {/* Mobile Header */}
            <div className="md:hidden bg-red-600 p-4 sticky top-20 z-30 shadow-md flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <div className="bg-white/20 p-1.5 rounded-lg"><Home className="text-white" size={16} /></div>
                    <span className="font-bold text-white">Step {currentStep}</span>
                </div>
                <div className="flex gap-1.5">
                    {STEPS.map(s => <div key={s.id} className={`h-1.5 w-8 rounded-full ${s.id <= currentStep ? "bg-white" : "bg-red-400/50"}`} />)}
                </div>
            </div>

            <main className="flex-1 p-6 md:p-12 max-w-5xl mx-auto w-full flex flex-col h-full">
                <div className="flex-1 mb-20 md:mb-0 relative">
                    <AnimatePresence mode="wait" custom={direction}>
                        <motion.div key={currentStep} custom={direction} variants={variants} initial="enter" animate="center" exit="exit" transition={{ x: { type: "spring", stiffness: 300, damping: 30 }, opacity: { duration: 0.2 } }} className="min-h-[520px]">
                            {currentStep === 1 && renderStep1()}
                            {currentStep === 2 && renderStep2()}
                            {currentStep === 3 && renderStep3()}
                            {currentStep === 4 && renderStep4()}
                            {currentStep === 5 && renderStep5()}
                            {currentStep === 6 && renderStep6()}
                        </motion.div>
                    </AnimatePresence>

                    <div className="flex justify-between items-center mt-12 pt-8 border-t border-gray-200">
                        <button onClick={handlePrev} disabled={currentStep === 1} className={`flex items-center gap-2 px-8 py-3 rounded-xl font-bold transition-all ${currentStep === 1 ? "text-gray-300 cursor-not-allowed" : "text-gray-600 hover:bg-gray-100"}`}>
                            <ChevronLeft size={18} /> Back
                        </button>

                        <div className="flex items-center gap-3">
                            {currentStep < 6 && (
                                // UPDATED: Blue primary button
                                <button onClick={handleNext} className="bg-blue-600 text-white px-10 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg shadow-blue-200 flex items-center gap-2">
                                    Next Step <ArrowRight size={18} />
                                </button>
                            )}
                            {currentStep === 6 && (
                                // UPDATED: Blue primary button
                                <button onClick={handleSubmit} disabled={isLoading} className="bg-blue-600 text-white px-10 py-3 rounded-xl font-bold hover:bg-blue-700 transition-all shadow-lg flex items-center gap-2">
                                    {isLoading ? "Publishing..." : <>Confirm & Publish <Check size={18} /></>}
                                </button>
                            )}
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
}