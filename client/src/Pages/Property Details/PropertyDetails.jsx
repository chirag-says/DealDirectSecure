import React, { useEffect, useState } from "react";
import { useLocation, useParams, useNavigate } from "react-router-dom";
import {
  HeartIcon,
  ShareIcon,
  MapPinIcon,
  BuildingStorefrontIcon,
  BanknotesIcon,
  HomeIcon,
  Square2StackIcon,
  TagIcon,
  CheckCircleIcon,
  ShieldCheckIcon,
  ChatBubbleLeftRightIcon,
} from "@heroicons/react/24/outline";
import { FlagIcon } from "@heroicons/react/24/outline";
import { HeartIcon as HeartIconSolid } from "@heroicons/react/24/solid";
import { toast } from "react-toastify";
import { useChat } from "../../context/ChatContext";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";

const API_BASE = import.meta.env.VITE_API_BASE;

// --- Design tokens (3‑color core + neutrals) ---
const BRAND_BLUE = "#0f4fb5";      // primary blue
const BRAND_BLUE_DARK = "#0c3f8f";
const BRAND_RED = "#e11d48";       // accent red
const BRAND_RED_DARK = "#be123c";
const BRAND_BG_SOFT = "bg-slate-50"; // subtle neutral background

// --- Reusable UI ---

const Card = ({ title, icon, children, sticky }) => (
  <div
    className={`bg-white/95 border border-slate-200/80 rounded-3xl shadow-[0_18px_45px_rgba(15,32,70,0.08)] ${sticky ? "sticky top-24" : ""
      }`}
  >
    <div className="p-6 sm:p-7 lg:p-8">
      <div className="flex items-center gap-3 mb-6">
        <div className="inline-flex h-9 w-9 items-center justify-center rounded-2xl bg-[#0f4fb5]/10 text-[#0f4fb5]">
          {icon}
        </div>
        <h2 className="text-xl sm:text-2xl font-semibold tracking-tight text-slate-900">
          {title}
        </h2>
      </div>
      {children}
    </div>
  </div>
);

const InfoChip = ({ label, value }) => (
  <div className="flex flex-col gap-1">
    <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-slate-500">
      {label}
    </span>
    <span className="text-sm font-semibold text-slate-900">{value}</span>
  </div>
);

const PrimaryButton = ({
  onClick,
  disabled,
  loading,
  label,
  icon,
  tone = "brand",
}) => {
  const tones = {
    brand: "bg-[#0f4fb5] hover:bg-[#0c3f8f] text-white",
    sky: "bg-sky-600 hover:bg-sky-700 text-white",
    emerald: "bg-emerald-600 hover:bg-emerald-700 text-white",
    red: "bg-[#e11d48] hover:bg-[#be123c] text-white",
    subtle:
      "bg-slate-50 hover:bg-slate-100 text-slate-800 border border-slate-200",
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`w-full inline-flex items-center justify-center gap-2 px-5 py-3.5 rounded-2xl font-semibold text-sm tracking-wide shadow-[0_10px_30px_rgba(15,32,70,0.18)] transition-transform duration-150 active:scale-[0.97] disabled:opacity-70 disabled:cursor-not-allowed ${tones[tone]}`}
    >
      {loading && (
        <svg
          className="animate-spin h-5 w-5 text-white"
          xmlns="http://www.w3.org/2000/svg"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
          ></circle>
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          ></path>
        </svg>
      )}
      {icon}
      <span>{label}</span>
    </button>
  );
};

const Row = ({ label, value, highlight }) => (
  <div
    className={`flex justify-between gap-4 border-b border-slate-100/80 pb-2.5 ${highlight ? "text-emerald-700 font-semibold" : ""
      }`}
  >
    <span className="text-sm text-slate-500">{label}</span>
    <span className="text-sm font-semibold text-slate-900 text-right">
      {value}
    </span>
  </div>
);

// --- Constants & helpers (unchanged logic, only formatting) ---

const COMMERCIAL_FIELD_LABELS = {
  workstations: "Workstations",
  conferenceRooms: "Conference Rooms",
  cabins: "Cabins",
  pantry: "Pantry",
  frontage: "Frontage",
  storage: "Storage",
  displayWindows: "Display Windows",
  displayArea: "Display Area",
  seatingCapacity: "Seating Capacity",
  kitchenArea: "Kitchen Area",
  barArea: "Bar Area",
  outdoorSeating: "Outdoor Seating",
  meetingRooms: "Meeting Rooms",
  privateCabins: "Private Cabins",
  phoneBooths: "Phone Booths",
  loungeArea: "Lounge Area",
  loadingDocks: "Loading Docks",
  ceilingHeight: "Ceiling Height",
  floorLoadCapacity: "Floor Load Capacity",
  powerConnection: "Power Connection",
  overheadCrane: "Overhead Crane",
  centralAC: "Central AC",
  powerBackup: "Power Backup",
  washrooms: "Washrooms",
  floorHeight: "Floor Height",
  powerLoad: "Power Load",
};

const formatCategoryDisplay = (name) => {
  const value = (name || "").toString();
  const lower = value.toLowerCase();
  if (lower.includes("commercial land")) return "Commercial Property";
  if (lower.includes("commercial property")) return "Commercial Property";
  if (lower.includes("residential land") || lower.includes("residential plot"))
    return "Residential Property";
  if (lower.includes("residential")) return "Residential Property";
  if (lower.includes("commercial")) return "Commercial Property";
  return value || "Property";
};

const COMMERCIAL_FIELD_ORDER = {
  "Office Space": [
    "workstations",
    "conferenceRooms",
    "cabins",
    "pantry",
    "washrooms",
    "floorHeight",
    "powerLoad",
    "powerBackup",
    "centralAC",
  ],
  "Shop / Retail": [
    "frontage",
    "displayWindows",
    "displayArea",
    "storage",
    "washrooms",
    "powerBackup",
  ],
  Showroom: ["frontage", "displayArea", "storage", "washrooms", "powerLoad"],
  "Restaurant / Cafe": [
    "seatingCapacity",
    "kitchenArea",
    "washrooms",
    "barArea",
    "outdoorSeating",
    "powerLoad",
    "floorHeight",
  ],
  "Co-Working Space": [
    "workstations",
    "meetingRooms",
    "privateCabins",
    "phoneBooths",
    "loungeArea",
    "washrooms",
    "pantry",
    "powerBackup",
  ],
  "Warehouse / Godown": [
    "loadingDocks",
    "ceilingHeight",
    "floorLoadCapacity",
    "powerConnection",
    "overheadCrane",
    "officeSpace",
    "washrooms",
  ],
  "Industrial Shed": [
    "ceilingHeight",
    "floorLoadCapacity",
    "powerConnection",
    "overheadCrane",
    "washrooms",
  ],
  "Commercial Building / Floor": [
    "washrooms",
    "pantry",
    "centralAC",
    "powerBackup",
    "floorHeight",
    "powerLoad",
  ],
};

const DEFAULT_COMMERCIAL_FIELDS = [
  "workstations",
  "conferenceRooms",
  "cabins",
  "pantry",
  "frontage",
  "storage",
  "displayWindows",
  "displayArea",
  "seatingCapacity",
  "kitchenArea",
  "barArea",
  "outdoorSeating",
  "meetingRooms",
  "privateCabins",
  "phoneBooths",
  "loungeArea",
  "loadingDocks",
  "ceilingHeight",
  "floorLoadCapacity",
  "powerConnection",
  "overheadCrane",
  "centralAC",
  "powerBackup",
  "washrooms",
  "floorHeight",
  "powerLoad",
];

// --- Sections (same logic, upgraded Tailwind) ---

const OverviewSection = ({ property, isResidential, isCommercial, ageOfProperty }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-y-5 gap-x-12">
    <Row
      label="Project / Society"
      value={property.locality || property.address?.area || "N/A"}
    />
    <Row
      label="Property Type"
      value={property.propertyTypeName || property.propertyType?.name || "N/A"}
    />

    {isResidential && (
      <>
        <Row label="BHK" value={property.bhk || "N/A"} />
        <Row label="Bedrooms" value={property.bedrooms || "N/A"} />
        <Row label="Bathrooms" value={property.bathrooms || "N/A"} />
        <Row label="Balconies" value={property.balconies || "N/A"} />
        <Row
          label="Floor"
          value={
            property.floorNo
              ? `${property.floorNo} of ${property.totalFloors || "?"}`
              : "N/A"
          }
        />
        <Row label="Facing" value={property.facing || "N/A"} />
        <Row label="Age of Property" value={ageOfProperty || "N/A"} />
        {property.allowedFor && (
          <Row label="Preferred" value={property.allowedFor} />
        )}
        {property.petFriendly && (
          <Row label="Pet Friendly" value={property.petFriendly} />
        )}
      </>
    )}

    {isCommercial && (
      <>
        <Row label="Washrooms" value={property.washrooms || "N/A"} />
        <Row
          label="Floor Height"
          value={property.floorHeight ? `${property.floorHeight} ft` : "N/A"}
        />
        <Row
          label="Power Load"
          value={property.powerLoad ? `${property.powerLoad} kW` : "N/A"}
        />
        {property.commercialSubType && (
          <Row label="Condition" value={property.commercialSubType} />
        )}
      </>
    )}

    <Row
      label="Parking"
      value={
        property.parking?.covered || property.parking?.open
          ? `${property.parking?.covered ? `${property.parking.covered} Covered` : ""}${property.parking?.covered && property.parking?.open ? ", " : ""
          }${property.parking?.open ? `${property.parking.open} Open` : ""}`
          : "N/A"
      }
    />
  </div>
);

const DimensionsSection = ({
  property,
  pricePerSqft,
  formattedPrice,
  bookingAmount,
  maintenanceDisplay,
}) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-y-5 gap-x-12">
    <Row
      label="Built-up Area"
      value={`${property.area?.builtUpSqft || property.builtUpArea || "N/A"} sq.ft`}
    />
    <Row
      label="Carpet Area"
      value={`${property.area?.carpetSqft || property.carpetArea || "N/A"} sq.ft`}
    />
    {property.area?.superBuiltUpSqft && (
      <Row
        label="Super Built-up"
        value={`${property.area.superBuiltUpSqft} sq.ft`}
      />
    )}
    {property.area?.plotSqft && (
      <Row label="Plot Area" value={`${property.area.plotSqft} sq.ft`} />
    )}
    <Row label="Expected Price" value={`₹${formattedPrice}`} />
    <Row label="Booking/Token Amount" value={`₹${bookingAmount || 0}`} />
    <Row
      label="Maintenance Charges"
      value={
        maintenanceDisplay === "Included"
          ? "Included"
          : `₹${maintenanceDisplay || 0} / month`
      }
    />
    {pricePerSqft && (
      <Row
        label="Price / sq.ft"
        value={`₹${pricePerSqft.toLocaleString()}`}
      />
    )}
  </div>
);

const AmenitiesSection = ({ property }) => {
  const list = Array.isArray(property.amenities)
    ? property.amenities
    : Array.isArray(property.selectedAmenities)
      ? property.selectedAmenities
      : [];

  if (list.length === 0) return null;

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-3.5">
      {list.map((amenity, idx) => (
        <div
          key={idx}
          className="flex items-center gap-2 text-sm text-slate-700"
        >
          <CheckCircleIcon className="w-5 h-5 text-emerald-500" />
          <span className="capitalize">
            {String(amenity).replace(/([A-Z])/g, " $1").trim()}
          </span>
        </div>
      ))}
    </div>
  );
};

const ExtrasSection = ({ property }) => {
  if (!property.extras || typeof property.extras !== "object") return null;

  const entries = Object.entries(property.extras).filter(([, val]) => !!val);
  if (entries.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-2.5">
      {entries.map(([key]) => (
        <span
          key={key}
          className="px-3 py-1.5 bg-slate-50 border border-slate-200 text-slate-700 rounded-full text-xs font-medium capitalize"
        >
          {key.replace(/([A-Z])/g, " $1").trim()}
        </span>
      ))}
    </div>
  );
};

const CommercialConfigSection = ({ property, fields }) => (
  <div className="grid grid-cols-1 md:grid-cols-2 gap-y-5 gap-x-12">
    {fields
      .map((field) => [field, property[field]])
      .filter(([, val]) => val !== undefined && val !== null && val !== "")
      .map(([key, val]) => (
        <Row
          key={key}
          label={
            COMMERCIAL_FIELD_LABELS[key] ||
            key
              .replace(/([A-Z])/g, " $1")
              .replace(/^./, (s) => s.toUpperCase())
          }
          value={typeof val === "boolean" ? (val ? "Yes" : "No") : val}
        />
      ))}
  </div>
);

const LegalSection = ({ property, isCommercial }) => {
  const legal = property.legal || {};

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-y-5 gap-x-12">
      <Row label="RERA ID" value={legal.reraId || "N/A"} />
      <Row
        label="Occupancy Certificate"
        value={legal.occupancyCertificate ? "Yes" : "No"}
      />
      {isCommercial && (
        <>
          <Row
            label="Trade License"
            value={legal.tradeLicense ? "Yes" : "No"}
          />
          <Row label="Fire NOC" value={legal.fireNoc ? "Yes" : "No"} />
        </>
      )}
    </div>
  );
};

const EmiSection = ({
  loanAmount,
  setLoanAmount,
  interestRate,
  setInterestRate,
  loanTenure,
  setLoanTenure,
  emi,
  totalInterest,
  totalPayment,
}) => (
  <div className="space-y-5">
    <div>
      <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1.5">
        Loan Amount (₹)
      </label>
      <input
        type="number"
        value={loanAmount}
        onChange={(e) => setLoanAmount(+e.target.value)}
        className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2.5 text-sm focus:ring-2 focus:ring-[#0f4fb5]/40 focus:border-[#0f4fb5] outline-none"
      />
    </div>
    <div className="grid grid-cols-2 gap-4">
      <div>
        <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1.5">
          Rate (%)
        </label>
        <input
          type="number"
          step="0.1"
          value={interestRate}
          onChange={(e) => setInterestRate(+e.target.value)}
          className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2.5 text-sm focus:ring-2 focus:ring-[#0f4fb5]/40 focus:border-[#0f4fb5] outline-none"
        />
      </div>
      <div>
        <label className="block text-[11px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1.5">
          Years
        </label>
        <input
          type="number"
          value={loanTenure}
          onChange={(e) => setLoanTenure(+e.target.value)}
          className="w-full bg-slate-50 border border-slate-200 rounded-xl px-3 py-2.5 text-sm focus:ring-2 focus:ring-[#0f4fb5]/40 focus:border-[#0f4fb5] outline-none"
        />
      </div>
    </div>

    <div className="mt-5 pt-4 border-t border-slate-100 space-y-2">
      <Row
        label="Monthly EMI"
        value={emi > 0 ? `₹${emi.toFixed(0).toLocaleString()}` : "0"}
        highlight
      />
      <Row
        label="Total Interest"
        value={totalInterest > 0 ? `₹${totalInterest.toFixed(0).toLocaleString()}` : "0"}
      />
      <Row
        label="Total Amount"
        value={totalPayment > 0 ? `₹${totalPayment.toFixed(0).toLocaleString()}` : "0"}
      />
    </div>
  </div>
);

// --- Main component (logic same, visuals upgraded) ---

const PropertyDetails = () => {
  const location = useLocation();
  const state = location.state;
  const { id } = useParams();
  const navigate = useNavigate();
  const { startConversation, openChat } = useChat();

  const [property, setProperty] = useState(state?.property || null);
  const [loading, setLoading] = useState(!state?.property);
  const [isInterested, setIsInterested] = useState(false);
  const [interestLoading, setInterestLoading] = useState(false);
  const [chatLoading, setChatLoading] = useState(false);
  const [error, setError] = useState(null);
  const [activeImage, setActiveImage] = useState(0);
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportReason, setReportReason] = useState("");
  const [reportLoading, setReportLoading] = useState(false);

  // EMI
  const [loanAmount, setLoanAmount] = useState();
  const [interestRate, setInterestRate] = useState();
  const [loanTenure, setLoanTenure] = useState();
  const [emi, setEmi] = useState(0);
  const [totalPayment, setTotalPayment] = useState(0);
  const [totalInterest, setTotalInterest] = useState(0);

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }, [id]);

  useEffect(() => {
    const interestedId = location.state?.interestedPropertyId;
    if (interestedId && interestedId === id) {
      setIsInterested(true);
      const newState = { ...(location.state || {}) };
      delete newState.interestedPropertyId;
      navigate(location.pathname, { replace: true, state: newState });
    }
  }, [location.state, location.pathname, id, navigate]);

  // Use AuthContext for auth checks
  const { isAuthenticated, user } = useAuth();

  useEffect(() => {
    const checkUserInterest = async () => {
      if (!isAuthenticated || !id) return;

      try {
        const res = await api.get(`/properties/interested/${id}/check`);
        if (res.data.success) {
          setIsInterested(res.data.isInterested);
        }
      } catch (error) {
        if (error.response?.status !== 401) {
          console.error("Error checking interest status:", error);
        }
      }
    };
    checkUserInterest();
  }, [id, isAuthenticated]);

  useEffect(() => {
    const fetchProperty = async () => {
      try {
        // Public endpoint - no auth needed, but use api client for consistency
        const res = await api.get(`/properties/${id}`);
        if (res.data) {
          setProperty(res.data);
        } else {
          setError("Property not found");
        }
      } catch (error) {
        console.error(error);
        if (!property) {
          setError("Error fetching property details");
        }
      } finally {
        setLoading(false);
      }
    };
    fetchProperty();
  }, [id]);

  const buildImageUrl = (img) => {
    if (!img) return "";
    const lower = img.toLowerCase();
    if (lower.startsWith("data:")) return img;
    if (lower.startsWith("http://") || lower.startsWith("https://")) return img;
    if (img.startsWith("/uploads")) return `${API_BASE}${img}`;
    return `${API_BASE}/uploads/${img}`;
  };

  const formatCategoryName = (key) =>
    key
      .replace(/([A-Z])/g, " $1")
      .replace(/^./, (str) => str.toUpperCase())
      .trim();

  const getAllImages = () => {
    const allImages = [];

    if (property?.categorizedImages) {
      const catImages = property.categorizedImages;

      if (catImages.residential) {
        Object.entries(catImages.residential).forEach(([category, images]) => {
          if (Array.isArray(images)) {
            images.forEach((img) => {
              if (img)
                allImages.push({
                  url: buildImageUrl(img),
                  category: formatCategoryName(category),
                });
            });
          }
        });
      }

      if (catImages.commercial) {
        Object.entries(catImages.commercial).forEach(([category, images]) => {
          if (Array.isArray(images)) {
            images.forEach((img) => {
              if (img)
                allImages.push({
                  url: buildImageUrl(img),
                  category: formatCategoryName(category),
                });
            });
          }
        });
      }
    }

    // Fallback for older properties that only used the legacy `images` array
    if (allImages.length === 0 && Array.isArray(property?.images)) {
      property.images.forEach((img) => {
        if (img) {
          allImages.push({
            url: buildImageUrl(img),
            category: "Exterior",
          });
        }
      });
    }

    return allImages;
  };

  const getVideoEmbedUrl = (url) => {
    if (!url) return null;
    try {
      const ytMatch = url.match(
        /(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/))([\w-]{11})/
      );
      if (ytMatch && ytMatch[1])
        return `https://www.youtube.com/embed/${ytMatch[1]}`;
      return url;
    } catch {
      return url;
    }
  };

  const allPropertyImages = getAllImages();
  const imgs = allPropertyImages.map((item) => item.url);

  const currentImageCategory =
    allPropertyImages[activeImage]?.category || null;
  const videoUrl = property?.videoUrl;
  const videoEmbed = getVideoEmbedUrl(videoUrl);

  useEffect(() => {
    if (property?.listingType === "Rent") return;

    const principal = Number(loanAmount) || 0;
    const rate = Number(interestRate) || 0;
    const tenureYears = Number(loanTenure) || 0;

    if (principal <= 0 || rate <= 0 || tenureYears <= 0) {
      setEmi(0);
      setTotalPayment(0);
      setTotalInterest(0);
      return;
    }

    const r = rate / 100 / 12;
    const n = tenureYears * 12;
    const emiCalc = (principal * r * Math.pow(1 + r, n)) / (Math.pow(1 + r, n) - 1);
    const totalPay = emiCalc * n;
    setEmi(emiCalc);
    setTotalPayment(totalPay);
    setTotalInterest(totalPay - principal);
  }, [loanAmount, interestRate, loanTenure, property]);

  if (loading)
    return (
      <div className="min-h-screen flex items-center justify-center text-slate-500 text-lg">
        Loading property details...
      </div>
    );

  if (error)
    return (
      <div className="min-h-screen flex items-center justify-center text-red-500">
        {error}
      </div>
    );

  if (!property)
    return (
      <div className="min-h-screen flex items-center justify-center">
        Property not found
      </div>
    );

  const price = property.price || property.expectedPrice || 0;
  const formattedPrice = Number(price).toLocaleString();

  const address = property.address || {};
  const lat = address.latitude ?? property.lat ?? property.latitude;
  const lng = address.longitude ?? property.lng ?? property.longitude;
  const city = property.city || address.city;
  const locality = property.locality || address.area;
  const landmark = address.landmark || property.landmark;

  const categoryName = (
    property.category?.name ||
    property.categoryName ||
    property.category ||
    property.propertyCategory ||
    ""
  ).toString();
  const categoryNameLower = categoryName.toLowerCase();
  const propertyTypeName =
    property.propertyTypeName ||
    property.propertyType?.name ||
    property.propertyType ||
    "";
  const propertyTypeLower = propertyTypeName.toLowerCase();
  const isResidential =
    categoryNameLower.includes("residen") ||
    /apartment|flat|villa|house|studio|row house|farm house|penthouse/.test(
      propertyTypeLower
    );
  const isCommercial =
    categoryNameLower.includes("commercial") ||
    /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial/.test(
      propertyTypeLower
    );

  const totalSqft =
    property.area?.totalSqft ||
    property.area?.builtUpSqft ||
    property.area?.carpetSqft ||
    property.area?.plotSqft;
  const pricePerSqft =
    property.area?.pricePerSqft ||
    (price && totalSqft ? Math.round(price / totalSqft) : null);
  const maintenanceDisplay = property.maintenanceIncluded
    ? "Included"
    : property.maintenance ?? property.area?.maintenance;
  const bookingAmount =
    property.bookingAmount ??
    property.securityDeposit ??
    property.expectedDeposit ??
    0;
  const ageOfProperty = property.ageOfProperty || property.propertyAge;
  const configurationValue = isResidential
    ? property.bhk || (property.bedrooms ? `${property.bedrooms} BHK` : null)
    : property.commercialSubType || propertyTypeName || null;

  const commercialOrder =
    COMMERCIAL_FIELD_ORDER[propertyTypeName] || DEFAULT_COMMERCIAL_FIELDS;
  const commercialFieldsToShow = commercialOrder.filter(
    (field) =>
      property[field] !== undefined &&
      property[field] !== null &&
      property[field] !== ""
  );
  const showCommercialConfig =
    (isCommercial ||
      propertyTypeName.toLowerCase().includes("office") ||
      propertyTypeName.toLowerCase().includes("shop") ||
      propertyTypeName.toLowerCase().includes("showroom") ||
      propertyTypeName.toLowerCase().includes("restaurant") ||
      propertyTypeName.toLowerCase().includes("warehouse") ||
      propertyTypeName.toLowerCase().includes("industrial") ||
      propertyTypeName.toLowerCase().includes("commercial")) &&
    commercialFieldsToShow.length > 0;

  const handleInterest = async () => {
    if (!isAuthenticated || !user) {
      toast.info("Please login to express interest in this property");
      navigate("/login", {
        state: {
          from: `/properties/${id}`,
          pendingAction: "interest",
          propertyId: id,
        },
      });
      return;
    }

    if (isInterested) {
      setInterestLoading(true);
      try {
        const res = await api.delete(
          `/properties/interested/${id}`
        );
        if (res.data.success) {
          setIsInterested(false);
          toast.success("Interest removed");
        } else {
          toast.error(res.data.message || "Failed to remove interest");
        }
      } catch (error) {
        console.error("Error removing interest:", error);
        const errorMsg =
          error.response?.data?.message || "Failed to remove interest";
        toast.error(errorMsg);
      } finally {
        setInterestLoading(false);
      }
      return;
    }

    setInterestLoading(true);
    try {
      const res = await api.post(
        `/properties/interested/${id}`,
        {}
      );

      if (res.data.success) {
        setIsInterested(true);
        toast.success("Interest registered! The owner will be notified.");
      } else {
        toast.error(res.data.message || "Failed to register interest");
      }
    } catch (error) {
      console.error("Error registering interest:", error);
      const errorMsg =
        error.response?.data?.message || "Failed to register interest";
      toast.error(errorMsg);
    } finally {
      setInterestLoading(false);
    }
  };

  const handleChatWithOwner = async () => {
    if (!isAuthenticated || !user?._id) {
      toast.info("Please login to chat with the owner");
      navigate("/login", { state: { from: `/properties/${id}` } });
      return;
    }

    const ownerId = property.owner?._id || property.owner;

    if (!ownerId) {
      toast.error("Unable to contact owner - no owner information available");
      return;
    }

    if (user._id === ownerId) {
      toast.info("This is your own property");
      return;
    }

    setChatLoading(true);
    try {
      // ChatContext.startConversation expects (propertyId, ownerId)
      const conversation = await startConversation(property._id, ownerId);
      if (conversation) {
        openChat(conversation);
      } else {
        toast.error("Unable to start chat right now");
      }
    } catch (error) {
      console.error("Error starting chat:", error);
      const msg = error.response?.data?.message || "Failed to start chat";
      toast.error(msg);
    } finally {
      setChatLoading(false);
    }
  };

  const handleSubmitReport = async () => {
    if (!isAuthenticated || !user?._id) {
      toast.info("Please login to report this property");
      navigate("/login", { state: { from: `/properties/${id}` } });
      return;
    }

    const trimmedReason = reportReason.trim();
    if (!trimmedReason || trimmedReason.length < 10) {
      toast.error("Please describe the issue (at least 10 characters)");
      return;
    }

    setReportLoading(true);
    try {
      const res = await api.post(
        `/properties/${id}/report`,
        { reason: trimmedReason }
      );

      if (res.data?.success) {
        toast.success("Thank you. Your report has been submitted.");
        setShowReportModal(false);
        setReportReason("");
      } else {
        toast.error(res.data?.message || "Failed to submit report");
      }
    } catch (error) {
      console.error("Error reporting property:", error);
      const msg =
        error.response?.data?.message || "Failed to submit report. Please try again.";
      toast.error(msg);
    } finally {
      setReportLoading(false);
    }
  };

  return (
    <div className={`min-h-screen ${BRAND_BG_SOFT} text-slate-900`}>
      <div className="max-w-6xl mx-auto px-4 sm:px-6 py-8 sm:py-10 lg:py-12 font-sans">
        {/* Hero */}
        <div className="bg-white/95 border border-slate-200/80 rounded-3xl shadow-[0_22px_60px_rgba(15,32,70,0.16)] overflow-hidden">
          <div className="grid lg:grid-cols-3 gap-0">
            {/* Media */}
            <div className="lg:col-span-2 relative">
              <div className="relative h-[380px] sm:h-[480px] lg:h-[520px] bg-slate-100">
                <img
                  src={
                    imgs[activeImage] ||
                    buildImageUrl(property.image) ||
                    "https://via.placeholder.com/800x600?text=No+Image"
                  }
                  alt={property.title}
                  className="w-full h-full object-cover"
                />
                <div className="absolute inset-0 bg-gradient-to-t from-slate-950/85 via-slate-900/20 to-transparent" />

                {/* Top-right actions */}
                <div className="absolute top-4 right-4 flex gap-3">
                  <button
                    onClick={() => setShowReportModal(true)}
                    className="bg-white/90 backdrop-blur-sm p-3 rounded-full shadow-[0_18px_40px_rgba(15,32,70,0.25)] hover:scale-110 transition flex items-center justify-center"
                    title="Report this property"
                  >
                    <FlagIcon className="w-6 h-6 text-red-600" />
                  </button>
                  <button
                    onClick={() => {
                      navigator.clipboard.writeText(window.location.href);
                      toast.success("Property link copied!");
                    }}
                    className="bg-white/90 backdrop-blur-sm p-3 rounded-full shadow-[0_18px_40px_rgba(15,32,70,0.25)] hover:scale-110 transition"
                  >
                    <ShareIcon className="w-6 h-6 text-slate-700" />
                  </button>
                </div>

                {/* Bottom overlay info */}
                <div className="absolute bottom-4 left-4 flex flex-wrap items-center gap-2">
                  <div className="bg-black/60 text-white text-xs px-3 py-1.5 rounded-full tracking-wide">
                    {activeImage + 1} / {imgs.length || 1}
                  </div>
                  {currentImageCategory && (
                    <div className="bg-[#0f4fb5] text-white text-xs px-3 py-1.5 rounded-full font-semibold">
                      {currentImageCategory}
                    </div>
                  )}
                </div>
              </div>

              {imgs.length > 0 && (
                <div className="flex gap-3 px-4 pb-4 pt-3 overflow-x-auto scrollbar-hide bg-white/90 border-t border-slate-100">
                  {imgs.map((img, i) => (
                    <button
                      key={i}
                      onClick={() => setActiveImage(i)}
                      className={`relative flex-shrink-0 rounded-xl overflow-hidden border ${i === activeImage
                        ? "border-[#0f4fb5] ring-2 ring-[#0f4fb5]/25"
                        : "border-slate-200"
                        }`}
                    >
                      <img
                        src={img}
                        alt=""
                        className="h-20 w-28 object-cover"
                      />
                      {allPropertyImages[i]?.category && (
                        <span className="absolute bottom-1 left-1 bg-black/65 text-white text-[10px] px-1.5 py-0.5 rounded">
                          {allPropertyImages[i].category}
                        </span>
                      )}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Right info panel */}
            <div className="bg-white/98 border-l border-slate-100/80 p-6 sm:p-7 lg:p-8 flex flex-col gap-6">
              {/* Badges */}
              <div className="flex flex-wrap items-center gap-2">
                <span className="px-3 py-1 rounded-full bg-[#0f4fb5]/10 text-[#0f4fb5] text-[11px] font-semibold uppercase tracking-[0.08em]">
                  {property.listingType || "For Sale"}
                </span>
                <span className="px-3 py-1 rounded-full bg-[#ffe4ea] text-[#e11d48] text-[11px] font-semibold uppercase tracking-[0.08em]">
                  {formatCategoryDisplay(
                    property.category?.name || property.propertyCategory
                  )}
                </span>
                {property.propertyTypeName && (
                  <span className="px-3 py-1 rounded-full bg-slate-100 text-slate-700 text-[11px] font-semibold">
                    {property.propertyTypeName}
                  </span>
                )}
              </div>

              {/* Title & location */}
              <div>
                <h1 className="text-2xl sm:text-3xl font-semibold text-slate-900 leading-tight mb-2">
                  {property.title}
                </h1>
                <p className="flex items-center text-sm sm:text-base text-slate-600">
                  <MapPinIcon className="w-5 h-5 mr-1 text-[#0f4fb5] flex-shrink-0" />
                  {locality || ""}
                  {locality && city ? ", " : ""}
                  {city || address?.city}
                </p>
                {property.owner?.name && (
                  <p className="mt-1 text-xs sm:text-sm text-slate-500">
                    Listed by
                    {" "}
                    <span className="font-semibold text-slate-700">
                      {property.owner.name}
                    </span>
                  </p>
                )}
              </div>

              {/* Price block */}
              <div className="space-y-3">
                <p className="text-xs font-semibold text-slate-500 uppercase tracking-[0.08em]">
                  Asking Price
                </p>
                <div className="flex flex-wrap items-baseline gap-3">
                  <span className="text-3xl sm:text-4xl font-semibold text-slate-900">
                    ₹{formattedPrice}
                  </span>
                  {pricePerSqft && (
                    <span className="px-3 py-1 rounded-full bg-slate-100 text-slate-700 text-xs sm:text-sm">
                      ₹{pricePerSqft.toLocaleString()} / sq.ft
                    </span>
                  )}
                </div>
                <div className="flex flex-wrap gap-2 text-[11px] font-semibold text-slate-700">
                  {maintenanceDisplay !== undefined &&
                    maintenanceDisplay !== null &&
                    maintenanceDisplay !== "" && (
                      <span className="px-3 py-1 rounded-full bg-slate-100">
                        Maintenance:{" "}
                        {maintenanceDisplay === "Included"
                          ? "Included"
                          : `₹${maintenanceDisplay}`}
                      </span>
                    )}
                  {bookingAmount > 0 && (
                    <span className="px-3 py-1 rounded-full bg-slate-100">
                      Token: ₹{Number(bookingAmount).toLocaleString()}
                    </span>
                  )}
                  {property.gstApplicable && (
                    <span className="px-3 py-1 rounded-full bg-slate-100">
                      GST Applicable
                    </span>
                  )}
                  {property.negotiable && (
                    <span className="px-3 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-100">
                      Negotiable
                    </span>
                  )}
                </div>
              </div>

              {/* Quick facts */}
              <div className="grid grid-cols-2 gap-3 bg-slate-50/70 border border-slate-100 rounded-2xl p-4">
                <InfoChip
                  label="Area"
                  value={`${property.area?.builtUpSqft ||
                    property.builtUpArea ||
                    property.area?.totalSqft ||
                    "N/A"
                    } sq.ft`}
                />
                {configurationValue && (
                  <InfoChip
                    label={isResidential ? "Configuration" : "Use Type"}
                    value={configurationValue}
                  />
                )}
                {!isCommercial && (
                  <InfoChip
                    label="Furnishing"
                    value={property.furnishing || "N/A"}
                  />
                )}
                <InfoChip
                  label="Available"
                  value={
                    property.availableFrom
                      ? new Date(
                        property.availableFrom
                      ).toLocaleDateString()
                      : "Ready to Move"
                  }
                />
              </div>

              {/* Actions */}
              <div className="space-y-3 pt-1">
                <PrimaryButton
                  onClick={handleInterest}
                  disabled={interestLoading}
                  tone={isInterested ? "red" : "brand"}
                  loading={interestLoading}
                  label={isInterested ? "Remove Interest" : "I'm Interested"}
                  icon={
                    isInterested ? (
                      <HeartIconSolid className="w-5 h-5" />
                    ) : (
                      <HeartIcon className="w-5 h-5" />
                    )
                  }
                />
                {isInterested && (
                  <PrimaryButton
                    onClick={handleChatWithOwner}
                    disabled={chatLoading}
                    loading={chatLoading}
                    tone="subtle"
                    label="Chat with Owner"
                    icon={<ChatBubbleLeftRightIcon className="w-5 h-5" />}
                  />
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Body */}
        <div className="mt-10 grid grid-cols-1 lg:grid-cols-3 gap-8 lg:gap-10">
          {/* Left column */}
          <div className="lg:col-span-2 space-y-8">
            <Card
              title="Property Overview"
              icon={
                <BuildingStorefrontIcon className="w-5 h-5 text-[#0f4fb5]" />
              }
            >
              <OverviewSection
                property={property}
                isResidential={isResidential}
                isCommercial={isCommercial}
                ageOfProperty={ageOfProperty}
              />
            </Card>

            <Card
              title="Dimensions & Pricing"
              icon={<Square2StackIcon className="w-5 h-5 text-[#0f4fb5]" />}
            >
              <DimensionsSection
                property={property}
                pricePerSqft={pricePerSqft}
                formattedPrice={formattedPrice}
                bookingAmount={bookingAmount}
                maintenanceDisplay={maintenanceDisplay}
              />
            </Card>

            {(property.amenities?.length > 0 ||
              property.selectedAmenities?.length > 0) && (
                <Card
                  title="Amenities"
                  icon={<TagIcon className="w-5 h-5 text-[#0f4fb5]" />}
                >
                  <AmenitiesSection property={property} />
                </Card>
              )}

            {isResidential &&
              property.extras &&
              Object.values(property.extras).some(Boolean) && (
                <Card
                  title="Extra Rooms"
                  icon={<ShieldCheckIcon className="w-5 h-5 text-[#0f4fb5]" />}
                >
                  <ExtrasSection property={property} />
                </Card>
              )}

            {showCommercialConfig && (
              <Card
                title={`${propertyTypeName || "Commercial"} Details`}
                icon={
                  <BuildingStorefrontIcon className="w-5 h-5 text-[#0f4fb5]" />
                }
              >
                <CommercialConfigSection
                  property={property}
                  fields={commercialFieldsToShow}
                />
              </Card>
            )}

            {property.legal && (
              <Card
                title="Legal & Compliance"
                icon={<ShieldCheckIcon className="w-5 h-5 text-[#0f4fb5]" />}
              >
                <LegalSection property={property} isCommercial={isCommercial} />
              </Card>
            )}

            {videoEmbed && (
              <Card
                title="Video Walkthrough"
                icon={<HomeIcon className="w-5 h-5 text-[#0f4fb5]" />}
              >
                {videoEmbed.startsWith("http") &&
                  videoEmbed.includes("youtube.com/embed") ? (
                  <div
                    className="relative w-full overflow-hidden rounded-2xl shadow-[0_16px_45px_rgba(15,32,70,0.18)]"
                    style={{ paddingTop: "56.25%" }}
                  >
                    <iframe
                      src={videoEmbed}
                      title="Property video"
                      className="absolute inset-0 w-full h-full"
                      allowFullScreen
                      loading="lazy"
                    />
                  </div>
                ) : (
                  <a
                    href={videoEmbed}
                    target="_blank"
                    rel="noreferrer"
                    className="text-[#0f4fb5] underline text-sm"
                  >
                    Open video in new tab
                  </a>
                )}
              </Card>
            )}

            <Card
              title="About Property"
              icon={<HomeIcon className="w-5 h-5 text-[#0f4fb5]" />}
            >
              <p className="text-sm sm:text-base text-slate-700 leading-relaxed whitespace-pre-line">
                {property.description || "No description provided."}
              </p>
            </Card>
          </div>

          {/* Right column */}
          <div className="space-y-8">
            {property?.listingType !== "Rent" && (
              <Card
                title="EMI Calculator"
                icon={<BanknotesIcon className="w-5 h-5 text-[#0f4fb5]" />}
                sticky
              >
                <EmiSection
                  loanAmount={loanAmount}
                  setLoanAmount={setLoanAmount}
                  interestRate={interestRate}
                  setInterestRate={setInterestRate}
                  loanTenure={loanTenure}
                  setLoanTenure={setLoanTenure}
                  emi={emi}
                  totalInterest={totalInterest}
                  totalPayment={totalPayment}
                />
              </Card>
            )}

            <Card
              title="Location"
              icon={<MapPinIcon className="w-5 h-5 text-[#0f4fb5]" />}
            >
              <div className="rounded-2xl overflow-hidden h-64 bg-slate-100 shadow-[0_14px_40px_rgba(15,32,70,0.15)]">
                <iframe
                  src={
                    lat && lng
                      ? `https://www.google.com/maps?q=${lat},${lng}&z=16&output=embed`
                      : `https://www.google.com/maps?q=${encodeURIComponent(
                        address.line || locality || city || "India"
                      )}&output=embed`
                  }
                  title="Map"
                  width="100%"
                  height="100%"
                  style={{ border: 0 }}
                  loading="lazy"
                />
              </div>
              <p className="text-sm text-slate-600 mt-3">
                {landmark ? `Near ${landmark}, ` : ""}
                {address.line || locality || address.area}, {city}
              </p>
              {address?.nearby && address.nearby.length > 0 && (
                <div className="mt-3">
                  <p className="text-[11px] font-semibold text-slate-500 uppercase tracking-[0.08em] mb-1">
                    Nearby
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {address.nearby.map((place, i) => (
                      <span
                        key={i}
                        className="text-[11px] bg-slate-50 text-slate-700 px-2 py-1 rounded-full border border-slate-200"
                      >
                        {place}
                      </span>
                    ))}
                  </div>
                  {showReportModal && (
                    <div className="fixed inset-0 bg-black/40 backdrop-blur-sm z-50 flex items-center justify-center px-4">
                      <div className="bg-white rounded-2xl shadow-xl max-w-md w-full p-6">
                        <h3 className="text-lg font-semibold text-slate-900 mb-2 flex items-center gap-2">
                          <FlagIcon className="w-5 h-5 text-red-600" />
                          Report this property
                        </h3>
                        <p className="text-sm text-slate-600 mb-4">
                          Tell us what is wrong with this listing. Our team will review your
                          report and take appropriate action.
                        </p>
                        <textarea
                          rows={4}
                          value={reportReason}
                          onChange={(e) => setReportReason(e.target.value)}
                          placeholder="Example: This property seems fraudulent or contains incorrect information."
                          className="w-full border border-slate-300 rounded-xl px-3 py-2 text-sm text-slate-800 focus:ring-2 focus:ring-red-500 focus:border-red-500 resize-none mb-4"
                        />
                        <div className="flex justify-end gap-3">
                          <button
                            type="button"
                            onClick={() => {
                              if (!reportLoading) {
                                setShowReportModal(false);
                              }
                            }}
                            className="px-4 py-2 text-sm rounded-xl border border-slate-200 text-slate-600 hover:bg-slate-50"
                          >
                            Cancel
                          </button>
                          <button
                            type="button"
                            onClick={handleSubmitReport}
                            disabled={reportLoading}
                            className="px-4 py-2 text-sm rounded-xl bg-red-600 text-white hover:bg-red-700 disabled:opacity-60 flex items-center gap-2"
                          >
                            {reportLoading && (
                              <span className="h-4 w-4 border-2 border-white/60 border-t-transparent rounded-full animate-spin" />
                            )}
                            Submit report
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PropertyDetails;
