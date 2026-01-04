import React, { useState, useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "react-toastify";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import ReactMarkdown from "react-markdown";
import {
  FaFileContract,
  FaShieldAlt,
  FaCheckCircle,
  FaLock,
  FaUserCheck,
  FaCertificate,
  FaDownload,
  FaPrint,
  FaCopy,
  FaRedo,
  FaInfoCircle,
  FaBuilding,
  FaUser,
  FaMapMarkerAlt,
  FaCalendarAlt,
  FaRupeeSign,
  FaHome,
  FaSpinner,
  FaLightbulb,
  FaGavel,
  FaEdit,
  FaEye,
  FaArrowLeft,
  FaArrowRight,
  FaMagic,
  FaFilePdf,
} from "react-icons/fa";
import { HiSparkles } from "react-icons/hi";



const INDIAN_STATES = [
  "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
  "Delhi", "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand",
  "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
  "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab", "Rajasthan",
  "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh",
  "Uttarakhand", "West Bengal", "Chandigarh", "Puducherry",
];

function AgreementGenerator() {
  const navigate = useNavigate();
  const agreementRef = useRef(null);
  const [step, setStep] = useState(1);
  const [loading, setLoading] = useState(false);
  const [generatedAgreement, setGeneratedAgreement] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const [formData, setFormData] = useState({
    // Landlord Details
    landlordName: "",
    landlordAge: "",
    landlordAddress: "",
    landlordPhone: "",
    landlordAadhaar: "",
    // Tenant Details
    tenantName: "",
    tenantAge: "",
    tenantAddress: "",
    tenantPhone: "",
    tenantAadhaar: "",
    // Property Details
    propertyAddress: "",
    state: "",
    city: "",
    propertyType: "Residential",
    bhkType: "",
    furnishing: "Unfurnished",
    carpetArea: "",
    // State-specific details
    scheduleEast: "",
    scheduleWest: "",
    scheduleNorth: "",
    scheduleSouth: "",
    lockInMonths: "",
    includePoliceVerification: false,
    includeForceMajeure: true,
    includeIndemnity: true,
    includeDiplomaticClause: false,
    // Financial Details
    rentAmount: "",
    securityDeposit: "",
    maintenanceCharges: "",
    // Agreement Details
    startDate: "",
    durationMonths: 11,
    noticePeriod: 1,
    rentDueDay: 5,
    additionalTerms: "",
  });

  const { isAuthenticated, user } = useAuth();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    if (isAuthenticated && user) {
      setIsLoggedIn(true);
      // Pre-fill landlord name if user is the owner
      if (user.name) {
        setFormData((prev) => ({ ...prev, landlordName: user.name }));
      }
    } else {
      setIsLoggedIn(false);
    }
  }, [isAuthenticated, user]);

  // Auto-enable Police Verification clause for Delhi
  useEffect(() => {
    if (!formData.state) return;
    const lower = formData.state.toLowerCase();
    if (lower === "delhi" && !formData.includePoliceVerification) {
      setFormData((prev) =>
        prev.includePoliceVerification
          ? prev
          : { ...prev, includePoliceVerification: true }
      );
    }
  }, [formData.state, formData.includePoliceVerification]);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const validateStep = (currentStep) => {
    switch (currentStep) {
      case 1:
        if (!formData.landlordName.trim() || !formData.tenantName.trim()) {
          toast.error("Please fill in both Landlord and Tenant names");
          return false;
        }
        const landlordAge = Number(formData.landlordAge);
        const tenantAge = Number(formData.tenantAge);
        if (!landlordAge || !tenantAge) {
          toast.error("Please provide age for both parties");
          return false;
        }
        if (landlordAge < 18 || tenantAge < 18) {
          toast.error("Both landlord and tenant must be at least 18 years old");
          return false;
        }
        if (!formData.landlordAddress.trim() || !formData.tenantAddress.trim()) {
          toast.error("Please provide permanent address for both parties");
          return false;
        }
        if (formData.landlordPhone && !/^\d{10}$/.test(formData.landlordPhone)) {
          toast.error("Please enter a valid 10-digit landlord phone number");
          return false;
        }
        if (formData.tenantPhone && !/^\d{10}$/.test(formData.tenantPhone)) {
          toast.error("Please enter a valid 10-digit tenant phone number");
          return false;
        }
        if (formData.landlordAadhaar && !/^\d{4}$/.test(formData.landlordAadhaar)) {
          toast.error("Landlord Aadhaar should be last 4 digits only");
          return false;
        }
        if (formData.tenantAadhaar && !/^\d{4}$/.test(formData.tenantAadhaar)) {
          toast.error("Tenant Aadhaar should be last 4 digits only");
          return false;
        }
        return true;
      case 2:
        if (!formData.propertyAddress.trim() || !formData.state || !formData.city.trim()) {
          toast.error("Please fill in all property details");
          return false;
        }
        if (formData.carpetArea && Number(formData.carpetArea) <= 0) {
          toast.error("Carpet area should be a positive number");
          return false;
        }
        if (formData.state.toLowerCase() === "karnataka") {
          const { scheduleEast, scheduleWest, scheduleNorth, scheduleSouth } = formData;
          if (
            !scheduleEast.trim() ||
            !scheduleWest.trim() ||
            !scheduleNorth.trim() ||
            !scheduleSouth.trim()
          ) {
            toast.error(
              "Please fill the Schedule of Property (East/West/North/South) for Karnataka."
            );
            return false;
          }
        }
        return true;
      case 3:
        if (!formData.rentAmount || !formData.securityDeposit || !formData.startDate) {
          toast.error("Please fill in all financial and date details");
          return false;
        }
        if (Number(formData.rentAmount) <= 0 || Number(formData.securityDeposit) <= 0) {
          toast.error("Rent and deposit must be positive amounts");
          return false;
        }
        return true;
      default:
        return true;
    }
  };

  const nextStep = () => {
    if (validateStep(step)) {
      setStep((prev) => Math.min(prev + 1, 4));
    }
  };

  const prevStep = () => {
    setStep((prev) => Math.max(prev - 1, 1));
  };

  const generateAgreement = async () => {
    if (!isLoggedIn) {
      toast.info("Please login to generate agreements");
      navigate("/login", { state: { from: "/agreements" } });
      return;
    }

    if (!validateStep(3)) return;

    setLoading(true);
    try {
      const response = await api.post(
        `/agreements/generate`,
        formData
      );

      if (response.data.success) {
        setGeneratedAgreement(response.data);
        setStep(4);
        toast.success("Agreement generated successfully!");
      } else {
        toast.error(response.data.message || "Failed to generate agreement");
      }
    } catch (error) {
      console.error("Generate agreement error:", error);
      toast.error(error.response?.data?.message || "Failed to generate agreement");
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    if (generatedAgreement?.agreement) {
      navigator.clipboard.writeText(generatedAgreement.agreement);
      toast.success("Agreement copied to clipboard!");
    }
  };

  const printAgreement = () => {
    const printContent = agreementRef.current;
    const printWindow = window.open("", "", "height=800,width=900");
    printWindow.document.write(`
      <html>
        <head>
          <title>Rental Agreement - ${formData.landlordName}</title>
          <style>
            body { font-family: 'Times New Roman', serif; padding: 40px; line-height: 1.8; }
            h1, h2, h3 { color: #1a1a1a; margin-top: 20px; }
            p { margin: 10px 0; text-align: justify; }
            strong { font-weight: bold; }
            .disclaimer { background: #fff3cd; padding: 15px; border: 1px solid #ffc107; margin: 20px 0; }
          </style>
        </head>
        <body>${printContent.innerHTML}</body>
      </html>
    `);
    printWindow.document.close();
    printWindow.print();
  };

  const downloadAsText = () => {
    if (generatedAgreement?.agreement) {
      const blob = new Blob([generatedAgreement.agreement], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `Agreement_${formData.landlordName}_${formData.tenantName}.txt`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Agreement downloaded!");
    }
  };

  const downloadAsPDF = async () => {
    if (!generatedAgreement?.agreement) return;

    toast.info("Generating PDF... Please wait");

    // Create a clean HTML document for PDF generation
    const printWindow = window.open("", "_blank");

    const htmlContent = `
      <!DOCTYPE html>
      <html>
        <head>
          <meta charset="UTF-8">
          <title>Rental Agreement - ${formData.landlordName} & ${formData.tenantName}</title>
          <style>
            * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
            }
            body {
              font-family: 'Times New Roman', Times, serif;
              font-size: 12pt;
              line-height: 1.6;
              color: #000;
              padding: 40px 50px;
              max-width: 210mm;
              margin: 0 auto;
            }
            h1 {
              font-size: 18pt;
              font-weight: bold;
              text-align: center;
              text-transform: uppercase;
              margin: 20px 0;
              border-bottom: 2px solid #000;
              padding-bottom: 10px;
            }
            h2 {
              font-size: 14pt;
              font-weight: bold;
              text-transform: uppercase;
              margin: 20px 0 10px 0;
              border-bottom: 1px solid #666;
              padding-bottom: 5px;
            }
            h3 {
              font-size: 12pt;
              font-weight: bold;
              margin: 15px 0 8px 0;
            }
            p {
              text-align: justify;
              margin-bottom: 10px;
            }
            strong {
              font-weight: bold;
            }
            em {
              font-style: italic;
            }
            ul, ol {
              margin-left: 25px;
              margin-bottom: 10px;
            }
            li {
              margin-bottom: 5px;
            }
            hr {
              border: none;
              border-top: 1px solid #ccc;
              margin: 20px 0;
            }
            .disclaimer {
              background: #fff8e1;
              border: 1px solid #ffb300;
              padding: 15px;
              margin: 15px 0;
              font-size: 10pt;
            }
            @media print {
              body {
                padding: 20px;
              }
            }
          </style>
        </head>
        <body>
          ${generatedAgreement.agreement
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/\*([^*]+)\*/g, '<em>$1</em>')
        .replace(/^### (.+)$/gm, '<h3>$1</h3>')
        .replace(/^## (.+)$/gm, '<h2>$1</h2>')
        .replace(/^# (.+)$/gm, '<h1>$1</h1>')
        .replace(/^---$/gm, '<hr>')
        .replace(/^- (.+)$/gm, '<li>$1</li>')
        .replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>')
        .replace(/\n\n/g, '</p><p>')
        .replace(/^(?!<[hulo])/gm, '<p>')
        .replace(/(?<![>])$/gm, '</p>')
        .replace(/<p><\/p>/g, '')
        .replace(/<p>(<[hulo])/g, '$1')
        .replace(/(<\/[hulo][^>]*>)<\/p>/g, '$1')
      }
        </body>
      </html>
    `;

    printWindow.document.write(htmlContent);
    printWindow.document.close();

    // Wait for content to load then print as PDF
    printWindow.onload = () => {
      setTimeout(() => {
        printWindow.print();
        toast.success("Use 'Save as PDF' in the print dialog to download!");
      }, 500);
    };
  };

  const resetForm = () => {
    setFormData({
      landlordName: "",
      landlordAge: "",
      landlordAddress: "",
      landlordPhone: "",
      landlordAadhaar: "",
      tenantName: "",
      tenantAge: "",
      tenantAddress: "",
      tenantPhone: "",
      tenantAadhaar: "",
      propertyAddress: "",
      state: "",
      city: "",
      propertyType: "Residential",
      bhkType: "",
      furnishing: "Unfurnished",
      carpetArea: "",
      rentAmount: "",
      securityDeposit: "",
      maintenanceCharges: "",
      startDate: "",
      durationMonths: 11,
      noticePeriod: 1,
      rentDueDay: 5,
      additionalTerms: "",
    });
    setGeneratedAgreement(null);
    setStep(1);
  };

  const isMaharashtra = formData.state.toLowerCase() === "maharashtra";

  // Step indicator component
  const StepIndicator = () => (
    <div className="flex items-center justify-center mb-8">
      {[1, 2, 3, 4].map((s, idx) => (
        <React.Fragment key={s}>
          <div
            className={`flex items-center justify-center w-10 h-10 rounded-full font-bold text-sm transition-all duration-300 ${step >= s
                ? "bg-blue-600 text-white shadow-lg shadow-blue-500/30"
                : "bg-gray-200 text-gray-500"
              }`}
          >
            {step > s ? <FaCheckCircle /> : s}
          </div>
          {idx < 3 && (
            <div
              className={`w-12 sm:w-20 h-1 mx-1 rounded transition-all duration-300 ${step > s ? "bg-blue-600" : "bg-gray-200"
                }`}
            />
          )}
        </React.Fragment>
      ))}
    </div>
  );

  const trustFeatures = [
    { icon: HiSparkles, text: "AI-Powered", subtext: "Smart legal-style drafting" },
    { icon: FaGavel, text: "State-Specific", subtext: "Compliant with local laws" },
    { icon: FaLock, text: "Secure", subtext: "Your data is protected" },
    { icon: FaCertificate, text: "Professional", subtext: "Legal quality drafts" },
  ];

  return (
    <div className="min-h-screen mt-20 sm:mt-28 py-12 px-4 sm:px-8 lg:px-20 bg-gradient-to-br from-slate-50 to-blue-50/30">
      {/* Header */}
      <div className="text-center mb-12">
        <div className="flex justify-center mb-6">
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-400 to-indigo-500 rounded-full blur-xl opacity-40 animate-pulse"></div>
            <div className="relative bg-gradient-to-r from-blue-600 to-indigo-600 p-4 rounded-2xl shadow-xl">
              <FaFileContract className="text-white text-3xl sm:text-4xl" />
            </div>
          </div>
        </div>

        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4 text-gray-900">
          Digital Agreement Generator
        </h1>
        <p className="text-gray-600 max-w-2xl mx-auto text-sm sm:text-base">
          Generate legally compliant rental agreements instantly using AI.
          Customized for each Indian state with proper legal clauses.
        </p>

        {/* Trust Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-8 max-w-4xl mx-auto">
          {trustFeatures.map((feature, index) => (
            <div
              key={index}
              className="bg-white/80 backdrop-blur rounded-xl p-4 shadow-sm border border-gray-100 hover:shadow-md transition-all"
            >
              <feature.icon className="text-blue-600 text-xl mx-auto mb-2" />
              <h3 className="font-semibold text-gray-900 text-sm">{feature.text}</h3>
              <p className="text-gray-500 text-xs">{feature.subtext}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Main Card */}
      <div className="max-w-4xl mx-auto">
        <div className="bg-white rounded-3xl shadow-xl border border-gray-100 overflow-hidden">
          {/* Step Indicator */}
          <div className="bg-gradient-to-r from-blue-600 to-indigo-600 px-6 py-6">
            <div className="flex items-center justify-between text-white mb-4">
              <h2 className="text-lg font-semibold">
                {step === 1 && "Step 1: Party Details"}
                {step === 2 && "Step 2: Property Details"}
                {step === 3 && "Step 3: Agreement Terms"}
                {step === 4 && "Generated Agreement"}
              </h2>
              <span className="text-blue-100 text-sm">
                {step < 4 ? `${step}/3` : "Complete"}
              </span>
            </div>
            <StepIndicator />
          </div>

          {/* Form Content */}
          <div className="p-6 sm:p-8">
            {/* Login Notice */}
            {!isLoggedIn && (
              <div className="mb-6 p-4 bg-amber-50 border border-amber-200 rounded-xl flex items-center gap-3">
                <FaLock className="text-amber-500 flex-shrink-0" />
                <div className="flex-1">
                  <p className="text-amber-800 text-sm font-medium">Login Required</p>
                  <p className="text-amber-600 text-xs">Please login to generate agreements.</p>
                </div>
                <button
                  onClick={() => navigate("/login", { state: { from: "/agreements" } })}
                  className="px-4 py-2 bg-amber-500 text-white text-sm font-medium rounded-lg hover:bg-amber-600 transition-colors"
                >
                  Login
                </button>
              </div>
            )}

            {/* Step 1: Party Details */}
            {step === 1 && (
              <div className="space-y-6">
                {/* Landlord Section */}
                <div className="bg-blue-50 rounded-xl p-5 border border-blue-100">
                  <h3 className="flex items-center gap-2 font-semibold text-gray-800 mb-4">
                    <FaUser className="text-blue-600" />
                    {isMaharashtra ? "Licensor Details" : "Landlord Details"}
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Full Name *</label>
                      <input
                        type="text"
                        name="landlordName"
                        value={formData.landlordName}
                        onChange={handleChange}
                        placeholder="Enter full legal name"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Age *</label>
                      <input
                        type="number"
                        name="landlordAge"
                        value={formData.landlordAge}
                        onChange={handleChange}
                        placeholder="e.g., 35"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2 md:col-span-2">
                      <label className="text-sm font-medium text-gray-700">Permanent Address *</label>
                      <input
                        type="text"
                        name="landlordAddress"
                        value={formData.landlordAddress}
                        onChange={handleChange}
                        placeholder="Enter complete permanent address"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Phone Number</label>
                      <input
                        type="tel"
                        name="landlordPhone"
                        value={formData.landlordPhone}
                        onChange={handleChange}
                        placeholder="+91 XXXXXXXXXX"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Aadhaar (Last 4 digits)</label>
                      <input
                        type="text"
                        name="landlordAadhaar"
                        value={formData.landlordAadhaar}
                        onChange={handleChange}
                        placeholder="XXXX"
                        maxLength={4}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                  </div>
                </div>

                {/* Tenant Section */}
                <div className="bg-green-50 rounded-xl p-5 border border-green-100">
                  <h3 className="flex items-center gap-2 font-semibold text-gray-800 mb-4">
                    <FaUserCheck className="text-green-600" />
                    {isMaharashtra ? "Licensee Details" : "Tenant Details"}
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Full Name *</label>
                      <input
                        type="text"
                        name="tenantName"
                        value={formData.tenantName}
                        onChange={handleChange}
                        placeholder="Enter full legal name"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Age *</label>
                      <input
                        type="number"
                        name="tenantAge"
                        value={formData.tenantAge}
                        onChange={handleChange}
                        placeholder="e.g., 28"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2 md:col-span-2">
                      <label className="text-sm font-medium text-gray-700">Permanent Address *</label>
                      <input
                        type="text"
                        name="tenantAddress"
                        value={formData.tenantAddress}
                        onChange={handleChange}
                        placeholder="Enter complete permanent address"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Phone Number</label>
                      <input
                        type="tel"
                        name="tenantPhone"
                        value={formData.tenantPhone}
                        onChange={handleChange}
                        placeholder="+91 XXXXXXXXXX"
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-sm font-medium text-gray-700">Aadhaar (Last 4 digits)</label>
                      <input
                        type="text"
                        name="tenantAadhaar"
                        value={formData.tenantAadhaar}
                        onChange={handleChange}
                        placeholder="XXXX"
                        maxLength={4}
                        className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                      />
                    </div>
                  </div>
                </div>

                {/* Info Box */}
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
                  <FaInfoCircle className="text-amber-500 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-amber-700">
                    <p className="font-medium">Privacy Note</p>
                    <p className="text-amber-600">
                      Only the last 4 digits of Aadhaar are stored for reference. Full details should be verified during physical agreement signing.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Step 2: Property Details */}
            {step === 2 && (
              <div className="space-y-6">
                {/* State & City */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <FaMapMarkerAlt className="text-red-500" />
                      State *
                    </label>
                    <select
                      name="state"
                      value={formData.state}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      <option value="">Select State</option>
                      {INDIAN_STATES.map((state) => (
                        <option key={state} value={state}>
                          {state}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <FaBuilding className="text-purple-600" />
                      City *
                    </label>
                    <input
                      type="text"
                      name="city"
                      value={formData.city}
                      onChange={handleChange}
                      placeholder="Enter city name"
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>
                </div>

                {/* Property Address */}
                <div className="space-y-2">
                  <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                    <FaHome className="text-indigo-600" />
                    Complete Property Address *
                  </label>
                  <textarea
                    name="propertyAddress"
                    value={formData.propertyAddress}
                    onChange={handleChange}
                    placeholder="Enter complete address including flat no., building, street, landmark, PIN code"
                    rows={3}
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none resize-none"
                  />
                </div>

                {/* Property Type & BHK */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Property Type</label>
                    <select
                      name="propertyType"
                      value={formData.propertyType}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      <option value="Residential">Residential</option>
                      <option value="Commercial">Commercial</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">BHK Type</label>
                    <select
                      name="bhkType"
                      value={formData.bhkType}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      <option value="">Select BHK</option>
                      <option value="1 RK">1 RK</option>
                      <option value="1 BHK">1 BHK</option>
                      <option value="2 BHK">2 BHK</option>
                      <option value="3 BHK">3 BHK</option>
                      <option value="4 BHK">4 BHK</option>
                      <option value="4+ BHK">4+ BHK</option>
                      <option value="Independent House">Independent House</option>
                      <option value="Villa">Villa</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Furnishing</label>
                    <select
                      name="furnishing"
                      value={formData.furnishing}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      <option value="Unfurnished">Unfurnished</option>
                      <option value="Semi-Furnished">Semi-Furnished</option>
                      <option value="Fully Furnished">Fully Furnished</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Carpet Area (sq.ft)</label>
                    <input
                      type="number"
                      name="carpetArea"
                      value={formData.carpetArea}
                      onChange={handleChange}
                      placeholder="e.g., 850"
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>
                </div>

                {/* Maharashtra Notice */}
                {formData.state.toLowerCase() === "maharashtra" && (
                  <div className="bg-purple-50 border border-purple-200 rounded-xl p-4 flex items-start gap-3">
                    <FaGavel className="text-purple-500 mt-0.5 flex-shrink-0" />
                    <div className="text-sm text-purple-700">
                      <p className="font-medium">Maharashtra State</p>
                      <p className="text-purple-600">
                        For Maharashtra, a "Leave and License Agreement" will be generated
                        as per the Maharashtra Rent Control Act, 1999.
                      </p>
                    </div>
                  </div>
                )}

                {/* Karnataka Schedule of Property */}
                {formData.state.toLowerCase() === "karnataka" && (
                  <div className="bg-indigo-50 border border-indigo-200 rounded-xl p-4 space-y-3">
                    <div className="flex items-start gap-3">
                      <FaGavel className="text-indigo-500 mt-0.5 flex-shrink-0" />
                      <div className="text-sm text-indigo-800">
                        <p className="font-medium">Karnataka Schedule of Property</p>
                        <p className="text-indigo-700 text-xs sm:text-sm">
                          Karnataka agreements usually carry a clear boundary schedule. Please describe
                          what lies on each side of the property (East / West / North / South).
                        </p>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-2">
                      <div className="space-y-1">
                        <label className="text-xs sm:text-sm font-semibold text-gray-700">
                          East Boundary *
                        </label>
                        <input
                          type="text"
                          name="scheduleEast"
                          value={formData.scheduleEast}
                          onChange={handleChange}
                          placeholder="e.g., 30 ft road / Neighbor's house"
                          className="w-full px-3 py-2 rounded-lg border border-gray-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 text-sm outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs sm:text-sm font-semibold text-gray-700">
                          West Boundary *
                        </label>
                        <input
                          type="text"
                          name="scheduleWest"
                          value={formData.scheduleWest}
                          onChange={handleChange}
                          placeholder="e.g., Neighbor's compound wall"
                          className="w-full px-3 py-2 rounded-lg border border-gray-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 text-sm outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs sm:text-sm font-semibold text-gray-700">
                          North Boundary *
                        </label>
                        <input
                          type="text"
                          name="scheduleNorth"
                          value={formData.scheduleNorth}
                          onChange={handleChange}
                          placeholder="e.g., Open land / Park"
                          className="w-full px-3 py-2 rounded-lg border border-gray-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 text-sm outline-none"
                        />
                      </div>
                      <div className="space-y-1">
                        <label className="text-xs sm:text-sm font-semibold text-gray-700">
                          South Boundary *
                        </label>
                        <input
                          type="text"
                          name="scheduleSouth"
                          value={formData.scheduleSouth}
                          onChange={handleChange}
                          placeholder="e.g., Existing building"
                          className="w-full px-3 py-2 rounded-lg border border-gray-200 focus:border-indigo-500 focus:ring-2 focus:ring-indigo-100 text-sm outline-none"
                        />
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Step 3: Agreement Terms */}
            {step === 3 && (
              <div className="space-y-6">
                {/* Financial Details */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <FaRupeeSign className="text-green-600" />
                      Monthly Rent (INR) *
                    </label>
                    <input
                      type="number"
                      name="rentAmount"
                      value={formData.rentAmount}
                      onChange={handleChange}
                      placeholder="e.g., 25000"
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <FaShieldAlt className="text-blue-600" />
                      Security Deposit (INR) *
                    </label>
                    <input
                      type="number"
                      name="securityDeposit"
                      value={formData.securityDeposit}
                      onChange={handleChange}
                      placeholder="e.g., 50000"
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">
                      Maintenance Charges (INR)
                    </label>
                    <input
                      type="number"
                      name="maintenanceCharges"
                      value={formData.maintenanceCharges}
                      onChange={handleChange}
                      placeholder="e.g., 2000 (Optional)"
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>
                </div>

                {/* Duration & Dates */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                      <FaCalendarAlt className="text-orange-500" />
                      Start Date *
                    </label>
                    <input
                      type="date"
                      name="startDate"
                      value={formData.startDate}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    />
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Duration (Months)</label>
                    <select
                      name="durationMonths"
                      value={formData.durationMonths}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      {[6, 11, 12, 24, 36].map((m) => (
                        <option key={m} value={m}>
                          {m} months {m === 11 && "(Recommended)"}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Notice Period</label>
                    <select
                      name="noticePeriod"
                      value={formData.noticePeriod}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      <option value={1}>1 month</option>
                      <option value={2}>2 months</option>
                      <option value={3}>3 months</option>
                    </select>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-semibold text-gray-700">Rent Due Day</label>
                    <select
                      name="rentDueDay"
                      value={formData.rentDueDay}
                      onChange={handleChange}
                      className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none"
                    >
                      {[1, 5, 7, 10, 15].map((d) => (
                        <option key={d} value={d}>
                          {d}{d === 1 ? "st" : d === 5 ? "th" : d === 7 ? "th" : d === 10 ? "th" : "th"} of month
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Additional Terms */}
                <div className="space-y-2">
                  <label className="flex items-center gap-2 text-sm font-semibold text-gray-700">
                    <FaEdit className="text-gray-600" />
                    Additional Terms (Optional)
                  </label>
                  <textarea
                    name="additionalTerms"
                    value={formData.additionalTerms}
                    onChange={handleChange}
                    placeholder="Add any specific terms or conditions you want to include..."
                    rows={3}
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 transition-all outline-none resize-none"
                  />
                </div>

                {/* Tip */}
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex items-start gap-3">
                  <FaLightbulb className="text-amber-500 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-amber-700">
                    <p className="font-medium">Pro Tip</p>
                    <p className="text-amber-600">
                      11-month agreements are recommended as they don't require mandatory
                      registration under the Registration Act, 1908. However, registration
                      is still advisable for legal protection.
                    </p>
                  </div>
                </div>

                {/* Quick Review Summary */}
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 sm:p-5">
                  <h3 className="text-sm font-semibold text-slate-800 mb-3 flex items-center gap-2">
                    <FaEye className="text-blue-600" />
                    Review before you generate
                  </h3>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs sm:text-sm text-slate-700">
                    <div className="space-y-1">
                      <p className="font-semibold text-slate-900">Parties</p>
                      <p>
                        <span className="font-medium">Landlord:&nbsp;</span>
                        {formData.landlordName || "â€”"}
                      </p>
                      <p>
                        <span className="font-medium">Tenant:&nbsp;</span>
                        {formData.tenantName || "â€”"}
                      </p>
                      <p>
                        <span className="font-medium">State / City:&nbsp;</span>
                        {formData.state || "â€”"} {formData.city && `â€¢ ${formData.city}`}
                      </p>
                    </div>
                    <div className="space-y-1">
                      <p className="font-semibold text-slate-900">Key Terms</p>
                      <p>
                        <span className="font-medium">Rent:&nbsp;</span>
                        {formData.rentAmount
                          ? `â‚¹${Number(formData.rentAmount).toLocaleString("en-IN")}`
                          : "â€”"}
                      </p>
                      <p>
                        <span className="font-medium">Deposit:&nbsp;</span>
                        {formData.securityDeposit
                          ? `â‚¹${Number(formData.securityDeposit).toLocaleString("en-IN")}`
                          : "â€”"}
                      </p>
                      <p>
                        <span className="font-medium">Start / Duration:&nbsp;</span>
                        {formData.startDate || "â€”"}
                        {formData.durationMonths && ` â€¢ ${formData.durationMonths} months`}
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Step 4: Generated Agreement */}
            {step === 4 && generatedAgreement && (
              <div className="space-y-6">
                {/* Metadata */}
                <div className="bg-gradient-to-r from-green-50 to-emerald-50 border border-green-200 rounded-xl p-5">
                  <div className="flex items-center gap-2 text-green-700 font-semibold mb-4">
                    <FaCheckCircle className="text-xl" />
                    Agreement Generated Successfully
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 text-sm">
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Type</p>
                      <p className="font-semibold text-gray-900 text-xs">{generatedAgreement.metadata?.agreementType || 'Rental Agreement'}</p>
                    </div>
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Duration</p>
                      <p className="font-semibold text-gray-900">{generatedAgreement.metadata?.duration || `${formData.durationMonths} months`}</p>
                    </div>
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Monthly Rent</p>
                      <p className="font-semibold text-green-700">â‚¹{Number(formData.rentAmount).toLocaleString('en-IN')}</p>
                    </div>
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Deposit</p>
                      <p className="font-semibold text-blue-700">â‚¹{Number(formData.securityDeposit).toLocaleString('en-IN')}</p>
                    </div>
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Start Date</p>
                      <p className="font-semibold text-gray-900">{generatedAgreement.metadata?.startDate || formData.startDate}</p>
                    </div>
                    <div className="bg-white/60 rounded-lg p-3">
                      <p className="text-gray-500 text-xs mb-1">Location</p>
                      <p className="font-semibold text-gray-900">{generatedAgreement.metadata?.city || formData.city}</p>
                    </div>
                  </div>
                </div>

                {/* Action Buttons */}
                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={downloadAsPDF}
                    className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-red-600 to-rose-600 text-white rounded-xl hover:from-red-700 hover:to-rose-700 transition-all shadow-lg shadow-red-500/30 font-medium"
                  >
                    <FaFilePdf /> Download PDF
                  </button>
                  <button
                    onClick={copyToClipboard}
                    className="flex items-center gap-2 px-4 py-2 bg-gray-100 text-gray-700 rounded-xl hover:bg-gray-200 transition-colors"
                  >
                    <FaCopy /> Copy
                  </button>
                  <button
                    onClick={printAgreement}
                    className="flex items-center gap-2 px-4 py-2 bg-blue-100 text-blue-700 rounded-xl hover:bg-blue-200 transition-colors"
                  >
                    <FaPrint /> Print
                  </button>
                  <button
                    onClick={downloadAsText}
                    className="flex items-center gap-2 px-4 py-2 bg-green-100 text-green-700 rounded-xl hover:bg-green-200 transition-colors"
                  >
                    <FaDownload /> Text File
                  </button>
                  <button
                    onClick={resetForm}
                    className="flex items-center gap-2 px-4 py-2 bg-orange-100 text-orange-700 rounded-xl hover:bg-orange-200 transition-colors"
                  >
                    <FaRedo /> New Agreement
                  </button>
                </div>

                {/* Agreement Content */}
                <div
                  ref={agreementRef}
                  className="bg-white border-2 border-gray-300 rounded-xl p-8 sm:p-10 max-h-[600px] overflow-y-auto shadow-inner"
                  style={{
                    fontFamily: "'Times New Roman', Georgia, serif",
                    lineHeight: "1.8",
                    fontSize: "14px",
                    color: "#1a1a1a",
                  }}
                >
                  <ReactMarkdown
                    components={{
                      h1: ({ children }) => (
                        <h1 className="text-xl font-bold text-center uppercase tracking-wide border-b-2 border-gray-800 pb-3 mb-6 mt-6">
                          {children}
                        </h1>
                      ),
                      h2: ({ children }) => (
                        <h2 className="text-lg font-bold uppercase border-b border-gray-300 pb-2 mt-6 mb-3">
                          {children}
                        </h2>
                      ),
                      h3: ({ children }) => (
                        <h3 className="text-base font-bold mt-4 mb-2">{children}</h3>
                      ),
                      p: ({ children }) => (
                        <p className="text-justify mb-3 leading-relaxed">{children}</p>
                      ),
                      strong: ({ children }) => (
                        <strong className="font-bold text-gray-900">{children}</strong>
                      ),
                      em: ({ children }) => (
                        <em className="italic">{children}</em>
                      ),
                      ul: ({ children }) => (
                        <ul className="list-disc ml-6 mb-3 space-y-1">{children}</ul>
                      ),
                      ol: ({ children }) => (
                        <ol className="list-decimal ml-6 mb-3 space-y-1">{children}</ol>
                      ),
                      li: ({ children }) => (
                        <li className="mb-1">{children}</li>
                      ),
                      hr: () => (
                        <hr className="border-t border-gray-300 my-6" />
                      ),
                      blockquote: ({ children }) => (
                        <blockquote className="bg-amber-50 border-l-4 border-amber-500 pl-4 py-3 my-4 italic">
                          {children}
                        </blockquote>
                      ),
                    }}
                  >
                    {generatedAgreement.agreement}
                  </ReactMarkdown>
                </div>
              </div>
            )}

            {/* Navigation Buttons */}
            {step < 4 && (
              <div className="flex justify-between mt-8 pt-6 border-t border-gray-100">
                <button
                  onClick={prevStep}
                  disabled={step === 1}
                  className="flex items-center gap-2 px-6 py-3 bg-gray-100 text-gray-700 rounded-xl hover:bg-gray-200 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <FaArrowLeft /> Previous
                </button>

                {step < 3 ? (
                  <button
                    onClick={nextStep}
                    className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-blue-600 to-indigo-600 text-white rounded-xl hover:from-blue-700 hover:to-indigo-700 transition-all shadow-lg shadow-blue-500/30"
                  >
                    Next <FaArrowRight />
                  </button>
                ) : (
                  <button
                    onClick={generateAgreement}
                    disabled={loading || !isLoggedIn}
                    className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-green-600 to-emerald-600 text-white rounded-xl hover:from-green-700 hover:to-emerald-700 transition-all shadow-lg shadow-green-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {loading ? (
                      <>
                        <FaSpinner className="animate-spin" /> Generating...
                      </>
                    ) : (
                      <>
                        <FaMagic /> Generate Agreement
                      </>
                    )}
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Footer Disclaimer */}
      <div className="max-w-4xl mx-auto mt-8 text-center">
        <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
          <p className="text-amber-800 text-xs sm:text-sm">
            <strong>âš–ï¸ Legal Disclaimer:</strong> This is an AI-generated draft for informational purposes only.
            Please verify with a qualified lawyer and ensure proper stamp paper and registration as per the Registration Act, 1908.
          </p>
        </div>
      </div>
    </div>
  );
}

export default AgreementGenerator;