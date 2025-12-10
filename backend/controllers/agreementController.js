import { GoogleGenerativeAI } from "@google/generative-ai";

// Initialize Gemini AI (optional - we will gracefully fall back if not configured or fails)
const genAI = process.env.GEMINI_API_KEY
  ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
  : null;

// Format date to Indian format
const formatDate = (dateString) => {
  const date = new Date(dateString);
  const options = { day: 'numeric', month: 'long', year: 'numeric' };
  return date.toLocaleDateString('en-IN', options);
};

// Calculate end date
const calculateEndDate = (startDate, months) => {
  const date = new Date(startDate);
  date.setMonth(date.getMonth() + parseInt(months));
  date.setDate(date.getDate() - 1);
  return formatDate(date);
};

// Simple local agreement generator used as a fallback when Gemini is unavailable
const buildLocalAgreement = ({
  agreementType,
  landlordTitle,
  tenantTitle,
  landlordName,
  landlordAge,
  landlordAddress,
  landlordPhone,
  landlordAadhaar,
  tenantName,
  tenantAge,
  tenantAddress,
  tenantPhone,
  tenantAadhaar,
  propertyAddress,
  state,
  city,
  propertyType,
  bhkType,
  furnishing,
  carpetArea,
  rentAmount,
  securityDeposit,
  maintenanceCharges,
  rentInWords,
  depositInWords,
  maintenanceInWords,
  rentDueDay,
  formattedStartDate,
  formattedEndDate,
  durationMonths,
  noticePeriod,
  executionDate,
  actReference,
  additionalTerms,
}) => {
  const rentDateSuffix =
    rentDueDay === 1 ? "st" : rentDueDay === 2 ? "nd" : rentDueDay === 3 ? "rd" : "th";

  return `---\n⚠️ **LEGAL DISCLAIMER**\n\nThis document is an automatically generated draft for informational purposes only and does not constitute legal advice. Before signing:\n• Verify contents with a qualified legal professional\n• Print on appropriate Stamp Paper as per ${state} Stamp Act\n• Register as required under the Registration Act, 1908\n---\n\n# ${agreementType}\n\nThis ${agreementType} is made and executed on this **${executionDate}** at **${city}, ${state}**.\n\nBETWEEN\n\n**${landlordName}**, aged about ${landlordAge || "Adult"} years, residing at ${landlordAddress || "address as per ID proof"}, hereinafter called the **\"${landlordTitle}\"**, which expression shall, unless repugnant to the context or meaning thereof, include his/her heirs, executors, administrators and assigns, of the **FIRST PART**;\n\nAND\n\n**${tenantName}**, aged about ${tenantAge || "Adult"} years, residing at ${tenantAddress || "address as per ID proof"}, hereinafter called the **\"${tenantTitle}\"**, which expression shall, unless repugnant to the context or meaning thereof, include his/her heirs, executors, administrators and assigns, of the **SECOND PART**.\n\n(Each a **\"Party\"** and collectively the **\"Parties\"**.)\n\n---\n\n## RECITALS\n\n1. The ${landlordTitle} is the lawful owner/authorized holder of the premises described below (\"Premises\").\n2. The ${tenantTitle} has approached the ${landlordTitle} for ${agreementType.toLowerCase()} of the Premises for lawful ${propertyType.toLowerCase()} use.\n3. The Parties are desirous of recording the terms and conditions of this arrangement in writing.\n\nNOW, THEREFORE, in consideration of the mutual covenants herein contained, the Parties hereby agree as follows:\n\n---\n\n## 1. PROPERTY DESCRIPTION\n\n- Address: ${propertyAddress}, ${city}, ${state}\n- Type: ${bhkType ? bhkType + " " : ""}${propertyType}\n- Furnishing: ${furnishing}\n${carpetArea ? `- Carpet Area: ${carpetArea} sq.ft.` : ""}\n\n---\n\n## 2. TERM OF ${agreementType.includes("LICENSE") ? "LICENSE" : "TENANCY"}\n\n- Commencement Date: **${formattedStartDate}**\n- Expiry Date: **${formattedEndDate}**\n- Total Duration: **${durationMonths} months**\n- Notice Period: **${noticePeriod} month(s)** by either Party.\n\n---\n\n## 3. ${agreementType.includes("LICENSE") ? "LICENSE FEE" : "RENT"}\n\n- Monthly Amount: **₹${parseInt(rentAmount).toLocaleString("en-IN")}** (Rupees **${rentInWords} Only**)\n- Due Date: On or before the **${rentDueDay}${rentDateSuffix}** of each calendar month in advance.\n- Mode of Payment: Bank transfer/UPI/cheque or such other mode as mutually agreed.\n\n---\n\n## 4. SECURITY DEPOSIT\n\n- Amount: **₹${parseInt(securityDeposit).toLocaleString("en-IN")}** (Rupees **${depositInWords} Only**)\n- Nature: Interest-free, refundable subject to deductions for unpaid dues and damages, if any.\n- Refund: Within 30 (thirty) days of the ${tenantTitle} vacating the Premises and handing over peaceful possession.\n\n---\n\n## 5. MAINTENANCE AND CHARGES\n\n$${maintenanceCharges
    ? `- Monthly Maintenance: **₹${parseInt(maintenanceCharges).toLocaleString("en-IN")}** (Rupees **${maintenanceInWords} Only**).`
    : `- Society/common area maintenance shall be borne by the **${tenantTitle}**, as per actuals.`}\n- Minor repairs up to ₹2,000 per incident shall be borne by the **${tenantTitle}**.\n- Major structural repairs shall be borne by the **${landlordTitle}**.\n\n---\n\n## 6. USE OF PREMISES\n\n1. The Premises shall be used strictly for lawful ${propertyType.toLowerCase()} purposes only.\n2. The ${tenantTitle} shall not carry out any illegal, immoral or hazardous activities in or from the Premises.\n3. No structural alterations shall be made without prior written consent of the ${landlordTitle}.\n\n---\n\n## 7. TERMINATION AND VACATION\n\n1. Either Party may terminate this Agreement by giving not less than **${noticePeriod} month(s)** written notice to the other Party.\n2. Upon expiry or earlier termination, the ${tenantTitle} shall hand over peaceful and vacant possession of the Premises to the ${landlordTitle}.\n\n---\n\n## 8. INDEMNITY AND COMPLIANCE\n\n1. The ${tenantTitle} shall be responsible for compliance with all applicable laws in relation to its use of the Premises and shall indemnify the ${landlordTitle} against any claims arising out of such use.\n\n---\n\n## 9. GOVERNING LAW AND JURISDICTION\n\nThis Agreement shall be governed by and construed in accordance with the laws of India and the provisions of ${actReference}. The courts at **${city}, ${state}** shall have exclusive jurisdiction.\n\n---\n\n## 10. MISCELLANEOUS\n\n1. This Agreement constitutes the entire understanding between the Parties with respect to the subject matter hereof.\n2. Any amendment shall be in writing and signed by both Parties.\n\n$${additionalTerms ? `---\n\n## 11. SPECIAL CONDITIONS\n\n${additionalTerms}\n\n` : ""}---\n\n## SIGNATURES\n\nIN WITNESS WHEREOF, the Parties hereto have set their respective hands to this Agreement on the day, month and year first above written.\n\n**FOR ${landlordTitle.toUpperCase()}:**\n\n_______________________________\nName: ${landlordName}\nDate: ${executionDate}\nPlace: ${city}\n\n**FOR ${tenantTitle.toUpperCase()}:**\n\n_______________________________\nName: ${tenantName}\nDate: ${executionDate}\nPlace: ${city}\n\n**WITNESSES:**\n\n1. ________________________________\n   Name: ______________________\n   Address: ____________________\n\n2. ________________________________\n   Name: ______________________\n   Address: ____________________\n`;
};

// Generate Rental/Lease Agreement
export const generateAgreement = async (req, res) => {
  try {
    const {
      landlordName,
      landlordAge,
      landlordAddress,
      landlordPhone,
      landlordAadhaar,
      tenantName,
      tenantAge,
      tenantAddress,
      tenantPhone,
      tenantAadhaar,
      propertyAddress,
      state,
      city,
      rentAmount,
      securityDeposit,
      maintenanceCharges,
      startDate,
      durationMonths = 11,
      noticePeriod = 1,
      rentDueDay = 5,
      propertyType = "Residential",
      bhkType = "",
      furnishing = "Unfurnished",
      carpetArea = "",
      additionalTerms = "",
    } = req.body;

    // Validate required fields
    if (!landlordName || !tenantName || !propertyAddress || !state || !city || !rentAmount || !securityDeposit || !startDate) {
      return res.status(400).json({
        success: false,
        message: "All required fields must be provided",
      });
    }

    // Format dates
    const formattedStartDate = formatDate(startDate);
    const formattedEndDate = calculateEndDate(startDate, durationMonths);
    const executionDate = formatDate(new Date());

    // Determine agreement type based on state
    const isMaharashtra = state.toLowerCase() === "maharashtra";
    const agreementType = isMaharashtra ? "LEAVE AND LICENSE AGREEMENT" : "RESIDENTIAL RENTAL AGREEMENT";
    const landlordTitle = isMaharashtra ? "LICENSOR" : "LESSOR/LANDLORD";
    const tenantTitle = isMaharashtra ? "LICENSEE" : "LESSEE/TENANT";
    const actReference = isMaharashtra 
      ? "Maharashtra Rent Control Act, 1999 and the Maharashtra Rent Control Act (Unregistered Lease) Rules, 2017" 
      : `applicable Rent Control Act of ${state}`;

    // Format amounts in words
    const rentInWords = numberToWords(parseInt(rentAmount));
    const depositInWords = numberToWords(parseInt(securityDeposit));
    const maintenanceInWords = maintenanceCharges ? numberToWords(parseInt(maintenanceCharges)) : null;
    let agreementText;

    // Prefer Gemini AI when available, but fall back to local template on error
    if (genAI) {
      try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
        const result = await model.generateContent(`Generate a clear, professional Indian rental/leave-and-license agreement in markdown using ONLY the following details. Do not use placeholders.\n\n${JSON.stringify(
          {
            agreementType,
            landlordTitle,
            tenantTitle,
            landlordName,
            landlordAge,
            landlordAddress,
            landlordPhone,
            landlordAadhaar,
            tenantName,
            tenantAge,
            tenantAddress,
            tenantPhone,
            tenantAadhaar,
            propertyAddress,
            state,
            city,
            propertyType,
            bhkType,
            furnishing,
            carpetArea,
            rentAmount,
            securityDeposit,
            maintenanceCharges,
            rentInWords,
            depositInWords,
            maintenanceInWords,
            rentDueDay,
            formattedStartDate,
            formattedEndDate,
            durationMonths,
            noticePeriod,
            executionDate,
            actReference,
            additionalTerms,
          },
          null,
          2
        )}`);
        const aiResponse = await result.response;
        agreementText = aiResponse.text();
      } catch (aiError) {
        console.error("Gemini agreement generation failed, using local template:", aiError);
        agreementText = buildLocalAgreement({
          agreementType,
          landlordTitle,
          tenantTitle,
          landlordName,
          landlordAge,
          landlordAddress,
          landlordPhone,
          landlordAadhaar,
          tenantName,
          tenantAge,
          tenantAddress,
          tenantPhone,
          tenantAadhaar,
          propertyAddress,
          state,
          city,
          propertyType,
          bhkType,
          furnishing,
          carpetArea,
          rentAmount,
          securityDeposit,
          maintenanceCharges,
          rentInWords,
          depositInWords,
          maintenanceInWords,
          rentDueDay,
          formattedStartDate,
          formattedEndDate,
          durationMonths,
          noticePeriod,
          executionDate,
          actReference,
          additionalTerms,
        });
      }
    } else {
      console.warn("GEMINI_API_KEY not configured, using local agreement template.");
      agreementText = buildLocalAgreement({
        agreementType,
        landlordTitle,
        tenantTitle,
        landlordName,
        landlordAge,
        landlordAddress,
        landlordPhone,
        landlordAadhaar,
        tenantName,
        tenantAge,
        tenantAddress,
        tenantPhone,
        tenantAadhaar,
        propertyAddress,
        state,
        city,
        propertyType,
        bhkType,
        furnishing,
        carpetArea,
        rentAmount,
        securityDeposit,
        maintenanceCharges,
        rentInWords,
        depositInWords,
        maintenanceInWords,
        rentDueDay,
        formattedStartDate,
        formattedEndDate,
        durationMonths,
        noticePeriod,
        executionDate,
        actReference,
        additionalTerms,
      });
    }

    console.log("Agreement generated successfully for:", {
      landlord: landlordName,
      tenant: tenantName,
      state,
      type: agreementType,
    });

    res.json({
      success: true,
      agreement: agreementText,
      metadata: {
        agreementType,
        state,
        city,
        generatedAt: new Date().toISOString(),
        landlord: {
          name: landlordName,
          age: landlordAge,
          address: landlordAddress,
          phone: landlordPhone,
        },
        tenant: {
          name: tenantName,
          age: tenantAge,
          address: tenantAddress,
          phone: tenantPhone,
        },
        property: {
          address: propertyAddress,
          type: propertyType,
          bhkType,
          furnishing,
          carpetArea,
        },
        financial: {
          rent: rentAmount,
          rentFormatted: `₹${parseInt(rentAmount).toLocaleString('en-IN')}`,
          deposit: securityDeposit,
          depositFormatted: `₹${parseInt(securityDeposit).toLocaleString('en-IN')}`,
          maintenance: maintenanceCharges || null,
          rentDueDay,
        },
        duration: `${durationMonths} months`,
        startDate: formattedStartDate,
        endDate: formattedEndDate,
        noticePeriod: `${noticePeriod} month(s)`,
        lockInPeriod: `${Math.min(3, parseInt(durationMonths))} months`,
      },
    });
  } catch (error) {
    console.error("Agreement generation error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to generate agreement",
      error: error.message,
    });
  }
};

// Convert number to words (Indian format)
function numberToWords(num) {
  if (num === 0) return 'Zero';
  
  const ones = ['', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight', 'Nine',
    'Ten', 'Eleven', 'Twelve', 'Thirteen', 'Fourteen', 'Fifteen', 'Sixteen', 'Seventeen', 'Eighteen', 'Nineteen'];
  const tens = ['', '', 'Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy', 'Eighty', 'Ninety'];
  
  function convertLessThanThousand(n) {
    if (n === 0) return '';
    if (n < 20) return ones[n];
    if (n < 100) return tens[Math.floor(n / 10)] + (n % 10 ? ' ' + ones[n % 10] : '');
    return ones[Math.floor(n / 100)] + ' Hundred' + (n % 100 ? ' ' + convertLessThanThousand(n % 100) : '');
  }
  
  if (num < 1000) return convertLessThanThousand(num);
  if (num < 100000) {
    return convertLessThanThousand(Math.floor(num / 1000)) + ' Thousand' + 
      (num % 1000 ? ' ' + convertLessThanThousand(num % 1000) : '');
  }
  if (num < 10000000) {
    return convertLessThanThousand(Math.floor(num / 100000)) + ' Lakh' + 
      (num % 100000 ? ' ' + numberToWords(num % 100000) : '');
  }
  return convertLessThanThousand(Math.floor(num / 10000000)) + ' Crore' + 
    (num % 10000000 ? ' ' + numberToWords(num % 10000000) : '');
}

// Get agreement templates info
export const getAgreementTemplates = async (req, res) => {
  try {
    const templates = [
      {
        id: "residential-rent",
        title: "Residential Rental Agreement",
        description: "Standard rental agreement for residential properties",
        states: ["All States except Maharashtra"],
        duration: "11 months (default)",
      },
      {
        id: "maharashtra-leave-license",
        title: "Leave and License Agreement",
        description: "Mandatory format for Maharashtra state",
        states: ["Maharashtra"],
        duration: "11 months (default)",
      },
      {
        id: "commercial-rent",
        title: "Commercial Rental Agreement",
        description: "For commercial properties like shops, offices",
        states: ["All States"],
        duration: "11-36 months",
      },
    ];

    res.json({
      success: true,
      templates,
    });
  } catch (error) {
    console.error("Get templates error:", error);
    res.status(500).json({
      success: false,
      message: "Failed to fetch templates",
    });
  }
};

// Indian states list for dropdown
export const getIndianStates = async (req, res) => {
  try {
    const states = [
      "Andhra Pradesh",
      "Arunachal Pradesh",
      "Assam",
      "Bihar",
      "Chhattisgarh",
      "Goa",
      "Gujarat",
      "Haryana",
      "Himachal Pradesh",
      "Jharkhand",
      "Karnataka",
      "Kerala",
      "Madhya Pradesh",
      "Maharashtra",
      "Manipur",
      "Meghalaya",
      "Mizoram",
      "Nagaland",
      "Odisha",
      "Punjab",
      "Rajasthan",
      "Sikkim",
      "Tamil Nadu",
      "Telangana",
      "Tripura",
      "Uttar Pradesh",
      "Uttarakhand",
      "West Bengal",
      "Delhi",
      "Chandigarh",
      "Puducherry",
    ];

    res.json({
      success: true,
      states,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Failed to fetch states",
    });
  }
};
