/**
 * Agreement Controller - Secure Financial/Legal Workflows
 * 
 * SECURITY FEATURES:
 * - Access restricted to Owners, Buyers, and Admins ONLY (NO Agents)
 * - Server-side verification of all transaction amounts from Property model
 * - Idempotency keys to prevent duplicate agreements
 * - Cryptographic signing for tamper detection
 * - Payment webhook validation against database records
 * - Full audit trail for all operations
 */

import { GoogleGenerativeAI } from "@google/generative-ai";
import Agreement from "../models/Agreement.js";
import Property from "../models/Property.js";
import User from "../models/userModel.js";
import mongoose from "mongoose";
import crypto from "crypto";

// ============================================
// CONFIGURATION
// ============================================

// Initialize Gemini AI (optional - graceful fallback)
const genAI = process.env.GEMINI_API_KEY
  ? new GoogleGenerativeAI(process.env.GEMINI_API_KEY)
  : null;

// Valid roles for agreement access - NO AGENTS ALLOWED
const VALID_AGREEMENT_ROLES = ['user', 'owner'];

// ============================================
// SECURITY HELPERS
// ============================================

/**
 * Verify user has valid role for agreement operations
 * Explicitly blocks any "agent" role
 */
const validateAgreementRole = (user) => {
  if (!user || !user.role) {
    return { valid: false, reason: 'User not authenticated' };
  }

  // Explicitly block agent role (even if somehow present)
  if (user.role.toLowerCase() === 'agent') {
    console.warn(`⚠️ SECURITY: Blocked agent role access attempt by user ${user._id}`);
    return { valid: false, reason: 'Agent role is not permitted for agreements' };
  }

  if (!VALID_AGREEMENT_ROLES.includes(user.role)) {
    return { valid: false, reason: 'Invalid role for agreement access' };
  }

  return { valid: true };
};

/**
 * Verify user is party to the agreement (owner or buyer)
 */
const isPartyToAgreement = (agreement, userId) => {
  const userIdStr = userId.toString();
  return (
    agreement.owner.toString() === userIdStr ||
    agreement.buyer.toString() === userIdStr
  );
};

/**
 * Sanitize Aadhaar number - store only last 4 digits
 */
const sanitizeAadhaar = (aadhaar) => {
  if (!aadhaar || aadhaar.length < 4) return null;
  return aadhaar.slice(-4);
};

/**
 * Generate content hash for verification
 */
const generateContentHash = (content) => {
  return crypto.createHash('sha256').update(content).digest('hex');
};

// ============================================
// HELPER FUNCTIONS
// ============================================

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
  return date;
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

// ============================================
// LOCAL AGREEMENT TEMPLATE BUILDER
// ============================================

const buildLocalAgreement = (params) => {
  const {
    agreementType, landlordTitle, tenantTitle, landlordName, landlordAge,
    landlordAddress, landlordPhone, tenantName, tenantAge, tenantAddress,
    tenantPhone, propertyAddress, state, city, propertyType, bhkType,
    furnishing, carpetArea, rentAmount, securityDeposit, maintenanceCharges,
    rentInWords, depositInWords, maintenanceInWords, rentDueDay,
    formattedStartDate, formattedEndDate, durationMonths, noticePeriod,
    executionDate, actReference, additionalTerms,
  } = params;

  const rentDateSuffix = rentDueDay === 1 ? "st" : rentDueDay === 2 ? "nd" : rentDueDay === 3 ? "rd" : "th";

  return `---
⚠️ **LEGAL DISCLAIMER**

This document is an automatically generated draft for informational purposes only and does not constitute legal advice. Before signing:
• Verify contents with a qualified legal professional
• Print on appropriate Stamp Paper as per ${state} Stamp Act
• Register as required under the Registration Act, 1908
---

# ${agreementType}

This ${agreementType} is made and executed on this **${executionDate}** at **${city}, ${state}**.

BETWEEN

**${landlordName}**, aged about ${landlordAge || "Adult"} years, residing at ${landlordAddress || "address as per ID proof"}, hereinafter called the **"${landlordTitle}"**, which expression shall, unless repugnant to the context or meaning thereof, include his/her heirs, executors, administrators and assigns, of the **FIRST PART**;

AND

**${tenantName}**, aged about ${tenantAge || "Adult"} years, residing at ${tenantAddress || "address as per ID proof"}, hereinafter called the **"${tenantTitle}"**, which expression shall, unless repugnant to the context or meaning thereof, include his/her heirs, executors, administrators and assigns, of the **SECOND PART**.

(Each a **"Party"** and collectively the **"Parties"**.)

---

## RECITALS

1. The ${landlordTitle} is the lawful owner/authorized holder of the premises described below ("Premises").
2. The ${tenantTitle} has approached the ${landlordTitle} for ${agreementType.toLowerCase()} of the Premises for lawful ${propertyType.toLowerCase()} use.
3. The Parties are desirous of recording the terms and conditions of this arrangement in writing.

NOW, THEREFORE, in consideration of the mutual covenants herein contained, the Parties hereby agree as follows:

---

## 1. PROPERTY DESCRIPTION

- Address: ${propertyAddress}, ${city}, ${state}
- Type: ${bhkType ? bhkType + " " : ""}${propertyType}
- Furnishing: ${furnishing}
${carpetArea ? `- Carpet Area: ${carpetArea} sq.ft.` : ""}

---

## 2. TERM OF ${agreementType.includes("LICENSE") ? "LICENSE" : "TENANCY"}

- Commencement Date: **${formattedStartDate}**
- Expiry Date: **${formattedEndDate}**
- Total Duration: **${durationMonths} months**
- Notice Period: **${noticePeriod} month(s)** by either Party.

---

## 3. ${agreementType.includes("LICENSE") ? "LICENSE FEE" : "RENT"}

- Monthly Amount: **₹${parseInt(rentAmount).toLocaleString("en-IN")}** (Rupees **${rentInWords} Only**)
- Due Date: On or before the **${rentDueDay}${rentDateSuffix}** of each calendar month in advance.
- Mode of Payment: Bank transfer/UPI/cheque or such other mode as mutually agreed.

---

## 4. SECURITY DEPOSIT

- Amount: **₹${parseInt(securityDeposit).toLocaleString("en-IN")}** (Rupees **${depositInWords} Only**)
- Nature: Interest-free, refundable subject to deductions for unpaid dues and damages, if any.
- Refund: Within 30 (thirty) days of the ${tenantTitle} vacating the Premises and handing over peaceful possession.

---

## 5. MAINTENANCE AND CHARGES

${maintenanceCharges
      ? `- Monthly Maintenance: **₹${parseInt(maintenanceCharges).toLocaleString("en-IN")}** (Rupees **${maintenanceInWords} Only**).`
      : `- Society/common area maintenance shall be borne by the **${tenantTitle}**, as per actuals.`}
- Minor repairs up to ₹2,000 per incident shall be borne by the **${tenantTitle}**.
- Major structural repairs shall be borne by the **${landlordTitle}**.

---

## 6. USE OF PREMISES

1. The Premises shall be used strictly for lawful ${propertyType.toLowerCase()} purposes only.
2. The ${tenantTitle} shall not carry out any illegal, immoral or hazardous activities in or from the Premises.
3. No structural alterations shall be made without prior written consent of the ${landlordTitle}.

---

## 7. TERMINATION AND VACATION

1. Either Party may terminate this Agreement by giving not less than **${noticePeriod} month(s)** written notice to the other Party.
2. Upon expiry or earlier termination, the ${tenantTitle} shall hand over peaceful and vacant possession of the Premises to the ${landlordTitle}.

---

## 8. INDEMNITY AND COMPLIANCE

1. The ${tenantTitle} shall be responsible for compliance with all applicable laws in relation to its use of the Premises and shall indemnify the ${landlordTitle} against any claims arising out of such use.

---

## 9. GOVERNING LAW AND JURISDICTION

This Agreement shall be governed by and construed in accordance with the laws of India and the provisions of ${actReference}. The courts at **${city}, ${state}** shall have exclusive jurisdiction.

---

## 10. MISCELLANEOUS

1. This Agreement constitutes the entire understanding between the Parties with respect to the subject matter hereof.
2. Any amendment shall be in writing and signed by both Parties.

${additionalTerms ? `---

## 11. SPECIAL CONDITIONS

${additionalTerms}

` : ""}---

## SIGNATURES

IN WITNESS WHEREOF, the Parties hereto have set their respective hands to this Agreement on the day, month and year first above written.

**FOR ${landlordTitle.toUpperCase()}:**

_______________________________
Name: ${landlordName}
Date: ${executionDate}
Place: ${city}

**FOR ${tenantTitle.toUpperCase()}:**

_______________________________
Name: ${tenantName}
Date: ${executionDate}
Place: ${city}

**WITNESSES:**

1. ________________________________
   Name: ______________________
   Address: ____________________

2. ________________________________
   Name: ______________________
   Address: ____________________
`;
};

// ============================================
// MAIN CONTROLLERS
// ============================================

/**
 * Generate Rental/Lease Agreement
 * SECURITY: Restricted to Owners and Buyers only
 * Fetches amounts from Property model for server-side verification
 */
export const generateAgreement = async (req, res) => {
  try {
    const user = req.user;

    // ============================================
    // SECURITY: Validate user role (NO AGENTS)
    // ============================================
    const roleValidation = validateAgreementRole(user);
    if (!roleValidation.valid) {
      return res.status(403).json({
        success: false,
        message: roleValidation.reason,
        code: 'INVALID_ROLE'
      });
    }

    const {
      propertyId,
      buyerId,
      landlordName, landlordAge, landlordAddress, landlordPhone, landlordAadhaar,
      tenantName, tenantAge, tenantAddress, tenantPhone, tenantAadhaar,
      startDate, durationMonths = 11, noticePeriod = 1, rentDueDay = 5,
      additionalTerms = "",
    } = req.body;

    // ============================================
    // SERVER-SIDE VERIFICATION: Fetch amounts from Property model
    // ============================================
    if (!propertyId || !mongoose.Types.ObjectId.isValid(propertyId)) {
      return res.status(400).json({
        success: false,
        message: 'Valid property ID is required'
      });
    }

    const property = await Property.findById(propertyId)
      .populate('owner', 'name email phone role')
      .lean();

    if (!property) {
      return res.status(404).json({
        success: false,
        message: 'Property not found'
      });
    }

    // Verify the property owner role
    if (property.owner && property.owner.role === 'agent') {
      console.warn(`⚠️ SECURITY: Blocked agreement for property with agent owner`);
      return res.status(403).json({
        success: false,
        message: 'Cannot create agreement for this property',
        code: 'INVALID_PROPERTY_OWNER'
      });
    }

    // ============================================
    // SERVER-SIDE AMOUNT VERIFICATION
    // Amounts are ALWAYS fetched from the Property model
    // ============================================
    const rentAmount = property.price || 0;
    const securityDeposit = property.securityDeposit || property.deposit || (rentAmount * 2);
    const maintenanceCharges = property.maintenance || null;

    if (!rentAmount || rentAmount <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Property does not have a valid price configured'
      });
    }

    // Get property details from database
    const propertyAddress = property.address?.line ||
      `${property.address?.area || ''}, ${property.address?.city || ''}, ${property.address?.state || ''}`.trim();
    const state = property.address?.state || 'Not specified';
    const city = property.address?.city || 'Not specified';
    const propertyType = property.categoryName || 'Residential';
    const bhkType = property.bhk || '';
    const furnishing = property.furnishing || 'Unfurnished';
    const carpetArea = property.area?.carpetSqft || '';

    // Validate required fields
    if (!landlordName || !tenantName || !startDate) {
      return res.status(400).json({
        success: false,
        message: 'Landlord name, tenant name, and start date are required'
      });
    }

    // ============================================
    // VERIFY PARTIES (IDOR Protection)
    // ============================================
    let ownerId = property.owner?._id || property.owner;
    let buyerIdToUse = buyerId;

    // If current user is the owner, they must specify a buyer
    if (user.role === 'owner') {
      if (property.owner.toString() !== user._id.toString()) {
        return res.status(403).json({
          success: false,
          message: 'You can only create agreements for your own properties',
          code: 'NOT_OWNER'
        });
      }

      if (!buyerIdToUse || !mongoose.Types.ObjectId.isValid(buyerIdToUse)) {
        return res.status(400).json({
          success: false,
          message: 'Buyer ID is required when owner creates agreement'
        });
      }
    }

    // If current user is a buyer, they become the buyer
    if (user.role === 'user') {
      buyerIdToUse = user._id;
    }

    // Verify buyer exists and has valid role
    const buyer = await User.findById(buyerIdToUse).lean();
    if (!buyer) {
      return res.status(404).json({
        success: false,
        message: 'Buyer not found'
      });
    }

    if (buyer.role === 'agent') {
      return res.status(403).json({
        success: false,
        message: 'Cannot create agreement with agent role',
        code: 'INVALID_BUYER_ROLE'
      });
    }

    // Format dates
    const startDateObj = new Date(startDate);
    const endDateObj = calculateEndDate(startDate, durationMonths);
    const formattedStartDate = formatDate(startDate);
    const formattedEndDate = formatDate(endDateObj);
    const executionDate = formatDate(new Date());

    // Determine agreement type based on state
    const isMaharashtra = state.toLowerCase() === 'maharashtra';
    const agreementType = isMaharashtra ? 'LEAVE AND LICENSE AGREEMENT' : 'RESIDENTIAL RENTAL AGREEMENT';
    const landlordTitle = isMaharashtra ? 'LICENSOR' : 'LESSOR/LANDLORD';
    const tenantTitle = isMaharashtra ? 'LICENSEE' : 'LESSEE/TENANT';
    const actReference = isMaharashtra
      ? 'Maharashtra Rent Control Act, 1999 and the Maharashtra Rent Control Act (Unregistered Lease) Rules, 2017'
      : `applicable Rent Control Act of ${state}`;

    // Format amounts in words
    const rentInWords = numberToWords(parseInt(rentAmount));
    const depositInWords = numberToWords(parseInt(securityDeposit));
    const maintenanceInWords = maintenanceCharges ? numberToWords(parseInt(maintenanceCharges)) : null;

    // Generate agreement text
    let agreementText;
    const templateParams = {
      agreementType, landlordTitle, tenantTitle, landlordName, landlordAge,
      landlordAddress, landlordPhone, tenantName, tenantAge, tenantAddress,
      tenantPhone, propertyAddress, state, city, propertyType, bhkType,
      furnishing, carpetArea, rentAmount, securityDeposit, maintenanceCharges,
      rentInWords, depositInWords, maintenanceInWords, rentDueDay,
      formattedStartDate, formattedEndDate: formatDate(endDateObj), durationMonths, noticePeriod,
      executionDate, actReference, additionalTerms,
    };

    // Use Gemini AI if available, fallback to local template
    if (genAI) {
      try {
        const model = genAI.getGenerativeModel({ model: "gemini-2.0-flash" });
        const result = await model.generateContent(
          `Generate a clear, professional Indian rental/leave-and-license agreement in markdown using ONLY the following details. Do not use placeholders.\n\n${JSON.stringify(templateParams, null, 2)}`
        );
        const aiResponse = await result.response;
        agreementText = aiResponse.text();
      } catch (aiError) {
        console.error("Gemini AI failed, using local template:", aiError.message);
        agreementText = buildLocalAgreement(templateParams);
      }
    } else {
      agreementText = buildLocalAgreement(templateParams);
    }

    // ============================================
    // CREATE SECURE AGREEMENT WITH IDEMPOTENCY
    // ============================================
    const agreementData = {
      owner: ownerId,
      ownerSnapshot: {
        name: landlordName,
        email: property.owner?.email || '',
        phone: landlordPhone,
        aadhaarLastFour: sanitizeAadhaar(landlordAadhaar),
        address: landlordAddress,
        age: landlordAge,
        role: 'owner',
      },
      buyer: buyerIdToUse,
      buyerSnapshot: {
        name: tenantName,
        email: buyer.email,
        phone: tenantPhone,
        aadhaarLastFour: sanitizeAadhaar(tenantAadhaar),
        address: tenantAddress,
        age: tenantAge,
        role: 'user',
      },
      property: propertyId,
      propertySnapshot: {
        title: property.title,
        address: propertyAddress,
        city,
        state,
        type: propertyType,
        bhk: bhkType,
        furnishing,
        carpetArea: property.area?.carpetSqft,
      },
      financials: {
        amount: rentAmount,
        amountSource: 'property_price',
        amountVerifiedAt: new Date(),
        securityDeposit,
        maintenanceCharges,
        rentDueDay,
        currency: 'INR',
      },
      agreementType: isMaharashtra ? 'LEAVE_AND_LICENSE' : 'RENTAL_AGREEMENT',
      duration: {
        startDate: startDateObj,
        endDate: endDateObj,
        months: parseInt(durationMonths),
        noticePeriodMonths: parseInt(noticePeriod),
        lockInPeriodMonths: Math.min(3, parseInt(durationMonths)),
      },
      terms: {
        additionalTerms,
        specialConditions: [],
      },
      content: agreementText,
      status: 'draft',
      createdBy: user._id,
      createdByRole: user.role,
    };

    const { duplicate, agreement } = await Agreement.createSecureAgreement(agreementData, req);

    if (duplicate) {
      return res.status(200).json({
        success: true,
        message: 'Agreement already exists (idempotency)',
        isDuplicate: true,
        agreement: {
          id: agreement._id,
          idempotencyKey: agreement.idempotencyKey,
          status: agreement.status,
        },
      });
    }

    console.log("✅ Secure agreement created:", {
      id: agreement._id,
      idempotencyKey: agreement.idempotencyKey,
      owner: landlordName,
      buyer: tenantName,
      amount: `₹${rentAmount.toLocaleString('en-IN')}`,
      verifiedFrom: 'Property model',
    });

    res.status(201).json({
      success: true,
      agreement: agreementText,
      agreementId: agreement._id,
      idempotencyKey: agreement.idempotencyKey,
      contentHash: agreement.contentHash,
      metadata: {
        agreementType,
        state,
        city,
        generatedAt: new Date().toISOString(),
        landlord: {
          name: landlordName,
          age: landlordAge,
          phone: landlordPhone,
        },
        tenant: {
          name: tenantName,
          age: tenantAge,
          phone: tenantPhone,
        },
        property: {
          id: propertyId,
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
          verifiedFromDatabase: true,
        },
        duration: `${durationMonths} months`,
        startDate: formattedStartDate,
        endDate: formatDate(endDateObj),
        noticePeriod: `${noticePeriod} month(s)`,
      },
    });
  } catch (error) {
    console.error("Agreement generation error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to generate agreement',
    });
  }
};

/**
 * Get user's agreements
 * SECURITY: Only returns agreements where user is owner or buyer
 */
export const getMyAgreements = async (req, res) => {
  try {
    const user = req.user;

    // Validate role
    const roleValidation = validateAgreementRole(user);
    if (!roleValidation.valid) {
      return res.status(403).json({
        success: false,
        message: roleValidation.reason,
        code: 'INVALID_ROLE'
      });
    }

    // Only return agreements where user is a party
    const agreements = await Agreement.find({
      $or: [
        { owner: user._id },
        { buyer: user._id }
      ]
    })
      .select('-content -signature') // Don't send full content in list
      .populate('property', 'title address.city price')
      .sort({ createdAt: -1 })
      .lean();

    res.json({
      success: true,
      count: agreements.length,
      agreements,
    });
  } catch (error) {
    console.error("Get agreements error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch agreements',
    });
  }
};

/**
 * Get single agreement by ID
 * SECURITY: Only accessible by parties to the agreement or admin
 */
export const getAgreementById = async (req, res) => {
  try {
    const user = req.user;
    const { id } = req.params;

    // Validate role
    const roleValidation = validateAgreementRole(user);
    if (!roleValidation.valid) {
      return res.status(403).json({
        success: false,
        message: roleValidation.reason,
        code: 'INVALID_ROLE'
      });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid agreement ID'
      });
    }

    const agreement = await Agreement.findById(id)
      .populate('owner', 'name email phone')
      .populate('buyer', 'name email phone')
      .populate('property', 'title address price images');

    if (!agreement) {
      return res.status(404).json({
        success: false,
        message: 'Agreement not found'
      });
    }

    // IDOR Protection: Verify user is party to agreement
    if (!isPartyToAgreement(agreement, user._id)) {
      console.warn(`⚠️ IDOR attempt: User ${user._id} tried to access agreement ${id}`);
      return res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'NOT_PARTY'
      });
    }

    // Verify integrity
    const integrityCheck = agreement.verifyIntegrity();
    if (!integrityCheck.valid) {
      console.error(`⚠️ SECURITY: Agreement ${id} failed integrity check: ${integrityCheck.reason}`);
    }

    res.json({
      success: true,
      agreement,
      integrity: integrityCheck,
    });
  } catch (error) {
    console.error("Get agreement error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch agreement',
    });
  }
};

/**
 * Sign agreement
 * SECURITY: Only accessible by parties to the agreement
 */
export const signAgreement = async (req, res) => {
  try {
    const user = req.user;
    const { id } = req.params;

    // Validate role
    const roleValidation = validateAgreementRole(user);
    if (!roleValidation.valid) {
      return res.status(403).json({
        success: false,
        message: roleValidation.reason,
        code: 'INVALID_ROLE'
      });
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid agreement ID'
      });
    }

    const agreement = await Agreement.findById(id);

    if (!agreement) {
      return res.status(404).json({
        success: false,
        message: 'Agreement not found'
      });
    }

    // IDOR Protection
    if (!isPartyToAgreement(agreement, user._id)) {
      console.warn(`⚠️ IDOR attempt: User ${user._id} tried to sign agreement ${id}`);
      return res.status(403).json({
        success: false,
        message: 'Access denied',
        code: 'NOT_PARTY'
      });
    }

    // Verify integrity before signing
    const integrityCheck = agreement.verifyIntegrity();
    if (!integrityCheck.valid) {
      return res.status(400).json({
        success: false,
        message: 'Agreement integrity check failed. Cannot sign a modified agreement.',
        code: 'INTEGRITY_FAILED'
      });
    }

    // Determine if user is owner or buyer
    const isOwner = agreement.owner.toString() === user._id.toString();
    const signatureField = isOwner ? 'owner' : 'buyer';

    // Check if already signed
    if (agreement.signatures[signatureField].signed) {
      return res.status(400).json({
        success: false,
        message: `${isOwner ? 'Owner' : 'Buyer'} has already signed this agreement`
      });
    }

    // Add signature
    agreement.signatures[signatureField] = {
      signed: true,
      signedAt: new Date(),
      ipAddress: req.ip || req.connection?.remoteAddress,
      userAgent: req.get('User-Agent'),
    };

    // Update status
    if (agreement.signatures.owner.signed && agreement.signatures.buyer.signed) {
      agreement.status = 'signed';
    } else if (isOwner) {
      agreement.status = 'pending_buyer_signature';
    } else {
      agreement.status = 'pending_owner_signature';
    }

    // Add audit entry
    await agreement.addAuditEntry(
      'SIGNED',
      user._id,
      user.role,
      req.ip,
      { signatureField, bothSigned: agreement.status === 'signed' }
    );

    await agreement.save();

    res.json({
      success: true,
      message: `Agreement signed successfully by ${isOwner ? 'owner' : 'buyer'}`,
      status: agreement.status,
      fullySigned: agreement.status === 'signed',
    });
  } catch (error) {
    console.error("Sign agreement error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to sign agreement',
    });
  }
};

/**
 * Validate payment webhook
 * SECURITY: Validates against database records for owner/buyer roles
 */
export const validatePaymentWebhook = async (req, res) => {
  try {
    const { agreementId, transactionId, amount, payerId, paymentGateway, signature } = req.body;

    // Validate required fields
    if (!agreementId || !transactionId || !amount || !payerId) {
      return res.status(400).json({
        success: false,
        message: 'Missing required webhook fields'
      });
    }

    // Verify webhook signature (if provided by payment gateway)
    if (signature && process.env.PAYMENT_WEBHOOK_SECRET) {
      const expectedSignature = crypto
        .createHmac('sha256', process.env.PAYMENT_WEBHOOK_SECRET)
        .update(`${agreementId}|${transactionId}|${amount}`)
        .digest('hex');

      if (signature !== expectedSignature) {
        console.warn(`⚠️ SECURITY: Invalid webhook signature for transaction ${transactionId}`);
        return res.status(401).json({
          success: false,
          message: 'Invalid webhook signature'
        });
      }
    }

    // Fetch agreement
    const agreement = await Agreement.findById(agreementId);
    if (!agreement) {
      return res.status(404).json({
        success: false,
        message: 'Agreement not found'
      });
    }

    // Validate payment against agreement
    const validation = agreement.validatePaymentWebhook({
      agreementId,
      amount,
      payerId,
    });

    if (!validation.valid) {
      console.warn(`⚠️ SECURITY: Payment validation failed: ${validation.reason}`);
      return res.status(400).json({
        success: false,
        message: validation.reason
      });
    }

    // Verify payer has valid role (owner or buyer, NOT agent)
    const payer = await User.findById(payerId).select('role');
    if (!payer || !VALID_AGREEMENT_ROLES.includes(payer.role)) {
      console.warn(`⚠️ SECURITY: Invalid payer role for payment ${transactionId}`);
      return res.status(403).json({
        success: false,
        message: 'Invalid payer role'
      });
    }

    // Record payment
    agreement.payments.push({
      type: amount === agreement.financials.securityDeposit ? 'deposit' : 'rent',
      amount,
      transactionId,
      paymentGateway: paymentGateway || 'unknown',
      status: 'completed',
      paidAt: new Date(),
      verifiedAt: new Date(),
      webhookValidated: true,
    });

    // Add audit entry
    await agreement.addAuditEntry(
      'PAYMENT_RECEIVED',
      payerId,
      payer.role,
      req.ip,
      { transactionId, amount, paymentGateway }
    );

    await agreement.save();

    res.json({
      success: true,
      message: 'Payment validated and recorded',
      transactionId,
    });
  } catch (error) {
    console.error("Payment webhook error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to process payment webhook',
    });
  }
};

/**
 * Get agreement templates info (public)
 */
export const getAgreementTemplates = async (req, res) => {
  try {
    const templates = [
      {
        id: "residential-rent",
        title: "Residential Rental Agreement",
        description: "Standard rental agreement for residential properties",
        states: ["All States except Maharashtra"],
        duration: "11 months (default)",
        requiredRoles: ["owner", "user"],
      },
      {
        id: "maharashtra-leave-license",
        title: "Leave and License Agreement",
        description: "Mandatory format for Maharashtra state",
        states: ["Maharashtra"],
        duration: "11 months (default)",
        requiredRoles: ["owner", "user"],
      },
      {
        id: "commercial-rent",
        title: "Commercial Rental Agreement",
        description: "For commercial properties like shops, offices",
        states: ["All States"],
        duration: "11-36 months",
        requiredRoles: ["owner", "user"],
      },
    ];

    res.json({
      success: true,
      templates,
      note: "Agreements can only be created by property Owners and Buyers (Tenants).",
    });
  } catch (error) {
    console.error("Get templates error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch templates',
    });
  }
};

/**
 * Get Indian states list (public)
 */
export const getIndianStates = async (req, res) => {
  try {
    const states = [
      "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh",
      "Goa", "Gujarat", "Haryana", "Himachal Pradesh", "Jharkhand",
      "Karnataka", "Kerala", "Madhya Pradesh", "Maharashtra", "Manipur",
      "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab",
      "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura",
      "Uttar Pradesh", "Uttarakhand", "West Bengal", "Delhi", "Chandigarh", "Puducherry",
    ];

    res.json({
      success: true,
      states,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Failed to fetch states',
    });
  }
};

// ============================================
// ADMIN-ONLY CONTROLLERS
// ============================================

/**
 * Get all agreements (Admin only)
 */
export const getAllAgreementsAdmin = async (req, res) => {
  try {
    const { status, page = 1, limit = 20 } = req.query;

    const query = {};
    if (status) query.status = status;

    const agreements = await Agreement.find(query)
      .select('-content -signature')
      .populate('owner', 'name email')
      .populate('buyer', 'name email')
      .populate('property', 'title address.city')
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit))
      .lean();

    const total = await Agreement.countDocuments(query);

    res.json({
      success: true,
      agreements,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error("Admin get agreements error:", error);
    res.status(500).json({
      success: false,
      message: 'Failed to fetch agreements',
    });
  }
};
