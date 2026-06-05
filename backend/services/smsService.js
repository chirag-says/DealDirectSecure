/**
 * Equence SMS Service
 * Integrates with Equence Technologies Pvt Ltd HTTPS SMS API (api.equence.in)
 * 
 * API Docs: Equence SMS API Reference Document v1.0
 * API Format: POST https://api.equence.in/pushsms (JSON)
 * 
 * Required ENV variables:
 *   EQUENCE_USERNAME       - Your Equence account username
 *   EQUENCE_PASSWORD       - Your Equence account password
 *   EQUENCE_SENDER_ID      - Your approved 6-char Sender ID (registered on DLT platform)
 *   EQUENCE_PE_ID          - Principal Entity ID (DLT registration number)
 *   EQUENCE_OTP_TMPL_ID    - DLT Template ID for OTP messages
 *   EQUENCE_RESET_TMPL_ID  - DLT Template ID for password reset messages
 *   EQUENCE_BASE_URL       - API base URL (default: https://api.equence.in/pushsms)
 */

// ============================================
// CONFIGURATION
// ============================================

// Read config at call time (not import time) to ensure dotenv has loaded
const getEquenceConfig = () => ({
    username: process.env.EQUENCE_USERNAME,
    password: process.env.EQUENCE_PASSWORD,
    senderId: process.env.EQUENCE_SENDER_ID || 'DEALDR',
    peId: process.env.EQUENCE_PE_ID || '',
    baseUrl: process.env.EQUENCE_BASE_URL || 'https://api.equence.in/pushsms',

    // DLT Template IDs
    templates: {
        otp: {
            tmplId: process.env.EQUENCE_OTP_TMPL_ID || '',
        },
        passwordReset: {
            tmplId: process.env.EQUENCE_RESET_TMPL_ID || '',
        },
    },
});


// ============================================
// VALIDATION
// ============================================

/**
 * Check if Equence SMS service is configured
 */
export const isSmsConfigured = () => {
    const config = getEquenceConfig();
    const configured = !!(config.username && config.password && config.senderId && config.peId);
    if (!configured) {
        console.log('[SMS DEBUG] username:', config.username ? '✅ set' : '❌ empty');
        console.log('[SMS DEBUG] password:', config.password ? '✅ set' : '❌ empty');
        console.log('[SMS DEBUG] senderId:', config.senderId ? '✅ set' : '❌ empty');
        console.log('[SMS DEBUG] peId:', config.peId ? '✅ set' : '❌ empty');
    }
    return configured;
};


/**
 * Validate and format Indian mobile number
 * Accepts: 9876543210, 09876543210, 919876543210, +919876543210
 * Returns: 919876543210 (12 digits with 91 prefix — as required by Equence API)
 */
const formatMobileNumber = (phone) => {
    if (!phone) return null;

    // Remove spaces, dashes, and + prefix
    let cleaned = phone.toString().replace(/[\s\-\+]/g, '');

    // Remove leading 0
    if (cleaned.startsWith('0')) {
        cleaned = cleaned.substring(1);
    }

    // Add country code if not present (10-digit Indian mobile)
    if (cleaned.length === 10 && /^[6-9]\d{9}$/.test(cleaned)) {
        cleaned = '91' + cleaned;
    }

    // Validate final format (12 digits starting with 91)
    if (!/^91[6-9]\d{9}$/.test(cleaned)) {
        return null;
    }

    return cleaned;
};

// ============================================
// CORE SMS SENDING FUNCTION
// ============================================

/**
 * Send SMS via Equence HTTPS JSON POST API
 * 
 * Uses the JSON API format:
 *   POST https://api.equence.in/pushsms
 *   Content-Type: application/json
 *   Body: { username, password, peId, tmplId, to, from, text }
 * 
 * Response format:
 *   Success: {"response":[{"destination":"91...","mrid":"87...","segment":0,"status":"Success"}]}
 *   Error:   {"errorCode":400,"message":"...","status":"Failed"}
 * 
 * @param {string} mobile - Recipient mobile number
 * @param {string} message - Message text (must match DLT approved template)
 * @param {string} tmplId - DLT Template ID (mandatory)
 * @returns {Promise<{success: boolean, data?: any, error?: string, mrid?: string}>}
 */
export const sendSms = async (mobile, message, tmplId) => {
    try {
        // Validate configuration
        if (!isSmsConfigured()) {
            console.warn('[SMS] Equence is not configured. Set EQUENCE_USERNAME, EQUENCE_PASSWORD, EQUENCE_SENDER_ID, and EQUENCE_PE_ID in .env');
            return { success: false, error: 'SMS service not configured' };
        }

        // Format and validate mobile number
        const formattedMobile = formatMobileNumber(mobile);
        if (!formattedMobile) {
            console.error('[SMS] Invalid mobile number:', mobile);
            return { success: false, error: 'Invalid mobile number' };
        }

        if (!tmplId) {
            console.error('[SMS] DLT Template ID (tmplId) is required');
            return { success: false, error: 'Template ID is required' };
        }

        const config = getEquenceConfig();

        // Build JSON POST body as per Equence API spec
        const requestBody = {
            username: config.username,
            password: config.password,
            peId: config.peId,
            tmplId: tmplId,
            to: formattedMobile,
            from: config.senderId,
            text: message,
        };

        const maskedMobile = `${formattedMobile.slice(0, 4)}****${formattedMobile.slice(-2)}`;
        console.log(`[SMS] Sending SMS to ${maskedMobile} via Equence API`);

        // Make HTTPS POST request
        const response = await fetch(config.baseUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify(requestBody),
        });

        const responseText = await response.text();

        // Try to parse as JSON, fallback to text
        let responseData;
        try {
            responseData = JSON.parse(responseText);
        } catch {
            responseData = { raw: responseText };
        }


        // Check for Equence API error response format
        if (responseData.errorCode || responseData.status === 'Failed') {
            console.error('[SMS] ❌ Equence API error:', responseData);
            return {
                success: false,
                error: responseData.message || `API error code: ${responseData.errorCode}`,
                data: responseData,
            };
        }

        // Check for successful response format
        if (responseData.response && Array.isArray(responseData.response)) {
            const result = responseData.response[0];
            if (result && (result.status === 'Success' || result.status === 'success' || result.dispatch === 'success')) {
                console.log('[SMS] ✅ SMS sent successfully:', {
                    destination: result.destination,
                    mrid: result.mrid || result.mrId,
                    status: result.status || result.dispatch,
                });
                return {
                    success: true,
                    data: responseData,
                    mrid: result.mrid || result.mrId,
                };
            } else {
                console.error('[SMS] ❌ SMS delivery failed:', result);
                return {
                    success: false,
                    error: `SMS delivery status: ${result?.status || 'unknown'}`,
                    data: responseData,
                };
            }
        }

        // Fallback: if HTTP response is OK but format is unexpected
        if (response.ok) {
            console.log('[SMS] ✅ SMS sent (unrecognized response format):', responseData);
            return { success: true, data: responseData };
        } else {
            console.error('[SMS] ❌ SMS sending failed:', response.status, responseData);
            return { success: false, error: `API returned HTTP ${response.status}`, data: responseData };
        }
    } catch (error) {
        console.error('[SMS] ❌ SMS sending error:', error.message);
        return { success: false, error: error.message };
    }
};

// ============================================
// OTP SMS FUNCTIONS
// ============================================

/**
 * Send OTP via SMS for registration verification
 * 
 * IMPORTANT: The message text MUST exactly match your DLT-approved template.
 * DLT template: "Thank you for choosing DealDirect! Your OTP for registration is {#var#}. Valid for 10 minutes. Please do not share this code with anyone. - DealDirect"
 * 
 * @param {string} phone - Recipient phone number
 * @param {string} otp - The OTP code
 * @param {string} name - User's name (unused in current template, kept for API compatibility)
 */
export const sendOtpSms = async (phone, otp, name = 'User') => {
    const message = `Thank you for choosing DealDirect! Your OTP for registration is ${otp}. Valid for 10 minutes. Please do not share this code with anyone. - DealDirect`;

    return sendSms(
        phone,
        message,
        getEquenceConfig().templates.otp.tmplId
    );
};

/**
 * Send password reset OTP via SMS
 * 
 * IMPORTANT: The message text MUST exactly match your DLT-approved template.
 * DLT template: "Thank you for using DealDirect! Your OTP for password reset is {#var#}. Valid for 10 minutes. Please do not share this code with anyone. - DealDirect"
 * 
 * @param {string} phone - Recipient phone number
 * @param {string} otp - The OTP code
 * @param {string} name - User's name (unused in current template, kept for API compatibility)
 */
export const sendPasswordResetSms = async (phone, otp, name = 'User') => {
    const config = getEquenceConfig();
    const tmplId = config.templates.passwordReset.tmplId;

    const message = `Thank you for using DealDirect! Your OTP for password reset is ${otp}. Valid for 10 minutes. Please do not share this code with anyone. - DealDirect`;

    return sendSms(
        phone,
        message,
        tmplId
    );
};

/**
 * Send a generic SMS (for custom use cases like notifications)
 * 
 * @param {string} phone - Recipient phone number
 * @param {string} message - Message text (must match a DLT template)
 * @param {string} tmplId - DLT Template ID
 */
export const sendGenericSms = async (phone, message, tmplId) => {
    return sendSms(phone, message, tmplId);
};

// Default export
export default {
    sendSms,
    sendOtpSms,
    sendPasswordResetSms,
    sendGenericSms,
    isSmsConfigured,
};
