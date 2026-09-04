/**
 * WhatsApp Notification Service (WAHA API)
 * Integrates with WAHA (WhatsApp HTTP API) hosted on Railway
 *
 * API Endpoint: POST /api/sendText
 * Auth: X-Api-Key header
 *
 * Required ENV variables:
 *   WAHA_API_URL     - Base URL of the WAHA instance (e.g. https://your-instance.up.railway.app)
 *   WAHA_API_KEY     - API key for authentication
 *   WAHA_SESSION     - Session name (default: "default")
 *   WAHA_ADMIN_PHONE - Admin/owner phone number to receive notifications (e.g. 919876543210)
 */

// ============================================
// CONFIGURATION
// ============================================

// ============================================
// PROVIDER SELECTION (Phase 0, F5)
//
// WHATSAPP_PROVIDER=meta routes every user-facing send through Meta's Cloud
// API (the official Business Platform). WAHA stays available for the admin
// alerts (sendAdminWhatsAppNotification) and as the default where Meta is not
// configured, so nothing changes until the env says so. The exported
// functions keep their signatures; callers cannot tell which provider ran.
// ============================================

const getMetaConfig = () => ({
    phoneNumberId: process.env.META_WA_PHONE_NUMBER_ID || '',
    accessToken: process.env.META_WA_ACCESS_TOKEN || '',
    apiVersion: process.env.META_WA_API_VERSION || 'v20.0',
    baseUrl: process.env.META_WA_BASE_URL || 'https://graph.facebook.com',
});

export const isMetaConfigured = () => {
    const c = getMetaConfig();
    return !!(c.phoneNumberId && c.accessToken);
};

export const activeProvider = () => {
    const wanted = (process.env.WHATSAPP_PROVIDER || '').toLowerCase();
    if (wanted === 'meta') return isMetaConfigured() ? 'meta' : 'none';
    if (wanted === 'waha') return isWhatsAppConfigured() ? 'waha' : 'none';
    if (isMetaConfigured()) return 'meta';
    return isWhatsAppConfigured() ? 'waha' : 'none';
};

/**
 * Send through Meta's Cloud API. Free-form text is only delivered inside the
 * 24-hour customer-service window; outside it Meta requires an approved
 * template, which is what `template` is for. Callers that do not pass one get
 * the text send, which is correct for replies and best-effort for alerts
 * until the templates are approved.
 */
const sendViaMeta = async (phone, text, template) => {
    const config = getMetaConfig();
    const chatId = formatChatId(phone);
    if (!chatId) return { success: false, error: 'Invalid phone number' };
    const to = chatId.replace('@c.us', '');

    const body = template
        ? {
            messaging_product: 'whatsapp',
            to,
            type: 'template',
            template: {
                name: template.name,
                language: { code: template.language || 'en' },
                components: template.params?.length
                    ? [{ type: 'body', parameters: template.params.map((p) => ({ type: 'text', text: String(p) })) }]
                    : [],
            },
        }
        : { messaging_product: 'whatsapp', to, type: 'text', text: { body: text, preview_url: true } };

    const url = `${config.baseUrl.replace(/\/+$/, '')}/${config.apiVersion}/${config.phoneNumberId}/messages`;
    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.accessToken}` },
            body: JSON.stringify(body),
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok) return { success: true, data, provider: 'meta' };
        console.error('[WhatsApp][meta] send failed:', response.status, data?.error?.message || data);
        return { success: false, error: data?.error?.message || `API returned HTTP ${response.status}`, data };
    } catch (error) {
        console.error('[WhatsApp][meta] error:', error.message);
        return { success: false, error: error.message };
    }
};

const getWahaConfig = () => ({
    apiUrl: process.env.WAHA_API_URL || '',
    apiKey: process.env.WAHA_API_KEY || '',
    session: process.env.WAHA_SESSION || 'default',
    adminPhone: process.env.WAHA_ADMIN_PHONE || '',
});

// ============================================
// VALIDATION
// ============================================

/**
 * Check if WAHA WhatsApp service is configured
 */
export const isWhatsAppConfigured = () => {
    const config = getWahaConfig();
    const configured = !!(config.apiUrl && config.apiKey);
    if (!configured && process.env.NODE_ENV !== 'production') {
        console.log('[WhatsApp DEBUG] apiUrl:', config.apiUrl ? '✅ set' : '❌ empty');
        console.log('[WhatsApp DEBUG] apiKey:', config.apiKey ? '✅ set' : '❌ empty');
    }
    return configured;
};

/**
 * Format phone number to WhatsApp chat ID format
 * Accepts: 9876543210, 09876543210, 919876543210, +919876543210
 * Returns: 919876543210@c.us
 */
const formatChatId = (phone) => {
    if (!phone) return null;

    // If already in chatId format, return as-is
    if (phone.includes('@c.us')) return phone;

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

    // Validate final format (should be digits, at least 10)
    if (!/^\d{10,15}$/.test(cleaned)) {
        return null;
    }

    return `${cleaned}@c.us`;
};

// ============================================
// CORE WHATSAPP SENDING FUNCTION
// ============================================

/**
 * Send a WhatsApp text message via WAHA API
 *
 * @param {string} phone - Recipient phone number (any Indian format)
 * @param {string} text  - Message text to send
 * @returns {Promise<{success: boolean, data?: any, error?: string}>}
 */
export const sendWhatsAppMessage = async (phone, text, { template } = {}) => {
    try {
        const provider = activeProvider();
        if (provider === 'meta') return sendViaMeta(phone, text, template);
        if (provider === 'none') {
            console.warn('[WhatsApp] No provider configured (WAHA_* or META_WA_*)');
            return { success: false, error: 'WhatsApp service not configured' };
        }
        // Validate configuration
        if (!isWhatsAppConfigured()) {
            console.warn('[WhatsApp] WAHA is not configured. Set WAHA_API_URL and WAHA_API_KEY in .env');
            return { success: false, error: 'WhatsApp service not configured' };
        }

        // Format phone number to chatId
        const chatId = formatChatId(phone);
        if (!chatId) {
            console.error('[WhatsApp] Invalid phone number:', phone);
            return { success: false, error: 'Invalid phone number' };
        }

        const config = getWahaConfig();
        const url = `${config.apiUrl.replace(/\/+$/, '')}/api/sendText`;

        const requestBody = {
            chatId,
            reply_to: null,
            text,
            linkPreview: true,
            linkPreviewHighQuality: false,
            session: config.session,
        };

        const maskedPhone = chatId.replace('@c.us', '').replace(/(\d{4})\d{4}(\d+)/, '$1****$2');
        console.log(`[WhatsApp] Sending message to ${maskedPhone}`);

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-Api-Key': config.apiKey,
            },
            body: JSON.stringify(requestBody),
        });

        const responseText = await response.text();

        let responseData;
        try {
            responseData = JSON.parse(responseText);
        } catch {
            responseData = { raw: responseText };
        }

        if (response.ok) {
            console.log('[WhatsApp] ✅ Message sent successfully to', maskedPhone);
            return { success: true, data: responseData };
        } else {
            console.error('[WhatsApp] ❌ Message sending failed:', response.status, responseData);
            return {
                success: false,
                error: responseData.message || `API returned HTTP ${response.status}`,
                data: responseData,
            };
        }
    } catch (error) {
        console.error('[WhatsApp] ❌ Error sending message:', error.message);
        return { success: false, error: error.message };
    }
};

// ============================================
// NOTIFICATION HELPER FUNCTIONS
// ============================================

/**
 * Send a WhatsApp notification to the admin/business owner
 * Uses WAHA_ADMIN_PHONE from env
 */
export const sendAdminWhatsAppNotification = async (text) => {
    const config = getWahaConfig();
    if (!config.adminPhone) {
        console.warn('[WhatsApp] Admin phone (WAHA_ADMIN_PHONE) not configured. Skipping admin notification.');
        return { success: false, error: 'Admin phone not configured' };
    }
    return sendWhatsAppMessage(config.adminPhone, text);
};

/**
 * Notify property owner when someone shows interest (new lead)
 *
 * @param {string} ownerPhone - Property owner's phone number
 * @param {object} leadData   - { name, email, phone }
 * @param {object} propertyData - { title, price, listingType, city, locality }
 */
export const sendNewLeadWhatsApp = async (ownerPhone, leadData, propertyData) => {
    const priceFormatted = propertyData.price
        ? `₹${Number(propertyData.price).toLocaleString('en-IN')}`
        : 'N/A';
    const rentSuffix = propertyData.listingType === 'Rent' ? '/month' : '';
    const location = [propertyData.locality, propertyData.city].filter(Boolean).join(', ');

    const message = `🏠 *New Lead Alert — DealDirect*

Someone is interested in your property!

*Property:* ${propertyData.title || 'N/A'}
*Price:* ${priceFormatted}${rentSuffix}
*Location:* ${location || 'N/A'}

*Lead Details:*
👤 ${leadData.name || 'N/A'}
📧 ${leadData.email || 'N/A'}
📞 ${leadData.phone || 'Not provided'}

💡 _Respond quickly for better conversions!_
🔗 View leads: https://dealdirect.in/my-properties`;

    // Send to property owner
    const ownerResult = ownerPhone
        ? await sendWhatsAppMessage(ownerPhone, message)
        : { success: false, error: 'Owner phone not available' };

    // Also notify admin
    const adminMessage = `📋 *New Lead (Admin Copy)*

*Property:* ${propertyData.title || 'N/A'}
*Location:* ${location || 'N/A'}
*Price:* ${priceFormatted}${rentSuffix}

*Lead:* ${leadData.name || 'N/A'} — ${leadData.phone || 'N/A'}
*Owner notified:* ${ownerResult.success ? '✅' : '❌'}`;

    sendAdminWhatsAppNotification(adminMessage).catch(err =>
        console.error('[WhatsApp] Admin notification error:', err.message)
    );

    return ownerResult;
};

/**
 * Notify admin about a new contact inquiry
 *
 * @param {object} inquiryData - { userName, userEmail, userPhone, subject, message, category }
 */
export const sendContactInquiryWhatsApp = async (inquiryData) => {
    const message = `📩 *New Contact Inquiry — DealDirect*

*From:* ${inquiryData.userName || 'N/A'}
📧 ${inquiryData.userEmail || 'N/A'}
📞 ${inquiryData.userPhone || 'Not provided'}

*Subject:* ${inquiryData.subject || 'N/A'}
*Category:* ${inquiryData.category || 'General'}

*Message:*
${inquiryData.message || 'No message'}

🔗 View in admin panel: https://admin.dealdirect.in/inquiries`;

    return sendAdminWhatsAppNotification(message);
};

/**
 * Notify admin about a new user registration
 *
 * @param {object} userData - { name, email, phone, role }
 */
export const sendNewUserWhatsApp = async (userData) => {
    const message = `👤 *New User Registered — DealDirect*

*Name:* ${userData.name || 'N/A'}
📧 ${userData.email || 'N/A'}
📞 ${userData.phone || 'Not provided'}
*Role:* ${userData.role || 'Buyer'}

🔗 View users: https://admin.dealdirect.in/users`;

    return sendAdminWhatsAppNotification(message);
};

/**
 * Notify admin about a new property listing
 *
 * @param {object} propertyData - { title, price, listingType, city, locality, ownerName }
 */
export const sendNewPropertyWhatsApp = async (propertyData) => {
    const priceFormatted = propertyData.price
        ? `₹${Number(propertyData.price).toLocaleString('en-IN')}`
        : 'N/A';
    const rentSuffix = propertyData.listingType === 'Rent' ? '/month' : '';
    const location = [propertyData.locality, propertyData.city].filter(Boolean).join(', ');

    const message = `🏗️ *New Property Listed — DealDirect*

*Title:* ${propertyData.title || 'N/A'}
*Price:* ${priceFormatted}${rentSuffix}
*Location:* ${location || 'N/A'}
*Listed by:* ${propertyData.ownerName || 'N/A'}

⏳ _Awaiting admin approval_
🔗 Review: https://admin.dealdirect.in/properties`;

    return sendAdminWhatsAppNotification(message);
};

// ============================================
// DEFAULT EXPORT
// ============================================

export default {
    sendWhatsAppMessage,
    sendAdminWhatsAppNotification,
    sendNewLeadWhatsApp,
    sendContactInquiryWhatsApp,
    sendNewUserWhatsApp,
    sendNewPropertyWhatsApp,
    isWhatsAppConfigured,
};
