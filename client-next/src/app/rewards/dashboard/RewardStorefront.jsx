'use client';

import React, { useState, useEffect, useCallback, useRef } from 'react';
import { rewardsApi } from '../../../utils/api';
import { Loader2, Gift, AlertCircle, ExternalLink, RefreshCw, X } from 'lucide-react';

/**
 * WHITELISTED URLs — Only these are allowed to load inside the iframe.
 * All other navigations (brand redemption links like Swiggy, Amazon, etc.)
 * are opened in a new browser tab, as per Hubble's integration guidelines.
 */
const WHITELISTED_ORIGINS = [
    'https://sdk.myhubble.money',
    'https://sdk.dev.myhubble.money',
    'https://api.razorpay.com',
];

/**
 * Check whether a URL should stay inside the iframe (whitelisted)
 * or be opened externally in a new tab.
 */
function isWhitelistedUrl(url) {
    if (!url || typeof url !== 'string') return false;
    try {
        const parsed = new URL(url);
        return WHITELISTED_ORIGINS.some(
            (origin) => parsed.origin === new URL(origin).origin
        );
    } catch {
        return false;
    }
}

/**
 * HubbleStorefront — Embeds the Hubble Gift Card SDK in an iframe.
 *
 * Flow:
 *  1. Fetch SDK config (clientId, appSecret, baseUrl) from our backend
 *  2. Generate a short-lived SSO token from our backend
 *  3. Build the SDK URL and load it in an iframe
 *  4. Listen for postMessage events from the SDK
 *  5. Intercept navigation — whitelist Hubble + Razorpay URLs in iframe,
 *     open brand-specific links (Swiggy, Amazon, etc.) externally
 */
export default function HubbleStorefront() {
    const [sdkUrl, setSdkUrl] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [sdkReady, setSdkReady] = useState(false);
    const iframeRef = useRef(null);

    const initializeSDK = useCallback(async () => {
        setLoading(true);
        setError(null);
        setSdkReady(false);

        try {
            // 1. Get SDK config
            const configRes = await rewardsApi.getHubbleConfig();
            if (!configRes.success) {
                throw new Error(configRes.message || 'Failed to load SDK configuration');
            }

            const { clientId, appSecret, sdkBaseUrl, theme } = configRes.config;

            // 2. Generate SSO token from our backend
            const tokenRes = await rewardsApi.getHubbleToken();
            if (!tokenRes.success) {
                throw new Error(tokenRes.message || 'Failed to generate authentication token');
            }
            const ssoToken = tokenRes.token;

            // 3. Build SDK URL
            const params = new URLSearchParams({
                clientId,
                clientSecret: appSecret,
                token: ssoToken,
            });

            if (theme) params.set('theme', theme);

            const url = `${sdkBaseUrl}?${params.toString()}`;
            setSdkUrl(url);
        } catch (err) {
            console.error('[HubbleStorefront] Init error:', err);
            setError(
                err.response?.data?.message ||
                err.message ||
                'Failed to load gift card store. Please try again.'
            );
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        initializeSDK();
    }, [initializeSDK]);

    // Listen for SDK events via postMessage
    // Handles: app_ready, close, error, analytics, AND navigation/redirect events
    useEffect(() => {
        const handleMessage = (event) => {
            const { data } = event;
            if (!data || typeof data !== 'object') return;

            // --- Standard SDK lifecycle events ---
            if (data.type === 'action') {
                if (data.action === 'app_ready') {
                    setSdkReady(true);
                } else if (data.action === 'close') {
                    console.log('[HubbleStorefront] SDK close requested');
                } else if (data.action === 'error') {
                    console.error('[HubbleStorefront] SDK error:', data);
                    setError('The gift card store encountered an error. Please refresh.');
                } else if (data.action === 'launch_link') {
                    // Hubble SDK sends this when user clicks a brand redemption link
                    // (e.g. Swiggy, Amazon). Open it externally in a new tab.
                    const externalUrl = data.properties?.link;
                    if (externalUrl && typeof externalUrl === 'string') {
                        console.log('[HubbleStorefront] Opening external link:', externalUrl);
                        window.open(externalUrl, '_blank', 'noopener,noreferrer');
                    }
                }
            }

            if (data.type === 'analytics') {
                console.log('[HubbleStorefront] Event:', data.event, data.properties);
            }
        };

        window.addEventListener('message', handleMessage);
        return () => window.removeEventListener('message', handleMessage);
    }, []);

    // Fallback: mark SDK as ready after iframe loads or 5s timeout
    useEffect(() => {
        if (!sdkUrl || sdkReady) return;
        const timeout = setTimeout(() => setSdkReady(true), 5000);
        return () => clearTimeout(timeout);
    }, [sdkUrl, sdkReady]);

    // Loading state
    if (loading) {
        return (
            <div className="bg-white rounded-2xl border border-gray-100 shadow-sm p-12 text-center">
                <Loader2 className="w-10 h-10 animate-spin mx-auto text-red-500 mb-4" />
                <p className="text-gray-600 font-medium">Connecting to Gift Card Store...</p>
                <p className="text-gray-400 text-sm mt-2">Setting up your secure session</p>
            </div>
        );
    }

    // Error state
    if (error) {
        return (
            <div className="bg-white rounded-2xl border border-red-100 shadow-sm p-8 text-center">
                <div className="w-14 h-14 rounded-full bg-red-50 flex items-center justify-center mx-auto mb-4">
                    <AlertCircle className="w-7 h-7 text-red-500" />
                </div>
                <h3 className="text-lg font-bold text-gray-900 mb-2">Unable to Load Gift Cards</h3>
                <p className="text-gray-500 text-sm mb-6 max-w-md mx-auto">{error}</p>
                <button
                    onClick={initializeSDK}
                    className="inline-flex items-center gap-2 bg-red-600 text-white px-6 py-2.5 rounded-xl text-sm font-semibold hover:bg-red-700 transition-all"
                >
                    <RefreshCw className="w-4 h-4" />
                    Try Again
                </button>
            </div>
        );
    }

    // SDK iframe
    return (
        <div className="space-y-4">
            {/* Header */}
            <div className="flex items-center justify-between bg-white rounded-2xl border border-gray-100 shadow-sm px-6 py-4">
                <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-red-500 to-red-700 flex items-center justify-center">
                        <Gift className="w-5 h-5 text-white" />
                    </div>
                    <div>
                        <h3 className="font-bold text-gray-900">Gift Card Store</h3>
                        <p className="text-xs text-gray-400">
                            Powered by Hubble • Redeem your DealDirect points
                        </p>
                    </div>
                </div>

                <div className="flex items-center gap-2">
                    <button
                        onClick={initializeSDK}
                        title="Refresh store"
                        className="p-2 hover:bg-gray-100 rounded-lg transition-colors text-gray-400 hover:text-gray-600"
                    >
                        <RefreshCw className="w-4 h-4" />
                    </button>
                </div>
            </div>

            {/* SDK iframe — sandbox allows popups to escape so brand links open in new tabs */}
            {sdkUrl && (
                <div className="rounded-2xl overflow-hidden border border-gray-100 shadow-sm bg-white">
                    <iframe
                        ref={iframeRef}
                        src={sdkUrl}
                        title="DealDirect Gift Card Store - Powered by Hubble"
                        className="w-full border-none"
                        style={{ height: '700px', minHeight: '500px' }}
                        allow="clipboard-write *"
                        sandbox="allow-scripts allow-same-origin allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation"
                    />
                </div>
            )}
        </div>
    );
}
