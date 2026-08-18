/**
 * Server-Side Fetch Utility for SSR/ISR pages
 * 
 * Provides production-hardened fetch with:
 * - Timeout protection (prevents hanging SSR renders)
 * - Server-only API_INTERNAL_BASE support (avoids DNS roundtrips)
 * - Graceful error fallback (page renders with empty data instead of 503)
 * 
 * USAGE:
 *   import { ssrFetch, getServerApiBase } from '@/utils/ssrFetch';
 *   const data = await ssrFetch('/api/properties/list?limit=50', { revalidate: 120 });
 */

// Server-side API base URL
// Uses API_INTERNAL_BASE (server-only, no NEXT_PUBLIC_ prefix) if available.
// This allows the Next.js server to talk to the backend via internal network
// (e.g., localhost or private IP) instead of going through DNS + reverse proxy.
export function getServerApiBase() {
    // Priority 1: Internal/private URL (server-only, fastest path)
    if (process.env.API_INTERNAL_BASE) {
        return process.env.API_INTERNAL_BASE.replace(/\/+$/, '');
    }
    // Priority 2: Public API base (same as browser uses)
    if (process.env.NEXT_PUBLIC_API_BASE) {
        return process.env.NEXT_PUBLIC_API_BASE.replace(/\/+$/, '');
    }
    // Priority 3: Local development fallback
    return 'http://localhost:9000';
}

/**
 * Production-hardened fetch for SSR pages.
 * - Times out after `timeoutMs` (default 8s) to prevent page hangs
 * - Returns null on any error (page should handle null gracefully)
 * - Supports Next.js ISR revalidation via `revalidate` option
 * 
 * @param {string} path - API path (e.g., '/api/properties/list?limit=50')
 * @param {object} options
 * @param {number} options.revalidate - ISR revalidation interval in seconds
 * @param {number} options.timeoutMs - Fetch timeout in milliseconds (default 8000)
 * @returns {Promise<any|null>} Parsed JSON response or null on failure
 */
export async function ssrFetch(path, { revalidate = 120, timeoutMs = 8000 } = {}) {
    const url = `${getServerApiBase()}${path}`;

    // AbortController for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            next: { revalidate },
            headers: {
                'Accept': 'application/json',
                // Identify SSR requests in backend logs
                'X-SSR-Request': 'true',
            },
        });

        clearTimeout(timeoutId);

        if (!res.ok) {
            console.warn(`[SSR] ${path} responded with ${res.status}`);
            return null;
        }

        return await res.json();
    } catch (error) {
        clearTimeout(timeoutId);

        if (error.name === 'AbortError') {
            console.error(`[SSR] TIMEOUT after ${timeoutMs}ms: ${path}`);
        } else {
            console.error(`[SSR] Fetch failed for ${path}:`, error.message);
        }

        return null;
    }
}

/**
 * Like `ssrFetch`, but reports WHY it failed.
 *
 * `ssrFetch` collapses every outcome to `data ?? null`, which is fine for a
 * list that can render empty. It is not fine for a detail page deciding whether
 * to answer 404, because "this property does not exist" and "the API is
 * unreachable" arrive as the same `null`.
 *
 * Serving 404 for the second case is actively harmful: a backend blip would
 * make every live property answer 404, and search engines drop URLs that do.
 * So the caller needs the distinction, and gets it here.
 *
 * @returns {Promise<{data: any|null, notFound: boolean, unavailable: boolean, status: number|null}>}
 *   `notFound`    — the resource is definitively absent (404/410), or the id was
 *                   malformed (400). Neither is transient; both mean 404.
 *   `unavailable` — we could not find out (5xx, timeout, DNS). Never a 404.
 */
export async function ssrFetchWithStatus(path, { revalidate = 120, timeoutMs = 8000 } = {}) {
    const url = `${getServerApiBase()}${path}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const res = await fetch(url, {
            signal: controller.signal,
            next: { revalidate },
            headers: { 'Accept': 'application/json', 'X-SSR-Request': 'true' },
        });
        clearTimeout(timeoutId);

        if (res.ok) return { data: await res.json(), notFound: false, unavailable: false, status: res.status };

        // 400 is here because a malformed id cannot become valid on a retry —
        // it is a permanent "no such resource", same as 404.
        if (res.status === 404 || res.status === 410 || res.status === 400) {
            return { data: null, notFound: true, unavailable: false, status: res.status };
        }

        console.warn(`[SSR] ${path} responded with ${res.status}`);
        return { data: null, notFound: false, unavailable: true, status: res.status };
    } catch (error) {
        clearTimeout(timeoutId);
        if (error.name === 'AbortError') {
            console.error(`[SSR] TIMEOUT after ${timeoutMs}ms: ${path}`);
        } else {
            console.error(`[SSR] Fetch failed for ${path}:`, error.message);
        }
        return { data: null, notFound: false, unavailable: true, status: null };
    }
}

/**
 * Fetch multiple API endpoints in parallel with individual error isolation.
 * Each endpoint that fails returns null — others still succeed.
 * 
 * @param {Array<{path: string, revalidate?: number, timeoutMs?: number}>} requests
 * @returns {Promise<Array<any|null>>} Array of responses (null for failures)
 */
export async function ssrFetchAll(requests) {
    const results = await Promise.allSettled(
        requests.map(({ path, revalidate, timeoutMs }) =>
            ssrFetch(path, { revalidate, timeoutMs })
        )
    );

    return results.map((result) =>
        result.status === 'fulfilled' ? result.value : null
    );
}
