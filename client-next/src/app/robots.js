/**
 * Robots.txt configuration for DealDirect
 * Next.js automatically serves this at /robots.txt
 */
export default function robots() {
    return {
        rules: [
            {
                userAgent: '*',
                allow: '/',
                // Keep this list in step with PROTECTED_ROUTES in
                // src/middleware.js. /my-bookings and /rewards/dashboard were
                // protected there but crawlable here, so a bot could request
                // them and collect a login redirect on every pass.
                disallow: [
                    '/profile',
                    '/my-properties',
                    '/saved-properties',
                    '/notifications',
                    '/add-property',
                    '/edit-property/',
                    '/agreements',
                    '/my-bookings',
                    '/rewards/dashboard',
                    '/api/',
                ],
            },
        ],
        sitemap: 'https://dealdirect.in/sitemap.xml',
    };
}
