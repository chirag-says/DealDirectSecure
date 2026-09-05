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
                    // The shortlist is private by definition, and the prefix
                    // rule also covers /shortlist/shared/<token>: a share link
                    // is a private URL handed to one person, not content, and
                    // must never become a search result.
                    '/shortlist',
                    '/api/',
                ],
            },
        ],
        sitemap: 'https://dealdirect.in/sitemap.xml',
    };
}
