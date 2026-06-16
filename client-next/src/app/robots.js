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
                disallow: [
                    '/profile',
                    '/my-properties',
                    '/saved-properties',
                    '/notifications',
                    '/add-property',
                    '/edit-property/',
                    '/agreements',
                    '/api/',
                ],
            },
        ],
        sitemap: 'https://dealdirect.in/sitemap.xml',
    };
}
