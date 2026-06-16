/**
 * Dynamic Sitemap for DealDirect
 * Fetches all published property IDs from the backend and generates a comprehensive sitemap.
 * Next.js automatically serves this at /sitemap.xml
 */

import { ssrFetch } from '../utils/ssrFetch';

// Force dynamic rendering — sitemap is generated at request time, not build time
export const dynamic = 'force-dynamic';

const SITE_URL = 'https://dealdirect.in';

export default async function sitemap() {
    // Static pages with their priorities and change frequencies
    const staticPages = [
        {
            url: SITE_URL,
            lastModified: new Date(),
            changeFrequency: 'daily',
            priority: 1.0,
        },
        {
            url: `${SITE_URL}/properties`,
            lastModified: new Date(),
            changeFrequency: 'daily',
            priority: 0.9,
        },
        {
            url: `${SITE_URL}/about`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.5,
        },
        {
            url: `${SITE_URL}/contact`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.5,
        },
        {
            url: `${SITE_URL}/why-us`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.5,
        },
        {
            url: `${SITE_URL}/privacy`,
            lastModified: new Date(),
            changeFrequency: 'yearly',
            priority: 0.3,
        },
        {
            url: `${SITE_URL}/terms`,
            lastModified: new Date(),
            changeFrequency: 'yearly',
            priority: 0.3,
        },
        {
            url: `${SITE_URL}/blog`,
            lastModified: new Date(),
            changeFrequency: 'daily',
            priority: 0.8,
        },
        {
            url: `${SITE_URL}/login`,
            lastModified: new Date(),
            changeFrequency: 'yearly',
            priority: 0.2,
        },
        {
            url: `${SITE_URL}/register`,
            lastModified: new Date(),
            changeFrequency: 'yearly',
            priority: 0.2,
        },
    ];

    // Fetch all published properties from the backend (with timeout)
    let propertyPages = [];
    const propData = await ssrFetch('/api/properties/list?limit=5000', { revalidate: 3600, timeoutMs: 15000 });
    if (propData) {
        const properties = propData?.data || propData?.properties || propData || [];
        if (Array.isArray(properties)) {
            propertyPages = properties.map((property) => ({
                url: `${SITE_URL}/properties/${property._id}`,
                lastModified: property.updatedAt
                    ? new Date(property.updatedAt)
                    : new Date(),
                changeFrequency: 'weekly',
                priority: 0.8,
            }));
        }
    }

    // Fetch all published blog slugs (with timeout)
    let blogPages = [];
    const blogData = await ssrFetch('/api/blogs?limit=5000', { revalidate: 3600, timeoutMs: 15000 });
    if (blogData) {
        const blogs = blogData?.data || [];
        if (Array.isArray(blogs)) {
            blogPages = blogs.map((blog) => ({
                url: `${SITE_URL}/blog/${blog.slug}`,
                lastModified: blog.updatedAt ? new Date(blog.updatedAt) : new Date(),
                changeFrequency: 'monthly',
                priority: 0.7,
            }));
        }
    }

    return [...staticPages, ...propertyPages, ...blogPages];
}
