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
        // The builder-projects vertical. It has its own index, detail pages and
        // unit-type pages, and none of it was in the sitemap — an entire section
        // of the site that search engines could only find by following links.
        {
            url: `${SITE_URL}/projects`,
            lastModified: new Date(),
            changeFrequency: 'daily',
            priority: 0.9,
        },
        {
            url: `${SITE_URL}/faq`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.5,
        },
        {
            url: `${SITE_URL}/press-impressions`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.4,
        },
        {
            url: `${SITE_URL}/rewards`,
            lastModified: new Date(),
            changeFrequency: 'monthly',
            priority: 0.6,
        },
        {
            url: `${SITE_URL}/rewards/terms`,
            lastModified: new Date(),
            changeFrequency: 'yearly',
            priority: 0.3,
        },
        // /login and /register were listed here and have been removed. Asking
        // search engines to index a sign-in form gains nothing, and the pages
        // have no content to rank. Nothing links to them from a sitemap now;
        // they remain reachable, just not advertised.
        //
        // Private routes (/profile, /my-bookings, /rewards/dashboard and the
        // rest) are absent for the same reason and additionally disallowed in
        // robots.js.
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

    // Fetch builder projects. Same shape-tolerant read as properties above:
    // /api/projects returns an envelope, but the property list returns a bare
    // array, and this file should not care which.
    let projectPages = [];
    const projectData = await ssrFetch('/api/projects?limit=5000', { revalidate: 3600, timeoutMs: 15000 });
    if (projectData) {
        const projects = projectData?.data || projectData?.projects || projectData || [];
        if (Array.isArray(projects)) {
            projectPages = projects.map((project) => ({
                url: `${SITE_URL}/projects/${project._id}`,
                lastModified: project.updatedAt ? new Date(project.updatedAt) : new Date(),
                changeFrequency: 'weekly',
                priority: 0.7,
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

    return [...staticPages, ...propertyPages, ...projectPages, ...blogPages];
}
