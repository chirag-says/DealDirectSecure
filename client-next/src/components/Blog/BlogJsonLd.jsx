export function BlogJsonLd({ blog }) {
    if (!blog) return null;

    const schema = {
        '@context': 'https://schema.org',
        '@type': 'Article',
        headline: blog.seoTitle || blog.title,
        description: blog.seoDescription || blog.excerpt,
        image: blog.coverImage || undefined,
        datePublished: blog.publishedAt,
        dateModified: blog.updatedAt,
        author: {
            '@type': 'Organization',
            name: blog.author || 'DealDirect Team',
            url: 'https://dealdirect.in',
        },
        publisher: {
            '@type': 'Organization',
            name: 'DealDirect',
            url: 'https://dealdirect.in',
            logo: {
                '@type': 'ImageObject',
                url: 'https://dealdirect.in/logo.png',
            },
        },
        mainEntityOfPage: {
            '@type': 'WebPage',
            '@id': `https://dealdirect.in/blog/${blog.slug}`,
        },
        keywords: blog.tags?.join(', '),
    };

    return (
        <script
            type="application/ld+json"
            dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
        />
    );
}
