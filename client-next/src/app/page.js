import HomeContent from "./HomeContent";
import { OrganizationJsonLd, WebsiteJsonLd } from "../components/JsonLd";
import { ssrFetchAll } from "../utils/ssrFetch";

// Force dynamic rendering — never pre-render at build time
// (backend API is not available during Hostinger build)
export const dynamic = 'force-dynamic';

export const metadata = {
  title: {
    absolute: "DealDirect — Buy & Sell Properties Without Middlemen",
  },
  description:
    "DealDirect is India's #1 platform for buying, selling, and renting properties directly from owners — no brokerage, no middlemen. Browse apartments, villas, plots across Mumbai, Delhi, Bangalore and more.",
  keywords: ["real estate", "property", "buy property", "sell property", "rent property", "no brokerage", "India"],
  alternates: {
    canonical: 'https://dealdirect.in',
  },
};

// Server-side data fetching with timeout + graceful fallback
async function getHomeData() {
  const [propsData, catsData, ptData, blogData, projectsData] = await ssrFetchAll([
    { path: '/api/properties/property-list', revalidate: 120 },
    { path: '/api/categories/list-category', revalidate: 3600 },
    { path: '/api/propertyTypes/list-propertytype', revalidate: 3600 },
    { path: '/api/blogs?limit=3', revalidate: 600 },
    { path: '/api/projects?isActive=true&limit=8', revalidate: 120 },
  ]);

  return {
    properties: propsData?.data || [],
    categories: catsData?.data || catsData || [],
    propertyTypes: ptData?.data || ptData || [],
    latestPosts: blogData?.success ? (blogData.data || []) : [],
    builderProjects: projectsData?.data || (Array.isArray(projectsData) ? projectsData : []),
    // ssrFetch resolves to null on timeout, a non-2xx, or a network failure —
    // it never throws. Both a failed request and a genuinely empty result
    // therefore collapse to `[]` above, and the page rendered an empty
    // properties section either way, with no message and no way to retry.
    //
    // Distinguishing them is a one-line check: null means the request failed.
    propertiesUnavailable: propsData === null,
  };
}

export default async function HomePage() {
  const { properties, categories, propertyTypes, latestPosts, builderProjects, propertiesUnavailable } = await getHomeData();

  return (
    <>
      <OrganizationJsonLd />
      <WebsiteJsonLd />
      <HomeContent
        initialProperties={properties}
        initialCategories={categories}
        initialPropertyTypes={propertyTypes}
        initialLatestPosts={latestPosts}
        initialBuilderProjects={builderProjects}
        propertiesUnavailable={propertiesUnavailable}
      />
    </>
  );
}

