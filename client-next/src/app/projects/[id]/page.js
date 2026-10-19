import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { ssrFetch, ssrFetchWithStatus } from '../../../utils/ssrFetch';
import { BreadcrumbJsonLd } from '../../../components/JsonLd';
import ProjectDetailContent from './ProjectDetailContent';

export const dynamic = 'force-dynamic';

// Helper — single place for the fetch, no duplication.
//
// `missing` is kept separate from a null project on purpose. ssrFetch returns
// null for a timeout as readily as for a 404, so `if (!project) notFound()`
// answered 404 for every live project whenever the backend was slow — and
// search engines drop URLs that 404. Only a definitive absence may 404.
async function getProject(id) {
    if (!id) return { project: null, missing: true };
    const { data, notFound: missing } = await ssrFetchWithStatus(`/api/projects/${id}`, { revalidate: 60 });
    return { project: data?.data || null, missing };
}

async function getUnitTypes(projectId) {
    if (!projectId) return [];
    const res = await ssrFetch(`/api/unit-types/project/${projectId}`, { revalidate: 60 });
    return res?.data || [];
}

async function getCampaigns(projectId) {
    if (!projectId) return [];
    try {
        const res = await ssrFetch(`/api/campaigns/project/${projectId}?status=active`, { revalidate: 60 });
        return res?.data || [];
    } catch { return []; }
}

// ── SEO Metadata ──────────────────────────────────────────────────────────────
export async function generateMetadata(props) {
    const params = await props.params;
    const id = params?.id;
    const { project } = await getProject(id);

    if (!project) {
        // No canonical, and noindex: this page is about to answer 404.
        return {
            title: 'Project Not Found | DealDirect',
            robots: { index: false, follow: false },
        };
    }

    const name = project.basics?.name || 'Builder Project';
    const city = project.location?.city || 'India';

    return {
        title: `${name} in ${city} | DealDirect`,
        description: project.basics?.description?.substring(0, 160) || `Explore ${name} — a builder project in ${city}. Buy directly with DealDirect.`,
        openGraph: {
            title: `${name} | DealDirect`,
            description: project.basics?.description?.substring(0, 160),
            type: 'article',
        },
        twitter: {
            card: 'summary',
            title: `${name} | DealDirect`,
        },
        alternates: {
            canonical: `https://dealdirect.in/projects/${id}`,
        },
    };
}

// ── Page Component ────────────────────────────────────────────────────────────
export default async function ProjectDetailPage(props) {
    const params = await props.params;
    const id = params?.id;

    const [{ project, missing }, unitTypes, campaigns] = await Promise.all([
        getProject(id),
        getUnitTypes(id),
        getCampaigns(id),
    ]);

    if (missing) notFound();

    return (
        <>
            <BreadcrumbJsonLd items={[
                { name: 'Home', href: '/' },
                { name: 'Builder Projects', href: '/projects' },
                { name: project.basics?.name || 'Project', href: `/projects/${id}` },
            ]} />
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading project...</div>}>
                <ProjectDetailContent project={project} unitTypes={unitTypes} campaigns={campaigns} />
            </Suspense>
        </>
    );
}
