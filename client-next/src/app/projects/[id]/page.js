import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { ssrFetch } from '../../../utils/ssrFetch';
import { BreadcrumbJsonLd } from '../../../components/JsonLd';
import ProjectDetailContent from './ProjectDetailContent';

export const dynamic = 'force-dynamic';

// Helper — single place for the fetch, no duplication
async function getProject(id) {
    if (!id) return null;
    const res = await ssrFetch(`/api/projects/${id}`, { revalidate: 60 });
    return res?.data || null;
}

async function getUnitTypes(projectId) {
    if (!projectId) return [];
    const res = await ssrFetch(`/api/unit-types/project/${projectId}`, { revalidate: 60 });
    return res?.data || [];
}

// ── SEO Metadata ──────────────────────────────────────────────────────────────
export async function generateMetadata(props) {
    const params = await props.params;
    const id = params?.id;
    const project = await getProject(id);

    if (!project) {
        return { title: 'Project Not Found | DealDirect' };
    }

    const name = project.basics?.name || 'Builder Project';
    const city = project.location?.city || 'India';

    return {
        title: `${name} in ${city} | DealDirect`,
        description: project.basics?.description?.substring(0, 160) || `Explore ${name} — a verified builder project in ${city}. Buy directly with DealDirect.`,
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

    const [project, unitTypes] = await Promise.all([
        getProject(id),
        getUnitTypes(id),
    ]);

    if (!project) notFound();

    return (
        <>
            <BreadcrumbJsonLd items={[
                { name: 'Home', href: '/' },
                { name: 'Builder Projects', href: '/projects' },
                { name: project.basics?.name || 'Project', href: `/projects/${id}` },
            ]} />
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading project...</div>}>
                <ProjectDetailContent project={project} unitTypes={unitTypes} />
            </Suspense>
        </>
    );
}
