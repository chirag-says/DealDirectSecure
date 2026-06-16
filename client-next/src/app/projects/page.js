import { Suspense } from 'react';
import { BreadcrumbJsonLd } from '../../components/JsonLd';
import { ssrFetchAll } from '../../utils/ssrFetch';
import ClientBuilderProjectsList from './ClientBuilderProjectsList';

export const dynamic = 'force-dynamic';

export const metadata = {
    title: 'Builder Projects | DealDirect',
    description: 'Explore premium builder projects across India\'s top cities. Buy directly from verified developers — no middlemen.',
    openGraph: {
        title: 'Builder Projects | DealDirect',
        description: 'Explore premium builder projects across India\'s top cities.',
    },
    twitter: {
        card: 'summary',
        title: 'Builder Projects | DealDirect',
        description: 'Explore premium builder projects across India\'s top cities.',
    },
    alternates: {
        canonical: 'https://dealdirect.in/projects',
    },
};

async function getInitialData() {
    const [projectsData] = await ssrFetchAll([
        { path: '/api/projects?isActive=true&limit=100', revalidate: 60 },
    ]);

    return {
        projects: projectsData?.data || (Array.isArray(projectsData) ? projectsData : []),
    };
}

export default async function BuilderProjectsPage() {
    const { projects } = await getInitialData();

    return (
        <>
            <BreadcrumbJsonLd items={[
                { name: 'Home', href: '/' },
                { name: 'Builder Projects', href: '/projects' },
            ]} />

            {/* Hidden SEO content */}
            <div className="sr-only" aria-hidden="true">
                <h1>Builder Projects for Sale on DealDirect</h1>
                <p>Browse {projects.length} verified builder projects directly from developers.</p>
                <ul>
                    {projects.slice(0, 20).map((p) => (
                        <li key={p._id}>
                            {p.basics?.name || `Project in ${p.location?.city || 'India'}`} —
                            {p.location?.city}
                        </li>
                    ))}
                </ul>
            </div>

            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading projects...</div>}>
                <ClientBuilderProjectsList initialProjects={projects} />
            </Suspense>
        </>
    );
}
