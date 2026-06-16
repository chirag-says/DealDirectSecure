'use client';
import dynamic from 'next/dynamic';

// Dynamically import the builder-project-aware content component.
// Uses the new /api/projects endpoint and Project schema fields.
const BuilderProjectsContent = dynamic(() => import('./BuilderProjectsContent'), {
    ssr: false,
    loading: () => <div className="min-h-screen flex items-center justify-center text-slate-500">Loading projects...</div>,
});

export default function ClientBuilderProjectsList({ initialProjects = [] }) {
    return <BuilderProjectsContent initialProjects={initialProjects} />;
}
