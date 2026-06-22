import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { ssrFetch } from '../../../../../utils/ssrFetch';
import { BreadcrumbJsonLd } from '../../../../../components/JsonLd';
import UnitDetailContent from './UnitDetailContent';

export const dynamic = 'force-dynamic';

async function getUnitType(id) {
    if (!id) return null;
    const res = await ssrFetch(`/api/unit-types/${id}`, { revalidate: 60 });
    return res?.data || null;
}

async function getCampaigns(unitTypeId) {
    if (!unitTypeId) return [];
    const res = await ssrFetch(`/api/campaigns/unit-type/${unitTypeId}`, { revalidate: 60 });
    return res?.data || [];
}

async function getProject(id) {
    if (!id) return null;
    const res = await ssrFetch(`/api/projects/${id}`, { revalidate: 120 });
    return res?.data || null;
}

// ── SEO Metadata ──────────────────────────────────────────────────────────────
export async function generateMetadata(props) {
    const params = await props.params;
    const unitType = await getUnitType(params?.unitTypeId);
    if (!unitType) return { title: 'Unit Not Found | DealDirect' };

    const name = unitType.config?.name || 'Unit Type';
    const beds = unitType.config?.bedrooms ? `${unitType.config.bedrooms} BHK` : '';
    const area = unitType.area?.carpetSqft ? `${unitType.area.carpetSqft} sqft` : '';

    return {
        title: `${name} ${beds} ${area} | DealDirect`,
        description: `Book ${name} — ${beds} ${area}. Get direct developer pricing, floor plans, and group-buy campaigns on DealDirect.`,
        alternates: {
            canonical: `https://dealdirect.in/projects/${params.id}/units/${params.unitTypeId}`,
        },
    };
}

// ── Page ──────────────────────────────────────────────────────────────────────
export default async function UnitDetailPage(props) {
    const params = await props.params;
    const { id: projectId, unitTypeId } = params;

    const [unitType, campaigns, project] = await Promise.all([
        getUnitType(unitTypeId),
        getCampaigns(unitTypeId),
        getProject(projectId),
    ]);

    if (!unitType) notFound();

    return (
        <>
            <BreadcrumbJsonLd items={[
                { name: 'Home', href: '/' },
                { name: 'Builder Projects', href: '/projects' },
                { name: project?.basics?.name || 'Project', href: `/projects/${projectId}` },
                { name: unitType.config?.name || 'Unit', href: `/projects/${projectId}/units/${unitTypeId}` },
            ]} />
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading unit details...</div>}>
                <UnitDetailContent unitType={unitType} campaigns={campaigns} project={project} projectId={projectId} />
            </Suspense>
        </>
    );
}
