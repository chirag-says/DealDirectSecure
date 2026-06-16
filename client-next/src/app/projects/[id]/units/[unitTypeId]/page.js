import { Suspense } from 'react';
import { notFound } from 'next/navigation';
import { ssrFetch } from '../../../../../utils/ssrFetch';
import UnitDetailContent from './UnitDetailContent';
import Link from 'next/link';

export const dynamic = 'force-dynamic';

async function getUnitType(unitTypeId) {
  const res = await ssrFetch(`/api/unit-types/${unitTypeId}`, { revalidate: 60 });
  return res?.data || null;
}

async function getProject(projectId) {
  const res = await ssrFetch(`/api/projects/${projectId}`, { revalidate: 60 });
  return res?.data || null;
}

export async function generateMetadata(props) {
  const params = await props.params;
  const [unitType, project] = await Promise.all([
    getUnitType(params.unitTypeId),
    getProject(params.id),
  ]);
  if (!unitType || !project) return { title: 'Unit Not Found | DealDirect' };
  const name = unitType.config?.name || 'Unit';
  const projectName = project.basics?.name || 'Project';
  const city = project.location?.city || 'India';
  return {
    title: `${name} in ${projectName}, ${city} | DealDirect`,
    description: `Book ${name} in ${projectName}. ${unitType.area?.carpetSqft || ''}sqft carpet. Starting ₹${unitType.pricing?.basePrice?.toLocaleString('en-IN') || 'On Request'}.`,
  };
}

export default async function UnitDetailPage(props) {
  const params = await props.params;
  const { id: projectId, unitTypeId } = params;

  const [unitType, project] = await Promise.all([
    getUnitType(unitTypeId),
    getProject(projectId),
  ]);

  if (!unitType || !project) notFound();

  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-slate-500">Loading...</div>}>
      <UnitDetailContent unitType={unitType} project={project} />
    </Suspense>
  );
}
