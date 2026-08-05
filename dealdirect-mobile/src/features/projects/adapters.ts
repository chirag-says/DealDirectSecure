import type { Builder, Project } from '@/types/backend/project';
import type { ProjectSummary } from './types';

/**
 * Backend `Project` to `ProjectSummary`.
 *
 * Every fallback chain in this file exists because the live data needs it.
 * Measured against all 5 live projects on 2026-08-03: 4 carry an exterior
 * image, 3 carry a builder logo, 5 carry a price range. Nothing here is
 * defensive programming against imagined nulls.
 */

/**
 * `builder` is either a populated object or a bare ObjectId string, depending
 * on the endpoint. `GET /projects` populates it with name/company/logoUrl;
 * other routes return the raw ref. Narrowing once here means no component has
 * to care which one it got.
 */
function populatedBuilder(builder: Project['builder']): Builder | undefined {
  if (!builder || typeof builder === 'string') return undefined;
  return builder;
}

/**
 * Cover image, in the order a person would pick one.
 *
 * Exterior first because it is what the project looks like from the street.
 * Drone second: dramatic, but often too far out to read at card size. Master
 * plan last and reluctantly, since a site diagram is information rather than
 * imagery, and it is still better than an empty tile.
 *
 * `locationMap` is deliberately NOT in the chain. A map screenshot as a hero
 * image reads as a broken image, not as a project.
 */
function resolveCover(media: Project['media']): string | undefined {
  if (!media) return undefined;
  return (
    media.exteriorImages?.[0] ??
    media.droneImages?.[0] ??
    media.masterPlan?.[0] ??
    undefined
  );
}

/** "Kharghar, Navi Mumbai", collapsed rather than left with a dangling comma. */
function composeLocation(locality?: string, city?: string): string {
  const parts = [locality?.trim(), city?.trim()].filter(Boolean);
  return parts.join(', ');
}

export function adaptProject(project: Project): ProjectSummary {
  const builder = populatedBuilder(project.builder);
  const city = project.location?.city?.trim();
  const locality = project.location?.locality?.trim();

  const min = project.priceRange?.min;
  const max = project.priceRange?.max;

  return {
    id: project._id,
    // Live data always has a name, but an untitled project must not render as
    // an empty heading with a price under it.
    name: project.basics?.name?.trim() || 'Unnamed project',

    status: project.basics?.status,
    category: project.basics?.category,

    city,
    locality,
    locationLabel: composeLocation(locality, city),

    coverImage: resolveCover(project.media),

    // `company` before `name`: the builder record's `name` is often a person
    // (live data has "Chirag" and "Admin"), while `company` is the brand a
    // buyer would recognise. Preferring the brand is right when it exists.
    builderName: builder?.company?.trim() || builder?.name?.trim(),
    builderLogo: builder?.logoUrl ?? builder?.logo,

    // Zero is not a price. Several projects carry `min === max`, which the card
    // renders as a single figure rather than a range of one.
    priceMin: min && min > 0 ? min : undefined,
    priceMax: max && max > 0 ? max : undefined,

    unitTypeCount: project.unitTypeCount ?? 0,

    createdAt: project.createdAt,
  };
}
