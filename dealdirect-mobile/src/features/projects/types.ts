/**
 * The project shape the UI consumes.
 *
 * The backend `Project` is a large admin-authored document: fourteen nested
 * groups covering legal, financials, bank approvals, construction updates and
 * payment plans, most of it typed loosely because only the admin panel writes
 * it. A card needs eight fields out of that.
 *
 * Same reasoning as `PropertySummary`. One adapter, one flat summary, and
 * components that render rather than resolve. A card that reaches into
 * `project.media.exteriorImages[0]` itself is a card that has to know the
 * fallback order, and the third one written will get it wrong.
 */

export interface ProjectSummary {
  id: string;
  name: string;

  /** "New Launch", "Under Construction", "Ready To Move", "Completed". */
  status?: string;
  /** "Residential", "Commercial", "Mixed Use". */
  category?: string;

  city?: string;
  locality?: string;
  /** Pre-composed "Locality, City", collapsed if either is missing. */
  locationLabel: string;

  coverImage?: string;

  builderName?: string;
  builderLogo?: string;

  /**
   * Rupees. A project prices a RANGE across its unit types, unlike a property
   * which has one number, so both ends are carried and the card decides how to
   * render them.
   */
  priceMin?: number;
  priceMax?: number;

  unitTypeCount: number;

  createdAt?: string;
}
