/**
 * The attribute table, as data.
 *
 * ---------------------------------------------------------------------------
 * WHY A TABLE AND NOT A COMPONENT PER SECTION
 *
 * The property schema has roughly eighty fields split into a residential and a
 * commercial set. Written as JSX that is eighty conditionals, and every one of
 * them is a place to render an empty row, mislabel a field, or forget the
 * `toLocaleString`. Written as a spec it is eighty single-line entries and ONE
 * renderer, and a new backend field is one line here rather than a component
 * edit.
 *
 * ---------------------------------------------------------------------------
 * PRESENCE DECIDES WHAT RENDERS, NOT CATEGORY
 *
 * The obvious design tags each field residential or commercial and picks a set
 * from `categoryName`. It is rejected because the taxonomy on this backend is
 * not trustworthy: `category` / `subcategory` / `propertyType` are null on
 * roughly 15 of 36 live listings and point at the wrong document on the rest.
 * A listing whose category is wrong would render the wrong half of its own
 * data, and the fields it does carry would silently vanish.
 *
 * Presence is self-correcting. A field renders when the listing carries a
 * usable value and does not when it does not, so a mislabelled commercial unit
 * still shows every commercial attribute its owner filled in. Sections whose
 * rows all resolve to nothing drop out entirely, which is what makes a
 * residential listing show residential sections without anyone asking it to.
 *
 * The cost, stated plainly: a listing carrying both `bathrooms` and
 * `washrooms` shows both rows. That is honest — the data really does say both.
 */

import type { Property } from '@/types/backend/property';
import { formatPrice } from '@/ui';

export interface FieldRow {
  label: string;
  value: string;
}

export interface FieldSection {
  id: string;
  title: string;
  rows: FieldRow[];
}

/**
 * One attribute. `read` returns the raw value; `format` turns it into a row,
 * or returns undefined to drop it.
 *
 * `read` is a function rather than a dotted string path because half these
 * fields are nested (`area.carpetSqft`, `legal.reraId`) and a string path
 * would need a runtime walker and would lose every type the contract provides.
 */
interface FieldSpec {
  label: string;
  read: (property: Property) => unknown;
  /** Defaults to `text`. Return undefined to drop the row. */
  format?: (value: unknown, property: Property) => string | undefined;
}

interface SectionSpec {
  id: string;
  title: string;
  fields: FieldSpec[];
}

// --- Formatters -----------------------------------------------------------

/**
 * The default. Anything that is a non-empty string or a finite number becomes
 * a row; everything else drops.
 *
 * `0` is deliberately kept: zero balconies is a fact an owner entered, unlike
 * an absent field. Empty strings are dropped because the website's forms write
 * one for any control the user opened and left alone.
 */
function text(value: unknown): string | undefined {
  if (typeof value === 'number') return Number.isFinite(value) ? String(value) : undefined;
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function sqft(value: unknown): string | undefined {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return undefined;
  return `${value.toLocaleString('en-IN')} sqft`;
}

/** Yes/No. A `false` here is an answer, not a missing value, so it renders. */
function yesNo(value: unknown): string | undefined {
  if (typeof value !== 'boolean') return undefined;
  return value ? 'Yes' : 'No';
}

/** True renders, false drops. For flags where "No" is the uninformative case. */
function yesOnly(value: unknown): string | undefined {
  return value === true ? 'Yes' : undefined;
}

/**
 * A `Mixed` money field.
 *
 * These accept either a number or free text: the schema types `deposit` and
 * `maintenance` as Mixed precisely because listings say "2 months",
 * "Included", or "On request" as often as they give a figure. A number is
 * formatted as currency and a string is passed through as written.
 */
function money(value: unknown): string | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) && value > 0 ? formatPrice(value) : undefined;
  }
  return text(value);
}

/** An ISO date as a readable day. Invalid dates drop rather than print "Invalid Date". */
function date(value: unknown): string | undefined {
  const raw = text(value);
  if (!raw) return undefined;

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return undefined;

  return parsed.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
}

/** "3 · Covered" style joins, empties dropped. */
function join(parts: (string | undefined)[]): string | undefined {
  const kept = parts.filter((part): part is string => !!part);
  return kept.length > 0 ? kept.join(' · ') : undefined;
}

// --- The table ------------------------------------------------------------

const SECTIONS: SectionSpec[] = [
  {
    id: 'configuration',
    title: 'Configuration',
    fields: [
      { label: 'Bedrooms', read: (p) => p.bhk ?? p.bedrooms },
      { label: 'Bathrooms', read: (p) => p.bathrooms },
      { label: 'Balconies', read: (p) => p.balconies },
      { label: 'Furnishing', read: (p) => p.furnishing },
      { label: 'Facing', read: (p) => p.facing },
      {
        label: 'Floor',
        // Two fields, one fact. "3 of 12" is what a reader wants; two rows
        // reading "3" and "12" makes them do the join themselves.
        read: (p) => join([text(p.floorNo), text(p.totalFloors) && `of ${text(p.totalFloors)}`]),
      },
      { label: 'Construction', read: (p) => p.constructionStatus },
      // `propertyAge` and `ageOfProperty` are the same fact under two names,
      // written by two different versions of the add-property form.
      { label: 'Age', read: (p) => p.propertyAge ?? p.ageOfProperty },
      { label: 'Suitable for', read: (p) => p.allowedFor },
      { label: 'Pets', read: (p) => p.petFriendly },
      {
        label: 'Additional rooms',
        // Four booleans as four "Yes" rows is noise. One row naming what is
        // actually there says the same thing in a quarter of the space.
        read: (p) =>
          join([
            p.extras?.servantRoom ? 'Servant room' : undefined,
            p.extras?.poojaRoom ? 'Pooja room' : undefined,
            p.extras?.studyRoom ? 'Study room' : undefined,
            p.extras?.storeRoom ? 'Store room' : undefined,
          ]),
      },
    ],
  },

  {
    id: 'workspace',
    title: 'Commercial details',
    fields: [
      { label: 'Property type', read: (p) => p.commercialSubType },
      { label: 'Workstations', read: (p) => p.workstations },
      { label: 'Cabins', read: (p) => p.cabins ?? p.privateCabins },
      { label: 'Meeting rooms', read: (p) => p.meetingRooms ?? p.conferenceRooms },
      { label: 'Phone booths', read: (p) => p.phoneBooths },
      { label: 'Lounge', read: (p) => p.loungeArea },
      { label: 'Pantry', read: (p) => p.pantry },
      { label: 'Washrooms', read: (p) => p.washrooms },
      { label: 'Seating capacity', read: (p) => p.seatingCapacity },
      { label: 'Frontage', read: (p) => p.frontage },
      { label: 'Display windows', read: (p) => p.displayWindows },
      { label: 'Display area', read: (p) => p.displayArea },
      { label: 'Kitchen area', read: (p) => p.kitchenArea },
      { label: 'Bar area', read: (p) => p.barArea },
      { label: 'Outdoor seating', read: (p) => p.outdoorSeating },
      { label: 'Storage', read: (p) => p.storage },
    ],
  },

  {
    id: 'building',
    title: 'Building and utilities',
    fields: [
      { label: 'Floor height', read: (p) => p.floorHeight ?? p.ceilingHeight },
      { label: 'Power load', read: (p) => p.powerLoad ?? p.powerConnection },
      { label: 'Power backup', read: (p) => p.powerBackup },
      { label: 'Central AC', read: (p) => p.centralAC },
      { label: 'Floor load capacity', read: (p) => p.floorLoadCapacity },
      { label: 'Overhead crane', read: (p) => p.overheadCrane },
      { label: 'Loading area', read: (p) => p.loadingArea },
      { label: 'Loading docks', read: (p) => p.loadingDocks },
      { label: 'Dock', read: (p) => p.dockAvailable, format: yesOnly },
      { label: 'Shutters', read: (p) => p.shutters },
    ],
  },

  {
    id: 'area',
    title: 'Area',
    fields: [
      // Carpet first: it is the honest number, the one a buyer is actually
      // getting, and the one a listing is least likely to lead with.
      { label: 'Carpet area', read: (p) => p.area?.carpetSqft, format: sqft },
      { label: 'Built-up area', read: (p) => p.area?.builtUpSqft, format: sqft },
      { label: 'Super built-up area', read: (p) => p.area?.superBuiltUpSqft, format: sqft },
      { label: 'Plot area', read: (p) => p.area?.plotSqft, format: sqft },
      { label: 'Total area', read: (p) => p.area?.totalSqft, format: sqft },
      {
        label: 'Price per sqft',
        read: (p) => p.area?.pricePerSqft,
        format: (value) => {
          if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return undefined;
          return `${formatPrice(value)} / sqft`;
        },
      },
    ],
  },

  {
    id: 'parking',
    title: 'Parking',
    fields: [
      { label: 'Covered', read: (p) => p.parking?.covered },
      { label: 'Open', read: (p) => p.parking?.open },
    ],
  },

  {
    id: 'charges',
    title: 'Charges',
    fields: [
      { label: 'Security deposit', read: (p) => p.deposit ?? p.securityDeposit, format: money },
      { label: 'Maintenance', read: (p) => p.maintenance, format: money },
      { label: 'Maintenance included', read: (p) => p.maintenanceIncluded, format: yesNo },
      { label: 'Booking amount', read: (p) => p.bookingAmount, format: money },
      { label: 'GST', read: (p) => p.gstApplicable },
    ],
  },

  {
    id: 'availability',
    title: 'Availability',
    fields: [{ label: 'Available from', read: (p) => p.availableFrom, format: date }],
  },

  {
    id: 'legal',
    title: 'Legal',
    fields: [
      { label: 'RERA ID', read: (p) => p.legal?.reraId },
      { label: 'Occupancy certificate', read: (p) => p.legal?.occupancyCertificate, format: yesNo },
      { label: 'Trade licence', read: (p) => p.legal?.tradeLicense, format: yesNo },
      { label: 'Fire NOC', read: (p) => p.legal?.fireNoc, format: yesNo },
    ],
  },
];

/**
 * The sections this listing can actually fill.
 *
 * Rows whose formatter returns undefined are dropped, then sections left with
 * no rows are dropped. A residential listing therefore never renders an empty
 * "Commercial details" heading, and nothing had to ask what kind of listing it
 * was to arrange that.
 */
export function resolveFieldSections(property: Property): FieldSection[] {
  const sections: FieldSection[] = [];

  for (const spec of SECTIONS) {
    const rows: FieldRow[] = [];

    for (const field of spec.fields) {
      const format = field.format ?? text;
      const value = format(field.read(property), property);
      if (value) rows.push({ label: field.label, value });
    }

    if (rows.length > 0) sections.push({ id: spec.id, title: spec.title, rows });
  }

  return sections;
}
