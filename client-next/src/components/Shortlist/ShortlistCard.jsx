'use client';

import Link from 'next/link';
import { MapPinIcon, TrashIcon } from '@heroicons/react/24/outline';

import { formatPrice } from '../../utils/formatPrice';

const API_BASE = process.env.NEXT_PUBLIC_API_BASE;
const FALLBACK_IMG =
    'https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800';

/**
 * Resolve a stored image reference to something an `<img>` can load.
 * Same three cases the property list handles: absolute URL, `/uploads/...`
 * path, or a bare filename.
 *
 * @param {string|null|undefined} img
 * @returns {string}
 */
function resolveImageSrc(img) {
    if (!img) return '';
    const s = String(img).trim();
    const lower = s.toLowerCase();
    if (lower.startsWith('data:') || lower.startsWith('http')) return s;
    if (s.startsWith('/uploads')) return `${API_BASE}${s}`;
    return `${API_BASE}/uploads/${s}`;
}

/**
 * Why a saved home can no longer be viewed, in the buyer's words.
 * @param {string|null|undefined} reason
 * @returns {string}
 */
function unavailableLabel(reason) {
    const r = String(reason || '').toLowerCase();
    if (r.includes('sold')) return 'Sold';
    if (r.includes('rent')) return 'Rented';
    if (r.includes('remov') || r.includes('delet')) return 'Listing removed';
    if (r.includes('expire')) return 'Listing expired';
    return 'No longer available';
}

/**
 * One saved home.
 *
 * Used by both the owner's own shortlist and the read-only shared view; the
 * `onRemove` prop is what separates them, and there is no other difference,
 * so a shared link can never grow an edit control by accident.
 *
 * @param {{
 *   entry: {id?: string, note?: string, available?: boolean,
 *           unavailableReason?: string, property?: object},
 *   onRemove?: (propertyId: string) => void,
 *   removing?: boolean
 * }} props
 */
export default function ShortlistCard({ entry, onRemove, removing }) {
    const property = entry?.property;
    if (!property) return null;

    const propertyId = property._id || property.id;
    const image = resolveImageSrc(property.images?.[0] || property.image) || FALLBACK_IMG;
    const place = [property.locality || property.address?.area, property.city || property.address?.city]
        .filter(Boolean)
        .join(', ');
    const available = entry.available !== false;

    return (
        <article className="overflow-hidden rounded-2xl border border-slate-200 bg-white transition-shadow hover:shadow-md">
            <div className="relative h-44 overflow-hidden bg-slate-100">
                {/*
                  A plain <img>, like every other property card in this app.
                  next/image would need every host in `images.remotePatterns`,
                  and these URLs resolve against NEXT_PUBLIC_API_BASE, which
                  differs per environment and is not listed there. Optimising
                  the image is not worth a broken one.
                */}
                {/* eslint-disable-next-line @next/next/no-img-element */}
                <img
                    src={image}
                    alt={property.title || 'Saved property'}
                    className={`h-full w-full object-cover ${available ? '' : 'opacity-60 grayscale'}`}
                    onError={(e) => {
                        e.target.onerror = null;
                        e.target.src = FALLBACK_IMG;
                    }}
                />
                {!available && (
                    <span className="absolute left-3 top-3 rounded-full bg-slate-900/90 px-3 py-1 text-[11px] font-semibold text-white">
                        {unavailableLabel(entry.unavailableReason)}
                    </span>
                )}
                {onRemove && propertyId && (
                    <button
                        type="button"
                        onClick={() => onRemove(propertyId)}
                        disabled={removing}
                        aria-label="Remove from shortlist"
                        className="absolute right-3 top-3 rounded-full bg-black/30 p-2 text-white backdrop-blur-sm transition-colors hover:bg-rose-600 disabled:cursor-not-allowed disabled:opacity-60"
                    >
                        <TrashIcon className="h-4 w-4" />
                    </button>
                )}
            </div>

            <div className="p-4">
                <p className="text-lg font-semibold text-slate-900">
                    {formatPrice(property.price)}
                    {String(property.listingType || '').toLowerCase() === 'rent' && (
                        <span className="text-sm font-normal text-slate-500"> / month</span>
                    )}
                </p>

                <h3 className="mt-1 line-clamp-1 text-sm font-medium text-slate-800">
                    {property.title || 'Property'}
                </h3>

                {place && (
                    <p className="mt-1 flex items-center gap-1 text-xs text-slate-500">
                        <MapPinIcon className="h-3.5 w-3.5 flex-shrink-0" />
                        <span className="line-clamp-1">{place}</span>
                    </p>
                )}

                {entry.note && (
                    <p className="mt-3 rounded-xl bg-amber-50 px-3 py-2 text-xs leading-relaxed text-amber-900">
                        {entry.note}
                    </p>
                )}

                {available && propertyId ? (
                    <Link
                        href={`/properties/${propertyId}`}
                        className="mt-3 inline-block text-sm font-semibold text-[#0f4fb5] hover:underline"
                    >
                        View listing
                    </Link>
                ) : (
                    <p className="mt-3 text-xs text-slate-500">
                        This listing is closed. It stays here until you remove it.
                    </p>
                )}
            </div>
        </article>
    );
}
