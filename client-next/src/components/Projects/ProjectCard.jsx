import Link from "next/link";
import Image from "next/image";
import { Sparkles, Construction, KeyRound, BadgeCheck, MapPin, ArrowRight, Bookmark, BookmarkCheck } from "lucide-react";
import { cloudinaryImage, isCloudinaryImageUrl } from "../../utils/cloudinaryImage";

/**
 * The builder project card, shared by the home page rail and /projects so the
 * two never drift apart.
 *
 * Status colours pair every colour with an icon and the status word, so colour
 * is never the only carrier.
 */
export const PROJECT_STATUS = {
    "New Launch": { icon: Sparkles, pill: "bg-blue-700" },
    "Under Construction": { icon: Construction, pill: "bg-amber-600" },
    "Ready To Move": { icon: KeyRound, pill: "bg-emerald-600" },
    "Completed": { icon: BadgeCheck, pill: "bg-slate-700" },
};
export const PROJECT_STATUS_ORDER = Object.keys(PROJECT_STATUS);

const FALLBACK_IMG = "https://images.unsplash.com/photo-1600585154340-be6161a56a0c?q=80&w=800";

export const compactPrice = (n) => {
    if (!n || n <= 0) return null;
    if (n >= 1e7) return `₹${(n / 1e7).toFixed(2).replace(/\.?0+$/, "")} Cr`;
    if (n >= 1e5) return `₹${(n / 1e5).toFixed(0)} L`;
    return `₹${n.toLocaleString("en-IN")}`;
};

const monthYear = (d) => {
    const dt = d ? new Date(d) : null;
    return dt && !isNaN(dt) ? dt.toLocaleDateString("en-IN", { month: "short", year: "numeric" }) : null;
};

/**
 * `className` sizes the card (a rail width on the home page, nothing in a
 * grid). Pass `onBookmark` to show the save button; it sits outside the link
 * so saving never navigates.
 */
export default function ProjectCard({ project, className = "", sizes = "(min-width: 1024px) 300px, (min-width: 640px) 50vw, 90vw", isBookmarked = false, onBookmark }) {
    const builderName = project.builder?.company || project.builder?.name;
    const heroImg = project.media?.exteriorImages?.[0];
    const projectName = project.basics?.name || "Builder Project";
    const status = project.basics?.status || "New Launch";
    const cfg = PROJECT_STATUS[status] || PROJECT_STATUS["New Launch"];
    const StatusIcon = cfg.icon;
    const loc = [project.location?.locality, project.location?.city].filter(Boolean).join(", ");
    const rera = project.basics?.reraNumber?.trim();

    const min = compactPrice(project.priceRange?.min);
    const max = compactPrice(project.priceRange?.max);
    const priceLabel = min && max && max !== min ? `${min} – ${max}` : min;

    const facts = [
        ["Possession", monthYear(project.overview?.possessionDate)],
        ["Units", project.overview?.totalUnits > 0 ? project.overview.totalUnits.toLocaleString("en-IN") : null],
        ["Type", project.basics?.subType || project.basics?.category],
    ].filter(([, value]) => value);

    return (
        <div className={`group relative transition-transform duration-300 hover:-translate-y-1 ${className}`}>
            <Link
                href={`/projects/${project._id}`}
                className="flex h-full flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm transition-all duration-300 group-hover:border-blue-200 group-hover:shadow-xl focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-600 focus-visible:ring-offset-2"
            >
                <div className="relative aspect-[16/10] overflow-hidden bg-slate-100">
                    {/* Cloudinary photos are requested at card size from
                        Cloudinary itself and marked unoptimized, so the website's
                        server does not download and resize them through
                        /_next/image. Other sources (the fallback) keep Next's default. */}
                    <Image
                        src={cloudinaryImage(heroImg, "thumb") || FALLBACK_IMG}
                        unoptimized={isCloudinaryImageUrl(heroImg)}
                        alt={projectName}
                        fill
                        sizes={sizes}
                        className="object-cover transition-transform duration-700 group-hover:scale-105"
                        onError={(e) => (e.currentTarget.src = FALLBACK_IMG)}
                    />
                    <span className={`absolute left-3 top-3 inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-semibold text-white shadow-sm ${cfg.pill}`}>
                        <StatusIcon className="h-3 w-3" aria-hidden="true" />
                        {status}
                    </span>
                </div>

                <div className="flex flex-1 flex-col p-4">
                    <h3 className="line-clamp-2 text-base font-bold leading-snug tracking-tight text-gray-900 transition-colors group-hover:text-blue-800">
                        {projectName}
                    </h3>
                    {builderName && (
                        <p className="mt-0.5 truncate text-[13px] text-slate-500">
                            by <span className="font-medium text-slate-700">{builderName}</span>
                        </p>
                    )}
                    <p className="mt-2 flex items-center gap-1.5 text-sm text-gray-600">
                        <MapPin className="h-3.5 w-3.5 shrink-0 text-blue-600" aria-hidden="true" />
                        <span className="truncate">{loc || "India"}</span>
                    </p>

                    {/* Everything from the fact strip down is pinned to the card's
                        foot as one block, so the strip, price, arrow and RERA line
                        sit at the same height on every card in a row, whether the
                        name above runs to one line or two. */}
                    <div className="mt-auto pt-3">
                        {facts.length > 0 && (
                            <dl className="flex divide-x divide-slate-200 rounded-xl bg-slate-50 py-2">
                                {facts.map(([label, value]) => (
                                    <div key={label} className="min-w-0 flex-auto px-2.5">
                                        <dt className="text-[10px] font-semibold uppercase tracking-wide text-slate-400">{label}</dt>
                                        <dd className="mt-0.5 truncate text-[13px] font-semibold text-slate-800">{value}</dd>
                                    </div>
                                ))}
                            </dl>
                        )}

                        <div className="flex items-end justify-between gap-3 pt-4">
                            <div className="min-w-0">
                                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">Price</p>
                                {priceLabel
                                    ? <p className="mt-0.5 whitespace-nowrap text-[17px] font-bold leading-tight tracking-tight text-gray-900 tabular-nums">{priceLabel}</p>
                                    : <p className="mt-0.5 text-sm font-medium text-slate-500">On request</p>}
                            </div>
                            <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-blue-50 text-blue-700 transition-colors group-hover:bg-blue-700 group-hover:text-white" aria-hidden="true">
                                <ArrowRight className="h-4 w-4" />
                            </span>
                        </div>

                        {/* The number as entered, not a tick: nothing checks it
                            against a state RERA register. With no number the line
                            still holds its height (invisible), keeping the price
                            row level. */}
                        <p
                            className={`mt-3 truncate border-t border-slate-100 pt-2.5 text-[11px] text-slate-500 ${rera ? "" : "invisible"}`}
                            aria-hidden={rera ? undefined : true}
                        >
                            RERA <span className="font-mono text-slate-600">{rera || "-"}</span>
                        </p>
                    </div>
                </div>
            </Link>

            {onBookmark && (
                <button
                    type="button"
                    onClick={() => onBookmark(project._id)}
                    aria-pressed={isBookmarked}
                    aria-label={isBookmarked ? `Remove ${projectName} from saved` : `Save ${projectName}`}
                    className="absolute right-3 top-3 flex h-8 w-8 items-center justify-center rounded-full bg-white/95 text-slate-600 shadow-sm ring-1 ring-slate-900/5 transition-colors hover:bg-white hover:text-blue-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-600"
                >
                    {isBookmarked
                        ? <BookmarkCheck className="h-4 w-4 text-blue-700" aria-hidden="true" />
                        : <Bookmark className="h-4 w-4" aria-hidden="true" />}
                </button>
            )}
        </div>
    );
}

/** Loading placeholder with the card's shape, so the grid does not jump when data lands. */
export function ProjectCardSkeleton() {
    return (
        <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white" aria-hidden="true">
            <div className="aspect-[16/10] animate-pulse bg-slate-200" />
            <div className="space-y-2.5 p-4">
                <div className="h-4 w-3/4 animate-pulse rounded bg-slate-200" />
                <div className="h-3 w-1/2 animate-pulse rounded bg-slate-200" />
                <div className="h-3 w-2/3 animate-pulse rounded bg-slate-200" />
                <div className="!mt-4 h-12 w-full animate-pulse rounded-xl bg-slate-100" />
                <div className="flex items-end justify-between pt-2">
                    <div className="h-6 w-28 animate-pulse rounded bg-slate-200" />
                    <div className="h-9 w-9 animate-pulse rounded-full bg-slate-100" />
                </div>
            </div>
        </div>
    );
}
