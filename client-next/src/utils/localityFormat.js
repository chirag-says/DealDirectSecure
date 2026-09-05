/**
 * Locality price page — wording, period arithmetic and chart geometry.
 *
 * Same contract as `priceIntelligence.js`: pure functions, null in / null out,
 * and no component in this app does arithmetic on a locality statistic.
 *
 * The locality pages are the only part of the upgrade that earns organic search
 * traffic, so their titles, descriptions and disclaimers are load-bearing. They
 * are written here, once, rather than inline in JSX where they would drift.
 *
 * HONESTY RULES baked into this file, from the upgrade plan:
 *   - Every number is an ASKING price taken from DealDirect's own live
 *     listings. India has no public sold-price registry; nothing here may be
 *     worded as a valuation, an estimate of worth, or a transacted price.
 *   - A locality is published only where at least `sampleFloor` listings exist.
 *     The disclaimer says so on every page.
 */

import { formatCompactRupees, formatPerSqft } from './priceIntelligence';

/**
 * Half-width, in percent, of the band in which a quarter-on-quarter move is
 * reported as "little changed" rather than up or down. Narrower than the
 * listing-vs-median dead band because a market-wide move of 1% across a whole
 * quarter is a real signal, where a single listing 1% off the median is noise.
 * @type {number}
 */
export const QOQ_FLAT_BAND_PCT = 0.5;

/** Months covered by each quarter label, for human-readable periods. */
const QUARTER_MONTHS = {
    1: 'Jan–Mar',
    2: 'Apr–Jun',
    3: 'Jul–Sep',
    4: 'Oct–Dec',
};

/** @param {*} v @returns {boolean} */
function isNum(v) {
    return typeof v === 'number' && Number.isFinite(v);
}

/** @param {string} s @returns {string} "1.20" → "1.2", "3.00" → "3" */
function trimDecimals(s) {
    return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s;
}

/**
 * Coerce anything to one of the two listing types the backend accepts.
 * Anything unrecognised becomes 'sale', which is also the default for the
 * canonical URL of a locality page.
 *
 * @param {*} value
 * @returns {'sale'|'rent'}
 */
export function normalizeListingType(value) {
    return String(value || '').toLowerCase() === 'rent' ? 'rent' : 'sale';
}

/**
 * "2026-Q3" → "Jul–Sep 2026". Falls back to the raw string when the label is
 * not in the expected shape, so an unexpected period never blanks the page.
 *
 * @param {string|null|undefined} period
 * @returns {string|null}
 */
export function formatPeriod(period) {
    if (typeof period !== 'string' || !period) return null;
    const m = /^(\d{4})-Q([1-4])$/.exec(period.trim());
    if (!m) return period;
    return `${QUARTER_MONTHS[Number(m[2])]} ${m[1]}`;
}

/**
 * "2026-Q3" → "Q3 2026", for axis labels and table headers where the month
 * range is too wide.
 *
 * @param {string|null|undefined} period
 * @returns {string|null}
 */
export function formatPeriodShort(period) {
    if (typeof period !== 'string' || !period) return null;
    const m = /^(\d{4})-Q([1-4])$/.exec(period.trim());
    if (!m) return period;
    return `Q${m[2]} ${m[1]}`;
}

/**
 * The verb a listing type takes when talking about its price.
 * sale → "ask", rent → "rent for".
 *
 * @param {'sale'|'rent'|string} listingType
 * @returns {string}
 */
export function askVerb(listingType) {
    return normalizeListingType(listingType) === 'rent' ? 'rent for' : 'ask';
}

/**
 * Noun for the money itself: "asking prices" or "asking rents".
 * @param {'sale'|'rent'|string} listingType
 * @returns {string}
 */
export function priceNoun(listingType) {
    return normalizeListingType(listingType) === 'rent' ? 'asking rents' : 'asking prices';
}

/**
 * Human label for a listing type in a heading: "for sale" / "to rent".
 * @param {'sale'|'rent'|string} listingType
 * @returns {string}
 */
export function listingTypeLabel(listingType) {
    return normalizeListingType(listingType) === 'rent' ? 'to rent' : 'for sale';
}

/**
 * "Wakad, Pune" — or just the half that exists.
 * @param {{locality?: string, city?: string}|null|undefined} place
 * @returns {string}
 */
export function localityLabel(place) {
    if (!place) return '';
    return [place.locality, place.city].filter(Boolean).join(', ');
}

/**
 * The configuration with the most listings behind it — the one a page title
 * should name, because it is the one the number is most solid for.
 *
 * @param {Array<{bhk?: string, count?: number}>|null|undefined} byConfiguration
 * @returns {object|null}
 */
export function dominantConfiguration(byConfiguration) {
    if (!Array.isArray(byConfiguration) || byConfiguration.length === 0) return null;
    let best = null;
    for (const row of byConfiguration) {
        if (!row || !row.bhk || !isNum(row.medianAsking)) continue;
        if (!best || (row.count || 0) > (best.count || 0)) best = row;
    }
    return best;
}

/**
 * The `<title>` for a locality page. Names the place, the city and the median,
 * because those three are what a search for "2BHK price in Wakad" contains.
 *
 * With a dominant configuration:
 *   "2 BHK flats in Wakad, Pune ask a median of ₹42L"
 * Without one:
 *   "Property prices in Wakad, Pune — median asking ₹42L"
 *
 * The site's metadata template appends " | DealDirect".
 *
 * @param {object|null|undefined} detail — the `data` object from GET /localities/:slug
 * @returns {string}
 */
export function localityPageTitle(detail) {
    if (!detail) return 'Locality prices';

    const place = localityLabel(detail);
    const listingType = normalizeListingType(detail.listingType);
    const median = formatCompactRupees(detail.headline?.medianAsking);
    const dominant = dominantConfiguration(detail.byConfiguration);

    if (dominant && median) {
        const verb = listingType === 'rent' ? 'rent for a median of' : 'ask a median of';
        return `${dominant.bhk} homes in ${place} ${verb} ${median}`;
    }

    const what = listingType === 'rent' ? 'Rents' : 'Property prices';
    return median
        ? `${what} in ${place} — median asking ${median}`
        : `${what} in ${place}`;
}

/**
 * The meta description. Repeats the median, adds the sample size and the
 * quarter, and states that the figure is an asking price — a search snippet is
 * the one place the disclaimer cannot be a footnote.
 *
 * @param {object|null|undefined} detail
 * @returns {string}
 */
export function localityMetaDescription(detail) {
    if (!detail) return 'Asking-price data from live DealDirect listings.';

    const place = localityLabel(detail);
    const listingType = normalizeListingType(detail.listingType);
    const h = detail.headline || {};
    const median = formatCompactRupees(h.medianAsking);
    const period = formatPeriod(detail.period);
    const range =
        formatCompactRupees(h.p25) && formatCompactRupees(h.p75)
            ? `${formatCompactRupees(h.p25)}–${formatCompactRupees(h.p75)}`
            : null;

    const parts = [];
    if (median) {
        parts.push(
            listingType === 'rent'
                ? `Homes ${listingTypeLabel(listingType)} in ${place} ask a median of ${median} a month`
                : `Homes ${listingTypeLabel(listingType)} in ${place} ask a median of ${median}`
        );
    } else {
        parts.push(`${priceNoun(listingType)} in ${place}`);
    }
    if (range) parts.push(`with the middle half between ${range}`);
    if (isNum(h.count) && h.count > 0) parts.push(`across ${h.count} live listings`);
    if (period) parts.push(`(${period})`);

    return `${parts.join(', ').replace(', (', ' (')}. Asking prices from DealDirect listings, not a valuation.`;
}

/**
 * Quarter-on-quarter movement in plain English, with a direction the caller can
 * colour by. Inside ±QOQ_FLAT_BAND_PCT it reads "little changed" — a 0.2% move
 * on a median of a few dozen listings is not a trend.
 *
 * @param {number|null|undefined} qoqPct — signed; negative = down
 * @param {number} [flatBandPct]
 * @returns {{direction: 'up'|'down'|'flat', text: string, pct: number}|null}
 */
export function describeQoq(qoqPct, flatBandPct = QOQ_FLAT_BAND_PCT) {
    if (!isNum(qoqPct)) return null;

    if (Math.abs(qoqPct) < flatBandPct) {
        return { direction: 'flat', pct: 0, text: 'Little changed from the previous quarter' };
    }

    const pct = Math.abs(qoqPct);
    const label = trimDecimals(pct.toFixed(1));
    return qoqPct > 0
        ? { direction: 'up', pct, text: `Up ${label}% on the previous quarter` }
        : { direction: 'down', pct, text: `Down ${label}% on the previous quarter` };
}

/**
 * Compact signed percentage for a table cell: "+3.2%", "−1.8%", "0%".
 * Uses a real minus sign so it lines up with the plus in a numeric column.
 *
 * @param {number|null|undefined} qoqPct
 * @param {number} [flatBandPct]
 * @returns {{text: string, direction: 'up'|'down'|'flat'}|null}
 */
export function formatQoqBadge(qoqPct, flatBandPct = QOQ_FLAT_BAND_PCT) {
    if (!isNum(qoqPct)) return null;
    if (Math.abs(qoqPct) < flatBandPct) return { text: '0%', direction: 'flat' };
    const label = trimDecimals(Math.abs(qoqPct).toFixed(1));
    return qoqPct > 0
        ? { text: `+${label}%`, direction: 'up' }
        : { text: `−${label}%`, direction: 'down' };
}

/**
 * "From 37 live listings this quarter" — the sample line that has to sit next
 * to every median.
 *
 * @param {number|null|undefined} count
 * @returns {string|null}
 */
export function describeSample(count) {
    if (!isNum(count) || count <= 0) return null;
    return `From ${count} live ${count === 1 ? 'listing' : 'listings'} this quarter`;
}

/**
 * "The middle half asks ₹34L–₹51L" — the interquartile range, which is a more
 * useful thing for a buyer than a standard deviation and easier to state
 * honestly.
 *
 * @param {number|null|undefined} p25
 * @param {number|null|undefined} p75
 * @param {'sale'|'rent'|string} [listingType]
 * @returns {string|null}
 */
export function describeSpread(p25, p75, listingType = 'sale') {
    const lo = formatCompactRupees(p25);
    const hi = formatCompactRupees(p75);
    if (!lo || !hi) return null;
    return `The middle half ${askVerb(listingType)} ${lo}–${hi}`;
}

/**
 * Bar geometry for the trend visual.
 *
 * Six numbers do not justify a charting dependency, so the page draws plain
 * divs and this function supplies the heights. Bars are measured from zero —
 * the honest baseline for a price — with a small floor so a genuinely low bar
 * is still visible and hoverable.
 *
 * @param {Array<{period: string, medianAsking: number, count?: number}>|null|undefined} trend
 * @param {{minHeightPct?: number}} [options]
 * @returns {Array<{period: string, label: string|null, medianAsking: number,
 *                  money: string|null, count: number|null, heightPct: number}>}
 */
export function trendBars(trend, { minHeightPct = 6 } = {}) {
    if (!Array.isArray(trend)) return [];

    const usable = trend.filter((p) => p && isNum(p.medianAsking) && p.medianAsking > 0);
    if (usable.length === 0) return [];

    const max = Math.max(...usable.map((p) => p.medianAsking));

    return usable.map((p) => ({
        period: p.period,
        label: formatPeriodShort(p.period),
        medianAsking: p.medianAsking,
        money: formatCompactRupees(p.medianAsking),
        count: isNum(p.count) ? p.count : null,
        heightPct: Math.max(minHeightPct, Math.round((p.medianAsking / max) * 100)),
    }));
}

/**
 * Median price per square foot as a display string, or null.
 * Re-exported through this module so locality components have one import.
 *
 * @param {number|null|undefined} value
 * @returns {string|null}
 */
export function formatMedianPerSqft(value) {
    return formatPerSqft(value);
}

/**
 * The disclaimer that appears at the foot of every locality page.
 *
 * This is not boilerplate. It is the difference between publishing a measured
 * statistic and implying a valuation, and it is why the sample floor is stated
 * as a number rather than described as "sufficient data".
 *
 * @param {number|null|undefined} sampleFloor
 * @param {'sale'|'rent'|string} [listingType]
 * @returns {string[]} sentences, in order
 */
export function disclaimerLines(sampleFloor, listingType = 'sale') {
    const floor = isNum(sampleFloor) && sampleFloor > 0 ? sampleFloor : null;
    const noun = priceNoun(listingType);

    return [
        `These are ${noun} taken from live listings on DealDirect. They are what owners are asking, not what homes sold for.`,
        floor
            ? `A locality is published only where at least ${floor} listings are live in the quarter. Below that the figure is withheld rather than estimated.`
            : 'A locality is published only where enough listings are live in the quarter. Below that the figure is withheld rather than estimated.',
        'This is not a valuation and must not be relied on as one. India has no public register of sold prices, and DealDirect does not pretend to one.',
    ];
}

/**
 * Canonical path for a locality page. Sale is the bare URL; rent carries the
 * query parameter, so the two never compete for the same canonical.
 *
 * @param {string} slug
 * @param {'sale'|'rent'|string} [listingType]
 * @returns {string}
 */
export function localityHref(slug, listingType = 'sale') {
    const lt = normalizeListingType(listingType);
    return lt === 'rent' ? `/localities/${slug}?listingType=rent` : `/localities/${slug}`;
}

/**
 * Group index rows by city and sort both levels for a stable render:
 * cities alphabetically, localities by sample size (largest first) so the
 * best-supported numbers lead.
 *
 * @param {Array<{city?: string, locality?: string, count?: number}>|null|undefined} items
 * @returns {Array<{city: string, items: Array<object>}>}
 */
export function groupByCity(items) {
    if (!Array.isArray(items)) return [];

    const byCity = new Map();
    for (const item of items) {
        if (!item || !item.slug) continue;
        const city = item.city || 'Other';
        if (!byCity.has(city)) byCity.set(city, []);
        byCity.get(city).push(item);
    }

    return [...byCity.entries()]
        .map(([city, rows]) => ({
            city,
            items: rows.slice().sort((a, b) => (b.count || 0) - (a.count || 0)),
        }))
        .sort((a, b) => a.city.localeCompare(b.city));
}

/**
 * Distinct city names present in the index, alphabetically — the filter chips.
 *
 * @param {Array<{city?: string}>|null|undefined} items
 * @returns {string[]}
 */
export function citiesIn(items) {
    if (!Array.isArray(items)) return [];
    return [...new Set(items.map((i) => i && i.city).filter(Boolean))].sort((a, b) =>
        a.localeCompare(b)
    );
}
