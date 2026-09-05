/**
 * Price intelligence — wording, thresholds and number formatting.
 *
 * Everything the "Price" block on a listing says about money lives here as a
 * pure function. The web app has no test runner, so the next best thing is to
 * keep the arithmetic and the sentence construction out of the components:
 * a component in this codebase should read a string off one of these functions
 * and render it, never compute a percentage inline.
 *
 * Two rules the whole module obeys, both from the upgrade plan:
 *
 *   1. Every field of `priceIntelligence` and `ownerStats` can be null. A null
 *      input must produce `null` out, never "0", "—" or "N/A". The caller
 *      renders nothing.
 *   2. Numbers published here are ASKING prices from DealDirect's own live
 *      listings. Nothing in this file may phrase a number as a valuation, an
 *      estimate of worth, or a sold price.
 *
 * SIGN CONVENTION for `deltaPct` and `qoqPct`: negative means lower.
 * `market.deltaPct` is (this listing − locality median) / median × 100, so a
 * negative value means the listing asks LESS than the median.
 */

import { formatPrice } from './formatPrice';

/**
 * Half-width of the dead band, in percent, around a zero difference from the
 * market median.
 *
 * A listing 0.4% off the median is not "a discount" in any sense a buyer would
 * recognise, and calling it one is the kind of dishonest number the plan warns
 * destroys the value of having data at all. Anything strictly inside ±2% is
 * reported as "in line with" instead of a direction.
 *
 * @type {number}
 */
export const MARKET_DEAD_BAND_PCT = 2;

/**
 * Minimum number of answered leads before an owner's response time is shown.
 * Below this the average is one or two data points pretending to be a habit.
 * @type {number}
 */
export const MIN_ANSWERED_FOR_RESPONSE_TIME = 3;

/** @param {*} v @returns {boolean} true only for a usable finite number. */
function isNum(v) {
    return typeof v === 'number' && Number.isFinite(v);
}

/**
 * Trim a fixed-decimal string back to its shortest honest form.
 * "1.20" → "1.2", "3.00" → "3".
 * @param {string} s
 * @returns {string}
 */
function trimDecimals(s) {
    return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s;
}

/**
 * Compact rupee formatting for inline sentences: "₹2L", "₹1.2Cr", "₹18,000".
 *
 * Distinct from `formatPrice`, which spells the unit out ("₹2 Lakh") and is
 * right for a headline figure but too long inside a sentence such as
 * "Price dropped ₹2L on 3 September".
 *
 * @param {number|string|null|undefined} amount — rupees
 * @returns {string|null} formatted amount, or null when there is nothing to show
 */
export function formatCompactRupees(amount) {
    const n = typeof amount === 'string' ? Number(amount) : amount;
    if (!isNum(n) || n <= 0) return null;

    if (n >= 10000000) return `₹${trimDecimals((n / 10000000).toFixed(1))}Cr`;
    if (n >= 100000) return `₹${trimDecimals((n / 100000).toFixed(1))}L`;
    return `₹${Math.round(n).toLocaleString('en-IN')}`;
}

/**
 * Long-form rupee formatting for headline figures ("₹42 Lakh").
 * Thin wrapper over the app-wide `formatPrice` that returns null instead of
 * "₹0" so callers can drop the element entirely.
 *
 * @param {number|string|null|undefined} amount — rupees
 * @returns {string|null}
 */
export function formatFullRupees(amount) {
    const n = typeof amount === 'string' ? Number(amount) : amount;
    if (!isNum(n) || n <= 0) return null;
    return formatPrice(n);
}

/**
 * Rupees per square foot, for the locality headline: "₹8,200 / sq.ft".
 * @param {number|null|undefined} amount
 * @returns {string|null}
 */
export function formatPerSqft(amount) {
    if (!isNum(amount) || amount <= 0) return null;
    return `₹${Math.round(amount).toLocaleString('en-IN')} / sq.ft`;
}

/**
 * "3 September" — day and month, no year.
 * @param {string|number|Date|null|undefined} value — anything `Date` accepts
 * @returns {string|null}
 */
export function formatDayMonth(value) {
    if (value === null || value === undefined || value === '') return null;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'long' });
}

/**
 * "3 September 2026" — day, month and year.
 * @param {string|number|Date|null|undefined} value
 * @returns {string|null}
 */
export function formatFullDate(value) {
    if (value === null || value === undefined || value === '') return null;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'long', year: 'numeric' });
}

/**
 * Date phrasing that drops the year only when it is the current one, so
 * "3 September" never silently means a date two years ago.
 *
 * @param {string|number|Date|null|undefined} value
 * @param {Date} [now] — injectable for deterministic checking
 * @returns {string|null}
 */
export function formatEventDate(value, now = new Date()) {
    if (value === null || value === undefined || value === '') return null;
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return null;
    return d.getFullYear() === now.getFullYear() ? formatDayMonth(d) : formatFullDate(d);
}

/**
 * How long the listing has been live, in plain English.
 *
 *   0   → "Listed today"
 *   1   → "Listed yesterday"
 *   2–60→ "Listed 12 days ago"
 *   61+ → "Listed 4 months ago"
 *
 * @param {number|null|undefined} daysListed
 * @returns {string|null}
 */
export function describeDaysListed(daysListed) {
    if (!isNum(daysListed) || daysListed < 0) return null;
    const n = Math.floor(daysListed);
    if (n === 0) return 'Listed today';
    if (n === 1) return 'Listed yesterday';
    if (n <= 60) return `Listed ${n} days ago`;
    const months = Math.max(2, Math.round(n / 30.44));
    return `Listed ${months} months ago`;
}

/**
 * The headline price-drop line: "Price dropped ₹2L on 3 September".
 *
 * Returns null unless the change really was downward and both ends are usable
 * numbers — an increase is not a drop, and the block that renders this is meant
 * to be a buyer-facing signal, not a changelog.
 *
 * @param {{from: number, to: number, at: string|Date}|null|undefined} lastDrop
 * @param {Date} [now] — injectable for deterministic checking
 * @returns {string|null}
 */
export function describePriceDrop(lastDrop, now = new Date()) {
    if (!lastDrop) return null;
    const { from, to, at } = lastDrop;
    if (!isNum(from) || !isNum(to) || to >= from) return null;

    const amount = formatCompactRupees(from - to);
    if (!amount) return null;

    const when = formatEventDate(at, now);
    return when ? `Price dropped ${amount} on ${when}` : `Price dropped ${amount}`;
}

/**
 * Where this listing sits against the market median, as a bare classification.
 * Kept separate from the wording so the caller can also pick a colour.
 *
 * @param {number|null|undefined} deltaPct — signed; negative = asks less than median
 * @param {number} [deadBandPct] — half-width of the "in line with" band
 * @returns {'below'|'above'|'inline'|null}
 */
export function classifyMarketPosition(deltaPct, deadBandPct = MARKET_DEAD_BAND_PCT) {
    if (!isNum(deltaPct)) return null;
    if (Math.abs(deltaPct) < deadBandPct) return 'inline';
    return deltaPct < 0 ? 'below' : 'above';
}

/**
 * Pluralise a configuration label for use mid-sentence.
 * "2 BHK" → "2 BHKs", "Studio" → "studios", already-plural passes through.
 *
 * @param {string|null|undefined} bhk
 * @returns {string|null}
 */
export function pluraliseConfiguration(bhk) {
    if (typeof bhk !== 'string') return null;
    const label = bhk.trim();
    if (!label) return null;
    if (/s$/i.test(label)) return label;
    if (/^studio$/i.test(label)) return 'studios';
    return `${label}s`;
}

/**
 * The market line: "Asks 8% below the Wakad median for 2 BHKs".
 *
 * Inside the dead band it becomes "In line with the Wakad median for 2 BHKs",
 * which is the whole reason the dead band exists.
 *
 * @param {{scope?: string, bhk?: string, city?: string, locality?: string,
 *          medianAsking?: number, deltaPct?: number}|null|undefined} market
 * @param {number} [deadBandPct]
 * @returns {{position: 'below'|'above'|'inline', text: string, pct: number}|null}
 */
export function describeMarketPosition(market, deadBandPct = MARKET_DEAD_BAND_PCT) {
    if (!market) return null;

    const position = classifyMarketPosition(market.deltaPct, deadBandPct);
    if (!position) return null;

    const place = market.locality || market.city;
    if (!place) return null;

    const config =
        market.scope === 'configuration' && market.bhk
            ? ` for ${pluraliseConfiguration(market.bhk)}`
            : '';

    if (position === 'inline') {
        return { position, pct: 0, text: `In line with the ${place} median${config}` };
    }

    const pct = Math.round(Math.abs(market.deltaPct));
    return { position, pct, text: `Asks ${pct}% ${position} the ${place} median${config}` };
}

/**
 * The supporting line under the market position: what the median actually is
 * and how many listings it came from. Without the sample size the percentage
 * above is an assertion rather than a measurement.
 *
 * @param {{locality?: string, city?: string, medianAsking?: number,
 *          count?: number, bhk?: string, scope?: string}|null|undefined} market
 * @returns {string|null}
 */
export function describeMarketMedian(market) {
    if (!market) return null;
    const median = formatCompactRupees(market.medianAsking);
    if (!median) return null;

    const place = market.locality || market.city;
    const config =
        market.scope === 'configuration' && market.bhk ? ` ${market.bhk}` : '';
    const where = place ? ` in ${place}` : '';

    if (!isNum(market.count) || market.count <= 0) {
        return `Median asking price${config ? ` for${config}` : ''}${where} is ${median}`;
    }
    const plural = market.count === 1 ? 'listing' : 'listings';
    return `Median asking price${config ? ` for${config}` : ''}${where} is ${median}, from ${market.count} live ${plural}`;
}

/**
 * One row of the price history disclosure, pre-formatted.
 *
 * @param {{from: number, to: number, deltaPct?: number, at: string}} change
 * @returns {{date: string|null, from: string|null, to: string|null,
 *            direction: 'up'|'down', deltaText: string|null}|null}
 */
export function formatPriceChange(change) {
    if (!change || !isNum(change.from) || !isNum(change.to)) return null;

    const direction = change.to < change.from ? 'down' : 'up';

    let pct = change.deltaPct;
    if (!isNum(pct) && change.from > 0) {
        pct = ((change.to - change.from) / change.from) * 100;
    }
    const deltaText = isNum(pct) ? `${trimDecimals(Math.abs(pct).toFixed(1))}%` : null;

    return {
        date: formatFullDate(change.at),
        from: formatCompactRupees(change.from),
        to: formatCompactRupees(change.to),
        direction,
        deltaText,
    };
}

/**
 * The whole price history, newest first, with unusable rows dropped.
 *
 * @param {Array<object>|null|undefined} changes
 * @returns {Array<object>} possibly empty, never null
 */
export function formatPriceHistory(changes) {
    if (!Array.isArray(changes)) return [];
    return changes
        .map(formatPriceChange)
        .filter(Boolean)
        .reverse();
}

/**
 * Owner responsiveness, shown only once there are enough answered leads for the
 * average to mean anything.
 *
 * @param {{responseHours?: number|null, answered?: number}|null|undefined} ownerStats
 * @param {number} [minAnswered]
 * @returns {string|null}
 */
export function describeOwnerResponse(ownerStats, minAnswered = MIN_ANSWERED_FOR_RESPONSE_TIME) {
    if (!ownerStats) return null;
    const { responseHours, answered } = ownerStats;
    if (!isNum(responseHours) || responseHours <= 0) return null;
    if (!isNum(answered) || answered < minAnswered) return null;

    if (responseHours < 1) return 'Usually replies within the hour';
    if (responseHours < 24) {
        const h = Math.round(responseHours);
        return `Usually replies in about ${h} ${h === 1 ? 'hour' : 'hours'}`;
    }
    const d = Math.round(responseHours / 24);
    return `Usually replies in about ${d} ${d === 1 ? 'day' : 'days'}`;
}

/**
 * Review summary: "4.6 out of 5 from 12 reviews".
 *
 * @param {{count?: number, overall?: number}|null|undefined} reviews
 * @returns {string|null}
 */
export function describeReviews(reviews) {
    if (!reviews) return null;
    const { count, overall } = reviews;
    if (!isNum(count) || count <= 0) return null;
    if (!isNum(overall) || overall <= 0) return null;
    const score = trimDecimals(overall.toFixed(1));
    return `${score} out of 5 from ${count} ${count === 1 ? 'review' : 'reviews'}`;
}

/**
 * The verification badges an owner has earned, as labels ready to render.
 * Returns an empty array rather than null so the caller can `.map` freely.
 *
 * @param {{verified?: boolean, documentsVerified?: boolean}|null|undefined} ownerStats
 * @returns {Array<{key: string, label: string}>}
 */
export function ownerBadges(ownerStats) {
    if (!ownerStats) return [];
    const badges = [];
    if (ownerStats.verified) badges.push({ key: 'identity', label: 'Identity verified' });
    if (ownerStats.documentsVerified) badges.push({ key: 'documents', label: 'Documents verified' });
    return badges;
}
