/**
 * Shortlist — one shared client-side cache of "which properties have I saved".
 *
 * WHY A MODULE SINGLETON RATHER THAN A CONTEXT
 * A save control appears on every card in a 50-item grid and again on the
 * detail page. Asking each one for its own state would mean fifty requests to
 * `GET /shortlist/ids`. A React context would work but has to be mounted above
 * every consumer, which means editing the root layout for a feature that only
 * some pages use. A module singleton with an explicit subscribe list costs
 * neither: the first consumer triggers one request, every later consumer reads
 * the same Set, and mutations fan out to all of them.
 *
 * The Set is REPLACED on every mutation, never mutated in place, so `useState`
 * consumers see a new identity and re-render.
 *
 * SSR NOTE: this module is imported by client components, so it is also
 * evaluated on the server. Nothing here mutates state outside an event handler
 * or an effect, so the server-side copy stays empty and every request renders
 * the same "not saved" markup that hydration then corrects.
 *
 * WHAT THIS IS NOT: the shortlist is not the "I'm Interested" flow. Saving
 * notifies nobody, creates no Lead, and does not count against the interest
 * cap. The two must stay visibly separate in the UI, and this module never
 * touches `/properties/interested/*`.
 */

import { useSyncExternalStore } from 'react';
import api from './api';

/** @type {Set<string>} */
let ids = new Set();
let loaded = false;
/** @type {Promise<Set<string>>|null} */
let inflight = null;
/** @type {Set<Function>} */
const listeners = new Set();

function emit() {
    for (const listener of listeners) listener();
}

/** @returns {Set<string>} the current saved-property id set (do not mutate) */
export function getShortlistIds() {
    return ids;
}

/**
 * @param {string} propertyId
 * @returns {boolean}
 */
export function isShortlisted(propertyId) {
    return ids.has(String(propertyId));
}

/**
 * @param {Function} listener — called with no arguments after every change
 * @returns {Function} unsubscribe
 */
export function subscribeShortlist(listener) {
    listeners.add(listener);
    return () => listeners.delete(listener);
}

/**
 * Load the saved ids once per session. Concurrent callers share one request.
 *
 * A failed read deliberately leaves `loaded` false rather than caching an empty
 * Set: an outage must not make every heart look un-saved for the rest of the
 * session.
 *
 * @param {{force?: boolean}} [options]
 * @returns {Promise<Set<string>>}
 */
export function loadShortlistIds({ force = false } = {}) {
    if (loaded && !force) return Promise.resolve(ids);
    if (inflight && !force) return inflight;

    inflight = (async () => {
        try {
            const res = await api.get('/shortlist/ids');
            const list = Array.isArray(res?.data?.data) ? res.data.data : [];
            ids = new Set(list.map(String));
            loaded = true;
            emit();
        } catch {
            // 401 for a guest is expected and silent; anything else is a
            // transient failure we simply do not cache.
            loaded = false;
        } finally {
            inflight = null;
        }
        return ids;
    })();

    return inflight;
}

/**
 * Save a property. Idempotent on the server, so a double click is harmless.
 *
 * @param {string} propertyId
 * @param {string} [note]
 * @returns {Promise<void>}
 */
export async function addToShortlist(propertyId, note) {
    const body = { propertyId };
    if (note) body.note = note;
    await api.post('/shortlist', body);

    const next = new Set(ids);
    next.add(String(propertyId));
    ids = next;
    emit();
}

/**
 * Remove a property from the shortlist.
 *
 * @param {string} propertyId
 * @returns {Promise<{removed?: boolean, total?: number}>}
 */
export async function removeFromShortlist(propertyId) {
    const res = await api.delete(`/shortlist/${propertyId}`);

    const next = new Set(ids);
    next.delete(String(propertyId));
    ids = next;
    emit();

    return res?.data ?? {};
}

/**
 * Drop everything — call when the session ends so the next user starts clean.
 *
 * The early return matters: every save button on a 50-card grid calls this on
 * mount while logged out. Without the guard each call would install a fresh Set
 * and notify every other button, turning one render into a quadratic storm of
 * state updates that all say "still empty".
 */
export function clearShortlistCache() {
    if (!loaded && ids.size === 0 && !inflight) return;
    ids = new Set();
    loaded = false;
    inflight = null;
    emit();
}

/**
 * Subscribe a component to the saved-id set.
 *
 * `useSyncExternalStore` rather than useState + useEffect: this is exactly the
 * shape it exists for, it cannot miss a change that lands between render and
 * subscription, and it gives React an explicit server snapshot so a save button
 * renders identically on the server and on first hydration.
 *
 * The snapshot is only ever a NEW Set when something changed, so the identity
 * comparison React does here is both cheap and correct.
 *
 * @returns {Set<string>}
 */
export function useShortlistIds() {
    return useSyncExternalStore(subscribeShortlist, getShortlistIds, getShortlistIds);
}
