import { PREF_KEYS, prefsStorage } from '@/storage';

/**
 * A stable id for this install, generated once and kept in `prefsStorage`.
 *
 * It identifies the INSTALL, not the person: it is what lets `POST /events`
 * count a guest's second session as a return rather than a new visitor, and
 * what lets the push-token model tell a reinstall from a second device. It
 * carries nothing about the user, is never combined with account data on the
 * device, and a reinstall (or Expo Go, where prefs are in memory) simply mints
 * a new one.
 *
 * `crypto.randomUUID` is a global in React Native 0.81. The fallback is for a
 * host where it is not, and it only needs to be unique, not unguessable: this
 * id grants nothing.
 */
export function getInstallationId(): string {
  const existing = prefsStorage.getString(PREF_KEYS.installationId);
  if (existing) return existing;

  const id = mintId();
  prefsStorage.set(PREF_KEYS.installationId, id);
  return id;
}

function mintId(): string {
  const webCrypto = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (typeof webCrypto?.randomUUID === 'function') return webCrypto.randomUUID();

  let hex = '';
  while (hex.length < 32) hex += Math.floor(Math.random() * 0x10000).toString(16).padStart(4, '0');
  return hex.slice(0, 32);
}
