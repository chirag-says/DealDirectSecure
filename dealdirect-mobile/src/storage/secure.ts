import * as SecureStore from 'expo-secure-store';

/**
 * Encrypted storage, backed by the iOS Keychain and the Android Keystore.
 *
 * ONLY credentials belong here. The session cookie is a bearer credential valid
 * for seven days: anyone holding it is the user. MMKV is not encrypted, so the
 * cookie never goes there, never into AsyncStorage, and never into a log line.
 *
 * SecureStore is not available during server rendering or in a bare Node
 * context, and every call can throw if the keystore is locked or unavailable.
 * Each function therefore degrades to a null or a no-op rather than crashing
 * the app: a device that cannot read the keychain should send the user to
 * login, not to a crash screen.
 */

const SESSION_COOKIE_KEY = 'dd.session.cookie';

async function getItem(key: string): Promise<string | null> {
  try {
    return await SecureStore.getItemAsync(key);
  } catch (error) {
    console.warn('[secure] read failed', error);
    return null;
  }
}

async function setItem(key: string, value: string): Promise<void> {
  try {
    await SecureStore.setItemAsync(key, value, {
      keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
    });
  } catch (error) {
    console.warn('[secure] write failed', error);
  }
}

async function removeItem(key: string): Promise<void> {
  try {
    await SecureStore.deleteItemAsync(key);
  } catch (error) {
    console.warn('[secure] delete failed', error);
  }
}

/**
 * The raw `user_session` cookie value.
 *
 * This is the opaque 48-byte token the backend issued. It is not a JWT and
 * carries no readable claims, so there is nothing to inspect and nothing to
 * validate locally: the only way to know whether it is still good is to call
 * `GET /users/me`.
 */
export const sessionCookieStorage = {
  get: () => getItem(SESSION_COOKIE_KEY),
  set: (value: string) => setItem(SESSION_COOKIE_KEY, value),
  clear: () => removeItem(SESSION_COOKIE_KEY),
};
