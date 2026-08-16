/**
 * Expo app configuration.
 *
 * Plain JavaScript, not TypeScript. `eas-cli`'s config evaluator
 * (`@expo/require-utils`) has a known bug transpiling `app.config.ts` on some
 * toolchains — it throws `Cannot read properties of undefined (reading
 * 'CommonJS')` before it ever reaches the config values, while `npx expo
 * config` (Expo's own loader) reads the identical content fine. The values
 * below are unchanged from the TypeScript version; only the file extension and
 * the removed type annotations differ, so nothing configured here has moved.
 *
 * FROZEN 2026-07-31 by explicit approval:
 *
 *   iOS bundleIdentifier   in.dealdirect.mobile
 *   Android package        in.dealdirect.mobile
 *
 * Do not change either without an explicit instruction. After a build reaches
 * a store, neither can be changed at all: a new identifier is a new app, with
 * no upgrade path for installed users.
 *
 * The deep-link ROUTING implementation belongs to M12. Only the identifiers and
 * the scheme are declared at this stage.
 */

/** @type {import('expo/config').ExpoConfig} */
const config = {
  name: 'DealDirect',
  slug: 'dealdirect-mobile',
  owner: 'chiragmtest',
  version: '0.1.0',
  orientation: 'portrait',
  scheme: 'dealdirect',
  userInterfaceStyle: 'automatic',
  newArchEnabled: true,

  ios: {
    bundleIdentifier: 'in.dealdirect.mobile',
    supportsTablet: true,
    // Associated domains for universal links are added in M12 together with the
    // apple-app-site-association file on the production domain.
  },

  android: {
    package: 'in.dealdirect.mobile',
    edgeToEdgeEnabled: true,
  },

  // EAS Update. Set by hand for the same reason the EAS project id below is:
  // `eas update:configure` patches app.json, and cannot write to a dynamic
  // config. The url is derived from the project id and is not a credential.
  updates: {
    url: 'https://u.expo.dev/9d0ec43d-f62d-4bf2-8c59-549fb239b8a0',
  },

  // `fingerprint` hashes the native side (packages, plugins, native config) and
  // uses that as the runtime version, so an update is only ever delivered to a
  // binary that can actually run it. The alternative, `appVersion`, would let a
  // JS bundle needing a new native module land on a build without it, which
  // fails at runtime rather than at publish time. Adding or removing any native
  // dependency changes the fingerprint and therefore requires a new build.
  runtimeVersion: {
    policy: 'fingerprint',
  },

  plugins: [
    'expo-router',
    'expo-secure-store',
    'expo-font',
    [
      'expo-image-picker',
      {
        photosPermission: 'DealDirect needs access to your photos to add listing images.',
        cameraPermission: 'DealDirect needs access to your camera to photograph a listing.',
      },
    ],
    // Client-side only (M13): local/in-app notifications for new chat
    // messages while the app is foregrounded. No server-initiated push —
    // that needs an FCM/APNs device-token pipeline the backend does not have,
    // tracked separately as a change request. See docs/HANDOFF.md.
    'expo-notifications',
  ],

  experiments: {
    typedRoutes: true,
  },

  extra: {
    // Read through src/config/env.ts, never directly.
    apiUrl: process.env.EXPO_PUBLIC_API_URL,
    socketUrl: process.env.EXPO_PUBLIC_SOCKET_URL,
    // EAS project link. A dynamic config (.js/.ts) can't be auto-patched by
    // `eas build`, so this is set by hand once rather than regenerated per
    // build. Safe to commit: it identifies the EAS project, it is not a
    // credential.
    eas: {
      projectId: '9d0ec43d-f62d-4bf2-8c59-549fb239b8a0',
    },
  },
};

module.exports = config;
