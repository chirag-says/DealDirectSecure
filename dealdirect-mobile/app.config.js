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

  /*
    THE APP MARK.

    There was no icon and no splash configured at all until 2026-08-24, so every
    build shipped with Expo's default artwork. Both stores reject that, and an
    internal tester cannot tell two dev builds apart on a home screen.

    Three renderings of one mark, because the platforms mask it differently:

      icon.png           1024², flattened onto opaque white and saved with NO
                         alpha channel. Apple rejects an icon that carries one.
                         The mark sits at 76% width; iOS only rounds the corners.

      adaptive-icon.png  1024², TRANSPARENT, mark at 62% width. Android hands
                         the launcher the foreground and lets it apply whatever
                         mask it likes — circle, squircle, teardrop — so
                         anything outside the central 66% can be cut off. The
                         mark is landscape at 1.55:1, which makes width the
                         binding constraint; 62% clears a circular mask with
                         margin. `backgroundColor` below is what shows around it.

      splash-icon.png    1024², transparent, mark at 46% — a splash mark sits
                         smaller than an icon because nothing crops it.

    White background rather than brand red: the mark is a red 'd' and a blue 'd'
    drawn with a white keyline, and that keyline needs white behind it to read
    as a keyline rather than as a gap.
  */
  icon: './assets/icon.png',

  ios: {
    bundleIdentifier: 'in.dealdirect.mobile',
    supportsTablet: true,
    // Associated domains for universal links are added in M12 together with the
    // apple-app-site-association file on the production domain.
  },

  android: {
    package: 'in.dealdirect.mobile',
    edgeToEdgeEnabled: true,
    adaptiveIcon: {
      foregroundImage: './assets/adaptive-icon.png',
      backgroundColor: '#FFFFFF',
    },
  },

  web: {
    favicon: './assets/favicon.png',
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
      /*
        The splash screen, which the root layout holds open until the fonts
        resolve or its own deadline passes — see `app/_layout.tsx`.

        `resizeMode: 'contain'` rather than 'cover': the mark has fixed
        proportions and cropping it on a narrow device would cut a letter in
        half. The background matches the icon's, so the splash and the launcher
        icon are the same white plate.
      */
      'expo-splash-screen',
      {
        image: './assets/splash-icon.png',
        imageWidth: 200,
        resizeMode: 'contain',
        backgroundColor: '#FFFFFF',
        dark: { backgroundColor: '#FFFFFF' },
      },
    ],
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
    // UPI app handoff for the Hubble rewards WebView. Declares the iOS query
    // schemes and the Android 11+ <queries> block — without them the OS hides
    // other apps from this one and a payment silently fails to open anything.
    './plugins/withUpiQueries',
    // FOREGROUND location only. Used for "search near me" and to preselect the
    // user's city, both at the moment the user asks — never in the background,
    // which is why no background permission is declared and the copy names the
    // benefit rather than asking for a blanket grant.
    [
      'expo-location',
      {
        locationWhenInUsePermission:
          'DealDirect uses your location to show properties near you and preselect your city.',
        isAndroidBackgroundLocationEnabled: false,
        isIosBackgroundLocationEnabled: false,
      },
    ],
    // Optional biometric app-lock, and a biometric confirm before the two
    // irreversible actions (delete account, revoke a session). The Android
    // USE_BIOMETRIC permission is added by the plugin; this only sets the iOS
    // Face ID string.
    [
      'expo-local-authentication',
      {
        faceIDPermission: 'DealDirect uses Face ID to unlock the app and confirm sensitive actions.',
      },
    ],
    // Native date picker, for the listing form's availability date and the
    // profile date of birth — both of which were free-text fields validated by
    // a regex because no picker was installed.
    '@react-native-community/datetimepicker',
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
