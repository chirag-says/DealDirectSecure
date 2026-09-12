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

/**
 * Google's iOS SDK expects its callback URL scheme to be the iOS client ID with
 * its dot-separated parts reversed:
 *
 *   1234-abcd.apps.googleusercontent.com
 *   → com.googleusercontent.apps.1234-abcd
 *
 * Derived rather than configured as a second variable, because the two can only
 * ever disagree by mistake, and the mistake is invisible: the wrong scheme
 * builds fine and sign-in hangs at the callback.
 *
 * Returns a harmless placeholder when no iOS client ID is set. The plugin
 * requires the option to be a string, and a build with Google unconfigured is a
 * supported state — the buttons simply do not render.
 */
function reversedIosClientId(clientId) {
  const trimmed = (clientId || '').trim();
  if (!trimmed) return 'com.googleusercontent.apps.unconfigured';
  return trimmed.split('.').reverse().join('.');
}

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

      splash-icon.png    1024², transparent, mark at 46%. NO LONGER USED for
                         the splash (2026-09-06): it was a separate, softer
                         rendering of the mark with ragged curves and a faint
                         box around it, and it did not match the icon. The
                         splash now shows icon.png itself, the one clean
                         source, on the same white it already carries. Kept on
                         disk only until nothing else references it.

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
    /*
      THE CHANNEL, FOR BUILDS MADE OUTSIDE EAS BUILD (2026-09-06).

      EAS Build writes the profile's channel into the app for you. A local
      Gradle build does not, and a binary with no channel never receives an
      update: it has no way to say which branch it wants, so the server has
      nothing to answer. The APK shipped on 2026-09-06 was built that way,
      which is why it could not be updated over the air. This header is what
      a local build was missing. "preview" matches the internal-distribution
      profile in eas.json, the one the APK is built with; an EAS Build with a
      profile of its own overrides it.
    */
    requestHeaders: {
      'expo-channel-name': 'preview',
    },
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
        half. The image is the app icon itself, an opaque white plate, on the
        same white, so only the mark is visible and it is drawn from the same
        pixels as the launcher icon. `AnimatedSplash` draws the same file at
        the same width, which is what makes the native-to-animated handoff
        invisible.
      */
      'expo-splash-screen',
      {
        image: './assets/icon.png',
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
    // Crash reporting (Phase 0). The plugin writes `sentry.properties` for the
    // native build's source-map upload. The upload needs SENTRY_AUTH_TOKEN in
    // the build environment and is NOT skipped without it: the Gradle task
    // fails the whole release build (verified 2026-09-06). A build with no
    // token must set SENTRY_DISABLE_AUTO_UPLOAD=true; eas.json does this for
    // the development and preview profiles.
    // The runtime DSN is EXPO_PUBLIC_SENTRY_DSN, read in
    // src/observability/sentry.ts; unset, the SDK never initialises.
    [
      '@sentry/react-native/expo',
      {
        organization: process.env.SENTRY_ORG || 'dealdirect',
        project: process.env.SENTRY_PROJECT || 'dealdirect-mobile',
        url: 'https://sentry.io/',
      },
    ],
    // Google Sign-In. A NATIVE module: it does not exist in Expo Go, and adding
    // it changes the fingerprint, so the first build carrying it cannot be
    // delivered as an OTA update.
    //
    // `iosUrlScheme` is the iOS client ID with its dot-separated parts
    // REVERSED, which is how Google's iOS SDK expects the callback scheme.
    // Passing the plain client ID here produces a scheme that never fires and a
    // sign-in that hangs on the callback.
    //
    // Android needs no option here, but it does need the signing-certificate
    // SHA-1 registered against the Android OAuth client, one per variant
    // (debug, upload, Play App Signing).
    //
    // The client IDs themselves are read at RUNTIME from EXPO_PUBLIC_* through
    // src/config/env.ts, not from here, so a build with none configured simply
    // hides the Google buttons rather than failing.
    [
      '@react-native-google-signin/google-signin',
      {
        iosUrlScheme: reversedIosClientId(process.env.EXPO_PUBLIC_GOOGLE_IOS_CLIENT_ID),
      },
    ],
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
