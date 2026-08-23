const { withAndroidManifest, withInfoPlist } = require('expo/config-plugins');

/**
 * Native declarations that let the app hand a payment off to a UPI app.
 *
 * The JavaScript half of this lives in `app/rewards/redeem.tsx`: the Hubble
 * WebView refuses non-Hubble URLs and passes them to `Linking.openURL`. That is
 * necessary and not sufficient — on both platforms the OS will refuse to tell
 * an app about other apps unless the query is declared up front, and the
 * refusal is silent. `canOpenURL` simply returns false and the payment appears
 * to do nothing.
 *
 * A config plugin rather than hand-edited native files because `/android` and
 * `/ios` are gitignored prebuild output here: anything written into them
 * directly is erased by the next `expo prebuild`.
 *
 * The list below is the common Indian UPI set. Hubble's integration guide asks
 * to have these confirmed against their own list — that check is outstanding.
 */

/** iOS: schemes the app is allowed to interrogate with `canOpenURL`. */
const IOS_SCHEMES = [
  'upi',
  'gpay',
  'tez',
  'phonepe',
  'paytmmp',
  'bhim',
  'credpay',
  'amazonpay',
  'mobikwik',
  'freecharge',
];

/** Android 11+ (API 30): packages and intents visible to the app. */
const ANDROID_PACKAGES = [
  'com.google.android.apps.nbu.paisa.user', // Google Pay
  'com.phonepe.app',
  'net.one97.paytm',
  'in.org.npci.upiapp', // BHIM
  'com.dreamplug.androidapp', // CRED
  'in.amazon.mShop.android.shopping',
  'com.mobikwik_new',
  'com.freecharge.android',
  'com.whatsapp',
];

function withIosSchemes(config) {
  return withInfoPlist(config, (mod) => {
    const existing = mod.modResults.LSApplicationQueriesSchemes ?? [];
    mod.modResults.LSApplicationQueriesSchemes = Array.from(
      new Set([...existing, ...IOS_SCHEMES])
    );
    return mod;
  });
}

function withAndroidQueries(config) {
  return withAndroidManifest(config, (mod) => {
    const manifest = mod.modResults.manifest;

    // `queries` is a sibling of `application`, not a child of it. Putting it
    // inside `application` parses without error and does nothing at all.
    manifest.queries = manifest.queries ?? [];
    if (manifest.queries.length === 0) manifest.queries.push({});
    const queries = manifest.queries[0];

    queries.package = queries.package ?? [];
    const declared = new Set(queries.package.map((entry) => entry.$?.['android:name']));
    for (const name of ANDROID_PACKAGES) {
      if (!declared.has(name)) queries.package.push({ $: { 'android:name': name } });
    }

    // The scheme intent covers UPI apps that are installed but not on the list
    // above, which matters because the list cannot be exhaustive.
    queries.intent = queries.intent ?? [];
    const hasUpiIntent = queries.intent.some((intent) =>
      intent.data?.some((data) => data.$?.['android:scheme'] === 'upi')
    );
    if (!hasUpiIntent) {
      queries.intent.push({
        action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
        data: [{ $: { 'android:scheme': 'upi' } }],
      });
    }

    return mod;
  });
}

module.exports = function withUpiQueries(config) {
  return withAndroidQueries(withIosSchemes(config));
};
