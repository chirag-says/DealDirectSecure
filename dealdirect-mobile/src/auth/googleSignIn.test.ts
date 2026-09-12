import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

/**
 * Source-level guards on how the Google SDK is loaded.
 *
 * The runtime behaviour cannot be exercised here (it needs React Native), so
 * these pin the two facts that stop the app breaking in a build without the
 * native module — Expo Go, or a dev client built before the module was added.
 * Both were real failures on 2026-09-12: the first a white screen at launch,
 * the second a red error overlay on the login screen.
 */
// A path string, not a URL object: this project's tsconfig loads the DOM lib,
// whose global `URL` is not the `URL` node:fs accepts, and the mismatch makes
// TypeScript pick the Buffer-returning overload.
const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'googleSignIn.ts'), 'utf8')
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/\/\/[^\r\n]*/g, '');

describe('googleSignIn.ts loads the native SDK safely', () => {
  it('never imports the package statically', () => {
    // A static import evaluates the package at app start. Without the native
    // half that throws before any screen renders: a white screen, not a
    // missing button.
    assert.doesNotMatch(
      src,
      /^\s*import\b[^;]*from\s+['"]@react-native-google-signin\/google-signin['"]/m,
      'the SDK must be require()d lazily, never imported at the top level'
    );
  });

  it('checks the native module is registered BEFORE requiring the package', () => {
    // A try/catch around require() is not enough: Metro reports a
    // module-evaluation failure to LogBox before the throw reaches the catch,
    // so the user still sees a red error. The package must not be evaluated
    // at all unless TurboModuleRegistry can see its native side.
    const gate = src.indexOf("TurboModuleRegistry.get<TurboModule>(NATIVE_MODULE_NAME)");
    const req = src.indexOf("require('@react-native-google-signin/google-signin')");
    assert.notEqual(gate, -1, 'the TurboModuleRegistry.get gate is missing');
    assert.notEqual(req, -1, 'the lazy require is missing');
    assert.ok(gate < req, 'the native-module check must come before the require');
    assert.match(src, /NATIVE_MODULE_NAME = 'RNGoogleSignin'/, 'must look up the name the package registers');
  });

  it('renders no button unless both a client ID and the native module exist', () => {
    assert.match(
      src,
      /GOOGLE_WEB_CLIENT_ID\.length > 0 && isGoogleSignInAvailable\(\)/,
      'a client ID with no native SDK would render a button that fails on tap'
    );
  });
});
