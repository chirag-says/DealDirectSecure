import { IS_EXPO_GO } from './runtime';

/**
 * Loads a native module that may not exist in the current host.
 *
 * Expo Go is a fixed, pre-built binary. It ships a set list of native modules
 * and cannot be extended, so several of this project's dependencies are simply
 * absent when the bundle runs there. A missing native module does not fail
 * politely at the call site: it throws while its JS is being EVALUATED, which
 * means an ordinary `import` at the top of a file takes down every module that
 * transitively imports it.
 *
 * That is not hypothetical here. `@react-native-community/netinfo` is imported
 * by `lib/useNetworkStatus` → `lib/index` → `ui/OfflineBanner` → `ui/index`,
 * and `ui/index` is the barrel almost every screen imports. One missing module
 * therefore took out the root layout, which meant `AuthProvider` never mounted,
 * which meant every route died with "useAuth must be used inside AuthProvider"
 * — an error naming none of the four things that actually went wrong.
 *
 * So: modules that are optional in this sense are loaded through here, and
 * each call site decides what "absent" means for it. The app boots either way.
 *
 * ---------------------------------------------------------------------------
 * WHY A THUNK RATHER THAN A MODULE NAME
 *
 * Metro resolves `require` calls statically, at bundle time, from a string
 * literal. Passing a name (`optionalNativeModule('expo-image-picker')`) would
 * leave nothing for the bundler to find and the module would not be included
 * at all — it would be missing in EVERY host, including real builds. The thunk
 * keeps the literal `require` where Metro can see it, while leaving the app in
 * control of when it runs.
 *
 * ---------------------------------------------------------------------------
 * THIS IS KEYED ON THE FAILURE, NOT ON `IS_EXPO_GO`
 *
 * The real question is "is this module present", and asking it directly means
 * a module that Expo Go starts shipping tomorrow is picked up with no code
 * change. `IS_EXPO_GO` only sharpens the log line.
 */

/** One warning per module, however many times the resolver is consulted. */
const warned = new Set<string>();

export function optionalNativeModule<T>(
  load: () => T,
  label: string,
  /** What the user loses when this is absent. Goes straight into the log. */
  consequence: string
): T | null {
  try {
    return load();
  } catch {
    if (!warned.has(label)) {
      warned.add(label);
      console.warn(
        `[native] ${label} is not available in this host` +
          `${IS_EXPO_GO ? ' (running in Expo Go)' : ''}. ${consequence}`
      );
    }
    return null;
  }
}
