import Constants, { ExecutionEnvironment } from 'expo-constants';

/**
 * Which host is running this bundle.
 *
 * Expo Go is a fixed, pre-built binary from the App Store. It contains a set
 * list of native modules and cannot be extended, so any module this project
 * depends on that Expo Go does not bundle is simply absent at runtime.
 *
 * Two of ours are in that position: `react-native-mmkv` (v4, Nitro-based) and
 * `@react-native-cookies/cookies`. Both sit behind a single module each
 * (`storage/mmkv.ts`, `auth/cookies.ts`), and both of those degrade to a
 * documented fallback rather than crashing. See those files for what is lost.
 *
 * ---------------------------------------------------------------------------
 * THIS FLAG IS FOR DIAGNOSTICS, NOT FOR BRANCHING
 *
 * The fallbacks key off whether the `require` actually succeeded, not off this
 * flag. That is the honest condition — "is the native module present?" — and
 * it means the app picks up the real implementation automatically if Expo Go
 * ever starts bundling one, with no code change here. This flag exists so the
 * startup log can say which mode the app is in, which is the difference
 * between "why is my theme not saving" taking ten seconds or an hour.
 */
export const IS_EXPO_GO = Constants.executionEnvironment === ExecutionEnvironment.StoreClient;
