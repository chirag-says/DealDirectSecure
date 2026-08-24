/**
 * Device capabilities, each behind graceful degradation.
 *
 * Every module here loads its native dependency through
 * `config/optionalNativeModule`, so a host that lacks it — Expo Go, or a build
 * that predates the dependency — degrades to the capability simply being
 * absent rather than crashing the screen that reached for it. The functions are
 * safe to call unconditionally; the `*Available` flags are for deciding whether
 * to OFFER a feature, not whether it is safe to invoke.
 *
 * These are the Phase 3 native layer. They are mobile-only and touch no
 * backend. Server-initiated push (Phase 4) is deliberately not here: it needs a
 * device-token pipeline the backend does not have.
 */

export { selection, press, success, warning, hapticsAvailable } from './haptics';
export { copyToClipboard, clipboardAvailable } from './clipboard';
export {
  getCoordinates,
  describeCoordinates,
  geocodeAddress,
  getCurrentCity,
  hasLocationPermission,
  locationAvailable,
  type Coordinates,
  type CityResult,
  type GeocodeResult,
  type LocationResult,
  type PlaceResult,
  type ResolvedPlace,
} from './location';
export {
  confirmWithBiometrics,
  unlockWithBiometrics,
  isBiometricReady,
  biometricsModuleAvailable,
} from './biometrics';
