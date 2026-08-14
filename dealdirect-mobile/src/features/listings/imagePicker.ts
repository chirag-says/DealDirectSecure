/**
 * Image picking and client-side compression for listing photos.
 *
 * The backend caps uploads at 10 MB per file (`middleware/upload.js`, see
 * `src/api/endpoints/properties.ts`). A modern phone camera photo is routinely
 * 4-8 MB before compression and multiple are picked at once, so compressing
 * here is not an optimisation, it is what keeps a listing submission from
 * failing on ordinary mobile data.
 */

import type * as ImageManipulatorModule from 'expo-image-manipulator';
import type * as ImagePickerModule from 'expo-image-picker';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * Both of these are absent in Expo Go, and both threw at import time, which
 * broke the whole `features/listings` barrel and every route reaching it —
 * including screens that never pick an image. Loading them optionally keeps
 * the failure where it belongs: at the moment someone actually tries to
 * attach a photo, with a message saying why. See `config/optionalNative.ts`.
 */
const UNAVAILABLE = 'Adding photos needs a full build of the app; it is not available in Expo Go.';

const ImageManipulator = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-image-manipulator') as typeof ImageManipulatorModule,
  'expo-image-manipulator',
  UNAVAILABLE
);

const ImagePicker = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-image-picker') as typeof ImagePickerModule,
  'expo-image-picker',
  UNAVAILABLE
);

/** True when this host can actually attach photos. Check before offering it. */
export const canPickImages = ImagePicker !== null && ImageManipulator !== null;

/** Resized so the long edge is at most this many px, then JPEG re-encoded. */
const MAX_DIMENSION = 1600;
const JPEG_QUALITY = 0.7;

async function compress(uri: string): Promise<string> {
  // Uncompressed rather than failed. The backend's 10 MB cap may still reject
  // it, but a large upload that might work beats refusing outright, and this
  // path is only reached in a host that has the picker but not the manipulator.
  if (!ImageManipulator) return uri;

  const result = await ImageManipulator.manipulateAsync(
    uri,
    [{ resize: { width: MAX_DIMENSION } }],
    { compress: JPEG_QUALITY, format: ImageManipulator.SaveFormat.JPEG }
  );
  return result.uri;
}

/** Requests permission, opens the library picker, and compresses every pick. */
export async function pickListingImages(options: {
  remainingSlots: number;
}): Promise<{ uris: string[]; deniedPermission: boolean }> {
  if (!ImagePicker) throw new Error(UNAVAILABLE);

  const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
  if (!permission.granted) {
    return { uris: [], deniedPermission: true };
  }

  const result = await ImagePicker.launchImageLibraryAsync({
    mediaTypes: ['images'],
    allowsMultipleSelection: true,
    selectionLimit: Math.max(1, options.remainingSlots),
    quality: 1,
  });

  if (result.canceled) return { uris: [], deniedPermission: false };

  const compressed = await Promise.all(result.assets.map((asset) => compress(asset.uri)));
  return { uris: compressed, deniedPermission: false };
}

/** Builds the `{uri,name,type}` shape React Native's FormData accepts as a file part. */
export function imagePart(uri: string, index: number): Blob {
  const name = `photo-${Date.now()}-${index}.jpg`;
  return { uri, name, type: 'image/jpeg' } as unknown as Blob;
}
