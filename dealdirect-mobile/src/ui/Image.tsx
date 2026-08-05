import { Image as ExpoImage, type ImageProps as ExpoImageProps } from 'expo-image';
import React from 'react';

/**
 * Image primitive.
 *
 * Wraps expo-image so the caching policy is decided once. Property photos are
 * already absolute Cloudinary URLs by the time they reach the client
 * (`withPublicImages` passes through anything starting with `http`), so the
 * `size` prop appends Cloudinary transformation parameters to request a
 * device-appropriate render instead of the full-resolution original. That is
 * URL construction on the client and touches no backend code.
 *
 * Non-Cloudinary URLs pass through untouched.
 */

export type ImageSize = 'thumb' | 'medium' | 'full';

/** Cloudinary transformation segments, keyed by the app's three size profiles. */
const CLOUDINARY_TRANSFORM: Record<ImageSize, string | null> = {
  thumb: 'f_auto,q_auto,w_400',
  medium: 'f_auto,q_auto,w_900',
  full: 'f_auto,q_auto',
};

const CLOUDINARY_UPLOAD_MARKER = '/image/upload/';

export function buildImageUrl(url: string | undefined, size: ImageSize): string | undefined {
  if (!url) return undefined;

  const transform = CLOUDINARY_TRANSFORM[size];
  if (!transform) return url;

  const markerIndex = url.indexOf(CLOUDINARY_UPLOAD_MARKER);
  if (markerIndex === -1) return url;

  // Skip URLs that already carry a transformation segment rather than stacking
  // a second one onto it.
  const afterMarker = url.slice(markerIndex + CLOUDINARY_UPLOAD_MARKER.length);
  if (/^[a-z]_[^/]+\//.test(afterMarker)) return url;

  const head = url.slice(0, markerIndex + CLOUDINARY_UPLOAD_MARKER.length);
  return `${head}${transform}/${afterMarker}`;
}

export interface ImageProps extends Omit<ExpoImageProps, 'source'> {
  uri?: string;
  size?: ImageSize;
  className?: string;
}

export function Image({ uri, size = 'medium', ...rest }: ImageProps) {
  return (
    <ExpoImage
      source={buildImageUrl(uri, size)}
      cachePolicy="memory-disk"
      contentFit="cover"
      transition={160}
      {...rest}
    />
  );
}
