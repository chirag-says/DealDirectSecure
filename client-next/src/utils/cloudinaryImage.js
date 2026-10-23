/**
 * Ask Cloudinary for a resized image instead of the uploaded original.
 *
 * Listing photos reach the website as absolute res.cloudinary.com URLs pointing
 * at the full-size upload, often several megabytes. Cloudinary resizes on the
 * fly when the URL carries a transformation segment right after
 * `/image/upload/`, so this only rewrites the URL. No request goes through the
 * website's own server.
 *
 * The three sizes and the rules match the mobile app (src/ui/Image.tsx in
 * dealdirecr-mobile), so the web and the app request the same URLs and share
 * Cloudinary's cached derived images:
 *
 *   thumb   f_auto,q_auto,w_400   cards, thumbnails, small previews
 *   medium  f_auto,q_auto,w_900   main gallery image
 *   full    f_auto,q_auto         zoomed views and floor plans (format and
 *                                 quality only, original dimensions)
 *
 * A URL is left unchanged when:
 *  - it is not a string, or is empty
 *  - its host is not res.cloudinary.com (Unsplash fallbacks, local /uploads
 *    paths, blob: and data: previews of files being uploaded)
 *  - it is not an `/image/upload/` URL. `raw/upload` (PDFs, documents) cannot
 *    be transformed and would return an error; `video/upload` is not an image.
 *  - the segment after `/image/upload/` is already a transformation, so a
 *    second one is not stacked on top of it
 */

const TRANSFORMS = {
  thumb: 'f_auto,q_auto,w_400',
  medium: 'f_auto,q_auto,w_900',
  full: 'f_auto,q_auto',
};

const CLOUDINARY_IMAGE_UPLOAD = /^(https?:)?\/\/res\.cloudinary\.com\/[^/]+\/image\/upload\//i;

// A transformation segment starts with a parameter key and an underscore
// (w_400, c_fill, ar_16:9, dpr_2.0, fl_progressive, t_named) or a `$` variable.
// The version segment (v1712345678) does not match, so a versioned URL is
// still transformed. The mobile app checks a one-letter key only; this also
// covers the two- and three-letter keys.
const TRANSFORMATION_SEGMENT = /^(?:[a-z]{1,3}_|\$)[^/]*\//i;

/** True for an image URL served from res.cloudinary.com/<cloud>/image/upload/. */
export function isCloudinaryImageUrl(url) {
  return typeof url === 'string' && CLOUDINARY_IMAGE_UPLOAD.test(url);
}

/**
 * Return `url` with a Cloudinary transformation for `size` inserted, or `url`
 * unchanged when it is not a transformable Cloudinary image URL.
 *
 * @param {string | null | undefined} url
 * @param {'thumb' | 'medium' | 'full'} [size='medium']
 */
export function cloudinaryImage(url, size = 'medium') {
  if (!isCloudinaryImageUrl(url)) return url;

  const transform = TRANSFORMS[size];
  if (!transform) return url;

  const match = url.match(CLOUDINARY_IMAGE_UPLOAD);
  const head = match[0];
  const rest = url.slice(head.length);
  if (TRANSFORMATION_SEGMENT.test(rest)) return url;

  return `${head}${transform}/${rest}`;
}
