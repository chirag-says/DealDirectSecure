import { cloudinary } from "../middleware/upload.js";

/**
 * Cloudinary asset cleanup for properties.
 *
 * Moved out of propertyController so the aggregate delete functions can use it
 * without a circular import: the controllers call the aggregates, so the
 * aggregates cannot reach back into the controllers. Asset cleanup was never
 * controller logic in any case.
 *
 * propertyController re-exports both names, so existing importers are unchanged.
 */

export const isCloudinaryUrl = (img = "") => typeof img === "string" && img.includes("cloudinary.com");

/**
 * Extract the Cloudinary public_id from a delivery URL.
 *
 * Assets are uploaded into nested folders ("dealdirect/properties/abc123"), so
 * the public_id is EVERY path segment after `upload/` (minus the optional
 * version), not just the last one.
 *
 * Two broken variants previously existed in this file:
 *   - deleteMyProperty used `slice(-2)` → produced "properties/abc123",
 *     dropping the "dealdirect/" prefix, so destroy() silently no-opped and
 *     owner-deleted images stayed publicly reachable forever.
 *   - deleteProperty used `slice(uploadIndex + 2)`, which assumes a version
 *     segment is always present. Cloudinary does not guarantee that; without
 *     one it silently drops a real folder segment.
 *
 * This handles both shapes:
 *   .../upload/v1712345678/dealdirect/properties/abc.jpg → dealdirect/properties/abc
 *   .../upload/dealdirect/properties/abc.jpg             → dealdirect/properties/abc
 *
 * @returns {string|null} public_id, or null if the URL is not a Cloudinary asset
 */
export const extractCloudinaryPublicId = (url) => {
  if (!isCloudinaryUrl(url)) return null;

  const parts = url.split("?")[0].split("/");
  const uploadIndex = parts.indexOf("upload");
  if (uploadIndex === -1) return null;

  let rest = parts.slice(uploadIndex + 1);
  // Drop the optional version segment (v1712345678) if present.
  if (rest.length && /^v\d+$/.test(rest[0])) rest = rest.slice(1);
  if (rest.length === 0) return null;

  // Strip the file extension from the final segment only.
  return rest.join("/").replace(/\.[^/.]+$/, "");
};

/**
 * Destroy every Cloudinary asset belonging to a property (flat images array
 * plus every categorised bucket). Never throws — deletion of the database
 * record must not be blocked by a storage failure.
 *
 * @returns {{ attempted: number, deleted: number, failed: number }}
 */
export const deletePropertyAssets = async (property) => {
  const urls = [
    ...(property.images || []),
    ...Object.values(property.categorizedImages?.residential || {}).flat(),
    ...Object.values(property.categorizedImages?.commercial || {}).flat(),
  ].filter(isCloudinaryUrl);

  // The same image can appear in both `images` and a categorised bucket.
  const publicIds = [...new Set(urls.map(extractCloudinaryPublicId).filter(Boolean))];

  let deleted = 0;
  let failed = 0;

  for (const publicId of publicIds) {
    try {
      const res = await cloudinary.uploader.destroy(publicId);
      // Cloudinary returns { result: "ok" | "not found" } rather than throwing.
      if (res?.result === "ok") deleted++;
      else {
        failed++;
        console.warn(`[Cloudinary] destroy("${publicId}") returned "${res?.result}"`);
      }
    } catch (err) {
      failed++;
      console.error(`[Cloudinary] destroy("${publicId}") failed:`, err.message);
    }
  }

  if (publicIds.length) {
    console.log(`[Cloudinary] property ${property._id}: ${deleted}/${publicIds.length} assets deleted${failed ? `, ${failed} failed` : ""}`);
  }
  return { attempted: publicIds.length, deleted, failed };
};
