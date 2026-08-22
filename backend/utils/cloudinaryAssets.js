/**
 * Destroying Cloudinary assets, in one place.
 *
 * WHY THIS EXISTS
 *
 * Property deletion has always cleaned up after itself (propertyAssets.js).
 * Nothing else did. Project media was append-only with no removal at all;
 * replacing a brochure or a floor plan overwrote the URL and orphaned the file;
 * removing a unit photo filtered the array and left the asset behind forever.
 *
 * The cost is the smaller half. Payment screenshots live in the same account,
 * so an orphan is a payment record with no document pointing at it — invisible
 * to every delete guard that exists precisely to protect that evidence.
 *
 * ONE-WAY REFERENCES
 *
 * Assets are stored as bare URL strings with no reverse index, so nothing can
 * answer "which document owns this file". That makes historical orphans
 * unrecoverable except by sweeping the account, and it is why removal has to
 * destroy at the moment of removal rather than be reconciled later.
 */

import { cloudinary } from "../middleware/upload.js";

/**
 * Extract the public_id from a Cloudinary delivery URL.
 *
 *   https://res.cloudinary.com/<cloud>/image/upload/v123/folder/name.jpg
 *                                                     └────────┬───────┘
 *                                                         public_id
 *
 * Returns null for anything that is not a Cloudinary URL — an externally hosted
 * image must never be "destroyed", and asking Cloudinary to delete a public_id
 * derived from someone else's URL is at best a no-op and at worst deletes an
 * unrelated asset that happens to collide.
 */
export function publicIdFromUrl(url) {
  if (typeof url !== "string") return null;

  try {
    const parsed = new URL(url);

    // The HOSTNAME, not a substring of the whole URL.
    //
    // `url.includes("res.cloudinary.com")` was the first version and it is a
    // real hole: https://evil.test/res.cloudinary.com.attacker.net/image/upload/
    // v1/x.jpg contains the string, so a hostile URL stored on a document would
    // yield a public_id and get handed to destroy. Found by testing the
    // function rather than reading it.
    if (parsed.hostname !== "res.cloudinary.com") return null;

    const { pathname } = parsed;
    // /<cloud>/<resource_type>/upload/[transformations/][v123/]<public_id>.<ext>
    const parts = pathname.split("/").filter(Boolean);
    const uploadAt = parts.indexOf("upload");
    if (uploadAt === -1) return null;

    let rest = parts.slice(uploadAt + 1);
    // Drop a version segment (v1234567890) if present.
    if (rest[0] && /^v\d+$/.test(rest[0])) rest = rest.slice(1);
    if (rest.length === 0) return null;

    const joined = rest.join("/");
    // Strip the extension from the final segment only — folders may contain dots.
    return joined.replace(/\.[a-z0-9]+$/i, "");
  } catch {
    return null;
  }
}

/**
 * Destroy assets by delivery URL. Never throws.
 *
 * A failed cleanup must not roll back the removal the user asked for: the
 * document change is what they wanted, the orphan is a cost. Failures are
 * logged loudly enough to be swept later rather than swallowed.
 *
 * @param {string[]} urls
 * @param {{ resourceType?: "image" | "raw" | "video" }} [opts]
 * @returns {Promise<{ destroyed: string[], skipped: string[], failed: string[] }>}
 */
export async function destroyAssets(urls = [], { resourceType = "image" } = {}) {
  const result = { destroyed: [], skipped: [], failed: [] };
  const list = (Array.isArray(urls) ? urls : [urls]).filter(Boolean);

  for (const url of list) {
    const publicId = publicIdFromUrl(url);
    if (!publicId) {
      // Not ours to delete — an Unsplash placeholder, a builder's own CDN.
      result.skipped.push(url);
      continue;
    }
    try {
      await cloudinary.uploader.destroy(publicId, { resource_type: resourceType });
      result.destroyed.push(publicId);
    } catch (err) {
      console.error(`[cloudinary] destroy failed for ${publicId}: ${err.message}`);
      result.failed.push(publicId);
    }
  }

  return result;
}

/**
 * Replace a single-asset field, destroying whatever it held.
 *
 * The brochure and floor-plan case: assignment alone silently orphans the old
 * file, and does so on every edit.
 */
export async function replaceAsset(oldUrl, newUrl, opts) {
  if (oldUrl && oldUrl !== newUrl) await destroyAssets([oldUrl], opts);
  return newUrl;
}
