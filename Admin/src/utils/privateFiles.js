/**
 * Payment proofs and deal documents uploaded while SENSITIVE_UPLOADS_PRIVATE is
 * on are stored as private Cloudinary assets. The API then returns a reference
 * instead of a URL:
 *
 *     cloudinary-private:v1:<resource_type>:<format>:<public_id>
 *
 * It opens nothing by itself. The admin panel asks the API for a link each
 * time (backend controllers/privateFileController.js), and that link expires
 * after five minutes. Anything else is a URL from before the switch and is
 * shown the way it always was.
 */

const PREFIX = 'cloudinary-private:v1:';

export const isPrivateFileRef = (value) => typeof value === 'string' && value.startsWith(PREFIX);

/** 'image' or 'pdf', from the reference alone. Deal PDFs are stored as raw files. */
export function privateFileKind(ref) {
  const [resourceType, format] = ref.slice(PREFIX.length).split(':');
  return resourceType === 'image' && format !== 'pdf' ? 'image' : 'pdf';
}

/** GET one link from an endpoint that answers `{ success, data: { url, expiresAt } }`. */
export async function fetchPrivateLink(url) {
  const res = await fetch(url, { credentials: 'include' });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.success) throw new Error(body.message || 'Could not open the file.');
  return body.data;
}
