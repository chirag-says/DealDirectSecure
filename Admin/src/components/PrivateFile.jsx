import { useCallback, useEffect, useRef, useState } from 'react';
import { ExternalLink, Lock, RefreshCw } from 'lucide-react';
import { privateFileKind } from '../utils/privateFiles';

/**
 * A privately stored deal document.
 *
 * The page never holds a lasting link. `fetchLink` asks the API for one, which
 * checks the admin session, records the access, and returns a signed URL that
 * stops working after five minutes. An image preview asks once when it mounts;
 * "Open" asks again on every click, so a modal left open past the expiry still
 * opens the file.
 *
 * No third-party viewer: a PDF opens in the browser's own viewer. The signed
 * link must not be handed to another service.
 */
export default function PrivateFile({ value, fetchLink, label }) {
  const kind = privateFileKind(value);
  const request = useRef(fetchLink);
  request.current = fetchLink;

  const [preview, setPreview] = useState({ url: null, error: null, loading: kind === 'image' });
  const [openError, setOpenError] = useState(null);
  // When the browser blocks the new tab, the fresh link is offered to click instead.
  const [blockedLink, setBlockedLink] = useState(null);

  const loadPreview = useCallback(async () => {
    setPreview({ url: null, error: null, loading: true });
    try {
      const { url } = await request.current();
      setPreview({ url, error: null, loading: false });
    } catch (err) {
      setPreview({ url: null, error: err.message || 'Could not load the preview.', loading: false });
    }
  }, []);

  useEffect(() => {
    if (kind === 'image') loadPreview();
  }, [kind, value, loadPreview]);

  const openFresh = async () => {
    setOpenError(null);
    setBlockedLink(null);
    // Opened before the request, inside the click, so it is not blocked as a
    // pop-up; pointed at the file once the link arrives.
    const tab = window.open('', '_blank');
    try {
      const { url } = await request.current();
      if (!tab) {
        setBlockedLink(url);
        return;
      }
      tab.opener = null;
      tab.location.replace(url);
    } catch (err) {
      tab?.close();
      setOpenError(err.message || 'Could not open the file.');
    }
  };

  return (
    <div>
      {kind === 'image' && (
        <div className="mb-2">
          {preview.loading && (
            <div className="h-32 rounded-lg border border-slate-200 bg-slate-50 flex items-center justify-center text-xs text-slate-400">
              Loading preview…
            </div>
          )}
          {preview.url && (
            <img
              src={preview.url}
              alt={label}
              referrerPolicy="no-referrer"
              className="w-full rounded-lg border border-slate-200 object-contain max-h-48"
              onError={() => setPreview({ url: null, error: 'The preview did not load. The link may have expired.', loading: false })}
            />
          )}
          {preview.error && (
            <div className="flex items-center justify-between gap-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
              <span>{preview.error}</span>
              <button type="button" onClick={loadPreview} className="flex items-center gap-1 font-semibold hover:underline">
                <RefreshCw size={11} /> Reload
              </button>
            </div>
          )}
        </div>
      )}

      <div className="flex items-center justify-between gap-2">
        <span className="flex items-center gap-1 text-[11px] text-slate-500">
          <Lock size={11} /> Stored privately · each link works for 5 minutes
        </span>
        <button
          type="button"
          onClick={openFresh}
          className="flex items-center gap-1 text-xs font-medium text-indigo-600 hover:text-indigo-800"
        >
          <ExternalLink size={11} /> {kind === 'image' ? 'Open full size' : 'Open document'}
        </button>
      </div>
      {openError && <p className="mt-1 text-xs text-red-600">{openError}</p>}
      {blockedLink && (
        <p className="mt-1 text-xs text-slate-600">
          The browser blocked a new tab.{' '}
          <a
            href={blockedLink}
            target="_blank"
            rel="noopener noreferrer"
            referrerPolicy="no-referrer"
            onClick={() => setTimeout(() => setBlockedLink(null), 0)}
            className="font-semibold text-indigo-600 hover:underline"
          >
            Open the file
          </a>{' '}
          (this link works for 5 minutes).
        </p>
      )}
    </div>
  );
}
