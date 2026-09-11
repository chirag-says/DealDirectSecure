'use client';

import { useEffect, useRef, useState } from 'react';

/**
 * "Sign in with Google", rendered by Google Identity Services.
 *
 * ---------------------------------------------------------------------------
 * WHY GIS AND NOT A LIBRARY
 *
 * The site already has a working session: an opaque token in an HttpOnly
 * cookie, issued by our backend. `next-auth` would bring a second session
 * system alongside it, with its own cookie, its own callback routes and its own
 * idea of who the user is — two sources of truth for one question. All we
 * actually need is Google's signed ID token, which the GIS script hands us
 * directly. Everything after that is the backend's existing login path.
 *
 * Google renders the button itself, so the mark and wording are the official
 * ones rather than an approximation.
 *
 * ---------------------------------------------------------------------------
 * RENDERS NOTHING WITHOUT A CLIENT ID
 *
 * `NEXT_PUBLIC_GOOGLE_CLIENT_ID` unset means the feature is not switched on,
 * and a button that always fails is worse than no button: it reads as a broken
 * site rather than as a feature that is not configured, and it would be the
 * first thing every visitor clicked. This is also what lets the backend deploy
 * before the OAuth credentials exist.
 */

const GIS_SRC = 'https://accounts.google.com/gsi/client';

const loadGis = () =>
  new Promise((resolve, reject) => {
    if (typeof window === 'undefined') {
      reject(new Error('not a browser'));
      return;
    }
    if (window.google?.accounts?.id) {
      resolve(window.google);
      return;
    }

    // One script tag for the whole app, however many buttons mount. A second
    // copy would re-initialise GIS and detach the first button's handler.
    let script = document.querySelector(`script[src="${GIS_SRC}"]`);
    if (!script) {
      script = document.createElement('script');
      script.src = GIS_SRC;
      script.async = true;
      script.defer = true;
      document.head.appendChild(script);
    }

    script.addEventListener('load', () => resolve(window.google), { once: true });
    script.addEventListener('error', () => reject(new Error('GIS failed to load')), { once: true });
  });

export default function GoogleSignInButton({ onCredential, text = 'continue_with' }) {
  const containerRef = useRef(null);
  const [failed, setFailed] = useState(false);

  // The callback is held in a ref so GIS keeps calling the CURRENT one. GIS is
  // initialised once and closes over whatever it was given; without this, a
  // re-render would leave it holding a stale handler that updates nothing.
  const callbackRef = useRef(onCredential);
  useEffect(() => {
    callbackRef.current = onCredential;
  }, [onCredential]);

  const clientId = process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID;

  useEffect(() => {
    if (!clientId || !containerRef.current) return;

    let cancelled = false;

    loadGis()
      .then((google) => {
        if (cancelled || !containerRef.current) return;

        google.accounts.id.initialize({
          client_id: clientId,
          callback: (response) => callbackRef.current?.(response.credential),
          // One Tap is deliberately off. It appears unprompted over whatever
          // the visitor is reading, and on a property site that is usually a
          // listing they are in the middle of. The button is an offer; One Tap
          // is an interruption.
          auto_select: false,
          cancel_on_tap_outside: true,
        });

        google.accounts.id.renderButton(containerRef.current, {
          theme: 'outline',
          size: 'large',
          width: 320,
          text,
          shape: 'rectangular',
          logo_alignment: 'left',
        });
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });

    return () => {
      cancelled = true;
    };
  }, [clientId, text]);

  if (!clientId) return null;

  if (failed) {
    return (
      <p className="text-center text-sm text-slate-500">
        Google sign-in could not load. Please use your email and password below.
      </p>
    );
  }

  return <div ref={containerRef} className="flex justify-center" />;
}
