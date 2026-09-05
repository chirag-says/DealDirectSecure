import * as Sentry from '@sentry/nextjs';

/**
 * Attach (or clear) the signed-in user on Sentry events.
 *
 * Without this every issue is anonymous, so there is no way to tell one user
 * hitting a bug fifty times from fifty users hitting it once — which is the
 * first question you ask when triaging.
 *
 * Only the account id and role are sent. No email, name or phone number: the
 * backend's instrument.js sets `sendDefaultPii: false` and strips credential
 * headers precisely so this data does not reach a third party, and the frontend
 * has no business undoing that. The id is enough to look an account up in the
 * admin panel when a report needs following up.
 */
export function setSentryUser(user) {
    if (!user?._id) {
        Sentry.setUser(null);
        return;
    }
    Sentry.setUser({
        id: String(user._id),
        // `role` is low cardinality (buyer / user / owner) and makes it obvious
        // when a bug only affects one side of the marketplace.
        role: user.role,
    });
}
