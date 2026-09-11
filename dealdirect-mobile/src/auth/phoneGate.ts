/**
 * The just-in-time phone gate, as seen from the transport layer.
 *
 * ---------------------------------------------------------------------------
 * THE PROBLEM THIS EXISTS FOR
 *
 * The backend answers six actions with 403 PHONE_VERIFICATION_REQUIRED until
 * the account has proved a mobile number: listing a property, editing a
 * listing, expressing interest, closing a deal, signing an agreement, claiming
 * a reward.
 *
 * Handled per screen, that is six copies of "catch the code, open a sheet, and
 * afterwards remember what I was doing" — and the sixth copy is the one that
 * gets forgotten, so one action bounces the user to an error with no way
 * forward. It is also exactly the kind of duplication that drifts: five screens
 * resume the action and the sixth quietly does not.
 *
 * So the interception lives in `call()`, which every typed endpoint already
 * funnels through. A gated request opens the sheet, waits, and then REPLAYS
 * ITSELF. From the screen's point of view the request simply took longer. The
 * user presses "I'm interested", verifies, and lands back on that listing with
 * the interest registered — rather than on the home screen wondering what
 * happened.
 *
 * ---------------------------------------------------------------------------
 * SINGLE FLIGHT
 *
 * A screen can easily fire two gated requests at once. Without coalescing,
 * that is two sheets stacked on top of each other, two OTPs sent, and two
 * charges from Equence. Every waiter therefore shares ONE in-flight promise:
 * the first caller opens the sheet, the rest queue behind it, and all of them
 * replay together when it resolves.
 *
 * ---------------------------------------------------------------------------
 * ONE REPLAY, NEVER A LOOP
 *
 * A replay that is itself gated must NOT re-open the sheet. If the backend
 * still says the phone is unverified after a successful verification,
 * something is wrong that another sheet cannot fix, and retrying would spin
 * the user in a loop they cannot escape. The second 403 is allowed through to
 * the screen as an ordinary error.
 */

/**
 * The 403 code the backend answers a gated action with. A contract shared with
 * `middleware/requirePhoneVerified.js`; changing one without the other silently
 * disables the whole flow.
 */
export const PHONE_GATE_CODE = 'PHONE_VERIFICATION_REQUIRED';

/**
 * Opens the verification UI. Resolves true once the phone is verified, false if
 * the user backed out.
 *
 * Registered by `PhoneGateProvider` at mount. Null until then, which is the
 * correct state during the cold-start probe: there is no UI to show yet, and a
 * gated request that early should fail rather than hang.
 */
type Presenter = () => Promise<boolean>;

let present: Presenter | null = null;

export function setPhoneGatePresenter(presenter: Presenter | null): void {
  present = presenter;
}

/** The shared in-flight verification, if one is already running. */
let inFlight: Promise<boolean> | null = null;

/**
 * Checked structurally rather than with `instanceof ApiError`, for two reasons.
 *
 * The code is the actual contract — an ApiError carrying some other code is not
 * this, and a normalised error carrying this code is, whatever its constructor.
 * And it keeps this module free of any import, so the transport layer can
 * depend on it without threading a cycle back through `@/api`, and so the rules
 * below are testable without pulling React Native into the test process.
 */
export function isPhoneGateError(error: unknown): boolean {
  return (
    typeof error === 'object' &&
    error !== null &&
    (error as { code?: unknown }).code === PHONE_GATE_CODE
  );
}

/**
 * Runs the verification flow, coalescing concurrent callers onto one sheet.
 *
 * Resolves false when no presenter is mounted, rather than throwing or
 * hanging: the caller then surfaces the original 403, which is honest about
 * what happened.
 */
export function requestPhoneVerification(): Promise<boolean> {
  if (!present) return Promise.resolve(false);

  if (!inFlight) {
    inFlight = present().finally(() => {
      inFlight = null;
    });
  }

  return inFlight;
}
