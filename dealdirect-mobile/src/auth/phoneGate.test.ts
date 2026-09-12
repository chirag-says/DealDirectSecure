import assert from 'node:assert/strict';
import { afterEach, describe, it } from 'node:test';

import {
  PHONE_GATE_CODE,
  isPhoneGateError,
  requestPhoneVerification,
  setPhoneGatePresenter,
} from './phoneGate.ts';

/**
 * The gate's rules, which are the part that can go quietly wrong.
 *
 * The sheet itself is a component and not tested here; what matters is that a
 * burst of gated requests raises ONE sheet and not five, that a request made
 * before the sheet exists fails instead of hanging, and that the single-flight
 * latch actually resets — a latch that sticks would mean the gate works exactly
 * once per app launch, which is the kind of bug that only shows up on a user's
 * second listing attempt.
 */

afterEach(() => setPhoneGatePresenter(null));

/** A presenter whose resolution the test controls, counting how often it ran. */
function controllablePresenter() {
  let resolve!: (verified: boolean) => void;
  let calls = 0;

  const presenter = () => {
    calls += 1;
    return new Promise<boolean>((r) => {
      resolve = r;
    });
  };

  return {
    presenter,
    settle: (verified: boolean) => resolve(verified),
    get calls() {
      return calls;
    },
  };
}

describe('recognising the refusal', () => {
  it('matches the backend code and nothing else', () => {
    assert.equal(isPhoneGateError({ code: PHONE_GATE_CODE }), true);
    assert.equal(isPhoneGateError({ code: 'FORBIDDEN' }), false);
    assert.equal(isPhoneGateError({ code: 'PHONE_ALREADY_LINKED' }), false);
  });

  it('survives anything that is not an error object', () => {
    // `call()` catches whatever axios threw, which is not always shaped.
    assert.equal(isPhoneGateError(null), false);
    assert.equal(isPhoneGateError(undefined), false);
    assert.equal(isPhoneGateError('PHONE_VERIFICATION_REQUIRED'), false);
    assert.equal(isPhoneGateError(new Error('boom')), false);
  });

  it('pins the code the backend actually sends', () => {
    // Shared with middleware/requirePhoneVerified.js. Drift here disables the
    // entire flow silently: every gated action would just show a 403.
    assert.equal(PHONE_GATE_CODE, 'PHONE_VERIFICATION_REQUIRED');
  });
});

describe('presenting', () => {
  it('refuses rather than hangs when no sheet is mounted', async () => {
    // True during the cold-start probe. A pending promise here would freeze the
    // request forever with no UI able to release it.
    setPhoneGatePresenter(null);
    assert.equal(await requestPhoneVerification(), false);
  });

  it('raises one sheet for a burst of gated requests', async () => {
    // Not destructured: `calls` is a getter, and pulling it out here would
    // freeze it at its value before any call happened.
    const sheet = controllablePresenter();
    setPhoneGatePresenter(sheet.presenter);

    const waiters = [
      requestPhoneVerification(),
      requestPhoneVerification(),
      requestPhoneVerification(),
    ];

    sheet.settle(true);
    const results = await Promise.all(waiters);

    assert.deepEqual(results, [true, true, true], 'every waiter resumes together');
    assert.equal(sheet.calls, 1, 'three sheets would mean three OTPs and three SMS charges');
  });

  it('lets a later request raise the sheet again', async () => {
    // The latch has to clear. If it stuck, the gate would work once per launch
    // and every later gated action would fail with no way forward.
    const first = controllablePresenter();
    setPhoneGatePresenter(first.presenter);
    const firstCall = requestPhoneVerification();
    first.settle(false);
    assert.equal(await firstCall, false);

    const second = controllablePresenter();
    setPhoneGatePresenter(second.presenter);
    const secondCall = requestPhoneVerification();
    second.settle(true);

    assert.equal(await secondCall, true);
    assert.equal(second.calls, 1);
  });

  it('clears the latch even when the sheet throws', async () => {
    // A crash inside the sheet must not wedge the gate shut for the rest of the
    // session.
    setPhoneGatePresenter(() => Promise.reject(new Error('sheet exploded')));
    await assert.rejects(requestPhoneVerification());

    setPhoneGatePresenter(() => Promise.resolve(true));
    assert.equal(await requestPhoneVerification(), true);
  });
});
