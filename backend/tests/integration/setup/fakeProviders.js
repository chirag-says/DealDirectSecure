/**
 * Local stand-ins for outbound providers.
 *
 * Some flows cannot be tested with the integration simply switched off.
 * `registerUser` (userController.js:302-317) returns 500 when
 * `isSmsConfigured()` is false, and 500 again if the send reports failure. So
 * with SMS disabled there is no way to reach the OTP path at all, and the
 * single most security-relevant flow in the product would go untested.
 *
 * The answer is not a mock of the SMS module. That would skip the code that
 * builds the request body and parses the provider's reply, which is exactly
 * where a regression would hide. Instead a real HTTP server runs on 127.0.0.1
 * and EQUENCE_BASE_URL points at it. The application makes a genuine fetch,
 * genuinely parses the response, and the traffic is provably local: the egress
 * blocker permits nothing else.
 *
 * It also gives tests the message body, so the OTP flow can be driven the way a
 * real user drives it: read the code out of the message rather than plant one in
 * the database.
 */

import http from 'node:http';

let server = null;
const messages = [];
const pushBatches = [];

/** Provider-shaped success reply, matching what smsService.js:167 accepts. */
function equenceSuccess(to) {
  return JSON.stringify({
    response: [{ status: 'Success', destination: to, mrid: 'test-mrid-0001' }],
  });
}

/**
 * Start the fake provider and point the SMS client at it.
 * Must be called before server.js is imported so dotenv leaves the values alone.
 */
export async function startFakeProviders() {
  if (server) return;

  server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      let parsed = {};
      try { parsed = JSON.parse(body); } catch { parsed = { raw: body }; }

      // Expo push: one ticket per message, in order. A token containing the
      // word "dead" is reported as DeviceNotRegistered so the disable path
      // can be exercised without a real device.
      if (req.url.startsWith('/push/send')) {
        const batch = Array.isArray(parsed) ? parsed : [];
        pushBatches.push(batch);
        const data = batch.map((m, i) =>
          String(m.to).includes('dead')
            ? { status: 'error', message: 'not registered', details: { error: 'DeviceNotRegistered' } }
            : { status: 'ok', id: `ticket-${pushBatches.length}-${i}` }
        );
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data }));
        return;
      }
      if (req.url.startsWith('/push/getReceipts')) {
        const ids = Array.isArray(parsed.ids) ? parsed.ids : [];
        const data = {};
        for (const id of ids) data[id] = { status: 'ok' };
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ data }));
        return;
      }

      messages.push({
        path: req.url,
        to: parsed.to,
        from: parsed.from,
        text: parsed.text,
        receivedIndex: messages.length,
      });

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(equenceSuccess(parsed.to));
    });
  });

  // Ephemeral port on loopback only. unref so the fake never keeps the test
  // process alive by itself.
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  server.unref();

  const { port } = server.address();

  // Synthetic credentials. These are not secrets and authenticate nothing.
  // The only thing that reads them is the server above.
  process.env.EQUENCE_BASE_URL = `http://127.0.0.1:${port}/pushsms`;

  // Expo push, same loopback server. The application never learns the real
  // endpoint under test; the egress blocker would refuse it anyway.
  process.env.EXPO_PUSH_URL = `http://127.0.0.1:${port}/push/send`;
  process.env.EXPO_PUSH_RECEIPTS_URL = `http://127.0.0.1:${port}/push/getReceipts`;
  process.env.EQUENCE_USERNAME = 'integration-test-sms-user';
  process.env.EQUENCE_PASSWORD = 'integration-test-sms-pass';
  process.env.EQUENCE_SENDER_ID = 'DDTEST';
  process.env.EQUENCE_PE_ID = 'integration-test-pe-id';
  process.env.EQUENCE_OTP_TMPL_ID = 'integration-test-otp-tmpl';
  process.env.EQUENCE_RESET_TMPL_ID = 'integration-test-reset-tmpl';

  // Synthetic Cloudinary configuration.
  //
  // `validateAndUploadToCloudinary` (upload.js:379) returns 503 for ANY request
  // on a route it guards, whether or not the request carries a file. Owner
  // property create and update both sit behind it, so with Cloudinary disabled
  // even a title-only JSON update is refused and the two most important
  // authorisation paths in the product cannot be tested at all.
  //
  // Marking it configured lets a file-carrying request reach the validation and
  // upload code. No outbound call happens on a file-less path: the middleware
  // only contacts Cloudinary when there are files to stream. The one call this
  // does trigger is the startup `cloudinary.api.ping()` at upload.js:184, which
  // the egress blocker refuses and the module's own .catch swallows. That
  // refusal is the proof that these credentials reach nothing: they are not
  // real, and could not be used even if they were.
  //
  // A suite that needs storage to look genuinely absent opts out. `upload.js`
  // reads CLOUDINARY_URL once at import and captures the result in a module
  // constant, so this cannot be toggled per test: the only way to exercise the
  // unconfigured branch is a process that never had it set. Node runs each test
  // file in its own process, which makes that a per-file decision.
  if (process.env.HARNESS_DISABLE_CLOUDINARY !== '1') {
    process.env.CLOUDINARY_URL = 'cloudinary://123456789012345:integration-test-secret@integration-test-cloud';
  }
}

/** Every push batch the application posted, in order. */
export function pushBatchesSent() {
  return pushBatches.slice();
}

export function clearPushBatches() {
  pushBatches.length = 0;
}

/** Every message the application tried to send, most recent last. */
export function sentMessages() {
  return [...messages];
}

/** The most recent message sent to a given phone number, if any. */
export function lastMessageTo(phone) {
  const digits = String(phone).replace(/\D/g, '').slice(-10);
  return [...messages].reverse().find((m) => String(m.to || '').endsWith(digits)) || null;
}

/**
 * Pull the six-digit code out of the most recent message to a number.
 * Returns null when no message was sent, which is itself a useful assertion.
 */
export function otpSentTo(phone) {
  const msg = lastMessageTo(phone);
  if (!msg?.text) return null;
  const match = String(msg.text).match(/\b(\d{6})\b/);
  return match ? match[1] : null;
}

export function clearMessages() {
  messages.length = 0;
}

export async function stopFakeProviders() {
  if (!server) return;
  await new Promise((resolve) => server.close(resolve));
  server = null;
}

/** The loopback base URL in use, for isolation assertions. */
export const providerBaseUrl = () => process.env.EQUENCE_BASE_URL;

// ---------------------------------------------------------------------------
// Email observation
// ---------------------------------------------------------------------------

/**
 * Records which addresses the application tried to email.
 *
 * Email has no loopback stand-in: with SMTP unconfigured `sendEmail`
 * (utils/emailService.js:440) returns `{skipped: true}` before building a
 * transporter, so there is no socket to intercept and no stored artefact to
 * query. The only externally visible trace is the line it logs:
 *
 *     console.log("📧 Would have sent email to:", to);
 *
 * so that is what this watches. The coupling to a log string is real and worth
 * naming, but the alternative is worse: a mock of the mail module would stop
 * exercising `sendEmail`'s own skip logic, and standing up an SMTP server to
 * catch a message the app never sends would test the harness rather than the
 * app. If that log line changes, `emailedAddresses()` returns empty and the
 * tests that assert an email WAS attempted fail loudly, which is the direction
 * an error should point.
 *
 * This matters for notifications specifically: the model emails from a
 * post-save hook, and marking a notification read is a save. Without a way to
 * observe dispatch, "marking read does not re-send the email" is unprovable.
 */
const emailed = [];
let consoleHooked = false;
let originalLog = null;

const EMAIL_LOG_PREFIX = 'Would have sent email to:';

export function watchEmail() {
  if (consoleHooked) return;
  originalLog = console.log;
  console.log = (...args) => {
    const first = typeof args[0] === 'string' ? args[0] : '';
    if (first.includes(EMAIL_LOG_PREFIX)) {
      emailed.push(String(args[1] ?? '').trim());
    }
    return originalLog.apply(console, args);
  };
  consoleHooked = true;
}

export function unwatchEmail() {
  if (!consoleHooked) return;
  console.log = originalLog;
  consoleHooked = false;
}

/** Addresses the application attempted to email, most recent last. */
export function emailedAddresses() {
  return [...emailed];
}

export function clearEmails() {
  emailed.length = 0;
}

/**
 * Email is dispatched from a post-save hook without being awaited, so it lands
 * a tick or two after the HTTP response. Give it a moment before asserting an
 * absence, or the test would pass simply by looking too early.
 */
export async function settleEmail(ms = 60) {
  await new Promise((resolve) => setTimeout(resolve, ms));
}
