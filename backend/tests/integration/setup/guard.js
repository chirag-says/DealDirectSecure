/**
 * Database isolation guard.
 *
 * This is the control that makes it impossible for the integration suite to
 * reach a real database. It runs before anything else in the harness, and
 * before `server.js` is imported.
 *
 * The threat is mundane and entirely plausible: `server.js` loads `.env` at
 * import time, and on a developer machine that file points MONGO_URI at the
 * shared development Atlas cluster. A harness that forgot to override it, or a
 * test run started with the wrong NODE_ENV, would happily truncate real
 * collections between tests. Nothing about that failure is loud.
 *
 * The guard is deliberately allow-list shaped: it does not try to recognise
 * production URIs, because a blocklist of hostnames is exactly the kind of
 * control that is one new cluster away from being wrong, and putting a real
 * production URI into the repository to detect it would be worse than the
 * problem. Instead only an in-memory server, or an explicitly-marked local test
 * database, is permitted. Anything else fails closed.
 */

/** Hosts an in-memory replica set is allowed to bind. */
const LOCAL_HOSTS = ['127.0.0.1', 'localhost', '0.0.0.0', '::1'];

/**
 * A URI is acceptable only if it is local AND its database name marks it as a
 * test database. `mongodb+srv://` is rejected outright, a hosted cluster is
 * never a test target, whatever it is called.
 */
export function assertIsTestDatabaseUri(uri) {
  if (!uri || typeof uri !== 'string') {
    throw new Error('[test-guard] No MongoDB URI was provided to the harness.');
  }

  if (uri.startsWith('mongodb+srv://')) {
    throw new Error(
      '[test-guard] Refusing to run against a hosted (mongodb+srv) cluster. ' +
      'Integration tests may only target an in-memory or explicitly-marked local test database.'
    );
  }

  let parsed;
  try {
    // The URL parser understands mongodb:// well enough for host and path.
    parsed = new URL(uri);
  } catch {
    throw new Error('[test-guard] Could not parse the MongoDB URI.');
  }

  const host = parsed.hostname;
  if (!LOCAL_HOSTS.includes(host)) {
    throw new Error(
      `[test-guard] Refusing to run against non-local host "${host}". ` +
      'Integration tests may only target a local in-memory database.'
    );
  }

  const dbName = parsed.pathname.replace(/^\//, '').split('?')[0];
  if (!dbName) {
    throw new Error('[test-guard] The MongoDB URI carries no database name.');
  }
  if (!/test/i.test(dbName)) {
    throw new Error(
      `[test-guard] Database "${dbName}" is not marked as a test database. ` +
      'Its name must contain "test".'
    );
  }

  return true;
}

/**
 * Assert the whole process is in a state where integration tests may run.
 * Called once, before the harness connects and before server.js is imported.
 */
export function assertTestEnvironment() {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('[test-guard] NODE_ENV is "production". Refusing to run integration tests.');
  }

  if (process.env.NODE_ENV !== 'test') {
    throw new Error(
      `[test-guard] NODE_ENV is "${process.env.NODE_ENV || '(unset)'}", expected "test". ` +
      'Run the suite through `npm run test:integration`, which sets it. ' +
      'Without it server.js would open its own connection to whatever MONGO_URI is in .env.'
    );
  }

  return true;
}
