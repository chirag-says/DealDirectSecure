/**
 * Isolated MongoDB harness for integration tests.
 *
 * Starts a real mongod as a single-node REPLICA SET, not a standalone. That is
 * not a preference: `addProperty` opens a session and runs a transaction for
 * the one-listing-per-owner check, and MongoDB refuses transactions on a
 * standalone. A standalone harness would make the property-creation tests fail
 * for a reason that has nothing to do with the code under test.
 *
 * CLEANUP TRADE-OFF
 * -----------------
 * Between tests we delete the documents in each non-system collection rather
 * than dropping the database or restarting the server.
 *
 *   truncate    ~5-20 ms   keeps indexes, so the unique and partial-unique
 *                          indexes the application depends on stay in force,
 *                          which matters, because two of them (pending
 *                          verification, campaign membership) are the actual
 *                          concurrency guards under test.
 *   dropDatabase ~50 ms+   destroys indexes; Mongoose only rebuilds them on
 *                          model init, so later tests would silently run
 *                          without the constraint they mean to exercise.
 *   restart      ~2-5 s    correct but far too slow per test.
 *
 * Truncation is the right default here precisely because index behaviour is
 * part of what these tests assert.
 */

import mongoose from 'mongoose';
import { MongoMemoryReplSet } from 'mongodb-memory-server';
import { assertTestEnvironment, assertIsTestDatabaseUri } from './guard.js';

let replSet = null;

/**
 * Boot the in-memory replica set and connect Mongoose to it.
 * Returns the URI actually used, so callers can assert on it.
 */
export async function startTestDatabase() {
  assertTestEnvironment();

  if (replSet) return mongoose.connection.host;

  replSet = await MongoMemoryReplSet.create({
    replSet: { count: 1, storageEngine: 'wiredTiger' },
    instanceOpts: [{ storageEngine: 'wiredTiger' }],
  });

  // Name the database so the guard can recognise it as a test target.
  // getUri() takes the db name as an argument, string-concatenating it onto
  // the returned URI lands after the `?replicaSet=` query and yields a URI with
  // no database at all.
  const uri = replSet.getUri('dealdirect_test');

  // Belt and braces: the guard checks the URI we are about to use, not the one
  // we intended to use.
  assertIsTestDatabaseUri(uri);

  // server.js reads MONGO_URI at import time. Setting it here means that even
  // if the NODE_ENV seam were ever removed, the value it would find is the
  // in-memory one rather than whatever .env holds.
  process.env.MONGO_URI = uri;

  await mongoose.connect(uri, { serverSelectionTimeoutMS: 20000 });

  return uri;
}

/**
 * Delete every document from every application collection.
 * Indexes survive, which is deliberate, see the trade-off note above.
 */
export async function truncateAll() {
  if (mongoose.connection.readyState !== 1) return;

  const collections = await mongoose.connection.db
    .listCollections({}, { nameOnly: true })
    .toArray();

  await Promise.all(
    collections
      .filter((c) => !c.name.startsWith('system.'))
      .map((c) => mongoose.connection.db.collection(c.name).deleteMany({}))
  );
}

/** Disconnect Mongoose and stop the in-memory server. */
export async function stopTestDatabase() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
  }
  if (replSet) {
    await replSet.stop();
    replSet = null;
  }
}

/** The URI in use, for assertions. */
export const currentUri = () => process.env.MONGO_URI;

/** True when the connection can run transactions (i.e. it is a replica set). */
export async function supportsTransactions() {
  const admin = mongoose.connection.db.admin();
  const info = await admin.command({ hello: 1 });
  return Boolean(info.setName);
}
