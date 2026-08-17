/**
 * Copy a MongoDB database from MONGO_URI (source) to MONGO_URI_NEW (target).
 *
 *   node scripts/db-migration/migrate.js preflight   # check both ends, change nothing
 *   node scripts/db-migration/migrate.js dump        # source -> dumps/<stamp>/
 *   node scripts/db-migration/migrate.js restore     # dumps/<stamp>/ -> target
 *   node scripts/db-migration/migrate.js verify      # diff target against source
 *   node scripts/db-migration/migrate.js all         # all four in order
 *
 * Design notes:
 *
 * - Connection strings are handed to mongodump/mongorestore through a
 *   short-lived YAML config file, never as an argv element, so they do not
 *   appear in the process list or in shell history. Nothing here ever logs a
 *   URI; only host and database name are printed.
 *
 * - `restore` refuses to run against a target that already holds data. Set
 *   FORCE_OVERWRITE_TARGET=1 to override, which also switches mongorestore to
 *   --drop. That flag is the only way this script can destroy anything.
 *
 * - `auditlogs` is a time-series collection on the source, created outside
 *   Mongoose. mongorestore recreates it from the dump metadata, but only if the
 *   app has not already connected to the target and let Mongoose autocreate a
 *   plain collection of that name. Restore first, repoint the app second.
 */
import { MongoClient } from "mongodb";
import { serialize } from "bson";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import dotenv from "dotenv";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, "..", "..");
const dumpRoot = path.join(here, "dumps");

for (const file of [".env", ".env.new"]) {
  const full = path.join(backendRoot, file);
  if (fs.existsSync(full)) dotenv.config({ path: full, quiet: true });
}

// The source is named explicitly, because MONGO_URI in .env is the value being
// cut over — once it points at the new cluster, it is no longer the source.
// MONGO_URI_OLD wins when present; MONGO_URI is only a fallback for a first run.
const SOURCE_KEY = process.env.MONGO_URI_OLD ? "MONGO_URI_OLD" : "MONGO_URI";
const TARGET_KEY = "MONGO_URI_NEW";
const FORCE = process.env.FORCE_OVERWRITE_TARGET === "1";

// ---------------------------------------------------------------- helpers

const die = (message) => {
  console.error(`\n  ✗ ${message}\n`);
  process.exit(1);
};

const readUri = (key) => {
  const value = process.env[key];
  if (!value) {
    die(
      `${key} is not set.\n` +
        `    Put it in backend/.env.new as:  ${key}=mongodb+srv://...\n` +
        `    That file is already covered by .gitignore.`,
    );
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    die(`${key} is not a parseable connection string.`);
  }
  const database = parsed.pathname.replace(/^\//, "");
  if (!database) {
    die(
      `${key} has no database name in its path.\n` +
        `    Append the database, e.g. ...mongodb.net/Deal-Direct?retryWrites=true`,
    );
  }
  return { uri: value, host: parsed.host, database };
};

/** Resolve mongodump/mongorestore from PATH, falling back to the Windows default. */
const findTool = (name) => {
  const exe = process.platform === "win32" ? `${name}.exe` : name;
  const candidates = [
    ...(process.env.PATH || "").split(path.delimiter).map((dir) => path.join(dir, exe)),
    `C:\\Program Files\\MongoDB\\Tools\\100\\bin\\${exe}`,
  ];
  const found = candidates.find((p) => p && fs.existsSync(p));
  if (!found) {
    die(
      `${name} not found.\n` +
        `    Install it with:  winget install --id MongoDB.DatabaseTools -e`,
    );
  }
  return found;
};

/**
 * Run a database tool with the connection string in a temp config file rather
 * than argv. The file is written with owner-only permissions and removed in a
 * finally block, including on crash.
 */
const runTool = (toolName, uri, args) => {
  const configPath = path.join(
    os.tmpdir(),
    `dd-migrate-${process.pid}-${toolName}.yaml`,
  );
  // The value is quoted because connection strings contain ':' and '#'.
  fs.writeFileSync(configPath, `uri: ${JSON.stringify(uri)}\n`, { mode: 0o600 });
  try {
    const result = spawnSync(findTool(toolName), [`--config=${configPath}`, ...args], {
      stdio: "inherit",
    });
    if (result.error) die(`${toolName} failed to start: ${result.error.message}`);
    if (result.status !== 0) die(`${toolName} exited with code ${result.status}.`);
  } finally {
    fs.rmSync(configPath, { force: true });
  }
};

/** Collections a fresh Atlas cluster may contain without being "in use". */
const isIncidental = (name) => name.startsWith("system.");

const inspect = async ({ uri, database }) => {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  try {
    const db = client.db(database);
    const listed = await db.listCollections({}, { nameOnly: false }).toArray();
    const collections = {};
    for (const entry of listed) {
      if (isIncidental(entry.name)) continue;
      const collection = db.collection(entry.name);
      // Index *names* matching is not enough. A TTL index that lost its
      // expireAfterSeconds, or a unique index restored without the unique flag,
      // keeps its name and silently stops enforcing anything. Compare the
      // behavioural options too.
      const indexes = {};
      for (const i of await collection.indexes()) {
        indexes[i.name] = {
          key: i.key,
          unique: i.unique ?? false,
          sparse: i.sparse ?? false,
          expireAfterSeconds: i.expireAfterSeconds ?? null,
          partialFilterExpression: i.partialFilterExpression ?? null,
          weights: i.weights ?? null, // text indexes
          default_language: i.default_language ?? null,
          collation: i.collation ? { locale: i.collation.locale, strength: i.collation.strength } : null,
        };
      }

      collections[entry.name] = {
        type: entry.type,
        timeseries: entry.options?.timeseries ?? null,
        validator: entry.options?.validator ?? null,
        count: await collection.countDocuments(),
        indexes,
      };
    }
    return { host: new URL(uri).host, database, collections };
  } finally {
    await client.close();
  }
};

/**
 * SHA-256 over every document in a collection, in _id order.
 *
 * Matching document counts prove nothing about document contents. This hashes
 * the actual BSON so a truncated string, a dropped subdocument or a mangled
 * Date shows up as a mismatch. Cheap here because the whole database is 1.5 MB;
 * it streams rather than buffering, but it is still O(data) on both ends.
 */
const contentHashes = async ({ uri, database }, names) => {
  const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  try {
    const db = client.db(database);
    const hashes = {};
    for (const name of names) {
      const digest = createHash("sha256");
      const cursor = db.collection(name).find({}, { sort: { _id: 1 } });
      for await (const doc of cursor) digest.update(serialize(doc));
      hashes[name] = digest.digest("hex").slice(0, 16);
    }
    return hashes;
  } finally {
    await client.close();
  }
};

const summarise = (snapshot) => {
  const names = Object.keys(snapshot.collections);
  const documents = names.reduce((n, k) => n + snapshot.collections[k].count, 0);
  return `${snapshot.host} / ${snapshot.database} — ${names.length} collections, ${documents} documents`;
};

const latestDump = () => {
  if (!fs.existsSync(dumpRoot)) return null;
  const entries = fs
    .readdirSync(dumpRoot)
    .filter((name) => fs.statSync(path.join(dumpRoot, name)).isDirectory())
    .sort();
  return entries.length ? path.join(dumpRoot, entries[entries.length - 1]) : null;
};

/** Sortable UTC stamp, e.g. 20260817-190531. Passed in so reruns are traceable. */
const stamp = () =>
  new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);

// ---------------------------------------------------------------- phases

const preflight = async () => {
  const source = readUri(SOURCE_KEY);
  const target = readUri(TARGET_KEY);

  console.log(`\n  source  ${source.host} / ${source.database}`);
  console.log(`  target  ${target.host} / ${target.database}`);

  if (source.host === target.host) {
    die("Source and target are the same host. Check MONGO_URI_NEW in backend/.env.new.");
  }

  console.log("\n  connecting to source...");
  const sourceState = await inspect(source);
  console.log(`  ✓ ${summarise(sourceState)}`);

  console.log("  connecting to target...");
  const targetState = await inspect(target);
  console.log(`  ✓ ${summarise(targetState)}`);

  const occupied = Object.entries(targetState.collections).filter(([, c]) => c.count > 0);
  if (occupied.length) {
    console.log(`\n  ! target is not empty — ${occupied.length} collections hold data:`);
    for (const [name, c] of occupied.slice(0, 10)) console.log(`      ${name} (${c.count})`);
    if (occupied.length > 10) console.log(`      ...and ${occupied.length - 10} more`);
    if (!FORCE) {
      die(
        "Refusing to restore into a database that already has data.\n" +
          "    If overwriting is genuinely what you want, rerun with\n" +
          "    FORCE_OVERWRITE_TARGET=1, which drops each collection first.",
      );
    }
    console.log("\n  FORCE_OVERWRITE_TARGET=1 is set — restore will drop these first.");
  } else {
    console.log("\n  ✓ target is empty, safe to restore into");
  }

  const timeseries = Object.entries(sourceState.collections).filter(([, c]) => c.timeseries);
  if (timeseries.length) {
    console.log(`\n  time-series collections to preserve: ${timeseries.map(([n]) => n).join(", ")}`);
  }

  return { source, target, sourceState };
};

const dump = async () => {
  const source = readUri(SOURCE_KEY);
  const destination = path.join(dumpRoot, stamp());
  fs.mkdirSync(destination, { recursive: true });

  console.log(`\n  dumping ${source.host} / ${source.database}`);
  console.log(`  into    ${path.relative(backendRoot, destination)}\n`);

  runTool("mongodump", source.uri, [
    `--db=${source.database}`,
    `--out=${destination}`,
    "--gzip",
  ]);

  console.log(`\n  ✓ dump written to ${path.relative(backendRoot, destination)}`);
  return destination;
};

const restore = async (fromDirectory) => {
  const source = readUri(SOURCE_KEY);
  const target = readUri(TARGET_KEY);
  const directory = fromDirectory || latestDump();

  if (!directory || !fs.existsSync(directory)) {
    die("No dump found. Run the dump phase first.");
  }

  const payload = path.join(directory, source.database);
  if (!fs.existsSync(payload)) {
    die(`Dump at ${path.relative(backendRoot, directory)} has no ${source.database} directory.`);
  }

  console.log(`\n  restoring ${path.relative(backendRoot, directory)}`);
  console.log(`  into      ${target.host} / ${target.database}\n`);

  const args = [
    `--nsFrom=${source.database}.*`,
    `--nsTo=${target.database}.*`,
    `--dir=${payload}`,
    "--gzip",
    "--stopOnError",
  ];
  // Only ever passed when the operator explicitly opted into overwriting.
  if (FORCE) args.push("--drop");

  runTool("mongorestore", target.uri, args);
  console.log("\n  ✓ restore complete");
};

const verify = async () => {
  const source = readUri(SOURCE_KEY);
  const target = readUri(TARGET_KEY);

  const [before, after] = await Promise.all([inspect(source), inspect(target)]);

  const names = [...new Set([...Object.keys(before.collections), ...Object.keys(after.collections)])].sort();
  const problems = [];
  const width = Math.max(...names.map((n) => n.length), 10);

  console.log(`\n  source  ${summarise(before)}`);
  console.log(`  target  ${summarise(after)}\n`);

  // Only worth hashing where both sides have the collection and it holds data.
  const hashable = names.filter(
    (n) => before.collections[n]?.count > 0 && after.collections[n],
  );
  console.log(`  hashing contents of ${hashable.length} non-empty collections on both ends...\n`);
  const [sourceHashes, targetHashes] = await Promise.all([
    contentHashes(source, hashable),
    contentHashes(target, hashable),
  ]);

  for (const name of names) {
    const a = before.collections[name];
    const b = after.collections[name];

    if (!a) {
      // Extra collections on the target are usually Mongoose autocreating empty
      // ones. Harmless when empty, worth naming when not.
      const note = b.count > 0 ? "EXTRA (has data)" : "extra, empty";
      if (b.count > 0) problems.push(`${name}: exists on target only, holds ${b.count} documents`);
      console.log(`  ${name.padEnd(width)}  ${note}`);
      continue;
    }
    if (!b) {
      problems.push(`${name}: missing from target`);
      console.log(`  ${name.padEnd(width)}  MISSING`);
      continue;
    }

    const issues = [];
    if (a.count !== b.count) issues.push(`count ${a.count} → ${b.count}`);

    if (a.type !== b.type) issues.push(`type ${a.type} → ${b.type}`);

    const missing = Object.keys(a.indexes).filter((i) => !(i in b.indexes));
    if (missing.length) issues.push(`missing indexes: ${missing.join(", ")}`);

    // Same name, different behaviour — the failure that a name-only check misses.
    const altered = Object.keys(a.indexes)
      .filter((i) => i in b.indexes)
      .filter((i) => JSON.stringify(a.indexes[i]) !== JSON.stringify(b.indexes[i]));
    for (const i of altered) {
      issues.push(`index "${i}" options differ: ${JSON.stringify(a.indexes[i])} → ${JSON.stringify(b.indexes[i])}`);
    }

    const ts = [a.timeseries, b.timeseries].map((v) => JSON.stringify(v));
    if (ts[0] !== ts[1]) issues.push(`time-series options differ (${ts[0]} → ${ts[1]})`);

    const validators = [a.validator, b.validator].map((v) => JSON.stringify(v));
    if (validators[0] !== validators[1]) issues.push("schema validator differs");

    const hashed = name in sourceHashes;
    if (hashed && sourceHashes[name] !== targetHashes[name]) {
      issues.push(`contents differ (${sourceHashes[name]} → ${targetHashes[name]})`);
    }

    const counts = Object.keys(a.indexes).length;
    if (issues.length) {
      problems.push(`${name}: ${issues.join("; ")}`);
      console.log(`  ${name.padEnd(width)}  ✗ ${issues.join("; ")}`);
    } else {
      // Name the guarantees that actually matter, so a clean run is evidence
      // rather than just a tick.
      const enforced = Object.entries(a.indexes)
        .filter(([, i]) => i.unique || i.expireAfterSeconds !== null || i.weights)
        .map(([n, i]) =>
          i.expireAfterSeconds !== null ? `ttl(${i.expireAfterSeconds}s)` : i.weights ? "text" : `uniq:${n}`,
        );
      console.log(
        `  ${name.padEnd(width)}  ✓ ${String(a.count).padStart(4)} docs, ${String(counts).padStart(2)} indexes  ` +
          (hashed ? sourceHashes[name] : "empty".padEnd(16)) +
          (a.timeseries ? "  timeseries" : "") +
          (enforced.length ? `  ${enforced.join(" ")}` : ""),
      );
    }
  }

  if (problems.length) {
    console.error(`\n  ✗ ${problems.length} discrepancies — do not cut over yet:\n`);
    for (const p of problems) console.error(`      ${p}`);
    console.error("");
    process.exitCode = 1;
  } else {
    console.log(`\n  ✓ target matches source across all ${names.length} collections\n`);
  }
};

// ---------------------------------------------------------------- entry

const phase = process.argv[2];

try {
  switch (phase) {
    case "preflight":
      await preflight();
      break;
    case "dump":
      await dump();
      break;
    case "restore":
      await restore();
      break;
    case "verify":
      await verify();
      break;
    case "all": {
      await preflight();
      const directory = await dump();
      await restore(directory);
      await verify();
      break;
    }
    default:
      console.error(
        "\n  usage: node scripts/db-migration/migrate.js <preflight|dump|restore|verify|all>\n",
      );
      process.exit(1);
  }
} catch (error) {
  die(error.message);
}
