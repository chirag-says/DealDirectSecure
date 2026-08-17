/**
 * Read-only inventory of a MongoDB database.
 *
 * Prints collection names, document counts, storage sizes and index definitions.
 * Writes nothing. Never prints the connection string or any credential.
 *
 *   node scripts/db-migration/inventory.js              # inventories MONGO_URI
 *   node scripts/db-migration/inventory.js MONGO_URI_NEW  # inventories another key
 *
 * The output doubles as the before/after baseline for the migration: run it
 * against the source, run it against the target, diff the two JSON files.
 */
import { MongoClient } from "mongodb";
import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, "..", "..");

// Load .env first, then .env.new. dotenv never overwrites an existing key, so
// a value already in the real environment still wins.
for (const file of [".env", ".env.new"]) {
  const full = path.join(backendRoot, file);
  if (fs.existsSync(full)) dotenv.config({ path: full });
}

const envKey = process.argv[2] || "MONGO_URI";
const uri = process.env[envKey];

if (!uri) {
  console.error(`${envKey} is not set. Expected it in backend/.env or backend/.env.new.`);
  process.exit(1);
}

/** Host and database only. Deliberately drops user, password and query string. */
const describeTarget = (connectionString) => {
  try {
    const parsed = new URL(connectionString);
    return { host: parsed.host, database: parsed.pathname.replace(/^\//, "") || "(default)" };
  } catch {
    return { host: "(unparseable)", database: "(unknown)" };
  }
};

const target = describeTarget(uri);

const bytes = (n) => {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB"];
  let value = n / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(1)} ${units[unit]}`;
};

const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });

try {
  await client.connect();
  const db = client.db();

  const stats = await db.stats();
  const collections = (await db.listCollections().toArray())
    .filter((c) => c.type !== "view")
    .sort((a, b) => a.name.localeCompare(b.name));

  const report = {
    envKey,
    host: target.host,
    database: db.databaseName,
    totals: {
      collections: collections.length,
      documents: 0,
      dataSize: stats.dataSize,
      storageSize: stats.storageSize,
      indexSize: stats.indexSize,
    },
    collections: [],
  };

  for (const { name } of collections) {
    const collection = db.collection(name);
    const count = await collection.countDocuments();
    const indexes = await collection.indexes();

    // collStats is deprecated as a command but still the only way to get
    // per-collection storage on shared tiers, where $collStats is restricted.
    let size = null;
    try {
      const s = await db.command({ collStats: name });
      size = { dataSize: s.size, storageSize: s.storageSize, indexSize: s.totalIndexSize };
    } catch {
      // Non-fatal: counts and indexes are what the verification actually needs.
    }

    report.totals.documents += count;
    report.collections.push({
      name,
      count,
      size,
      indexes: indexes.map((i) => ({
        name: i.name,
        key: i.key,
        unique: i.unique ?? false,
        expireAfterSeconds: i.expireAfterSeconds ?? null,
        partialFilterExpression: i.partialFilterExpression ?? null,
        weights: i.weights ?? null, // present on text indexes
      })),
    });
  }

  console.log(`\nhost      ${report.host}`);
  console.log(`database  ${report.database}`);
  console.log(
    `totals    ${report.totals.collections} collections, ` +
      `${report.totals.documents} documents, ` +
      `${bytes(report.totals.dataSize)} data, ` +
      `${bytes(report.totals.indexSize)} indexes\n`,
  );

  const nameWidth = Math.max(...report.collections.map((c) => c.name.length), 10);
  for (const c of report.collections) {
    const special = c.indexes
      .filter((i) => i.expireAfterSeconds !== null || i.weights || i.unique)
      .map((i) =>
        i.expireAfterSeconds !== null ? `ttl:${i.name}` : i.weights ? `text:${i.name}` : `uniq:${i.name}`,
      );
    console.log(
      `  ${c.name.padEnd(nameWidth)}  ${String(c.count).padStart(7)} docs  ` +
        `${String(c.indexes.length).padStart(2)} idx  ` +
        `${(c.size ? bytes(c.size.dataSize) : "-").padStart(9)}` +
        (special.length ? `  ${special.join(" ")}` : ""),
    );
  }

  const out = path.join(here, `inventory.${envKey}.json`);
  fs.writeFileSync(out, JSON.stringify(report, null, 2));
  console.log(`\nwritten to ${path.relative(backendRoot, out)}`);
} catch (error) {
  console.error(`\nFailed against ${target.host}: ${error.message}`);
  if (/timed out|ECONNREFUSED|ENOTFOUND/i.test(error.message)) {
    console.error("Likely the Atlas network access list does not contain this machine's IP.");
  }
  process.exitCode = 1;
} finally {
  await client.close();
}
