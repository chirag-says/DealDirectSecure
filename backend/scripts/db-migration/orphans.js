/**
 * Find writes that landed on the OLD cluster after the final copy was taken.
 *
 *   node scripts/db-migration/orphans.js            # cutoff = newest dump's timestamp
 *   node scripts/db-migration/orphans.js 2026-08-17T14:06:59Z
 *
 * Cutting over without a maintenance window leaves a gap: anything written to
 * the source between the last dump and the moment production repointed is not on
 * the new cluster. This finds those documents so they can be moved by hand.
 *
 * Do not fix a gap with another FORCE restore. By this point the new cluster
 * holds live production writes, and a restore would discard them.
 *
 * Detection uses two signals:
 *   - `_id` — an ObjectId embeds its creation second, so a range query on it
 *     dates every insert without depending on any schema field.
 *   - `updatedAt` — catches documents that already existed but were modified
 *     after the cutoff, which an _id check alone cannot see.
 *
 * Time-series collections have no _id index and are queried on their timeField.
 */
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, "..", "..");

for (const file of [".env", ".env.new"]) {
  const full = path.join(backendRoot, file);
  if (fs.existsSync(full)) dotenv.config({ path: full, quiet: true });
}

const uri = process.env.MONGO_URI_OLD;
if (!uri) {
  console.error("\n  MONGO_URI_OLD is not set. It must point at the cluster being left behind.\n");
  process.exit(1);
}

/** Dump directories are named YYYYMMDD-HHMMSS in UTC by migrate.js. */
const cutoffFromNewestDump = () => {
  const dumpRoot = path.join(here, "dumps");
  if (!fs.existsSync(dumpRoot)) return null;
  const stamps = fs
    .readdirSync(dumpRoot)
    .filter((n) => /^\d{8}-\d{6}$/.test(n))
    .sort();
  if (!stamps.length) return null;
  const s = stamps[stamps.length - 1];
  const iso =
    `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T` +
    `${s.slice(9, 11)}:${s.slice(11, 13)}:${s.slice(13, 15)}Z`;
  return { date: new Date(iso), from: `dump ${s}` };
};

const explicit = process.argv[2];
const cutoff = explicit
  ? { date: new Date(explicit), from: "argument" }
  : cutoffFromNewestDump();

if (!cutoff || Number.isNaN(cutoff.date.getTime())) {
  console.error("\n  Could not determine a cutoff. Pass one as an ISO timestamp.\n");
  process.exit(1);
}

const client = new MongoClient(uri, { serverSelectionTimeoutMS: 15000 });
await client.connect();

try {
  const db = client.db();
  console.log(`\n  cluster  ${new URL(uri).host} / ${db.databaseName}  (the one being left behind)`);
  console.log(`  cutoff   ${cutoff.date.toISOString()}  (from ${cutoff.from})\n`);

  const boundary = ObjectId.createFromTime(Math.floor(cutoff.date.getTime() / 1000));
  const entries = (await db.listCollections({}, { nameOnly: false }).toArray()).filter(
    (e) => !e.name.startsWith("system."),
  );

  const findings = [];

  for (const entry of entries) {
    const collection = db.collection(entry.name);
    const timeField = entry.options?.timeseries?.timeField;

    let inserted;
    if (timeField) {
      inserted = await collection.countDocuments({ [timeField]: { $gt: cutoff.date } });
    } else {
      inserted = await collection.countDocuments({ _id: { $gt: boundary } });
    }

    // updatedAt only exists where the schema enables timestamps; absent is fine.
    const modified = await collection.countDocuments({
      updatedAt: { $gt: cutoff.date },
      ...(timeField ? {} : { _id: { $lte: boundary } }),
    });

    if (inserted || modified) findings.push({ name: entry.name, inserted, modified, timeField });
  }

  if (!findings.length) {
    console.log("  ✓ nothing was written to the old cluster after the cutoff.");
    console.log("    The gap cost you no data. The new cluster is complete.\n");
  } else {
    const width = Math.max(...findings.map((f) => f.name.length), 10);
    console.log("  ! the old cluster received writes after the copy:\n");
    for (const f of findings) {
      const parts = [];
      if (f.inserted) parts.push(`${f.inserted} inserted`);
      if (f.modified) parts.push(`${f.modified} modified`);
      console.log(`  ${f.name.padEnd(width)}  ${parts.join(", ")}`);
    }
    console.log(
      "\n  These are not on the new cluster. Move them by hand.\n" +
        "  Do NOT run a FORCE restore — the new cluster now holds live writes\n" +
        "  that a restore would discard.\n",
    );
    process.exitCode = 1;
  }
} finally {
  await client.close();
}
