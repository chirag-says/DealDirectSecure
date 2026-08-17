/**
 * Back up the live database (MONGO_URI) and prune old backups.
 *
 *   node scripts/db-migration/backup.js
 *
 *   BACKUP_DIR=D:\backups\dealdirect  node scripts/db-migration/backup.js
 *   BACKUP_KEEP=30                    node scripts/db-migration/backup.js
 *
 * The new cluster is an Atlas M0, which has no automated backups. The whole
 * database compresses to about 330 KB, so keeping a rolling window costs nothing
 * and is the only recovery path that exists.
 *
 * Always backs up MONGO_URI — the database the app is actually using. Unlike
 * migrate.js it has no notion of a source and target, so it cannot be pointed at
 * the wrong cluster by a stale environment key.
 *
 * Exits non-zero on any failure so a scheduler surfaces it. A backup job that
 * fails silently is worse than no backup job, because it is trusted.
 */
import dotenv from "dotenv";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const backendRoot = path.resolve(here, "..", "..");

dotenv.config({ path: path.join(backendRoot, ".env"), quiet: true });

const die = (message) => {
  console.error(`  ✗ ${message}`);
  process.exit(1);
};

const uri = process.env.MONGO_URI;
if (!uri) die("MONGO_URI is not set.");

let host;
let database;
try {
  const parsed = new URL(uri);
  host = parsed.host;
  database = parsed.pathname.replace(/^\//, "");
} catch {
  die("MONGO_URI is not a parseable connection string.");
}
if (!database) die("MONGO_URI has no database name in its path.");

// Defaults inside the repo, where dumps/ is already gitignored. A real backup
// belongs on storage that does not share a fate with this machine — set
// BACKUP_DIR to a synced or external location.
const root = process.env.BACKUP_DIR || path.join(here, "dumps", "backups");
const keep = Number(process.env.BACKUP_KEEP || 14);
if (!Number.isInteger(keep) || keep < 1) die("BACKUP_KEEP must be a positive integer.");

const stamp = new Date().toISOString().replace(/[-:]/g, "").replace("T", "-").slice(0, 15);
const destination = path.join(root, stamp);

const findTool = (name) => {
  const exe = process.platform === "win32" ? `${name}.exe` : name;
  const candidates = [
    ...(process.env.PATH || "").split(path.delimiter).map((dir) => path.join(dir, exe)),
    `C:\\Program Files\\MongoDB\\Tools\\100\\bin\\${exe}`,
  ];
  const found = candidates.find((p) => p && fs.existsSync(p));
  if (!found) die(`${name} not found. Install: winget install --id MongoDB.DatabaseTools -e`);
  return found;
};

const directorySize = (dir) =>
  fs
    .readdirSync(dir, { withFileTypes: true })
    .reduce(
      (total, entry) =>
        total +
        (entry.isDirectory()
          ? directorySize(path.join(dir, entry.name))
          : fs.statSync(path.join(dir, entry.name)).size),
      0,
    );

fs.mkdirSync(destination, { recursive: true });

// The connection string goes in a 0600 temp file, not argv, so it stays out of
// the process list — which matters more for a scheduled job than an interactive
// one, since the command line may be logged by the scheduler.
const configPath = path.join(os.tmpdir(), `dd-backup-${process.pid}.yaml`);
fs.writeFileSync(configPath, `uri: ${JSON.stringify(uri)}\n`, { mode: 0o600 });

try {
  const result = spawnSync(
    findTool("mongodump"),
    [`--config=${configPath}`, `--db=${database}`, `--out=${destination}`, "--gzip", "--quiet"],
    { stdio: ["ignore", "inherit", "inherit"] },
  );
  if (result.error) die(`mongodump failed to start: ${result.error.message}`);
  if (result.status !== 0) die(`mongodump exited with code ${result.status}.`);
} finally {
  fs.rmSync(configPath, { force: true });
}

// A dump directory that exists but holds nothing is the failure mode this is
// guarding against: mongodump can exit 0 having written no collections.
const payload = path.join(destination, database);
if (!fs.existsSync(payload) || !fs.readdirSync(payload).some((f) => f.endsWith(".bson.gz"))) {
  die(`Backup at ${destination} contains no data. Treat this as a failed backup.`);
}

const collections = fs.readdirSync(payload).filter((f) => f.endsWith(".bson.gz")).length;
const size = directorySize(destination);
console.log(
  `  ✓ ${host}/${database} → ${destination}  (${collections} collections, ${(size / 1024).toFixed(0)} KB)`,
);

// Prune oldest first. Names are sortable UTC stamps.
const existing = fs
  .readdirSync(root)
  .filter((n) => /^\d{8}-\d{6}$/.test(n))
  .sort();
for (const old of existing.slice(0, Math.max(0, existing.length - keep))) {
  fs.rmSync(path.join(root, old), { recursive: true, force: true });
  console.log(`    pruned ${old}`);
}
console.log(`  ${Math.min(existing.length, keep)} backup(s) retained (BACKUP_KEEP=${keep})`);
