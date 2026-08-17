# Migrating the DealDirect database to a company-owned Atlas account

## Status: done, 2026-08-17

Production moved from `deal-direct.vwlhuto.mongodb.net` (an Atlas account
belonging to a former employee) to `dealdirect.rrp09uc.mongodb.net`.

| | |
|---|---|
| Final copy | 2026-08-17 14:06:59 UTC |
| Verified | 46/46 collections, all document hashes identical |
| Cutover | `MONGO_URI` changed in the Hostinger panel, app restarted |
| Confirmed | Login wrote `usersessions` at 14:17:18 UTC on the new cluster |
| Data lost in the gap | None. `orphans.js` found zero post-copy writes on the old cluster |

The cutover was done without a maintenance window, on the judgement that traffic
was near zero. `orphans.js` confirmed afterwards that nothing was written to the
old cluster in the eleven-minute gap. That was verified, not assumed.

`.env.new` has been deleted, which disarms `migrate.js`. See
[After cutover](#after-cutover-this-tooling-becomes-dangerous). One consequence:
**the old cluster's connection string is no longer on this machine.** The
recovery path is not a rollback but the offline dump in
`dumps/20260817-140659/`, which is a complete copy of the old cluster as of the
final read.

Still open: the old cluster has not been deleted, and the secrets that shared its
`.env` have not been rotated. See [Close out the exposure](#6-close-out-the-exposure).

The rest of this document is the runbook, kept because the same steps apply to
any future move.

---

## What was moved

Measured on 2026-08-17 against the live database:

| | |
|---|---|
| Collections | 47 |
| Documents | 2,005 |
| Data | 1.5 MB |
| Indexes | 7.2 MB |
| Compressed dump | 206 KB |

Small enough that the copy itself takes seconds. The care goes into sequencing,
not throughput.

### The one thing that is not obvious

`auditlogs` is a **time-series collection** on the server:

```
timeField: createdAt, metaField: category, granularity: minutes, bucketMaxSpanSeconds: 86400
```

`backend/models/AuditLog.js` does not declare this, because the collection was created
outside Mongoose. Two consequences:

1. `mongorestore` recreates it correctly from the dump metadata, but only into a
   database where no collection named `auditlogs` exists yet.
2. If the app connects to the new cluster **before** the restore, Mongoose
   autocreates `auditlogs` as an ordinary collection, and the restore then either
   fails or leaves you with a plain collection where a time-series one belongs.

**Restore first. Point the app at the new cluster second.** This ordering is not
negotiable, and `migrate.js verify` checks it explicitly.

## Scripts

| Command | Effect |
|---|---|
| `node scripts/db-migration/inventory.js` | Read-only census of `MONGO_URI`: counts, sizes, index definitions |
| `node scripts/db-migration/inventory.js MONGO_URI_NEW` | Same, against the target |
| `node scripts/db-migration/migrate.js preflight` | Connects to both, refuses to proceed if the target holds data |
| `node scripts/db-migration/migrate.js dump` | Source → `dumps/<utc-stamp>/` |
| `node scripts/db-migration/migrate.js restore` | Latest dump → target |
| `node scripts/db-migration/migrate.js verify` | Per-collection diff: counts, full index specs, collection type, time-series options, validators, and a SHA-256 of every document |
| `node scripts/db-migration/migrate.js all` | All four in order |
| `node scripts/db-migration/orphans.js` | Finds writes that landed on the old cluster after the last copy, the gap left by cutting over without a maintenance window |
| `node scripts/db-migration/backup.js` | Backs up whatever `MONGO_URI` points at, and prunes to `BACKUP_KEEP`. This is the one to schedule |

Connection strings are passed to `mongodump`/`mongorestore` through a temporary
`0600` config file, never as a command-line argument, so they stay out of the
process list and shell history. No script here prints a URI; host and database
name only.

`verify` checks three levels, because each one catches something the level above
misses:

1. **Counts**, which catch whole collections or batches that failed to restore.
2. **Full index specs**, not just names, because an index can keep its name and lose its
   `unique` flag or its `expireAfterSeconds`, at which point it silently stops
   enforcing anything. Collection type, time-series options and JSON schema
   validators are compared the same way.
3. **A SHA-256 over every document**, in `_id` order, on both ends. Matching
   counts say nothing about contents. This catches a truncated string, a dropped
   subdocument or a mangled `Date`.

`restore` refuses to write into a target that already contains data. The only
override is `FORCE_OVERWRITE_TARGET=1`, which additionally passes `--drop`. That
environment variable is the sole path by which anything here can destroy data.

`dumps/` is gitignored. It contains every user record, lead, agreement and audit
log in the system. Treat a dump exactly as you would the database.

## Prerequisites

MongoDB Database Tools 100.x:

```bash
winget install --id MongoDB.DatabaseTools -e
```

## Runbook

### 1. Prepare the new cluster (Atlas UI, company account)

- Region: pick the one closest to the Hostinger server, not to your laptop.
- Create a database user with `readWrite` on the target database. Use a
  generated password; do not reuse the old one.
- Network Access: add the **Hostinger server's outbound IP**, and your own IP for
  the duration of the migration. Remove your IP afterwards.
- Confirm the tier is a replica set. Every Atlas tier including M0 is, which
  matters because `addProperty` opens a real transaction
  (see `AI/DATABASE.md`, note 6) that fails on a standalone `mongod`.

Keep the database name as `Deal-Direct` unless you have a reason to change it.
If you do change it, `migrate.js` remaps namespaces automatically, but every
`.env` has to agree.

### 2. Supply the target connection string

Create `backend/.env.new` (already covered by `.gitignore`):

```
MONGO_URI_NEW=mongodb+srv://<user>:<password>@<new-host>/Deal-Direct?retryWrites=true&w=majority
```

Atlas's Connect dialog hands you a string with **no database in the path**:
`...mongodb.net/?appName=x`. `migrate.js` rejects that rather than guessing,
because a missing path silently means the `test` database. Append
`/Deal-Direct` yourself, and keep `retryWrites=true&w=majority`.

### 3. Rehearse

```bash
cd backend
node scripts/db-migration/migrate.js all
```

Run the whole thing once while the app is still live and still pointed at the
old cluster. Nothing is cut over; this only proves the pipeline works and that
`verify` comes back clean. Fix any discrepancy now, not during the window.

### 4. Cut over

Writes that land on the old cluster between the dump and the repoint are lost.
Traffic is low, so the simplest correct approach is a short freeze rather than
any replication scheme.

1. Stop the backend on Hostinger. Nothing can write from here on.
2. Re-run the copy, so the data is current as of the freeze:
   ```bash
   cd backend
   FORCE_OVERWRITE_TARGET=1 node scripts/db-migration/migrate.js all
   ```
   `FORCE_OVERWRITE_TARGET=1` is needed on this second pass because the rehearsal
   already populated the target.
3. Confirm `verify` reports no discrepancies. **If it does not, stop and
   investigate. The old cluster is untouched and restarting the backend rolls
   you straight back.**
4. Update `MONGO_URI` in three places:
   - `backend/.env` (local development)
   - `backend/.env.production` (the template)
   - **the live `.env` in `public_html` on Hostinger**
5. Check the Hostinger control panel for a platform-level `MONGO_URI`
   environment variable. `dotenv` does not overwrite a key already present in
   `process.env`, so a value injected by the host silently beats the file. If one
   exists, it must be changed too, or the app keeps using the old cluster while
   appearing to have been migrated.
6. Start the backend. Watch the log for
   `MongoDB Connected Successfully to: <new-host>`. `config/db.js` prints the
   host it actually reached, which is the real confirmation.

### 5. Verify against the running app

- `curl https://<api-host>/health`
- Log in as an existing user. This exercises `users`, `usersessions` and the
  unique index on `email`.
- Load the property listing page, which reads `properties`, `categories`, `subcategories`.
- Log into the admin dashboard and open the audit log. This is the one that
  proves the time-series collection survived.
- Create one throwaway property, then confirm it appears on the new cluster and
  **not** on the old one. That is the definitive proof the cutover took effect.

### 6. Close out the exposure

Copying the data does not end the problem. Until these are done, the former
employee still holds a full copy of the customer database:

- Get the old cluster deleted, or the account transferred. This needs their
  cooperation or the Atlas organisation owner's.
- Treat every secret in the old `.env` as known to them, not just `MONGO_URI`.
  `JWT_SECRET`, `CLOUDINARY_URL`, `SMTP_PASS`, `GEMINI_API_KEY` and the RewardPort
  and WAHA credentials were all in the same file. Rotating `JWT_SECRET` logs
  every user out, so schedule it deliberately.
- Ask them, or check the Atlas UI, for anything attached to the old project that
  is not data: Atlas Triggers, scheduled jobs, Charts dashboards, Data API keys.
  None of that is visible from a connection string and none of it comes across in
  a dump.

### After cutover: this tooling becomes dangerous

Before cutover, `FORCE_OVERWRITE_TARGET=1` drops a target holding nothing but a
rehearsal copy. After cutover, the same command drops **live production data** and
replaces it with a snapshot of the abandoned cluster.

Once production is confirmed on the new cluster, delete `backend/.env.new`.
`migrate.js` cannot run without `MONGO_URI_NEW`, so removing that file disarms it.
Recreate it only if you deliberately need to migrate again.

If writes landed on the old cluster after the final copy, do **not** fix it with
another `FORCE` run, which would discard everything written since. Run plain
`verify`, read which collections the source is ahead on, and move only those
documents across by hand.

### 7. Backups

M0 has no automated backups. The entire database is a ~200 KB gzipped dump, so a
rolling window costs nothing:

```bash
cd backend && node scripts/db-migration/backup.js
```

`backup.js` always dumps `MONGO_URI`, the database the app is actually using. It
has no source/target concept, so unlike `migrate.js` it cannot be aimed at the
wrong cluster by a stale environment key. It exits non-zero on failure, and it
treats an empty dump as a failure, because `mongodump` can exit 0 having written
nothing, and a backup job trusted while silently broken is worse than none.

Two environment variables:

| | |
|---|---|
| `BACKUP_DIR` | Where to write. Defaults inside `dumps/`, which is gitignored. **Set this to storage that does not share a fate with this machine.** |
| `BACKUP_KEEP` | How many to retain, oldest pruned first. Default 14. |

```bash
BACKUP_DIR=D:\backups\dealdirect BACKUP_KEEP=30 node scripts/db-migration/backup.js
```

Until this runs on a schedule against storage you control, the new cluster is a
single point of failure with no recovery path.
