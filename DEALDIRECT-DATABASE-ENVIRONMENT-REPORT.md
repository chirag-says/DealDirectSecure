# DealDirect: Database Environment Report

Phase 3B.0. Read-only investigation of repository configuration.

**No database was contacted during this phase.** Per the brief, no query was run
against any `MONGO_URI`, because the point of the exercise is to avoid treating
an unknown environment as a development database.

No credentials, usernames, passwords or connection strings appear in this
document. Hosts, database names and variable names only.

---

## 1. Current configuration

### `backend/.env`

| Property | Value |
|---|---|
| Keys defined | 34 |
| `NODE_ENV` | **absent** |
| Mongo host | `deal-direct.vwlhuto.mongodb.net` |
| Mongo database | `Deal-Direct` |
| Tracked in git | No, ignored |

### `backend/.env.production`

| Property | Value |
|---|---|
| Keys defined | 15 |
| `NODE_ENV` | present, `production` |
| Mongo host | `deal-direct.vwlhuto.mongodb.net` |
| Mongo database | `Deal-Direct` |
| Tracked in git | No, ignored |
| Header comment | `Copy this file to .env in public_html after each deployment` |

**The two `MONGO_URI` values are byte-identical.**

### `backend/.env.example`

Template only. Host `cluster.mongodb.net`, database `database`. Placeholders.

### Runtime selection

`backend/server.js:34-43`:

```
if (.env exists)                 -> load .env
else if (.env.production exists) -> load .env.production
else                             -> dotenv.config() with no path
```

`backend/config/db.js` then reads `process.env.MONGO_URI` directly. It has no
concept of environment and performs no validation of which database it is
reaching. Its only environment-dependent behaviour is on failure: it calls
`process.exit(1)` when `NODE_ENV !== 'production'` and keeps running otherwise.

**Critical precedence fact, verified by direct test:** `dotenv` does not
overwrite a key that already exists in `process.env`. A variable injected by the
hosting platform therefore **wins over any `.env` file**, and the file's value is
never used. This is what makes the two accounts in §2 mutually exclusive rather
than merely different.

---

## 2. How the deployed backend actually receives `MONGO_URI`

The repository contains **two contradictory accounts**, and nothing that
adjudicates between them.

**Account A: the hosting panel supplies it.**
`HOSTINGER_DEPLOYMENT.md` §2.3, "Set Environment Variables", instructs:
*"In Hostinger hPanel → Environment Variables, add:"* followed by a list that
includes `NODE_ENV=production` and `MONGO_URI=...`. Under this account the
backend's variables are platform-injected, `.env.production` is never read in
production, and its contents are irrelevant to the live database.

**Account B: the file is copied onto the server.**
`backend/.env.production` line 2 says *"Copy this file to .env in public_html
after each deployment"*. `AI/ENVIRONMENT.md:17` repeats this as the deploy
procedure. The `HOSTINGER WORKAROUND` fallback in `server.js` only makes sense if
the file reaches the server at all. Under this account the live database is
whatever `.env.production` names, which is the same database as `.env`.

**These cannot both be true of the same value.** Because platform variables win,
Account A makes the file inert; Account B assumes the file is authoritative.

Note also that the two "update `.env.production` before pushing" instructions in
the deployment guide (§3.1 and §4.1) are about the **client and admin** Vite apps
and their `VITE_*` variables. Neither concerns the backend. An earlier revision
of §0 in `DEALDIRECT-TAXONOMY-DECISION.md` stated that production runs on
`.env.production` per repository documentation; that reading came from the file
header and the AI note without §2.3, and is withdrawn here.

**The deployment chain, as far as the repository establishes it:**

```
git push
   |
   v
Hostinger "Import Git Repository" build       (HOSTINGER_DEPLOYMENT.md 2.1-2.2)
   |
   v
npm install; npm start                        (build/start commands, 2.2)
   |
   v
??? environment supplied by hPanel variables  (Account A, 2.3)
    OR by a manually copied .env              (Account B, file header)
   |
   v
server.js selects .env > .env.production > system env
   |
   v
config/db.js connects to process.env.MONGO_URI
```

The `???` step is the whole question, and the repository does not answer it.

---

## 3. Evidence

| # | Evidence | Bearing |
|---|---|---|
| E1 | `.env` and `.env.production` hold byte-identical `MONGO_URI` | If the file is what production reads, both roles share one database |
| E2 | `.env` has no `NODE_ENV`; `.env.production` sets it to `production` | The only functional difference between the two files is security posture, not database |
| E3 | `server.js:34-43` prefers `.env`, falls back to `.env.production` | A copied file would be picked up; so would a pre-existing one |
| E4 | `HOSTINGER_DEPLOYMENT.md` §2.3 lists `MONGO_URI` among hPanel variables | Account A |
| E5 | `.env.production` header: copy to `.env` in `public_html` | Account B |
| E6 | `AI/ENVIRONMENT.md:17` repeats E5 | Account B, same source |
| E7 | dotenv never overrides an existing `process.env` key, verified by test | Makes A and B mutually exclusive; under A the file is dead weight |
| E8 | No CI/CD workflow, Dockerfile, compose file, PM2 ecosystem file, systemd unit or platform config anywhere in the repository | No third mechanism, and no automation that would record the answer |
| E9 | Exactly one real Atlas host appears anywhere in the repository. The only others are the `cluster.mongodb.net` placeholder in the deployment guide and `cluster0.example.mongodb.net` in a test fixture | No second database is configured anywhere |
| E10 | No deployment logs, no release notes, no backup or restore procedure for the application database, no documented database names | No external record to consult |
| E11 | `README.md:217` documents dev setup as copying `.env.example` to `.env` | `.env` is the developer-machine convention, which says nothing about which database it should point at |
| E12 | `backend/scripts/` holds four one-off scripts (`migrateLegacyUsers`, `normalizeCategoryName`, `seedBlogs`, `sync-bookings-to-campaigns`), all reading the same single `MONGO_URI` | Past data operations ran against whatever that one URI serves |
| E13 | The only isolated writable database in the repository is the in-memory replica set started by the integration harness | Ephemeral, per test process |

---

## 4. Environment identity

```
Development DB: UNKNOWN
Production DB:  UNKNOWN
```

**Development: UNKNOWN.** A `MONGO_URI` is configured and a developer machine
will use it, but nothing establishes that it is *a development database*. It
names the same cluster and database as the production file.

**Production: UNKNOWN.** Under Account A the live value lives in the Hostinger
panel and is not visible from here. Under Account B it is the value in
`.env.production`. The repository supports both readings equally.

**DATABASE ROLE CANNOT BE ESTABLISHED FROM THIS REPOSITORY**

---

## 5. Separation status

```
Unknown
```

Not "shared", which would be a finding; not "separate", which would be a relief.
The two possibilities the repository leaves open are:

1. **Shared.** hPanel does not set `MONGO_URI`, `.env.production` is copied, and
   development and production are the same database. Everything in the repo is
   consistent with this.
2. **Separate.** hPanel sets `MONGO_URI` to a different cluster,
   `.env.production` is a stale artefact that is never read in production, and
   the database configured here is a development or staging copy that happens to
   carry a production-shaped corpus.

What can be said with confidence: **the repository contains no separate
development database configuration**, and **no persistent isolated writable
development database exists** for rehearsing a migration.

---

## 6. Risk

If a migration were run against the configured URI while its role is unknown:

**If it is production.** The taxonomy migration writes three reference fields on
47 property documents and seeds 23 taxonomy documents. Stages 1 and 2 are
additive and stage 3 is reversible from its own log, so the *designed* blast
radius is small. But it would be an unreviewed, unannounced write to live
customer data, performed from a developer machine, at a moment nobody chose. The
rollback depends on a migration log written in the same run: if the run dies
partway, recovery depends on an artefact that may itself be incomplete. There is
no documented backup or restore procedure for this database anywhere in the
repository, so the fallback position is unknown.

**If it is development but shares a cluster with production.** A mistyped
database name, or a script that omits the database segment, reaches production on
the same credentials. The scripts in `backend/scripts/` all read the same single
`MONGO_URI`, so this is not hypothetical.

**If it is genuinely development.** Nothing bad happens, and the migration is
rehearsed exactly as intended. This is the outcome everyone assumes, and it is
the one the repository cannot confirm.

The asymmetry is the point: two of three outcomes are bad, the third is
indistinguishable from them beforehand, and the cost of checking is minutes.

A second, quieter risk: `config/db.js` does not `process.exit` on connection
failure when `NODE_ENV === 'production'`. A migration script inheriting that
behaviour could continue past a failed connection.

---

## 7. Recommended end state, not yet implemented

Three files with three unambiguous roles:

| File | Role | `MONGO_URI` target |
|---|---|---|
| `backend/.env` | developer machine | a **separate development database** |
| `backend/.env.production` | deployment template only, never read at runtime | placeholder, no live credentials |
| `backend/.env.test` | integration harness | unused; the harness supplies its own in-memory URI and its guard rejects anything else |

Supporting changes, all deferred:

- Add `NODE_ENV=development` to `.env` so the running environment is explicit
  rather than inferred from absence.
- Have `config/db.js` log the resolved database **name** at startup, so the
  target is visible in any console without exposing the URI.
- Consider a startup assertion that refuses to run destructive scripts when the
  resolved database name matches the production name.

**No file has been modified.** The `.env.test` row describes a convention, not a
requirement: the existing harness already refuses any non-local database.

---

## 8. Required next action

The smallest safe action, and it is not a code change:

> **Open Hostinger hPanel → Environment Variables for the backend service and
> read whether `MONGO_URI` is set there.**

That single fact discriminates between Accounts A and B and therefore between the
two scenarios in §5.

- **Set in hPanel** → its cluster host is the production database. Compare it to
  `deal-direct.vwlhuto.mongodb.net`. If they differ, the environments are already
  separate and the local database is safe to use. If they match, they are shared.
- **Not set in hPanel** → production reads `.env.production`, which is the same
  database as `.env`. The environments are shared.

Then, in MongoDB Atlas, confirm how many clusters and databases exist under the
project. Two independent readings beat one.

If the outcome is "shared", the follow-up before any migration is to create a
genuinely separate development database, point `.env` at it, and populate it from
a production export. That is a data-copy task, not a schema task, and it should
be scoped separately.

Neither step requires this repository, and neither should be guessed at from
inside it.

---

## 9. Confirmation

- **Database writes: 0**
- **Taxonomy writes: 0**
- **Property writes: 0**
- **Schema changes: 0**
- No database of any kind was contacted during this phase
- No credentials, usernames, passwords or connection strings recorded
- No environment file modified
- No marker document written, and none proposed: environment identification here
  is entirely non-destructive and stays that way
