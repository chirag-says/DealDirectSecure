/**
 * Taxonomy migration: UP, DOWN, STATUS.
 *
 *   node scripts/taxonomy-migration.js status
 *   node scripts/taxonomy-migration.js up
 *   node scripts/taxonomy-migration.js down
 *
 * Safety
 * ------
 * Refuses to run unless the target database name is on the allow-list below.
 * The list is positive: a database that is not named there fails, so a new
 * production cluster cannot be reached by a stale block-list. `Deal-Direct`,
 * the production database name, is deliberately absent, and adding it should be
 * a reviewed change rather than a convenience.
 *
 * Reversibility
 * -------------
 * Every property write records its previous reference state in
 * `taxonomy_migration_log` before the change, keyed by run id. DOWN replays that
 * log and never reconstructs the old values from the mapping table: 25 of the
 * 47 rows carry references that are wrong in ways no rule reproduces, and
 * "restore" means back to the previous state, not back to a better one.
 *
 * Stages 1 and 2 are additive: they insert canonical taxonomy documents and
 * leave the obsolete rows alone. Nothing is deleted here. Destructive cleanup of
 * the six obsolete taxonomy rows and the 48 subcategories is a separate task
 * with its own confirmation.
 *
 * `categoryName` and `propertyTypeName` are never written by either direction.
 * They are the reconstruction input, and a migration that does not modify its
 * own source of truth can always be undone from it.
 */

import mongoose from 'mongoose';
import Category from '../models/Category.js';
import PropertyType from '../models/PropertyType.js';
import Property from '../models/Property.js';
import { CANONICAL_TAXONOMY, mappingFor } from '../config/taxonomy.js';

const ALLOWED_DATABASES = ['dealdirect_dev', 'dealdirect_test'];
const LOG_COLLECTION = 'taxonomy_migration_log';

/**
 * Production is NOT on the allow-list above, and must not be added to it.
 *
 * Adding it would make every future run of this script production-capable by
 * default, including the ones someone fires off against dev without thinking.
 * Instead production requires four separate things to line up, none of which
 * happens by accident:
 *
 *   MIGRATION_TARGET=production
 *   CONFIRM_DATABASE=Deal-Direct
 *   CONFIRM_CLUSTER=dealdirect.rrp09uc
 *   CONFIRM_PRODUCTION_MIGRATION=YES_I_UNDERSTAND
 *
 * The database name and cluster are confirmed against what the connection
 * actually reports, not against what the operator believes, so a correct
 * confirmation aimed at the wrong URI still fails.
 */
const PRODUCTION_DATABASE = 'Deal-Direct';
const PRODUCTION_CLUSTER = 'dealdirect.rrp09uc';
const CONFIRMATION_PHRASE = 'YES_I_UNDERSTAND';

export function assertSafeTarget(connection) {
  const dbName = connection.name;
  const host = String(connection.host || '');

  if (process.env.MIGRATION_TARGET === 'production') {
    return assertProductionTarget(dbName, host);
  }

  // Any non-production run must be on the allow-list, AND must not be pointing
  // at production. Both, because a developer who forgets MIGRATION_TARGET while
  // aimed at production should be stopped by the database name too.
  if (!ALLOWED_DATABASES.includes(dbName)) {
    throw new Error(
      `[taxonomy-migration] Refusing to run against database "${dbName}". ` +
      `Allowed: ${ALLOWED_DATABASES.join(', ')}. ` +
      `For production, set MIGRATION_TARGET=production and the confirmation variables.`
    );
  }
  if (host.includes(PRODUCTION_CLUSTER)) {
    throw new Error(
      `[taxonomy-migration] Database "${dbName}" is allowed, but the connection is on the ` +
      `production cluster. Refusing.`
    );
  }
  return dbName;
}

function assertProductionTarget(dbName, host) {
  const problems = [];

  if (dbName !== PRODUCTION_DATABASE) {
    problems.push(`connected database is "${dbName}", expected "${PRODUCTION_DATABASE}"`);
  }
  if (!host.includes(PRODUCTION_CLUSTER)) {
    problems.push(`connected cluster does not look like "${PRODUCTION_CLUSTER}"`);
  }
  if (process.env.CONFIRM_DATABASE !== PRODUCTION_DATABASE) {
    problems.push(`CONFIRM_DATABASE must be exactly "${PRODUCTION_DATABASE}"`);
  }
  if (process.env.CONFIRM_CLUSTER !== PRODUCTION_CLUSTER) {
    problems.push(`CONFIRM_CLUSTER must be exactly "${PRODUCTION_CLUSTER}"`);
  }
  if (process.env.CONFIRM_PRODUCTION_MIGRATION !== CONFIRMATION_PHRASE) {
    problems.push(`CONFIRM_PRODUCTION_MIGRATION must be exactly "${CONFIRMATION_PHRASE}"`);
  }

  if (problems.length) {
    throw new Error(
      ['[taxonomy-migration] PRODUCTION GATE FAILED:', ...problems.map((p) => `  - ${p}`)].join('\n')
    );
  }
  return dbName;
}

/** Seed canonical categories and property types. Additive and idempotent. */
export async function seedCanonicalTaxonomy() {
  const created = { categories: 0, propertyTypes: 0 };
  const categoryIds = new Map();

  for (const categoryName of Object.keys(CANONICAL_TAXONOMY)) {
    let doc = await Category.findOne({ name: categoryName });
    if (!doc) { doc = await Category.create({ name: categoryName }); created.categories += 1; }
    categoryIds.set(categoryName, doc._id);
  }

  for (const [categoryName, types] of Object.entries(CANONICAL_TAXONOMY)) {
    const category = categoryIds.get(categoryName);
    for (const name of types) {
      const existing = await PropertyType.findOne({ name, category });
      if (!existing) { await PropertyType.create({ name, category }); created.propertyTypes += 1; }
    }
  }

  return { created, categoryIds };
}

/** Resolve the canonical documents a mapping row points at. */
async function resolveTargets() {
  const categories = new Map((await Category.find({}).lean()).map((c) => [c.name, c._id]));
  const types = new Map();
  for (const t of await PropertyType.find({}).lean()) types.set(`${String(t.category)}|${t.name}`, t._id);
  return { categories, types };
}

/**
 * Plan the repoint without writing. Aborts on any pair the table does not
 * cover, rather than guessing.
 */
export async function planRepoint() {
  const { categories, types } = await resolveTargets();
  const properties = await Property.find({}, {
    categoryName: 1, propertyTypeName: 1, category: 1, propertyType: 1, subcategory: 1,
  }).lean();

  const plan = [];
  const unknown = [];

  for (const p of properties) {
    const mapping = mappingFor(p.categoryName, p.propertyTypeName);
    if (!mapping) { unknown.push({ _id: p._id, pair: `${p.categoryName}|${p.propertyTypeName}` }); continue; }

    const categoryId = categories.get(mapping.category);
    const typeId = categoryId ? types.get(`${String(categoryId)}|${mapping.propertyType}`) : undefined;
    if (!categoryId || !typeId) {
      unknown.push({ _id: p._id, pair: `${p.categoryName}|${p.propertyTypeName}`, reason: 'canonical target not seeded' });
      continue;
    }

    plan.push({
      _id: p._id,
      previous: { category: p.category ?? null, propertyType: p.propertyType ?? null, subcategory: p.subcategory ?? null },
      next: { category: categoryId, propertyType: typeId },
      changed: String(p.category ?? '') !== String(categoryId) || String(p.propertyType ?? '') !== String(typeId) || p.subcategory != null,
    });
  }

  return { plan, unknown, total: properties.length };
}

export async function migrateUp({ runId } = {}) {
  const dbName = assertSafeTarget(mongoose.connection);
  const id = runId || `up-${new mongoose.Types.ObjectId()}`;

  const seeded = await seedCanonicalTaxonomy();
  const { plan, unknown, total } = await planRepoint();

  if (unknown.length) {
    throw new Error(
      `[taxonomy-migration] ABORT: ${unknown.length} property(ies) have no mapping. ` +
      `First: ${unknown.slice(0, 3).map((u) => u.pair).join(' | ')}`
    );
  }

  const log = mongoose.connection.db.collection(LOG_COLLECTION);
  let written = 0;

  for (const row of plan) {
    if (!row.changed) continue;
    await log.insertOne({
      migrationBatch: id,
      propertyId: row._id,
      previousCategory: row.previous.category,
      previousPropertyType: row.previous.propertyType,
      previousSubcategory: row.previous.subcategory,
      targetCategory: row.next.category,
      targetPropertyType: row.next.propertyType,
      timestamp: new Date(),
    });
    await Property.updateOne(
      { _id: row._id },
      { $set: { category: row.next.category, propertyType: row.next.propertyType }, $unset: { subcategory: '' } }
    );
    written += 1;
  }

  return { runId: id, database: dbName, seeded: seeded.created, total, planned: plan.length, written };
}

export async function migrateDown({ runId } = {}) {
  const dbName = assertSafeTarget(mongoose.connection);
  const log = mongoose.connection.db.collection(LOG_COLLECTION);

  const batch = runId || (await log.find({}).sort({ timestamp: -1 }).limit(1).toArray())[0]?.migrationBatch;
  if (!batch) return { runId: null, database: dbName, restored: 0, note: 'no migration log found, nothing to roll back' };

  const entries = await log.find({ migrationBatch: batch }).toArray();
  let restored = 0;

  for (const e of entries) {
    const set = {};
    const unset = {};
    // Restore exactly what was there, including null. A property whose refs
    // were null before must be null again, not merely different.
    if (e.previousCategory) set.category = e.previousCategory; else unset.category = '';
    if (e.previousPropertyType) set.propertyType = e.previousPropertyType; else unset.propertyType = '';
    if (e.previousSubcategory) set.subcategory = e.previousSubcategory; else unset.subcategory = '';

    const update = {};
    if (Object.keys(set).length) update.$set = set;
    if (Object.keys(unset).length) update.$unset = unset;
    await Property.updateOne({ _id: e.propertyId }, update);
    restored += 1;
  }

  await log.deleteMany({ migrationBatch: batch });
  return { runId: batch, database: dbName, restored };
}

export async function status() {
  const dbName = mongoose.connection.name;
  const properties = await Property.find({}, { categoryName: 1, propertyTypeName: 1, category: 1, propertyType: 1, subcategory: 1 })
    .populate('category', 'name').populate('propertyType', 'name category').lean();

  let consistent = 0;
  const broken = [];
  for (const p of properties) {
    const okCategory = p.category && p.category.name === p.categoryName;
    const okType = p.propertyType && p.propertyType.name === p.propertyTypeName;
    const okParent = p.category && p.propertyType && String(p.propertyType.category) === String(p.category._id);
    if (okCategory && okType && okParent) consistent += 1;
    else broken.push({ _id: p._id, categoryName: p.categoryName, propertyTypeName: p.propertyTypeName, okCategory, okType, okParent });
  }

  return {
    database: dbName,
    properties: properties.length,
    consistent,
    broken: broken.length,
    nullRefs: properties.filter((p) => !p.category && !p.propertyType).length,
    withSubcategory: properties.filter((p) => p.subcategory).length,
    categories: await Category.countDocuments(),
    propertyTypes: await PropertyType.countDocuments(),
    sample: broken.slice(0, 5),
  };
}

// ---------------------------------------------------------------------------

const isDirect = process.argv[1] && process.argv[1].endsWith('taxonomy-migration.js');
if (isDirect) {
  const command = process.argv[2];
  const dotenv = (await import('dotenv')).default;
  dotenv.config({ quiet: true });

  await mongoose.connect(process.env.MONGO_URI, { serverSelectionTimeoutMS: 20000 });
  console.log(`connected: database=${mongoose.connection.name} host=${mongoose.connection.host}`);

  try {
    if (command === 'up') console.log(JSON.stringify(await migrateUp(), null, 2));
    else if (command === 'down') console.log(JSON.stringify(await migrateDown(), null, 2));
    else if (command === 'status') console.log(JSON.stringify(await status(), null, 2));
    else { console.log('usage: node scripts/taxonomy-migration.js [status|up|down]'); process.exitCode = 1; }
  } catch (err) {
    console.error(String(err.message));
    process.exitCode = 1;
  } finally {
    await mongoose.disconnect();
  }
}
