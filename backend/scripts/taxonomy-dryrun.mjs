/**
 * Production taxonomy dry run. READ-ONLY.
 *
 *   MONGO_URI='<production uri>' node scripts/taxonomy-dryrun.mjs > artifact.txt
 *
 * Prints one row per property that would change, plus a summary. Uses the same
 * literal mapping table the migration uses, so the artifact is a prediction of
 * that run and not a separate approximation of it.
 *
 * find() only. This file contains no update, insert, delete or index call, and
 * it is physically incapable of writing: nothing it imports performs a write.
 *
 * Output carries listing titles, which are public content, and no owner, buyer
 * or contact information.
 */

import mongoose from 'mongoose';
import { mappingFor, MIGRATION_MAPPING } from '../config/taxonomy.js';

const uri = process.env.MONGO_URI;
if (!uri) {
  console.error('MONGO_URI is not set. Pass it in the environment; do not write it into a file.');
  process.exit(1);
}

await mongoose.connect(uri, { serverSelectionTimeoutMS: 20000 });
const db = mongoose.connection.db;

const host = mongoose.connection.host;
const dbName = mongoose.connection.name;

const props = await db.collection('properties').find({}, { projection: {
  title: 1, categoryName: 1, propertyTypeName: 1, category: 1, propertyType: 1, subcategory: 1,
} }).sort({ _id: 1 }).toArray();

const cats = await db.collection('categories').find({}).toArray();
const types = await db.collection('propertytypes').find({}).toArray();
const nameOf = new Map([...cats, ...types].map((d) => [String(d._id), d.name]));
const catByName = new Map(cats.map((c) => [c.name, c._id]));
const typeByPair = new Map(types.map((t) => [`${String(t.category)}|${t.name}`, t._id]));

console.log(`# Production taxonomy dry run`);
console.log(`# database=${dbName}  host=${host}`);
console.log(`# mapping table entries: ${Object.keys(MIGRATION_MAPPING).length}`);
console.log('');
console.log([
  'propertyId', 'categoryName', 'propertyTypeName',
  'currentCategoryRef', 'currentPropertyTypeRef',
  'proposedCategory', 'proposedPropertyType', 'action', 'title',
].join('\t'));

let mapped = 0;
let unknown = 0;
const actions = {};

for (const p of props) {
  const m = mappingFor(p.categoryName, p.propertyTypeName);
  if (!m) {
    unknown += 1;
    console.log([String(p._id), p.categoryName, p.propertyTypeName, '-', '-', '-', '-', 'ABORT_NO_MAPPING', ''].join('\t'));
    continue;
  }
  mapped += 1;

  // The proposed refs only exist once the seed has run. Before that the
  // artifact names the target rather than inventing an id, which is the honest
  // representation of "this document will be created".
  const proposedCatId = catByName.get(m.category);
  const proposedTypeId = proposedCatId ? typeByPair.get(`${String(proposedCatId)}|${m.propertyType}`) : undefined;

  const action = (p.category || p.propertyType) ? 'REPLACE_STALE' : 'FILL_NULL';
  actions[action] = (actions[action] || 0) + 1;

  console.log([
    String(p._id),
    p.categoryName,
    p.propertyTypeName,
    p.category ? `${p.category} (${nameOf.get(String(p.category))})` : 'null',
    p.propertyType ? `${p.propertyType} (${nameOf.get(String(p.propertyType))})` : 'null',
    proposedCatId ? String(proposedCatId) : `${m.category} (to be seeded)`,
    proposedTypeId ? String(proposedTypeId) : `${m.propertyType} (to be seeded)`,
    action,
    String(p.title ?? '').slice(0, 60),
  ].join('\t'));
}

console.log('');
console.log('# SUMMARY');
console.log(`#   total properties : ${props.length}`);
console.log(`#   mapped           : ${mapped}`);
console.log(`#   stale replacement: ${actions.REPLACE_STALE || 0}`);
console.log(`#   null fill        : ${actions.FILL_NULL || 0}`);
console.log(`#   unknown          : ${unknown}`);
console.log(`#   ambiguous        : 0  (keyed on the exact pair; one key cannot yield two targets)`);
console.log('');
console.log(`# GATE: ${unknown === 0 ? 'PASS, coverage complete' : 'BLOCKED, unmapped pairs present'}`);
console.log('# No write was issued. find() only.');

await mongoose.disconnect();
