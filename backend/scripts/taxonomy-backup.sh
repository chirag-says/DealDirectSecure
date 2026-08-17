#!/usr/bin/env bash
#
# Independent pre-migration backup of the production taxonomy and property refs.
#
#   MONGO_URI='<production uri>' bash scripts/taxonomy-backup.sh
#
# READ-ONLY at the source. mongodump reads; it cannot write to what it reads.
#
# This is the second of two rollback mechanisms and the only one that does not
# depend on the migration completing. The first is the migration log, which is
# written inside the run: if the run dies halfway, that log describes only the
# rows it reached. This archive is taken before anything starts, so it covers
# every row regardless of how the run ends.
#
# Nothing is written inside the repository. The archive lands outside it, because
# it contains a copy of production data.

set -euo pipefail

TOOLS="${MONGO_TOOLS:-/c/Program Files/MongoDB/Tools/100/bin}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${BACKUP_DIR:-$HOME/dealdirect-taxonomy-backup-$STAMP}"

COLLECTIONS=(properties categories propertytypes subcategories)

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------

if [[ -z "${MONGO_URI:-}" ]]; then
  echo "ERROR: MONGO_URI is not set. Pass the production URI in the environment;" >&2
  echo "       it must not be written into a file in this repository." >&2
  exit 1
fi

# Confirm the target before dumping. A backup of the wrong database is worse
# than no backup, because it looks like one.
HOST="$(node -e 'const u=process.env.MONGO_URI;const m=u.match(/^mongodb(?:\+srv)?:\/\/(?:[^@]*@)?([^\/?]+)/);console.log(m?m[1]:"")')"
DB="$(node -e 'const u=process.env.MONGO_URI;const m=u.match(/^mongodb(?:\+srv)?:\/\/(?:[^@]*@)?[^\/?]+\/([^?]*)/);console.log(m?m[1]:"")')"

echo "target host : $HOST"
echo "target db   : $DB"

if [[ "$DB" != "Deal-Direct" ]]; then
  echo "ERROR: expected database 'Deal-Direct', got '$DB'. Refusing." >&2
  exit 1
fi
if [[ "$HOST" != *"dealdirect.rrp09uc"* ]]; then
  echo "ERROR: expected the production cluster 'dealdirect.rrp09uc', got '$HOST'. Refusing." >&2
  exit 1
fi
case "$OUT" in
  */DD-CLONE/DealDirectSecure*) echo "ERROR: backup path is inside the repository. Refusing." >&2; exit 1 ;;
esac

# ---------------------------------------------------------------------------
# Dump
# ---------------------------------------------------------------------------

mkdir -p "$OUT"
echo "writing to  : $OUT"

for c in "${COLLECTIONS[@]}"; do
  "$TOOLS/mongodump" --uri="$MONGO_URI" --collection="$c" --out="$OUT/dump" --quiet
  echo "  dumped $c"
done

# ---------------------------------------------------------------------------
# Verify the archive is real
# ---------------------------------------------------------------------------

DUMPDIR="$OUT/dump/$DB"
FAIL=0

for c in "${COLLECTIONS[@]}"; do
  BSON="$DUMPDIR/$c.bson"
  META="$DUMPDIR/$c.metadata.json"
  if [[ ! -s "$BSON" ]]; then echo "  MISSING OR EMPTY: $c.bson" >&2; FAIL=1; continue; fi
  if [[ ! -s "$META" ]]; then echo "  MISSING metadata: $c.metadata.json" >&2; FAIL=1; continue; fi
  echo "  verified $c  ($(wc -c < "$BSON") bytes, indexes preserved in metadata)"
done

[[ $FAIL -eq 0 ]] || { echo "BACKUP FAILED VERIFICATION" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Manifest and checksums
# ---------------------------------------------------------------------------

MANIFEST="$OUT/manifest.txt"
{
  echo "DealDirect taxonomy pre-migration backup"
  echo "taken     : $STAMP"
  echo "host      : $HOST"
  echo "database  : $DB"
  echo "collections: ${COLLECTIONS[*]}"
  echo ""
  echo "document counts at dump time:"
  MONGO_URI="$MONGO_URI" node -e '
    const { MongoClient } = require("mongodb");
    (async () => {
      const c = new MongoClient(process.env.MONGO_URI);
      await c.connect();
      const db = c.db();
      for (const n of ["properties","categories","propertytypes","subcategories"]) {
        console.log("  " + String(await db.collection(n).countDocuments()).padStart(6) + "  " + n);
      }
      const p = await db.collection("properties").find({}, { projection: { category: 1, propertyType: 1 } }).toArray();
      console.log("  refs: " + p.filter(x => x.category || x.propertyType).length + " with-ref, "
        + p.filter(x => !x.category && !x.propertyType).length + " null");
      await c.close();
    })();
  '
  echo ""
  echo "sha256:"
  ( cd "$OUT/dump" && find . -type f -print0 | sort -z | xargs -0 sha256sum )
} > "$MANIFEST"

echo ""
echo "manifest  : $MANIFEST"
sha256sum "$MANIFEST" | sed 's/^/manifest sha256: /'
echo ""
echo "BACKUP COMPLETE. Retain until the migration is verified in production and"
echo "for 30 days afterwards, then delete: it is a copy of production data."
