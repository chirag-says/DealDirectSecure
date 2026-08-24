import type { EntityMatch, TransactionType } from './types.ts';
import { wordBoundaryTest } from './propertyType.ts';

/**
 * Stage — buy or rent.
 *
 * ---------------------------------------------------------------------------
 * "RENTAL INCOME" MEANS BUY
 *
 * This is the ambiguity that matters most, because getting it wrong inverts the
 * result set. A user who types "property for rental income" or "good rental
 * yield" is an INVESTOR: they intend to purchase something and let it out. A
 * naive `/rent/` match reads the word "rental" and shows them rentals, which is
 * the exact opposite of what they asked for and looks like the app cannot read.
 *
 * So investment phrases are tested FIRST and, when one is present, it decides
 * the transaction and the rent vocabulary is not consulted at all. The same
 * applies to "buy to let" and "rental yield".
 *
 * The reverse trap exists too and is handled by the same ordering: "renting out
 * my flat" is an owner listing, not a search, and is left unresolved rather
 * than guessed.
 */

/**
 * Phrases where a rent-shaped word describes the RETURN on a purchase.
 *
 * Ordered longest-first for the same reason the type vocabulary is: a shorter
 * phrase must never pre-empt a longer one that contains it.
 */
const INVESTMENT_PHRASES: readonly string[] = [
  'property for rental income',
  'suitable for rental income',
  'buy to let',
  'buy-to-let',
  'rental income',
  'rental yield',
  'rental return',
  'rental returns',
  'investment property',
  'investment purpose',
  'for investment',
  'rent out',
  'renting out',
  'let out',
].sort((a, b) => b.length - a.length);

const RENT_WORDS: readonly string[] = [
  'rent',
  'rental',
  'rentals',
  'renting',
  'lease',
  'leasing',
  'leased',
  'tenant',
  'tenants',
  'to let',
  'pg',
];

const BUY_WORDS: readonly string[] = [
  'buy',
  'buying',
  'purchase',
  'purchasing',
  'sale',
  'for sale',
  'resale',
  'own',
  'ownership',
  'invest',
  'investment',
  'investing',
];

export interface TransactionResult {
  transaction?: TransactionType;
  matches: EntityMatch[];
  consumed: string[];
  /** True when an investment phrase decided this, so the caller can tag it. */
  investment: boolean;
}

export function extractTransaction(text: string): TransactionResult {
  // 1. Investment phrasing wins outright. See the module doc.
  for (const phrase of INVESTMENT_PHRASES) {
    if (wordBoundaryTest(text, phrase)) {
      return {
        transaction: 'sale',
        matches: [{ kind: 'transaction', text: phrase, label: 'To buy' }],
        consumed: [phrase],
        investment: true,
      };
    }
  }

  // 2. Explicit rent vocabulary.
  const rent = RENT_WORDS.find((word) => wordBoundaryTest(text, word));
  // 3. Explicit buy vocabulary.
  const buy = BUY_WORDS.find((word) => wordBoundaryTest(text, word));

  /*
    Both present and neither an investment phrase: unresolved on purpose.
    "buy or rent a 2 bhk" is a real query and answering it with either half is
    worse than answering it with both, which is what leaving this undefined
    does.
  */
  if (rent && buy) return { matches: [], consumed: [], investment: false };

  if (rent) {
    return {
      transaction: 'rent',
      matches: [{ kind: 'transaction', text: rent, label: 'To rent' }],
      consumed: [rent],
      investment: false,
    };
  }

  if (buy) {
    return {
      transaction: 'sale',
      matches: [{ kind: 'transaction', text: buy, label: 'To buy' }],
      consumed: [buy],
      investment: /invest/.test(buy),
    };
  }

  /*
    Nothing stated. Deliberately NOT defaulted to sale.

    Roughly two thirds of this corpus is rental, so defaulting to sale would
    hide most of the inventory from every query that does not say "rent" —
    including "2 bhk in Bandra", where the user plainly wants to see both.
  */
  return { matches: [], consumed: [], investment: false };
}
