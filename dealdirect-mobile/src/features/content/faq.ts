/**
 * FAQ content, ported from the website's `client-next/src/app/faq/FAQContent.jsx`.
 *
 * Copy is reproduced rather than rewritten so the two products answer the same
 * question the same way. Two deliberate departures:
 *
 *   - The website's per-category gradients, accent colours and ring colours are
 *     dropped. They are web-page decoration; this renders as a grouped list in
 *     the app's own type and colour.
 *   - The redemption answer is amended. The website's copy still describes
 *     redeeming for "partner vouchers, premium listing boosts, or cashback"
 *     against a dashboard section it no longer ships — its in-house store was
 *     removed on 2026-08-01 and redemption moved into the Hubble SDK. Mobile
 *     has no redemption path at all yet (HANDOFF §9.1 D3), so the answer says
 *     what is true here rather than repeating a claim the app cannot honour.
 *
 * Static, so this is a table rather than a fetch. `GET /blogs` is the only
 * content endpoint the backend has; nothing serves FAQ copy.
 */

export interface FaqEntry {
  q: string;
  a: string;
}

export interface FaqCategory {
  title: string;
  questions: readonly FaqEntry[];
}

export const FAQ_CATEGORIES: readonly FaqCategory[] = [
  {
    title: 'General',
    questions: [
      {
        q: 'What is DealDirect?',
        a: 'DealDirect is a property portal designed to eliminate middlemen. We connect owners, buyers and actual tenants directly, to save you from paying heavy brokerage fees.',
      },
      {
        q: 'Is DealDirect really free from brokers?',
        a: 'Yes. The platform is built with strict filters and a one-post-per-user policy, so only genuine individuals list properties, not agencies.',
      },
    ],
  },
  {
    title: 'Posting & listings',
    questions: [
      {
        q: 'Why can I only post one property?',
        a: 'To keep the platform spam-free and the listings high quality, each account has one active post. This stops brokers flooding the site with duplicates and means every listing comes from a real person.',
      },
      {
        q: 'Can I edit or delete my post?',
        a: 'Yes. You can update your listing or close it as sold or rented at any time from My Listings. Once a post is deleted you are free to post a new one.',
      },
      {
        q: 'How do I make my listing stand out?',
        a: 'Since you only have one post, make it count. Use clear photos, write a detailed description, and be straightforward about the price and what is included.',
      },
    ],
  },
  {
    title: 'Rewards & referrals',
    questions: [
      {
        q: 'How do I earn rewards?',
        a: 'You earn points for taking part: posting a verified property, making genuine enquiries on listings, closing a deal through the platform, and referring friends and family.',
      },
      {
        q: 'How do I refer someone?',
        a: 'Open Rewards from your profile to find your referral code and link. Share it however you like. When someone signs up with it, you both earn points.',
      },
      {
        q: 'What can I do with my points?',
        a: 'Points accumulate in your wallet and move you up the reward tiers, which increase what you earn from every future action. Redeeming points is handled on the DealDirect website for now; the Rewards screen links straight through to it.',
      },
    ],
  },
  {
    title: 'Safety & trust',
    questions: [
      {
        q: 'Is my data safe?',
        a: 'Your contact details are only shared with people you choose to interact with. We never sell your data to third-party telemarketers.',
      },
      {
        q: 'How do I report a suspicious listing?',
        a: 'Open the listing and use Report at the bottom of the page. Every report is reviewed to keep the platform clean.',
      },
    ],
  },
];
