import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/faq/faqData.js`: same categories, same ids,
 * same wording. That file is the one `pages.test.ts` reads back when the
 * website checkout is beside this one, so a question changed on the website
 * and not here fails the suite rather than drifting quietly.
 */
export const faqPage: ContentPage = {
  id: 'faq',
  eyebrow: 'Help',
  title: 'Questions, answered',
  intro: 'What DealDirect is, how listings work, and what your points are worth.',
  webPath: '/faq',
  sections: [
    {
      id: 'general',
      title: 'General',
      blurb: 'What DealDirect is and how it stays broker-free.',
      icon: 'business-outline',
      blocks: [
        {
          type: 'faq',
          items: [
            {
              id: 'what-is-deal-direct',
              question: 'What is Deal Direct?',
              answer:
                'Deal Direct is a property portal built to remove the middleman. Owners, buyers and tenants deal with each other directly, so nobody pays brokerage.',
            },
            {
              id: 'really-broker-free',
              question: 'Is Deal Direct really free from brokers?',
              answer:
                'Yes. Listings pass through filters and a one-post-per-user rule, so the people posting are individuals rather than agencies.',
            },
          ],
        },
      ],
    },
    {
      id: 'listings',
      title: 'Posting & Listings',
      blurb: 'Rules for putting a property on the site.',
      icon: 'list-outline',
      blocks: [
        {
          type: 'faq',
          items: [
            {
              id: 'one-property-only',
              question: 'Why can I only post one property?',
              answer:
                'One active post per user keeps the site free of duplicates and bulk broker uploads. It also means every listing you see came from a real person with a real property.',
            },
            {
              id: 'edit-or-delete',
              question: 'Can I edit or delete my post?',
              answer:
                'Any time, from your dashboard. Update the details, or mark it Sold or Rented. Deleting a post frees you to publish a new one.',
            },
            {
              id: 'stand-out',
              question: 'How do I make my listing stand out?',
              answer:
                'You get one post, so make it count. Add sharp, well-lit photos, write a specific description, and state the price and amenities plainly.',
            },
          ],
        },
      ],
    },
    {
      id: 'rewards',
      title: 'Rewards & Referrals',
      blurb: 'How points are earned, and what they are worth.',
      icon: 'gift-outline',
      blocks: [
        {
          type: 'faq',
          items: [
            {
              id: 'how-to-earn',
              question: 'How do I earn rewards on Deal Direct?',
              answer:
                'Four ways: post a verified property, send a genuine enquiry on a listing, close a deal through the platform, or refer someone who signs up.',
            },
            {
              id: 'how-to-refer',
              question: 'How do I refer someone?',
              answer:
                'Your Rewards tab holds a referral link that is unique to you. Share it however you like. When someone signs up through it, you both earn.',
            },
            {
              id: 'point-value',
              question: 'What can I do with my reward points?',
              answer:
                'Redeem them for partner vouchers, premium listing boosts, or cashback. Your dashboard lists the current options.',
            },
          ],
        },
      ],
    },
    {
      id: 'safety',
      title: 'Safety & Trust',
      blurb: 'What happens to your data, and how to report a listing.',
      icon: 'lock-closed-outline',
      blocks: [
        {
          type: 'faq',
          items: [
            {
              id: 'data-safety',
              question: 'Is my data safe?',
              answer:
                'Your contact details go only to users you choose to interact with. We do not sell your data to third-party telemarketers.',
            },
            {
              id: 'report-listing',
              question: 'How do I report a suspicious listing?',
              answer:
                'Use the Report button on the listing page. Every report is reviewed within 24 hours.',
            },
          ],
        },
      ],
    },
  ],
};
