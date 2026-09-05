/**
 * FAQ content, kept free of JSX so the server component can import it too.
 *
 * page.js uses this to emit FAQPage structured data; FAQContent.jsx renders it.
 * Both read the same source, so the rich result can never drift from the page.
 * `icon` is a key into the icon map in FAQContent — not a component — because a
 * server component cannot serialise one across the boundary.
 */

export const faqCategories = [
    {
        id: 'general',
        title: 'General',
        blurb: 'What DealDirect is and how it stays broker-free.',
        icon: 'building',
        questions: [
            {
                id: 'what-is-deal-direct',
                q: 'What is Deal Direct?',
                a: 'Deal Direct is a property portal built to remove the middleman. Owners, buyers and tenants deal with each other directly, so nobody pays brokerage.',
            },
            {
                id: 'really-broker-free',
                q: 'Is Deal Direct really free from brokers?',
                a: 'Yes. Listings pass through filters and a one-post-per-user rule, so the people posting are individuals rather than agencies.',
            },
        ],
    },
    {
        id: 'listings',
        title: 'Posting & Listings',
        blurb: 'Rules for putting a property on the site.',
        icon: 'list',
        questions: [
            {
                id: 'one-property-only',
                q: 'Why can I only post one property?',
                a: 'One active post per user keeps the site free of duplicates and bulk broker uploads. It also means every listing you see came from a real person with a real property.',
            },
            {
                id: 'edit-or-delete',
                q: 'Can I edit or delete my post?',
                a: 'Any time, from your dashboard. Update the details, or mark it Sold or Rented. Deleting a post frees you to publish a new one.',
            },
            {
                id: 'stand-out',
                q: 'How do I make my listing stand out?',
                a: 'You get one post, so make it count. Add sharp, well-lit photos, write a specific description, and state the price and amenities plainly.',
            },
        ],
    },
    {
        id: 'rewards',
        title: 'Rewards & Referrals',
        blurb: 'How points are earned, and what they are worth.',
        icon: 'gift',
        questions: [
            {
                id: 'how-to-earn',
                q: 'How do I earn rewards on Deal Direct?',
                a: 'Four ways: post a verified property, send a genuine enquiry on a listing, close a deal through the platform, or refer someone who signs up.',
            },
            {
                id: 'how-to-refer',
                q: 'How do I refer someone?',
                a: 'Your Rewards tab holds a referral link that is unique to you. Share it however you like. When someone signs up through it, you both earn.',
            },
            {
                id: 'point-value',
                q: 'What can I do with my reward points?',
                a: 'Redeem them for partner vouchers, premium listing boosts, or cashback. Your dashboard lists the current options.',
            },
        ],
    },
    {
        id: 'safety',
        title: 'Safety & Trust',
        blurb: 'What happens to your data, and how to report a listing.',
        icon: 'lock',
        questions: [
            {
                id: 'data-safety',
                q: 'Is my data safe?',
                a: 'Your contact details go only to users you choose to interact with. We do not sell your data to third-party telemarketers.',
            },
            {
                id: 'report-listing',
                q: 'How do I report a suspicious listing?',
                a: 'Use the Report button on the listing page. Every report is reviewed within 24 hours.',
            },
        ],
    },
];

/** Flattened list, for the JSON-LD FAQPage schema and for search. */
export const allFaqs = faqCategories.flatMap((cat) =>
    cat.questions.map((item) => ({
        ...item,
        categoryId: cat.id,
        categoryTitle: cat.title,
    }))
);
