import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/rewards/terms/RewardsTermsContent.jsx`.
 *
 * The website prints "Last updated" as TODAY's month, computed at render time,
 * which says nothing about when the text last changed. No `meta` here rather
 * than a date that is not one.
 */
export const rewardsTermsPage: ContentPage = {
  id: 'rewards-terms',
  eyebrow: 'Legal',
  title: 'Rewards terms',
  intro:
    'At Deal Direct, we believe in rewarding genuine engagement. Our rewards program is designed to build a high-quality, broker-free community. To keep the ecosystem fair for everyone, the following terms apply:',
  webPath: '/rewards/terms',
  sections: [
    {
      id: 'earning',
      title: '1. Earning Rewards',
      icon: 'gift-outline',
      blocks: [
        { type: 'heading', text: 'Property Posting' },
        {
          type: 'paragraph',
          text: 'Rewards are credited once a listing is verified as a "Direct Owner" or "Direct Tenant" post.',
        },
        { type: 'heading', text: 'Making Enquiries' },
        {
          type: 'paragraph',
          text: 'Rewards are granted for genuine inquiries. To prevent "spam-clicking," rewards are capped at a specific number of unique inquiries per day.',
        },
        { type: 'heading', text: 'Closing a Deal' },
        {
          type: 'paragraph',
          text: 'Milestone rewards are released once both parties confirm a successful transaction through the portal.',
        },
        { type: 'heading', text: 'Referrals' },
        {
          type: 'paragraph',
          text: 'Referral rewards are credited only after the referred user completes their profile and makes their first verified post or inquiry.',
        },
      ],
    },
    {
      id: 'guardrails',
      title: '2. The "Anti-Broker" & Anti-Spam Guardrails',
      icon: 'shield-checkmark-outline',
      blocks: [
        { type: 'heading', text: 'The Power of One' },
        {
          type: 'paragraph',
          text: 'Our platform strictly enforces a **1-listing-per-user** limit. Attempting to create multiple accounts to bypass this limit will result in a permanent ban and forfeiture of all accumulated rewards.',
        },
        { type: 'heading', text: 'Verification' },
        {
          type: 'paragraph',
          text: 'We reserve the right to verify any listing. If a post is found to be uploaded by a broker or agency, the post will be removed immediately.',
        },
      ],
    },
    {
      id: 'redemption',
      title: '3. Redemption & Validity',
      icon: 'wallet-outline',
      blocks: [
        { type: 'heading', text: 'Non-Transferable' },
        {
          type: 'paragraph',
          text: 'Rewards earned on DealDirect.in are tied to your specific account and cannot be transferred to other users.',
        },
        { type: 'heading', text: 'Expiry' },
        {
          type: 'paragraph',
          text: 'Rewards may have an expiration period (e.g., 12 months) from the date of credit.',
        },
        { type: 'heading', text: 'Platform Rights' },
        {
          type: 'paragraph',
          text: 'Deal Direct reserves the right to modify the reward values or redemption methods to ensure the sustainability of the platform.',
        },
      ],
    },
    {
      id: 'misuse',
      title: 'Zero Tolerance for Misuse',
      icon: 'ban-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'Any attempt to "game" the system (using bots, fake accounts, or fraudulent enquiries) will lead to an immediate account audit.',
        },
        {
          type: 'callout',
          tone: 'success',
          text: 'We value real people making real deals.',
        },
      ],
    },
  ],
};
