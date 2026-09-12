import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/why-us/WhyUsContent.jsx`, revenue model and
 * price bands included. Those are the website's forward-looking statements
 * ("here is exactly how we plan to earn"); they are reproduced, not endorsed.
 */
export const whyUsPage: ContentPage = {
  id: 'why-us',
  eyebrow: 'About',
  title: 'Why DealDirect?',
  intro:
    'We built DealDirect to make property transactions simple, transparent, and fair for both owners and seekers. No middlemen, no hidden charges – just clean, data-driven matchmaking.',
  webPath: '/why-us',
  sections: [
    {
      id: 'pillars',
      blocks: [
        {
          type: 'cards',
          items: [
            {
              icon: 'people-outline',
              title: 'Direct, No-Broker Model',
              text: 'Connect directly with verified owners and genuine tenants/buyers. Save on hefty brokerage and have full control over your conversations and decisions.',
            },
            {
              icon: 'search-outline',
              title: 'Smart Search & Alerts',
              text: 'Powerful filters, saved searches, and instant alerts help you find the right property faster – whether you are buying, renting, or exploring investment options.',
            },
            {
              icon: 'shield-checkmark-outline',
              title: 'Trust & Transparency',
              text: 'From detailed listings and rich media to agreement tools and notifications, we keep every step clear so you can make confident decisions.',
            },
          ],
        },
      ],
    },
    {
      id: 'for-whom',
      title: 'Built for both sides',
      icon: 'swap-horizontal-outline',
      blocks: [
        { type: 'heading', text: 'For Property Owners' },
        {
          type: 'paragraph',
          text: 'List your property in minutes, manage enquiries from a single dashboard, and get notified when serious leads show interest. You stay in control from listing to closing.',
        },
        { type: 'heading', text: 'For Seekers' },
        {
          type: 'paragraph',
          text: 'Explore curated listings, compare options, save favourites, and receive updates when new properties match your preferences.',
        },
      ],
    },
    {
      id: 'revenue',
      title: 'Simple, Transparent Revenue Model',
      icon: 'cash-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'DealDirect is designed so that the core experience stays accessible while power users and partners pay for advanced value. Here is exactly how we plan to earn, without compromising trust between owners and seekers.',
        },
        {
          type: 'cards',
          items: [
            {
              title: '1. Freemium Listings',
              meta: 'Who pays: Property Owners',
              text: 'Basic listings stay **free** so any owner can get started. Paid tiers boost visibility in search results and highlight serious, well-presented listings.',
              footnote: 'Pricing: Free → ₹299 → ₹999 per listing',
            },
            {
              title: '2. Owner Subscription Plans',
              meta: 'Who pays: Property Owners',
              text: 'Power owners and builders can unlock dashboards, deeper lead insights, bulk listing tools, and campaign style promotion with simple monthly plans.',
              footnote: 'Pricing: ₹499 / ₹1,499 / ₹4,999 per month',
            },
            {
              title: '3. Lead Packs (No-Broker)',
              meta: 'Who pays: Owners',
              text: 'Owners can purchase verified, intent-based buyer or tenant contacts, with clear tracking from first enquiry to closure.',
              footnote: 'Pricing: Rent ₹20–₹50/lead • Sale ₹100–₹200/lead',
            },
            {
              title: '4. DealSuccess Fee (Optional)',
              meta: 'Who pays: Owners (on successful deal)',
              text: 'For owners who want extra handholding, we may charge a small success fee only when a deal closes through DealDirect. No closure, no fee.',
              footnote: 'Pricing: Rent 10–20% of 1-month rent • Sale 0.5%',
            },
            {
              title: '5. Home Services Marketplace',
              meta: 'Who pays: Service Providers',
              text: 'Movers, cleaners, painting, interiors and more – we partner with trusted vendors and charge them a commission for confirmed jobs, not the end user.',
              footnote: 'Pricing: 15–25% commission on service value',
            },
            {
              title: '6. Loan & Finance Partnerships',
              meta: 'Who pays: Partner Banks/NBFCs',
              text: 'When buyers opt to explore home loans, we may pass qualified leads to partner institutions and earn a fee per approved loan.',
              footnote: 'Pricing: ~₹1,000–₹4,000 per approved loan',
            },
            {
              title: '7. Smart, Non-Intrusive Ads',
              meta: 'Who pays: Brands & Service Providers',
              text: 'Selective project promotions, banners and featured slots for developers and home service brands – always labelled, never mixed with organic results.',
              footnote: 'Pricing: ~₹15,000–₹50,000 per month',
            },
            {
              title: '8. Verification & Screening',
              meta: 'Who pays: Owners / Tenants',
              text: 'Optional verification checks – from owner KYC and document validation to tenant screening – to build more trust into every interaction.',
              footnote: 'Pricing: ~₹249–₹699 per verification',
            },
            {
              title: '9. Premium Tools for Seekers',
              meta: 'Who pays: Buyers / Tenants',
              text: 'Advanced features like granular price alerts, smart saved searches, neighbourhood insights and affordability calculators will be available as small add-ons.',
              footnote: 'Pricing: ~₹49–₹99 per premium feature',
            },
            {
              title: '10. Home Discovery Add-ons',
              meta: 'Who pays: Owners',
              text: 'Rich media experiences – virtual tours, 3D walkthroughs, drone videos and more – that help serious buyers experience the property before stepping in.',
              footnote: 'Pricing: ~₹499–₹2,999 per shoot',
            },
          ],
        },
      ],
    },
    {
      id: 'evolving',
      blocks: [
        {
          type: 'callout',
          tone: 'neutral',
          text: 'DealDirect is continuously evolving – we ship new features often, based on real user feedback. If you have suggestions, we would love to hear from you via the Contact page.',
        },
        {
          type: 'actions',
          items: [{ label: 'Contact us', href: '/legal/contact', variant: 'secondary' }],
        },
      ],
    },
  ],
};
