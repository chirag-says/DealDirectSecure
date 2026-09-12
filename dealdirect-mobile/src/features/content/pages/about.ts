import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/about/AboutContent.jsx`. The website's three
 * closing buttons become in-app routes: Browse properties opens the search
 * tab, List your property opens the listing form (which handles the sign-in
 * and one-listing gates itself), and Contact opens the in-app contact page.
 */
export const aboutPage: ContentPage = {
  id: 'about',
  eyebrow: "India's Leading PropTech Platform",
  title: 'About Deal Direct',
  intro:
    '**DealDirect**, a venture by **Agrawal Business Network LLP**, is revolutionizing the way India buys, sells, and rents properties. By connecting you directly with verified property owners, we eliminate middlemen and save you lakhs in brokerage fees — making real estate transactions **transparent, simple, and affordable**.',
  webPath: '/about',
  sections: [
    {
      id: 'metrics',
      blocks: [
        {
          type: 'stats',
          items: [
            { value: '₹50Cr+', label: 'Brokerage saved' },
            { value: '10,000+', label: 'Happy families' },
            { value: '12+', label: 'Cities covered' },
            { value: '100%', label: 'Verified listings' },
          ],
        },
      ],
    },
    {
      id: 'story',
      title: 'Born from a Simple Question: Why Pay Brokerage?',
      blurb: 'Our story',
      icon: 'home-outline',
      blocks: [
        {
          type: 'paragraph',
          text: '**Agrawal Business Network LLP** founded Deal Direct with a clear mission — to disrupt the traditional real estate brokerage model that has burdened Indian homebuyers and sellers for decades.',
        },
        {
          type: 'paragraph',
          text: 'We realized that in an age of digital connectivity, paying 1-2% brokerage (often lakhs of rupees!) to a middleman was outdated. Property owners and buyers should be able to connect directly.',
        },
        {
          type: 'paragraph',
          text: "Today, we're proud to be India's fastest-growing PropTech platform, having helped thousands of families find their dream homes while saving them crores in brokerage fees.",
        },
        { type: 'heading', text: 'Our Mission' },
        {
          type: 'quote',
          text: 'To make property transactions in India completely brokerage-free, transparent, and accessible to everyone — regardless of where they are or how much they have.',
        },
      ],
    },
    {
      id: 'advantage',
      title: 'The Deal Direct Advantage',
      blurb: "We're not just another property listing site. Here's what makes us different.",
      icon: 'sparkles-outline',
      blocks: [
        {
          type: 'cards',
          items: [
            {
              icon: 'shield-checkmark-outline',
              title: '100% Verified Owners',
              text: 'Every property listing is verified. We ensure you deal only with genuine owners — no brokers, no fraud.',
            },
            {
              icon: 'hand-left-outline',
              title: 'Zero Brokerage',
              text: 'Connect directly with owners and save lakhs in brokerage fees. Your money stays in your pocket.',
            },
            {
              icon: 'trending-up-outline',
              title: 'Smart Insights',
              text: 'Get market trends, price history, and locality data to make informed property decisions.',
            },
            {
              icon: 'headset-outline',
              title: '24/7 Support',
              text: 'Our dedicated support team is always ready to help you through your property journey.',
            },
          ],
        },
      ],
    },
    {
      id: 'how-it-works',
      title: 'How Deal Direct Works',
      blurb: 'Real estate, reimagined',
      icon: 'construct-outline',
      blocks: [
        {
          type: 'paragraph',
          text: "Most property portals are built for brokers. Deal Direct is built for **you**. We've stripped away the noise, the spam, and the expensive commissions to create a marketplace based on **transparency and rewards**.",
        },
        {
          type: 'cards',
          items: [
            {
              icon: 'shield-outline',
              title: 'The Power of "One"',
              meta: 'Anti-spam policy',
              text: 'To ensure every listing is **high-quality and genuine**, we enforce a **Strict 1-Post Per User** rule.\n\n**Why?** This prevents brokers from flooding the site with duplicate listings.\n\n**The Result:** Every property you see is from the actual owner or primary decision-maker. No clutter, just real options.',
            },
            {
              icon: 'cash-outline',
              title: 'Connect Directly, Save Lacs',
              meta: 'Zero brokerage',
              text: 'We believe that finding a home shouldn\'t cost you a fortune in "introduction fees."\n\n**Direct Communication:** Browse, chat, and negotiate directly with owners, buyers, or actual tenants.\n\n**Zero Brokerage:** Save anywhere from ₹50,000 to ₹5,00,000+ in brokerage fees depending on your deal size.',
            },
            {
              icon: 'gift-outline',
              title: 'Participate & Get Rewarded',
              meta: 'Earn at every step',
              text: 'Unlike other sites that just take your data, we **value your engagement**. Our ecosystem rewards you at every step:\n\n**Post a Property:** Earn rewards just for listing your space.\n\n**Make Enquiries:** Get credited for being an active seeker.\n\n**Close the Deal:** We celebrate your success with special rewards once your transaction is complete.',
            },
            {
              icon: 'people-outline',
              title: 'Grow the Community',
              meta: 'Referral rewards',
              text: "Know someone looking to buy, sell, or rent? **Refer them to Deal Direct!**\n\nWhen your friends join and use the platform, **you get rewarded**.\n\nIt's our way of building a **community of trust** where everyone wins.",
            },
          ],
        },
      ],
    },
    {
      id: 'vision',
      title: 'Building a Brokerage-Free India',
      icon: 'flag-outline',
      blocks: [
        {
          type: 'paragraph',
          text: "We envision a future where every Indian can buy, sell, or rent property without paying a single rupee in brokerage. Through technology, transparency, and trust, we're making this vision a reality — one transaction at a time.",
        },
        {
          type: 'tags',
          items: [
            'Transparent Pricing',
            'No Hidden Fees',
            'Verified Listings',
            'Direct Connections',
            'Secure Platform',
          ],
        },
      ],
    },
    {
      id: 'cta',
      title: 'Ready to Find Your Dream Home?',
      blocks: [
        {
          type: 'paragraph',
          text: 'Join thousands of happy families who found their perfect property through Deal Direct — without paying any brokerage.',
        },
        {
          type: 'actions',
          items: [
            { label: 'Browse properties', href: '/(tabs)/search', variant: 'primary' },
            { label: 'List your property', href: '/owner/property/new', variant: 'secondary' },
            { label: 'Contact us', href: '/legal/contact', variant: 'secondary' },
          ],
        },
      ],
    },
  ],
};
