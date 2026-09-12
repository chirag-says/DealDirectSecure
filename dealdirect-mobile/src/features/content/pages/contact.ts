// Explicit `.ts`: the page files are imported by `pages.test.ts` under
// `node --test`, which resolves ES modules by exact specifier. Same convention
// as `src/analytics`; see the note in tsconfig.json.
import { SUPPORT_CONTACT } from '../support.ts';
import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/contact/ContactContent.jsx` — the static half.
 * The message form is `components/ContactForm.tsx`, rendered under this by
 * `app/legal/contact.tsx`, because a form needs auth state and a mutation and
 * this file is data.
 *
 * ONE DELIBERATE DEPARTURE. The website's contact page shows
 * "+91 98765 43210", "+91 22 1234 5678", support@ and business@dealdirect.in.
 * The first two are sequential-digit placeholders, and neither address appears
 * anywhere else: the footer, the privacy policy and the terms all give
 * +91 92-8963 8963 and contact@ / grievance@dealdirect.in. This page uses the
 * numbers the rest of the site agrees on (`SUPPORT_CONTACT`). The website
 * should be corrected to match; until it is, this is the one page whose copy
 * is not verbatim.
 */
export const contactPage: ContentPage = {
  id: 'contact',
  eyebrow: 'Support',
  title: 'Get in touch',
  intro:
    "Whether you're a buyer, seller, or just have a question, our team is here to help you navigate your property journey. We generally respond within 2 hours during business days.",
  webPath: '/contact',
  sections: [
    {
      id: 'office',
      title: 'Contact information',
      icon: 'business-outline',
      blocks: [
        {
          type: 'contact',
          org: 'Agrawal Business Network LLP',
          role: 'Corporate office',
          address: 'Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210',
          phone: SUPPORT_CONTACT.phone,
          email: SUPPORT_CONTACT.email,
        },
      ],
    },
    {
      id: 'hours',
      blocks: [
        {
          type: 'cards',
          items: [
            {
              icon: 'time-outline',
              title: 'Operating hours',
              text: 'Mon - Sat: 9:00 AM - 8:00 PM',
            },
            {
              icon: 'headset-outline',
              title: 'Direct support',
              text: 'Dedicated team for premium listings',
            },
            {
              icon: 'business-outline',
              title: 'Office visits',
              text: 'By appointment only',
            },
          ],
        },
      ],
    },
  ],
};
