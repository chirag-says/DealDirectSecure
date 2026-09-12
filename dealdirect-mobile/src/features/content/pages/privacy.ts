import type { ContentPage } from './model';

/**
 * Mirrors `client-next/src/app/privacy/PrivacyContent.jsx`. Copy is verbatim;
 * a change there must be made here in the same commit.
 */
export const privacyPage: ContentPage = {
  id: 'privacy',
  eyebrow: 'Legal',
  title: 'Privacy Policy',
  intro:
    'At DealDirect, operated by **Agrawal Business Network LLP**, we value your trust. This policy outlines how we collect, use, and protect your information on our B2B platform.',
  meta: 'Last updated: February 2026',
  webPath: '/privacy',
  sections: [
    {
      id: 'introduction',
      title: 'Introduction',
      icon: 'shield-checkmark-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'Welcome to **DealDirect**, a venture by **Agrawal Business Network LLP**. This Privacy Policy is published in accordance with the provisions of the Information Technology Act, 2000, the Information Technology (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules, 2011, and the IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021.',
        },
        {
          type: 'paragraph',
          text: 'This policy explains how we collect, use, disclose, and safeguard your information when you visit our website (**www.dealdirect.in**), use our mobile application, or engage with our B2B services. By using DealDirect, you consent to the data practices described in this policy.',
        },
        {
          type: 'paragraph',
          text: 'The Platform is a **business-to-business (B2B)** platform. All data collection is done in the context of commercial/business use.',
        },
      ],
    },
    {
      id: 'information-collection',
      title: 'Information We Collect',
      icon: 'document-text-outline',
      blocks: [
        { type: 'heading', text: '1. Business & Identity Information' },
        {
          type: 'bullets',
          items: [
            '**Registration Data:** Business name, entity type, name, email, phone number, business address.',
            '**Verification Data:** PAN, Aadhaar, GST registration number, and other documents as required for account verification.',
            '**Bank Details:** Bank account information for payment settlement purposes.',
          ],
        },
        { type: 'heading', text: '2. Transaction Data' },
        {
          type: 'paragraph',
          text: 'Order details, product listings, payment history, invoices, delivery notes, and settlement records.',
        },
        { type: 'heading', text: '3. Communications' },
        {
          type: 'paragraph',
          text: 'Messages exchanged between Buyers and Sellers via the Platform, support tickets, and grievance submissions.',
        },
        { type: 'heading', text: '4. Technical Data' },
        {
          type: 'paragraph',
          text: 'IP address, browser type, device information, access times, pages viewed, and referring URL.',
        },
      ],
    },
    {
      id: 'data-usage',
      title: 'How We Use Your Data',
      icon: 'server-outline',
      blocks: [
        {
          type: 'cards',
          items: [
            {
              title: 'Account Management',
              text: 'To register and manage your account, verify identity, and maintain your business profile on the Platform.',
            },
            {
              title: 'Order Fulfilment',
              text: 'To process orders, manage logistics, coordinate deliveries, handle payments and settlements between Buyers and Sellers.',
            },
            {
              title: 'Communication',
              text: 'To send OTPs, order confirmations, delivery updates, payment notifications via email, SMS, WhatsApp, or in-app notifications.',
            },
            {
              title: 'Legal & Tax Compliance',
              text: 'To comply with GST, TDS/TCS obligations, and other regulatory requirements under Indian law.',
            },
            {
              title: 'Platform Improvement',
              text: 'To analyse usage patterns, improve services, develop new features, and enhance user experience.',
            },
            {
              title: 'Security & Fraud Prevention',
              text: 'To detect and prevent fraud, unauthorized access, and other illegal activities on the Platform.',
            },
          ],
        },
      ],
    },
    {
      id: 'data-sharing',
      title: 'Data Sharing & Disclosure',
      icon: 'share-social-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'We do not sell your personal data. However, we may share data in the following circumstances:',
        },
        {
          type: 'bullets',
          items: [
            '**Between Buyers & Sellers:** Transaction-related information is shared between parties to facilitate orders, deliveries, and payments.',
            '**Third-Party Service Providers:** We engage logistics partners, payment processors, warehousing partners, and technology providers who process data on our behalf.',
            '**Verification Partners:** Identity and business verification services to validate your account information.',
            '**Legal Requirements:** We may disclose information if required by law, court order, government authority, or to protect our rights and safety.',
            '**With Your Consent:** Any other sharing will be done with your explicit consent.',
          ],
        },
      ],
    },
    {
      id: 'security',
      title: 'Data Security',
      icon: 'lock-closed-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'We implement robust security measures to protect your data, including:',
        },
        {
          type: 'cards',
          items: [
            {
              icon: 'lock-closed-outline',
              title: 'Encryption',
              text: 'Passwords are hashed. Data is encrypted in transit (SSL/TLS).',
            },
            {
              icon: 'shield-checkmark-outline',
              title: 'Secure Access',
              text: 'Token-based authentication and role-based access controls.',
            },
            {
              icon: 'eye-outline',
              title: 'Monitoring',
              text: 'Regular security audits and infrastructure monitoring.',
            },
          ],
        },
      ],
    },
    {
      id: 'cookies',
      title: 'Cookies & Tracking',
      icon: 'analytics-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'We use cookies and similar tracking technologies to enhance your experience:',
        },
        {
          type: 'bullets',
          items: [
            '**Essential Cookies:** Required for authentication, session management, and security.',
            '**Analytics Cookies:** Help us understand how users interact with the Platform to improve performance.',
            '**Preference Cookies:** Store your language and display preferences.',
          ],
        },
        {
          type: 'paragraph',
          text: 'You can manage cookie preferences through your browser settings. Disabling cookies may affect Platform functionality.',
        },
      ],
    },
    {
      id: 'rights',
      title: 'Your Rights',
      icon: 'person-outline',
      blocks: [
        { type: 'paragraph', text: 'Subject to applicable law, you have the right to:' },
        {
          type: 'bullets',
          items: [
            '**Access:** Request access to your personal data held by us.',
            '**Correction:** Request correction of inaccurate or incomplete data.',
            '**Deletion:** Request deletion of your account and associated data (subject to legal retention requirements).',
            '**Withdraw Consent:** Withdraw consent for data processing, where applicable.',
            '**Data Portability:** Request a copy of your data in a structured, machine-readable format.',
          ],
        },
        {
          type: 'paragraph',
          text: 'To exercise any of these rights, please contact our Grievance Officer using the details below.',
        },
      ],
    },
    {
      id: 'contact',
      title: 'Contact & Grievance Officer',
      icon: 'mail-outline',
      blocks: [
        {
          type: 'paragraph',
          text: 'If you have questions about this Privacy Policy, wish to exercise your data rights, or have any grievance, please contact:',
        },
        {
          type: 'contact',
          name: 'Arti Jadhav',
          role: 'Grievance Officer',
          org: 'Agrawal Business Network LLP',
          address: 'Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210',
          email: 'grievance@dealdirect.in',
          phone: '+91 92-8963 8963',
          hours: 'Mon – Fri (10:00 AM – 06:00 PM)',
        },
      ],
    },
  ],
};
