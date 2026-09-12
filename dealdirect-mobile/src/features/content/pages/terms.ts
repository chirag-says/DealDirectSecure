import type { ContentPage, Section } from './model';

/**
 * Mirrors `client-next/src/app/terms/TermsContent.jsx`. Copy is verbatim,
 * including the website's own clause numbering (the buyer and seller parts
 * skip numbers, as the source does). A change there must be made here in the
 * same commit.
 */

const GRIEVANCE: Section = {
  id: 'grievance',
  title: '14. Grievance Mechanism',
  icon: 'hammer-outline',
  collapsible: true,
  blocks: [
    {
      type: 'paragraph',
      text: 'Submit grievances regarding the Platform, Services, abuse, or information processing to:',
    },
    {
      type: 'contact',
      name: 'Arti Jadhav',
      role: 'Grievance Officer, Agrawal Business Network LLP',
      address: 'Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210',
      phone: '+91 92-8963 8963',
      email: 'grievance@dealdirect.in',
      hours: 'Available: Mon – Fri (10:00 AM – 06:00 PM)',
    },
  ],
};

export const termsPage: ContentPage = {
  id: 'terms',
  eyebrow: 'Legal',
  title: 'Terms of Use',
  intro:
    'This document is an electronic record in terms of Information Technology Act, 2000. Published in accordance with Rule 3(1)(a) of the IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021 for access or usage of **www.dealdirect.in** ("Platform").',
  meta: 'Effective date: 21 February 2026',
  webPath: '/terms',
  parts: [
    {
      id: 'general',
      label: 'General',
      blocks: [
        {
          type: 'callout',
          tone: 'info',
          text: 'This document is a legally binding agreement between a **Seller** or a **Buyer** (collectively **"you"**, **"User"**) who access or transact on the Platform for commercial purposes only and **Agrawal Business Network LLP** (**"DEALDIRECT"**, **"we"**, **"us"**). The Platform is a **business-to-business (B2B)** platform providing services to business entities only.',
        },
        {
          type: 'paragraph',
          text: 'Upon your written request, we may make these terms available in languages specified in the VIIIth Schedule of the Constitution of India. Send requests to **info@dealdirect.in**. In case of discrepancy, the English version shall prevail.',
        },
        {
          type: 'callout',
          tone: 'danger',
          text: 'PLEASE READ THE TERMS CAREFULLY. BY ACCESSING THE PLATFORM YOU AGREE TO ALL THESE TERMS. IF YOU DO NOT AGREE, DO NOT USE THE PLATFORM.',
        },
      ],
      sections: [
        {
          id: 'effective-date',
          title: '1. Effective Date',
          icon: 'book-outline',
          collapsible: true,
          defaultOpen: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'These Terms of Use shall come into force with effect from **0000 hours of 21st February 2026**.',
            },
          ],
        },
        {
          id: 'acceptance',
          title: '2. Application and Acceptance of the Terms',
          icon: 'shield-checkmark-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'Your use of the Platform and DEALDIRECT\'s services, features, functionality, software and products (collectively the **"Services"**) is subject to these Terms, the Privacy Policy, The Product Listing Policy, The Infringement Policy and any other rules and policies of the Platform.',
                'You must read DEALDIRECT Privacy Policy which governs the collection, use, and disclosure of personal information. You accept the terms of the Privacy Policy and agree to the use of personal information about you in accordance with it.',
              ],
            },
          ],
        },
        {
          id: 'provision',
          title: '3. Provision of Services',
          icon: 'settings-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'You must register on the Platform to access and use the Services. DEALDIRECT reserves the right to restrict access to Services subject to conditions at its discretion.',
                'Services supported by third-party providers — your contracting entity will be such third-party provider(s). DEALDIRECT disclaims all liability for claims arising from such third-party services.',
                'Services are provided on a **"best efforts"** basis. We shall not be liable for failure, delay, temporary disablement, or permanent discontinuance of Services.',
                'Services are provided **"as is"** and **"as available"** and may be interrupted. We reserve the right to suspend the Services without assigning any reason.',
                'DEALDIRECT may withdraw, terminate, and/or suspend any Services at any time with or without notice.',
              ],
            },
          ],
        },
        {
          id: 'eligibility',
          title: '4. Eligibility',
          icon: 'person-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'The Platform is available to Users who can form legally binding contracts under Indian Contract Act, 1872. **"Persons"** includes sole proprietors, firms, companies, corporations, government agencies, associations, trusts, joint ventures, consortiums, partnerships, or any body corporate incorporated under Indian law.',
            },
            {
              type: 'paragraph',
              text: 'User must use the Platform and its Services for their personal use and only for their personal purposes.',
            },
          ],
        },
        {
          id: 'accounts',
          title: '5. User Accounts and Verification',
          icon: 'lock-closed-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'User must be registered to access Services. One User may only register one account. DEALDIRECT may cancel or terminate accounts if multiple accounts are suspected.',
                'A set of user ID and OTP / password is unique to a single account. Any action triggered on your account will be deemed authorized by you. You are solely responsible for maintaining confidentiality and security of your credentials.',
                'DEALDIRECT may communicate with you by e-mail, SMS, WhatsApp, phone call, in-app notifications or by posting notices on the Platform. You consent to receive such communications.',
                'While registering you will furnish identification details including PAN, Aadhar, address, phone number. We may validate this information directly or through third-party providers. If information is found incorrect, DEALDIRECT reserves the right to take appropriate steps under Clause 7.',
              ],
            },
          ],
        },
        {
          id: 'users-generally',
          title: '6. Users Generally',
          icon: 'people-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'You will not copy, reproduce, download, sell, distribute or resell any Platform Content, or use it for operating a competing business.',
                'DEALDIRECT may allow access to third-party content via hyperlinks or APIs. DEALDIRECT has no control over such third-party web sites.',
                "You agree not to undertake any action which may undermine the integrity of DEALDIRECT's feedback system.",
                'By posting User Content on the Platform, you grant a **perpetual, worldwide, royalty-free, sub-licensable license** to DEALDIRECT to display, transmit, distribute, reproduce, publish, translate, and otherwise use the content.',
              ],
            },
            {
              type: 'callout',
              tone: 'danger',
              title:
                'Prohibited Content — You shall NOT host, display, upload, modify, publish, transmit, store, update or share any information which:',
              items: [
                'Belongs to another person without right',
                'Is harmful, harassing, defamatory, obscene, or unlawful',
                'Is misleading or patently offensive',
                'Infringes intellectual property or privacy rights',
                'Promotes illegal activities or unauthorized copies of copyrighted work',
                'Contains viruses or malicious code',
                'Threatens unity, integrity, defence, or sovereignty of India',
                'Is false, inaccurate or misleading',
                'Directly or indirectly deals in prohibited or restricted items',
              ],
            },
            {
              type: 'paragraph',
              text: 'Users shall comply with the IT Act 2000, modern slavery and human trafficking laws, the Code of Conduct at **https://dealdirect.in/pages/code-of-conduct**, and indemnify DEALDIRECT from all damages arising from breach.',
            },
          ],
        },
        {
          id: 'breaches',
          title: '7. Breaches and Suspension',
          icon: 'warning-outline',
          collapsible: true,
          blocks: [
            { type: 'paragraph', text: 'If any User breaches any Terms, DEALDIRECT may:' },
            {
              type: 'bullets',
              items: [
                "Suspend or terminate the User's account and related accounts",
                'Block, restrict, downgrade, suspend or terminate access to Services',
                'Remove product listings or User Content',
                'Withhold settlement of payments',
                'Take any other corrective actions or penalties deemed necessary',
              ],
            },
            {
              type: 'paragraph',
              text: 'DEALDIRECT does not pre-screen content and is under no obligation to do so. DEALDIRECT may suspend, reduce visibility, de-activate, or de-list any product listings or User accounts for any reasons at its sole discretion.',
            },
            {
              type: 'paragraph',
              text: 'DEALDIRECT reserves the right to cooperate with governmental authorities and disclose User identity if requested by law enforcement or as a result of legal action.',
            },
          ],
        },
        {
          id: 'transactions',
          title: '8. Transactions Between Buyer and Seller',
          icon: 'swap-horizontal-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'DEALDIRECT is merely a **facilitator** — not a party to any transaction.',
                'Products sold to Buyer by the Seller are governed by their bipartite contractual arrangement. DEALDIRECT does not confirm Seller identity and encourages Buyers to exercise discretion and caution.',
                'User shall use the Platform only for lawful business purposes. Buyer shall purchase products for further resale or commercial purpose, not personal use.',
                'DEALDIRECT does not control quality, safety, suitability, lawfulness or availability of products. No right, title or interest in products vests with DEALDIRECT.',
                'Each User fully assumes **Transaction Risk** and uses best and prudent judgment before entering any transaction.',
                'Users agree to release and indemnify DEALDIRECT from all claims arising from disputes with any transaction party.',
              ],
            },
          ],
        },
        {
          id: 'liability',
          title: '9. Limitation of Liability and Indemnity',
          icon: 'alert-circle-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'Services are provided **"as is"**, **"as available"** and **"with all faults"**. DEALDIRECT expressly disclaims all warranties.',
                'DEALDIRECT makes no representations about validity, accuracy, or completeness of information on the Platform. Aggregate liability shall not exceed **INR 1000/-**.',
                'Under no circumstances will DEALDIRECT be liable for any consequential, incidental, special, exemplary or punitive damages, including lost profits.',
              ],
            },
          ],
        },
        {
          id: 'force-majeure',
          title: '10. Force Majeure',
          icon: 'globe-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'DEALDIRECT shall not be held liable for losses, delay or failure resulting from acts of nature, internet failures, equipment failures, strikes, riots, fires, floods, war, pandemics, government actions, or non-performance of third parties.',
            },
          ],
        },
        {
          id: 'ip',
          title: '11. Intellectual Property Rights',
          icon: 'ribbon-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'DEALDIRECT is the sole owner or lawful licensee of all rights in the Platform and Platform Content.',
                '**"DEALDIRECT"** and related icons/logos are registered trademarks of Agrawal Business Network LLP. Unauthorized use is strictly prohibited.',
                'All user-generated content on the Platform is third-party content; DEALDIRECT acts as an intermediary.',
                'By uploading content, you grant DEALDIRECT a **worldwide, fully paid-up, perpetual and transferable licence** for use on the Platform.',
              ],
            },
          ],
        },
        {
          id: 'notices',
          title: '12. Notices',
          icon: 'notifications-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'All legal notices to DEALDIRECT shall be sent to: **Agrawal Business Network LLP, Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210**, Attn: Legal Department.',
            },
            {
              type: 'paragraph',
              text: 'Notices to Users are effective when delivered personally, by courier, certified mail, email, SMS, WhatsApp, in-app notifications, or posted on the Platform.',
            },
          ],
        },
        {
          id: 'misc',
          title: '13. Miscellaneous Provisions',
          icon: 'document-text-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'These Terms constitute the entire agreement and supersede all prior agreements.',
                'DEALDIRECT and User are independent contractors — no agency, partnership, or joint venture is created.',
                'If any provision is held invalid, remaining provisions remain valid and enforced.',
                'DEALDIRECT may assign the Terms to any person or entity. User may not assign.',
                'These Terms shall be governed by the **laws of India**, subject to exclusive jurisdiction of the **courts of Mumbai, Maharashtra**.',
              ],
            },
          ],
        },
        GRIEVANCE,
      ],
    },
    {
      id: 'buyer',
      label: 'Buyer',
      blocks: [
        {
          type: 'callout',
          tone: 'success',
          text: 'These Buyer Terms apply only to **Buyers** and shall be read with the General Terms. In case of conflict, Buyer Terms prevail.',
        },
      ],
      sections: [
        {
          id: 'buyer-definitions',
          title: '1. Definitions',
          icon: 'book-outline',
          collapsible: true,
          defaultOpen: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                '**"Buyer"** — a business entity intending to purchase Products on the Platform for commercial purposes.',
                '**"Consignee"** — the Buyer or person named in the Delivery Note taking delivery of Shipment.',
                '**"Dangerous Goods"** — hazardous, inflammable, radioactive, or damaging products.',
                '**"Delivery Note"** — the waybill with essential information for performance of logistics.',
                '**"Logistics Services"** — shipping, delivery, COD and allied services.',
                '**"Order(s)"** — order placed by Buyer for purchasing Products from Seller on Platform.',
                '**"Product(s)"** — goods of any categories (other than Dangerous Goods).',
                '**"Shipment(s)"** — all Products travelling under one Delivery Note.',
              ],
            },
          ],
        },
        {
          id: 'buyer-responsibilities',
          title: "2. Buyer's Responsibilities, Representations & Warranties",
          icon: 'shield-checkmark-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'You are a lawfully incorporated business entity, have full power and authority to accept these Terms.',
                'You will use the Platform and Services for **business purposes only**, not for personal consumption.',
                "The address provided during registration is the Buyer's place of business.",
                'Information/material submitted is true, accurate, current, and complete, and you will maintain it as such.',
                "Buyer consents to inclusion of contact information in DEALDIRECT's database per Privacy Policy.",
              ],
            },
          ],
        },
        {
          id: 'buyer-payments',
          title: 'Payments by Buyers',
          icon: 'card-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'Buyer can pay using modes available on the Platform. We act in a **fiduciary capacity** only.',
                'A **convenience fee** (incl. GST) may be charged for credit card payments — non-refundable.',
                "A non-interest-bearing **Token Amount** may be required, adjusted from final payment. On cancellation after 'ready to ship', a Cancellation Penalty Fee may be deducted or the Token Amount forfeited.",
                'Buyer is solely responsible for payment transactions. We are acting as a payment collector only.',
                'Post-dated cheques must be correctly filled in the name of the Seller. Failure to replace returned cheques may lead to account suspension.',
                'Refunds are subject to Return Shipments Policy and Undelivered Shipment Policy, processed in the same manner as received.',
              ],
            },
          ],
        },
        {
          id: 'buyer-logistics',
          title: 'Logistics Services',
          icon: 'car-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'We may engage third-party service providers for Logistics Services.',
                'Title and risk in the Shipment passes to Buyer at pickup time.',
                'We will use best endeavours to deliver to the designated address. Buyer authorises contact via calls, SMS, or WhatsApp for transactional purposes.',
                'Dangerous Goods or prohibited goods shall not be accepted for delivery.',
                'Shipments to incomplete addresses or post box numbers will be rejected.',
                'Consignees must behave professionally with delivery associates. Misbehaviour may lead to account suspension.',
                "Shipments delivered on **'as is'** basis. No open box delivery is provided.",
              ],
            },
          ],
        },
        {
          id: 'buyer-returns',
          title: 'Undelivered Shipment & Returns',
          icon: 'cube-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'In relation to Undelivered Shipments and Return Requests, you agree to be bound by the provisions of the Undelivered Shipment Policy and Return Shipments Policy respectively.',
            },
          ],
        },
        {
          id: 'buyer-lien',
          title: 'Lien, Fees & Charges',
          icon: 'card-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                "We have a general and particular **lien** on goods for unpaid amounts. After 15 calendar days' written notice, we may sell the Shipments.",
                'Logistics charges are exclusive of GST and displayed in the Rate Card section. Charges may be modified at our sole discretion.',
                'Any taxes, duties, or levies by authorities shall be extra and payable by Buyer.',
                'DEALDIRECT may charge additional fees for additional services and may levy penalties for delayed payments.',
              ],
            },
          ],
        },
        {
          id: 'buyer-liability',
          title: 'Limitation of Liability',
          icon: 'alert-circle-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'We shall not be liable for claims arising from: your acts/omissions; compliance with your instructions; government orders; insufficiency of packing; nature of Shipment; force majeure; any cause we could not avoid by reasonable diligence; and/or disputes between Seller and Buyer.',
            },
          ],
        },
        {
          id: 'buyer-acquisition',
          title: 'Customer Acquisition Program',
          icon: 'megaphone-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: "DEALDIRECT runs a Customer Acquisition Program for Buyers to service unserviceable locations for additional benefits. Interested Buyers should contact their respective field executives. Selection is at DEALDIRECT's discretion per its terms and conditions.",
            },
          ],
        },
      ],
    },
    {
      id: 'seller',
      label: 'Seller',
      blocks: [
        {
          type: 'callout',
          tone: 'info',
          text: 'These Seller Terms apply only to **Sellers** and shall be read with the General Terms. In case of conflict, Seller Terms prevail.',
        },
      ],
      sections: [
        {
          id: 'seller-definitions',
          title: '1. Definitions',
          icon: 'book-outline',
          collapsible: true,
          defaultOpen: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                '**"S&D Services"** — Standard Platform Services, Payment & Settlement Services, Standard Warehousing Services, goods handling and allied services.',
                '**"Standard Platform Services"** — use and access of the Platform for creation, display, updating of product listings and subsequent sale transactions.',
                '**"Standard Warehousing Services"** — storage, handling, tertiary packaging, printing invoices, special access to fulfil Orders.',
                '**"Payment and Settlement Services"** — remittance and settlement of payments collected from Buyers to designated Seller bank accounts.',
                '**"TPID"** — Tampering proof identifier affixed on Shipment.',
              ],
            },
          ],
        },
        {
          id: 'seller-obligations',
          title: "3. Seller's Obligations, Representations & Warranties",
          icon: 'shield-checkmark-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'You are a lawfully incorporated business entity with full authority. You will use the Platform for **business purposes only**.',
                'User Content does not infringe any Third Party Rights. You have the right to sell, trade, distribute or export the Products.',
                'Consignment descriptions (weight, content, measure, quality, condition, value) are complete and accurate.',
                'Shipments are properly packed, labelled, and comply with all applicable laws and regulations.',
                'Seller shall comply with packaging guidelines communicated by DEALDIRECT.',
                'Seller shall not enclose cash, digital currency, Dangerous Goods, firearms, or prohibited products in Shipments. Non-compliance results in full indemnification to DEALDIRECT.',
                'Seller is solely responsible for accurate value declaration, GST compliance, on-time handover, raising invoices directly on Buyer.',
                'Sellers must behave professionally with delivery associates. Misbehaviour may lead to removal of selling privileges.',
              ],
            },
          ],
        },
        {
          id: 'seller-audits',
          title: '4. Audits',
          icon: 'eye-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'DEALDIRECT may conduct random audits of Shipments and warehouse Products. Non-compliance penalties include:',
            },
            {
              type: 'bullets',
              items: [
                'Warning letter',
                'For invoice non-inclusion: higher of ₹1,000 or total invoice value of audited Shipment',
                'For other non-compliance: higher of 2× product value or total invoice value',
                'Account deactivation or suspension',
              ],
            },
          ],
        },
        {
          id: 'seller-fees',
          title: '5. Fees and Charges for S&D Services',
          icon: 'card-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'Seller pays **S&D Fee** calculated on total invoice value of the Order.',
                'S&D Fee is communicated via Platform or other modes. Continued use = deemed acceptance of fee changes.',
                'Seller authorizes DEALDIRECT to adjust S&D Fee from amounts collected from Buyers.',
                'S&D Fee is subject to applicable taxes. Seller shall deduct income tax as applicable and provide withholding certificates.',
                'DEALDIRECT may levy penalties or late payment charges for delayed dues and cancellation charges for cancelled Orders.',
              ],
            },
          ],
        },
        {
          id: 'seller-platform-services',
          title: '6(i). Standard Platform Services',
          icon: 'document-text-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'You may list Products subject to compliance with Seller Terms. Products must not infringe any IP or proprietary rights.',
                'All products must be listed in appropriate categories, kept in stock, and descriptions must not be misleading.',
                "Products sold shall be for Buyer's **resale or commercial purpose** only, not personal consumption.",
              ],
            },
          ],
        },
        {
          id: 'seller-warehousing',
          title: '6(ii). Standard Warehousing Services',
          icon: 'business-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'DEALDIRECT may provide Standard Warehousing Services and sub-contract them. DEALDIRECT shall take commercially reasonable security precautions.',
                'Seller authorizes DEALDIRECT to undertake insurance for Products and claim insurance in event of loss.',
                'DEALDIRECT is not responsible for Products found damaged at warehouse delivery. Products not meeting packaging guidelines may be rejected.',
                'Products remain property of Seller until delivered to Buyer. DEALDIRECT has a **lien** on Products for unpaid amounts.',
                'Seller is responsible for all licenses, registrations, permits, product recalls, and shall indemnify DEALDIRECT.',
                '**Returns:** Products returned for physical damage/wrong product are sent to designated warehouse. If damaged due to DEALDIRECT, order value is reimbursed. Products returned for manufacturing/quality defects are returned to Seller.',
                '**Undelivered Shipments:** Undamaged products are inventorized. Damaged products (attributable to DEALDIRECT) are reimbursed.',
                'Returned Products delivered within **90 days**. Seller can raise disputes within **72 hours** of delivery.',
                "**Termination:** Seller gives 90 days' written notice. DEALDIRECT gives 15 days' notice or immediate termination for breach. Products must be picked up within 7 days or DEALDIRECT may dispose them.",
              ],
            },
          ],
        },
        {
          id: 'seller-settlement',
          title: '6(iii). Payment and Settlement Services',
          icon: 'card-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'DEALDIRECT acts as a **payment collector in fiduciary capacity** only.',
                "Post-dated cheque bounces are the Buyer's sole responsibility.",
                'DEALDIRECT may withhold settlements for suspicious or fraudulent transactions.',
              ],
            },
            {
              type: 'callout',
              tone: 'info',
              title: 'Settlement Timelines:',
              items: [
                '**Non-food products:** 20 bank working days from delivery (settled on Tuesdays or Fridays)',
                '**Pharmaceuticals & fulfilment material:** 2 bank working days from delivery',
                '**Food, FMCG & fresh:** 4 bank working days from delivery',
                '**Online pre-payments:** T+1 bank working days (T = N+65 days from order date)',
              ],
            },
            {
              type: 'paragraph',
              text: 'Settlements include deductions for S&D Fees, refunds, applicable taxes (TCS under GST, TDS under Income Tax Act). Seller must provide correct GST registration number and HSN codes.',
            },
          ],
        },
        {
          id: 'seller-additional',
          title: '6(iv). Additional Services',
          icon: 'megaphone-outline',
          collapsible: true,
          blocks: [
            { type: 'heading', text: 'a. Advertisement Services' },
            {
              type: 'paragraph',
              text: 'Seller may subscribe to the ad program to promote Products. Seller retains IP rights in Ads and grants DEALDIRECT a non-exclusive, royalty-free license. Seller is solely liable for Ad content and indemnifies DEALDIRECT. Charges may be adjusted from Buyer payments.',
            },
            { type: 'heading', text: 'b. From Pay Services' },
            {
              type: 'paragraph',
              text: "DEALDIRECT may charge logistics/delivery charges from the Seller instead of Buyer. Charges subject to applicable taxes and may be modified at DEALDIRECT's discretion. For undelivered shipments, no charges are levied on Seller. For delivered-then-returned orders, Seller is liable for charges.",
            },
            {
              type: 'paragraph',
              text: '**Taxes:** Seller shall deduct income tax as applicable, remit to authorities, and provide withholding certificates to enable DEALDIRECT to claim tax credit.',
            },
          ],
        },
        {
          id: 'seller-liability',
          title: '8. Limitation of Liability and Indemnity',
          icon: 'alert-circle-outline',
          collapsible: true,
          blocks: [
            {
              type: 'paragraph',
              text: 'We shall not be liable for claims arising from: your acts/omissions; government orders; packing insufficiency; shipment nature; riots; strikes; fire; flood; storm; explosion; any unavoidable cause; loss or damage to Shipment; and/or Seller-Buyer disputes.',
            },
            {
              type: 'paragraph',
              text: 'Seller indemnifies DEALDIRECT from all damages, losses, claims arising from: User Content; Platform use; Terms breach; third-party services; Product defects/liability; negligence/misconduct; counterfeit products or IP infringement; personal injury/death/property damage; and consumer protection claims.',
            },
          ],
        },
        {
          id: 'seller-trade-credit',
          title: '9. Trade Credit by Seller(s)',
          icon: 'swap-horizontal-outline',
          collapsible: true,
          blocks: [
            {
              type: 'bullets',
              items: [
                'Sellers intending to grant **Trade Credit (TC)** to Buyers may send a request to the registered office with intended terms.',
                'DEALDIRECT will respond within **7 working days**. Final decision on TC enablement rests with DEALDIRECT.',
                'TC is governed by separate terms between Buyer and Seller. DEALDIRECT disclaims all liability regarding TC.',
              ],
            },
          ],
        },
      ],
    },
  ],
};
