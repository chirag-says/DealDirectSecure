'use client';

import React, { useEffect, useState, useRef } from "react";
import {
    Scale, UserCheck, ShieldCheck, FileText, AlertTriangle, Gavel, ChevronRight,
    ChevronDown, BookOpen, Truck, CreditCard, Package, ShoppingCart, Warehouse,
    Megaphone, Users, Eye, Lock, Bell, Globe, HandshakeIcon, Settings, Award
} from "lucide-react";

/* ────────────────────────── Accordion ────────────────────────── */
const Accordion = ({ title, children, defaultOpen = false, icon: Icon }) => {
    const [open, setOpen] = useState(defaultOpen);
    return (
        <div className="bg-white rounded-2xl shadow-sm border border-gray-200 overflow-hidden transition-all duration-300">
            <button onClick={() => setOpen(!open)}
                className="w-full flex items-center justify-between p-5 text-left hover:bg-gray-50 transition-colors">
                <span className="flex items-center gap-3 text-lg font-semibold text-gray-900">
                    {Icon && <Icon className="w-5 h-5 text-blue-600 flex-shrink-0" />}{title}
                </span>
                <ChevronDown className={`w-5 h-5 text-gray-400 transition-transform duration-300 ${open ? "rotate-180" : ""}`} />
            </button>
            {open && <div className="px-6 pb-6 text-gray-600 leading-relaxed space-y-4 border-t border-gray-100 pt-4">{children}</div>}
        </div>
    );
};

/* ────────────────────────── Sub-list helper ────────────────────────── */
const LI = ({ children }) => (
    <li className="flex gap-3"><span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-500 mt-2.5" /><span>{children}</span></li>
);

/* ══════════════════════════ MAIN COMPONENT ══════════════════════════ */
const TermsAndConditions = () => {
    const [activeTab, setActiveTab] = useState("general");
    useEffect(() => { window.scrollTo({ top: 0, behavior: "auto" }); }, []);

    const tabs = [
        { id: "general", label: "I. General Terms", icon: Scale },
        { id: "buyer", label: "II. Buyer Terms", icon: ShoppingCart },
        { id: "seller", label: "III. Seller Terms", icon: Warehouse },
    ];

    /* ─── RENDER ─── */
    return (
        <div className="min-h-screen bg-slate-50 font-sans">
            {/* ──── HEADER ──── */}
            <div className="bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white py-16 px-6 relative overflow-hidden">
                <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_30%_50%,#3b82f6,transparent_70%)]" />
                <div className="max-w-5xl mx-auto text-center relative z-10">
                    <div className="flex justify-center mb-6">
                        <div className="p-4 bg-white/10 rounded-full backdrop-blur-md"><Scale className="w-12 h-12 text-blue-400" /></div>
                    </div>
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">Terms of Use</h1>
                    <p className="text-slate-400 max-w-3xl mx-auto text-lg">
                        This document is an electronic record in terms of Information Technology Act, 2000.
                        Published in accordance with Rule 3(1)(a) of the IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021
                        for access or usage of <strong className="text-white">www.dealdirect.in</strong> ("Platform").
                    </p>
                    <p className="text-slate-500 text-sm mt-4">Effective Date: 21 February 2026</p>
                </div>
            </div>

            {/* ──── PREAMBLE ──── */}
            <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-10">
                <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-100 rounded-2xl p-6 text-gray-700 text-sm leading-relaxed space-y-3">
                    <p>This document is a legally binding agreement between a <strong>Seller</strong> or a <strong>Buyer</strong> (collectively <strong>"you"</strong>, <strong>"User"</strong>) who access or transact on the Platform for <em>commercial purposes only</em> and <strong>Agrawal Business Network LLP</strong> (<strong>"DEALDIRECT"</strong>, <strong>"we"</strong>, <strong>"us"</strong>). The Platform is a <strong>business-to-business (B2B)</strong> platform providing services to business entities only.</p>
                    <p>Upon your written request, we may make these terms available in languages specified in the VIIIth Schedule of the Constitution of India. Send requests to <strong>info@dealdirect.in</strong>. In case of discrepancy, the English version shall prevail.</p>
                    <p className="font-semibold text-red-700">PLEASE READ THE TERMS CAREFULLY. BY ACCESSING THE PLATFORM YOU AGREE TO ALL THESE TERMS. IF YOU DO NOT AGREE, DO NOT USE THE PLATFORM.</p>
                </div>
            </div>

            {/* ──── TAB NAVIGATION ──── */}
            <div className="max-w-5xl mx-auto px-4 sm:px-6 pt-8">
                <div className="flex flex-wrap gap-3 mb-8">
                    {tabs.map(t => (
                        <button key={t.id} onClick={() => setActiveTab(t.id)}
                            className={`flex items-center gap-2 px-5 py-3 rounded-xl font-semibold text-sm transition-all duration-200 border
                            ${activeTab === t.id
                                    ? "bg-blue-600 text-white border-blue-600 shadow-lg shadow-blue-200"
                                    : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50 hover:border-gray-300"}`}>
                            <t.icon className="w-4 h-4" />{t.label}
                        </button>
                    ))}
                </div>
            </div>

            {/* ──── CONTENT ──── */}
            <div className="max-w-5xl mx-auto px-4 sm:px-6 pb-20 space-y-5">

                {/* ═══════════ I. GENERAL TERMS ═══════════ */}
                {activeTab === "general" && (<>
                    <Accordion title="1. Effective Date" icon={BookOpen} defaultOpen>
                        <p>These Terms of Use shall come into force with effect from <strong>0000 hours of 21st February 2026</strong>.</p>
                    </Accordion>

                    <Accordion title="2. Application and Acceptance of the Terms" icon={ShieldCheck}>
                        <ul className="space-y-3">
                            <LI>Your use of the Platform and DEALDIRECT's services, features, functionality, software and products (collectively the <strong>"Services"</strong>) is subject to these Terms, the Privacy Policy, The Product Listing Policy, The Infringement Policy and any other rules and policies of the Platform.</LI>
                            <LI>You must read DEALDIRECT Privacy Policy which governs the collection, use, and disclosure of personal information. You accept the terms of the Privacy Policy and agree to the use of personal information about you in accordance with it.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="3. Provision of Services" icon={Settings}>
                        <ul className="space-y-3">
                            <LI>You must register on the Platform to access and use the Services. DEALDIRECT reserves the right to restrict access to Services subject to conditions at its discretion.</LI>
                            <LI>Services supported by third-party providers — your contracting entity will be such third-party provider(s). DEALDIRECT disclaims all liability for claims arising from such third-party services.</LI>
                            <LI>Services are provided on a <strong>"best efforts"</strong> basis. We shall not be liable for failure, delay, temporary disablement, or permanent discontinuance of Services.</LI>
                            <LI>Services are provided <strong>"as is"</strong> and <strong>"as available"</strong> and may be interrupted. We reserve the right to suspend the Services without assigning any reason.</LI>
                            <LI>DEALDIRECT may withdraw, terminate, and/or suspend any Services at any time with or without notice.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="4. Eligibility" icon={UserCheck}>
                        <p>The Platform is available to Users who can form legally binding contracts under Indian Contract Act, 1872. <strong>"Persons"</strong> includes sole proprietors, firms, companies, corporations, government agencies, associations, trusts, joint ventures, consortiums, partnerships, or any body corporate incorporated under Indian law.</p>
                        <p>User must use the Platform and its Services for their personal use and only for their personal purposes.</p>
                    </Accordion>

                    <Accordion title="5. User Accounts and Verification" icon={Lock}>
                        <ul className="space-y-3">
                            <LI>User must be registered to access Services. One User may only register one account. DEALDIRECT may cancel or terminate accounts if multiple accounts are suspected.</LI>
                            <LI>A set of user ID and OTP / password is unique to a single account. Any action triggered on your account will be deemed authorized by you. You are solely responsible for maintaining confidentiality and security of your credentials.</LI>
                            <LI>DEALDIRECT may communicate with you by e-mail, SMS, WhatsApp, phone call, in-app notifications or by posting notices on the Platform. You consent to receive such communications.</LI>
                            <LI>While registering you will furnish identification details including PAN, Aadhar, address, phone number. We may validate this information directly or through third-party providers. If information is found incorrect, DEALDIRECT reserves the right to take appropriate steps under Clause 7.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="6. Users Generally" icon={Users}>
                        <ul className="space-y-3">
                            <LI>You will not copy, reproduce, download, sell, distribute or resell any Platform Content, or use it for operating a competing business.</LI>
                            <LI>DEALDIRECT may allow access to third-party content via hyperlinks or APIs. DEALDIRECT has no control over such third-party web sites.</LI>
                            <LI>You agree not to undertake any action which may undermine the integrity of DEALDIRECT's feedback system.</LI>
                            <LI>By posting User Content on the Platform, you grant a <strong>perpetual, worldwide, royalty-free, sub-licensable license</strong> to DEALDIRECT to display, transmit, distribute, reproduce, publish, translate, and otherwise use the content.</LI>
                        </ul>
                        <div className="bg-red-50 border border-red-100 rounded-xl p-4 mt-4">
                            <p className="font-semibold text-red-800 mb-2">Prohibited Content — You shall NOT host, display, upload, modify, publish, transmit, store, update or share any information which:</p>
                            <ul className="text-sm text-red-700 space-y-1 list-disc pl-5">
                                <li>Belongs to another person without right</li>
                                <li>Is harmful, harassing, defamatory, obscene, or unlawful</li>
                                <li>Is misleading or patently offensive</li>
                                <li>Infringes intellectual property or privacy rights</li>
                                <li>Promotes illegal activities or unauthorized copies of copyrighted work</li>
                                <li>Contains viruses or malicious code</li>
                                <li>Threatens unity, integrity, defence, or sovereignty of India</li>
                                <li>Is false, inaccurate or misleading</li>
                                <li>Directly or indirectly deals in prohibited or restricted items</li>
                            </ul>
                        </div>
                        <p className="mt-3 text-sm">Users shall comply with the IT Act 2000, modern slavery and human trafficking laws, the Code of Conduct at <strong>https://dealdirect.in/pages/code-of-conduct</strong>, and indemnify DEALDIRECT from all damages arising from breach.</p>
                    </Accordion>

                    <Accordion title="7. Breaches and Suspension" icon={AlertTriangle}>
                        <p>If any User breaches any Terms, DEALDIRECT may:</p>
                        <ul className="space-y-2 list-disc pl-5">
                            <li>Suspend or terminate the User's account and related accounts</li>
                            <li>Block, restrict, downgrade, suspend or terminate access to Services</li>
                            <li>Remove product listings or User Content</li>
                            <li>Withhold settlement of payments</li>
                            <li>Take any other corrective actions or penalties deemed necessary</li>
                        </ul>
                        <p className="mt-3">DEALDIRECT does not pre-screen content and is under no obligation to do so. DEALDIRECT may suspend, reduce visibility, de-activate, or de-list any product listings or User accounts for any reasons at its sole discretion.</p>
                        <p>DEALDIRECT reserves the right to cooperate with governmental authorities and disclose User identity if requested by law enforcement or as a result of legal action.</p>
                    </Accordion>

                    <Accordion title="8. Transactions Between Buyer and Seller" icon={HandshakeIcon}>
                        <ul className="space-y-3">
                            <LI>DEALDIRECT is merely a <strong>facilitator</strong> — not a party to any transaction.</LI>
                            <LI>Products sold to Buyer by the Seller are governed by their bipartite contractual arrangement. DEALDIRECT does not confirm Seller identity and encourages Buyers to exercise discretion and caution.</LI>
                            <LI>User shall use the Platform only for lawful business purposes. Buyer shall purchase products for further resale or commercial purpose, not personal use.</LI>
                            <LI>DEALDIRECT does not control quality, safety, suitability, lawfulness or availability of products. No right, title or interest in products vests with DEALDIRECT.</LI>
                            <LI>Each User fully assumes <strong>Transaction Risk</strong> and uses best and prudent judgment before entering any transaction.</LI>
                            <LI>Users agree to release and indemnify DEALDIRECT from all claims arising from disputes with any transaction party.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="9. Limitation of Liability and Indemnity" icon={AlertTriangle}>
                        <ul className="space-y-3">
                            <LI>Services are provided <strong>"as is"</strong>, <strong>"as available"</strong> and <strong>"with all faults"</strong>. DEALDIRECT expressly disclaims all warranties.</LI>
                            <LI>DEALDIRECT makes no representations about validity, accuracy, or completeness of information on the Platform. Aggregate liability shall not exceed <strong>INR 1000/-</strong>.</LI>
                            <LI>Under no circumstances will DEALDIRECT be liable for any consequential, incidental, special, exemplary or punitive damages, including lost profits.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="10. Force Majeure" icon={Globe}>
                        <p>DEALDIRECT shall not be held liable for losses, delay or failure resulting from acts of nature, internet failures, equipment failures, strikes, riots, fires, floods, war, pandemics, government actions, or non-performance of third parties.</p>
                    </Accordion>

                    <Accordion title="11. Intellectual Property Rights" icon={Award}>
                        <ul className="space-y-3">
                            <LI>DEALDIRECT is the sole owner or lawful licensee of all rights in the Platform and Platform Content.</LI>
                            <LI><strong>"DEALDIRECT"</strong> and related icons/logos are registered trademarks of Agrawal Business Network LLP. Unauthorized use is strictly prohibited.</LI>
                            <LI>All user-generated content on the Platform is third-party content; DEALDIRECT acts as an intermediary.</LI>
                            <LI>By uploading content, you grant DEALDIRECT a <strong>worldwide, fully paid-up, perpetual and transferable licence</strong> for use on the Platform.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="12. Notices" icon={Bell}>
                        <p>All legal notices to DEALDIRECT shall be sent to: <strong>Agrawal Business Network LLP, Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210</strong>, Attn: Legal Department.</p>
                        <p>Notices to Users are effective when delivered personally, by courier, certified mail, email, SMS, WhatsApp, in-app notifications, or posted on the Platform.</p>
                    </Accordion>

                    <Accordion title="13. Miscellaneous Provisions" icon={FileText}>
                        <ul className="space-y-3">
                            <LI>These Terms constitute the entire agreement and supersede all prior agreements.</LI>
                            <LI>DEALDIRECT and User are independent contractors — no agency, partnership, or joint venture is created.</LI>
                            <LI>If any provision is held invalid, remaining provisions remain valid and enforced.</LI>
                            <LI>DEALDIRECT may assign the Terms to any person or entity. User may not assign.</LI>
                            <LI>These Terms shall be governed by the <strong>laws of India</strong>, subject to exclusive jurisdiction of the <strong>courts of Mumbai, Maharashtra</strong>.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="14. Grievance Mechanism" icon={Gavel}>
                        <div className="bg-slate-900 text-white p-6 rounded-2xl">
                            <p className="text-slate-300 mb-4">Submit grievances regarding the Platform, Services, abuse, or information processing to:</p>
                            <div className="space-y-1 text-sm">
                                <p className="font-bold text-lg text-white">Arti Jadhav</p>
                                <p className="text-slate-400">Grievance Officer, Agrawal Business Network LLP</p>
                                <p className="text-slate-400">Growmore tower sector 2, plot no 5, kharghar, Navi Mumbai 410210</p>
                                <p className="text-slate-400">Phone: <strong className="text-blue-400">+91 92-8963 8963</strong></p>
                                <p className="text-slate-400">Email: <strong className="text-blue-400">grievance@dealdirect.in</strong></p>
                                <p className="text-slate-400">Available: Mon – Fri (10:00 AM – 06:00 PM)</p>
                            </div>
                        </div>
                    </Accordion>
                </>)}

                {/* ═══════════ II. BUYER TERMS ═══════════ */}
                {activeTab === "buyer" && (<>
                    <div className="bg-gradient-to-r from-emerald-50 to-teal-50 border border-emerald-100 rounded-2xl p-5 text-sm text-gray-700">
                        <p>These Buyer Terms apply only to <strong>Buyers</strong> and shall be read with the General Terms. In case of conflict, Buyer Terms prevail.</p>
                    </div>

                    <Accordion title="1. Definitions" icon={BookOpen} defaultOpen>
                        <ul className="space-y-2 text-sm">
                            <LI><strong>"Buyer"</strong> — a business entity intending to purchase Products on the Platform for commercial purposes.</LI>
                            <LI><strong>"Consignee"</strong> — the Buyer or person named in the Delivery Note taking delivery of Shipment.</LI>
                            <LI><strong>"Dangerous Goods"</strong> — hazardous, inflammable, radioactive, or damaging products.</LI>
                            <LI><strong>"Delivery Note"</strong> — the waybill with essential information for performance of logistics.</LI>
                            <LI><strong>"Logistics Services"</strong> — shipping, delivery, COD and allied services.</LI>
                            <LI><strong>"Order(s)"</strong> — order placed by Buyer for purchasing Products from Seller on Platform.</LI>
                            <LI><strong>"Product(s)"</strong> — goods of any categories (other than Dangerous Goods).</LI>
                            <LI><strong>"Shipment(s)"</strong> — all Products travelling under one Delivery Note.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="2. Buyer's Responsibilities, Representations & Warranties" icon={ShieldCheck}>
                        <ul className="space-y-3">
                            <LI>You are a lawfully incorporated business entity, have full power and authority to accept these Terms.</LI>
                            <LI>You will use the Platform and Services for <strong>business purposes only</strong>, not for personal consumption.</LI>
                            <LI>The address provided during registration is the Buyer's place of business.</LI>
                            <LI>Information/material submitted is true, accurate, current, and complete, and you will maintain it as such.</LI>
                            <LI>Buyer consents to inclusion of contact information in DEALDIRECT's database per Privacy Policy.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="Payments by Buyers" icon={CreditCard}>
                        <ul className="space-y-3">
                            <LI>Buyer can pay using modes available on the Platform. We act in a <strong>fiduciary capacity</strong> only.</LI>
                            <LI>A <strong>convenience fee</strong> (incl. GST) may be charged for credit card payments — non-refundable.</LI>
                            <LI>A non-interest-bearing <strong>Token Amount</strong> may be required, adjusted from final payment. On cancellation after 'ready to ship', a Cancellation Penalty Fee may be deducted or the Token Amount forfeited.</LI>
                            <LI>Buyer is solely responsible for payment transactions. We are acting as a payment collector only.</LI>
                            <LI>Post-dated cheques must be correctly filled in the name of the Seller. Failure to replace returned cheques may lead to account suspension.</LI>
                            <LI>Refunds are subject to Return Shipments Policy and Undelivered Shipment Policy, processed in the same manner as received.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="Logistics Services" icon={Truck}>
                        <ul className="space-y-3">
                            <LI>We may engage third-party service providers for Logistics Services.</LI>
                            <LI>Title and risk in the Shipment passes to Buyer at pickup time.</LI>
                            <LI>We will use best endeavours to deliver to the designated address. Buyer authorises contact via calls, SMS, or WhatsApp for transactional purposes.</LI>
                            <LI>Dangerous Goods or prohibited goods shall not be accepted for delivery.</LI>
                            <LI>Shipments to incomplete addresses or post box numbers will be rejected.</LI>
                            <LI>Consignees must behave professionally with delivery associates. Misbehaviour may lead to account suspension.</LI>
                            <LI>Shipments delivered on <strong>'as is'</strong> basis. No open box delivery is provided.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="Undelivered Shipment & Returns" icon={Package}>
                        <p>In relation to Undelivered Shipments and Return Requests, you agree to be bound by the provisions of the Undelivered Shipment Policy and Return Shipments Policy respectively.</p>
                    </Accordion>

                    <Accordion title="Lien, Fees & Charges" icon={CreditCard}>
                        <ul className="space-y-3">
                            <LI>We have a general and particular <strong>lien</strong> on goods for unpaid amounts. After 15 calendar days' written notice, we may sell the Shipments.</LI>
                            <LI>Logistics charges are exclusive of GST and displayed in the Rate Card section. Charges may be modified at our sole discretion.</LI>
                            <LI>Any taxes, duties, or levies by authorities shall be extra and payable by Buyer.</LI>
                            <LI>DEALDIRECT may charge additional fees for additional services and may levy penalties for delayed payments.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="Limitation of Liability" icon={AlertTriangle}>
                        <p>We shall not be liable for claims arising from: your acts/omissions; compliance with your instructions; government orders; insufficiency of packing; nature of Shipment; force majeure; any cause we could not avoid by reasonable diligence; and/or disputes between Seller and Buyer.</p>
                    </Accordion>

                    <Accordion title="Customer Acquisition Program" icon={Megaphone}>
                        <p>DEALDIRECT runs a Customer Acquisition Program for Buyers to service unserviceable locations for additional benefits. Interested Buyers should contact their respective field executives. Selection is at DEALDIRECT's discretion per its terms and conditions.</p>
                    </Accordion>
                </>)}

                {/* ═══════════ III. SELLER TERMS ═══════════ */}
                {activeTab === "seller" && (<>
                    <div className="bg-gradient-to-r from-purple-50 to-violet-50 border border-purple-100 rounded-2xl p-5 text-sm text-gray-700">
                        <p>These Seller Terms apply only to <strong>Sellers</strong> and shall be read with the General Terms. In case of conflict, Seller Terms prevail.</p>
                    </div>

                    <Accordion title="1. Definitions" icon={BookOpen} defaultOpen>
                        <ul className="space-y-2 text-sm">
                            <LI><strong>"S&D Services"</strong> — Standard Platform Services, Payment & Settlement Services, Standard Warehousing Services, goods handling and allied services.</LI>
                            <LI><strong>"Standard Platform Services"</strong> — use and access of the Platform for creation, display, updating of product listings and subsequent sale transactions.</LI>
                            <LI><strong>"Standard Warehousing Services"</strong> — storage, handling, tertiary packaging, printing invoices, special access to fulfil Orders.</LI>
                            <LI><strong>"Payment and Settlement Services"</strong> — remittance and settlement of payments collected from Buyers to designated Seller bank accounts.</LI>
                            <LI><strong>"TPID"</strong> — Tampering proof identifier affixed on Shipment.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="3. Seller's Obligations, Representations & Warranties" icon={ShieldCheck}>
                        <ul className="space-y-3">
                            <LI>You are a lawfully incorporated business entity with full authority. You will use the Platform for <strong>business purposes only</strong>.</LI>
                            <LI>User Content does not infringe any Third Party Rights. You have the right to sell, trade, distribute or export the Products.</LI>
                            <LI>Consignment descriptions (weight, content, measure, quality, condition, value) are complete and accurate.</LI>
                            <LI>Shipments are properly packed, labelled, and comply with all applicable laws and regulations.</LI>
                            <LI>Seller shall comply with packaging guidelines communicated by DEALDIRECT.</LI>
                            <LI>Seller shall not enclose cash, digital currency, Dangerous Goods, firearms, or prohibited products in Shipments. Non-compliance results in full indemnification to DEALDIRECT.</LI>
                            <LI>Seller is solely responsible for accurate value declaration, GST compliance, on-time handover, raising invoices directly on Buyer.</LI>
                            <LI>Sellers must behave professionally with delivery associates. Misbehaviour may lead to removal of selling privileges.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="4. Audits" icon={Eye}>
                        <p>DEALDIRECT may conduct random audits of Shipments and warehouse Products. Non-compliance penalties include:</p>
                        <ul className="list-disc pl-5 space-y-2 mt-2">
                            <li>Warning letter</li>
                            <li>For invoice non-inclusion: higher of ₹1,000 or total invoice value of audited Shipment</li>
                            <li>For other non-compliance: higher of 2× product value or total invoice value</li>
                            <li>Account deactivation or suspension</li>
                        </ul>
                    </Accordion>

                    <Accordion title="5. Fees and Charges for S&D Services" icon={CreditCard}>
                        <ul className="space-y-3">
                            <LI>Seller pays <strong>S&D Fee</strong> calculated on total invoice value of the Order.</LI>
                            <LI>S&D Fee is communicated via Platform or other modes. Continued use = deemed acceptance of fee changes.</LI>
                            <LI>Seller authorizes DEALDIRECT to adjust S&D Fee from amounts collected from Buyers.</LI>
                            <LI>S&D Fee is subject to applicable taxes. Seller shall deduct income tax as applicable and provide withholding certificates.</LI>
                            <LI>DEALDIRECT may levy penalties or late payment charges for delayed dues and cancellation charges for cancelled Orders.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="6(i). Standard Platform Services" icon={FileText}>
                        <ul className="space-y-3">
                            <LI>You may list Products subject to compliance with Seller Terms. Products must not infringe any IP or proprietary rights.</LI>
                            <LI>All products must be listed in appropriate categories, kept in stock, and descriptions must not be misleading.</LI>
                            <LI>Products sold shall be for Buyer's <strong>resale or commercial purpose</strong> only, not personal consumption.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="6(ii). Standard Warehousing Services" icon={Warehouse}>
                        <ul className="space-y-3">
                            <LI>DEALDIRECT may provide Standard Warehousing Services and sub-contract them. DEALDIRECT shall take commercially reasonable security precautions.</LI>
                            <LI>Seller authorizes DEALDIRECT to undertake insurance for Products and claim insurance in event of loss.</LI>
                            <LI>DEALDIRECT is not responsible for Products found damaged at warehouse delivery. Products not meeting packaging guidelines may be rejected.</LI>
                            <LI>Products remain property of Seller until delivered to Buyer. DEALDIRECT has a <strong>lien</strong> on Products for unpaid amounts.</LI>
                            <LI>Seller is responsible for all licenses, registrations, permits, product recalls, and shall indemnify DEALDIRECT.</LI>
                            <LI><strong>Returns:</strong> Products returned for physical damage/wrong product are sent to designated warehouse. If damaged due to DEALDIRECT, order value is reimbursed. Products returned for manufacturing/quality defects are returned to Seller.</LI>
                            <LI><strong>Undelivered Shipments:</strong> Undamaged products are inventorized. Damaged products (attributable to DEALDIRECT) are reimbursed.</LI>
                            <LI>Returned Products delivered within <strong>90 days</strong>. Seller can raise disputes within <strong>72 hours</strong> of delivery.</LI>
                            <LI><strong>Termination:</strong> Seller gives 90 days' written notice. DEALDIRECT gives 15 days' notice or immediate termination for breach. Products must be picked up within 7 days or DEALDIRECT may dispose them.</LI>
                        </ul>
                    </Accordion>

                    <Accordion title="6(iii). Payment and Settlement Services" icon={CreditCard}>
                        <ul className="space-y-3">
                            <LI>DEALDIRECT acts as a <strong>payment collector in fiduciary capacity</strong> only.</LI>
                            <LI>Post-dated cheque bounces are the Buyer's sole responsibility.</LI>
                            <LI>DEALDIRECT may withhold settlements for suspicious or fraudulent transactions.</LI>
                        </ul>
                        <div className="bg-blue-50 border border-blue-100 rounded-xl p-4 mt-3">
                            <p className="font-semibold text-blue-800 mb-2">Settlement Timelines:</p>
                            <ul className="text-sm space-y-1 text-blue-700">
                                <li>• <strong>Non-food products:</strong> 20 bank working days from delivery (settled on Tuesdays or Fridays)</li>
                                <li>• <strong>Pharmaceuticals & fulfilment material:</strong> 2 bank working days from delivery</li>
                                <li>• <strong>Food, FMCG & fresh:</strong> 4 bank working days from delivery</li>
                                <li>• <strong>Online pre-payments:</strong> T+1 bank working days (T = N+65 days from order date)</li>
                            </ul>
                        </div>
                        <p className="mt-3 text-sm">Settlements include deductions for S&D Fees, refunds, applicable taxes (TCS under GST, TDS under Income Tax Act). Seller must provide correct GST registration number and HSN codes.</p>
                    </Accordion>

                    <Accordion title="6(iv). Additional Services" icon={Megaphone}>
                        <div className="space-y-4">
                            <div className="border-l-4 border-blue-500 pl-4">
                                <h4 className="font-bold text-gray-800">a. Advertisement Services</h4>
                                <p className="text-sm mt-1">Seller may subscribe to the ad program to promote Products. Seller retains IP rights in Ads and grants DEALDIRECT a non-exclusive, royalty-free license. Seller is solely liable for Ad content and indemnifies DEALDIRECT. Charges may be adjusted from Buyer payments.</p>
                            </div>
                            <div className="border-l-4 border-green-500 pl-4">
                                <h4 className="font-bold text-gray-800">b. From Pay Services</h4>
                                <p className="text-sm mt-1">DEALDIRECT may charge logistics/delivery charges from the Seller instead of Buyer. Charges subject to applicable taxes and may be modified at DEALDIRECT's discretion. For undelivered shipments, no charges are levied on Seller. For delivered-then-returned orders, Seller is liable for charges.</p>
                            </div>
                            <p className="text-sm"><strong>Taxes:</strong> Seller shall deduct income tax as applicable, remit to authorities, and provide withholding certificates to enable DEALDIRECT to claim tax credit.</p>
                        </div>
                    </Accordion>

                    <Accordion title="8. Limitation of Liability and Indemnity" icon={AlertTriangle}>
                        <p>We shall not be liable for claims arising from: your acts/omissions; government orders; packing insufficiency; shipment nature; riots; strikes; fire; flood; storm; explosion; any unavoidable cause; loss or damage to Shipment; and/or Seller-Buyer disputes.</p>
                        <p className="mt-3">Seller indemnifies DEALDIRECT from all damages, losses, claims arising from: User Content; Platform use; Terms breach; third-party services; Product defects/liability; negligence/misconduct; counterfeit products or IP infringement; personal injury/death/property damage; and consumer protection claims.</p>
                    </Accordion>

                    <Accordion title="9. Trade Credit by Seller(s)" icon={HandshakeIcon}>
                        <ul className="space-y-3">
                            <LI>Sellers intending to grant <strong>Trade Credit (TC)</strong> to Buyers may send a request to the registered office with intended terms.</LI>
                            <LI>DEALDIRECT will respond within <strong>7 working days</strong>. Final decision on TC enablement rests with DEALDIRECT.</LI>
                            <LI>TC is governed by separate terms between Buyer and Seller. DEALDIRECT disclaims all liability regarding TC.</LI>
                        </ul>
                    </Accordion>
                </>)}
            </div>
        </div>
    );
};

export default TermsAndConditions;