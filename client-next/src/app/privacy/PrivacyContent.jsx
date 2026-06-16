'use client';

import React, { useEffect, useState } from "react";
import {
    Shield, Lock, Eye, FileText, Server, Share2, Cookie, Mail, ChevronRight
} from "lucide-react";

const PrivacyPolicy = () => {
    const [activeSection, setActiveSection] = useState("introduction");
    useEffect(() => { window.scrollTo({ top: 0, left: 0, behavior: "auto" }); }, []);

    const sections = [
        { id: "introduction", title: "Introduction", icon: Shield },
        { id: "information-collection", title: "Information We Collect", icon: FileText },
        { id: "data-usage", title: "How We Use Your Data", icon: Server },
        { id: "data-sharing", title: "Data Sharing & Disclosure", icon: Share2 },
        { id: "security", title: "Data Security", icon: Lock },
        { id: "cookies", title: "Cookies & Tracking", icon: Cookie },
        { id: "rights", title: "Your Rights", icon: Eye },
        { id: "contact", title: "Contact & Grievance", icon: Mail },
    ];

    const scrollToSection = (id) => {
        const el = document.getElementById(id);
        if (el) {
            const offset = 100;
            const pos = el.getBoundingClientRect().top + window.scrollY - offset;
            window.scrollTo({ top: pos, behavior: "smooth" });
            setActiveSection(id);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 font-sans">
            {/* Header */}
            <div className="bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white py-16 px-6 relative overflow-hidden">
                <div className="absolute inset-0 opacity-10 bg-[radial-gradient(circle_at_70%_50%,#10b981,transparent_70%)]" />
                <div className="max-w-7xl mx-auto text-center relative z-10">
                    <div className="flex justify-center mb-6">
                        <div className="p-4 bg-white/10 rounded-full backdrop-blur-md">
                            <Shield className="w-12 h-12 text-emerald-400" />
                        </div>
                    </div>
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">Privacy Policy</h1>
                    <p className="text-slate-400 max-w-2xl mx-auto text-lg">
                        At DealDirect, operated by <strong className="text-white">Agrawal Business Network LLP</strong>, we value your trust. This policy outlines how we collect, use, and protect your information on our B2B platform.
                    </p>
                    <p className="text-slate-500 text-sm mt-4">Last Updated: February 2026</p>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 flex flex-col lg:flex-row gap-12">
                {/* Sidebar */}
                <div className="lg:w-1/4 hidden lg:block">
                    <div className="sticky top-28 bg-white rounded-2xl shadow-sm border border-gray-200 p-2">
                        {sections.map((s) => (
                            <button key={s.id} onClick={() => scrollToSection(s.id)}
                                className={`w-full flex items-center justify-between p-3 rounded-xl text-sm font-medium transition-all duration-200 ${activeSection === s.id ? "bg-emerald-50 text-emerald-700 shadow-sm" : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"}`}>
                                <div className="flex items-center gap-3">
                                    <s.icon className={`w-4 h-4 ${activeSection === s.id ? "text-emerald-600" : "text-gray-400"}`} />
                                    {s.title}
                                </div>
                                {activeSection === s.id && <ChevronRight className="w-4 h-4" />}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Content */}
                <div className="lg:w-3/4 space-y-12">
                    <section id="introduction" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Introduction</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 leading-relaxed space-y-4">
                            <p>Welcome to <strong>DealDirect</strong>, a venture by <strong>Agrawal Business Network LLP</strong>. This Privacy Policy is published in accordance with the provisions of the Information Technology Act, 2000, the Information Technology (Reasonable Security Practices and Procedures and Sensitive Personal Data or Information) Rules, 2011, and the IT (Intermediary Guidelines and Digital Media Ethics Code) Rules, 2021.</p>
                            <p>This policy explains how we collect, use, disclose, and safeguard your information when you visit our website (<strong>www.dealdirect.in</strong>), use our mobile application, or engage with our B2B services. By using DealDirect, you consent to the data practices described in this policy.</p>
                            <p>The Platform is a <strong>business-to-business (B2B)</strong> platform. All data collection is done in the context of commercial/business use.</p>
                        </div>
                    </section>

                    <section id="information-collection" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Information We Collect</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 space-y-6">
                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">1. Business & Identity Information</h3>
                                <ul className="list-disc pl-5 text-gray-600 space-y-1">
                                    <li><strong>Registration Data:</strong> Business name, entity type, name, email, phone number, business address.</li>
                                    <li><strong>Verification Data:</strong> PAN, Aadhaar, GST registration number, and other documents as required for account verification.</li>
                                    <li><strong>Bank Details:</strong> Bank account information for payment settlement purposes.</li>
                                </ul>
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">2. Transaction Data</h3>
                                <p className="text-gray-600">Order details, product listings, payment history, invoices, delivery notes, and settlement records.</p>
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">3. Communications</h3>
                                <p className="text-gray-600">Messages exchanged between Buyers and Sellers via the Platform, support tickets, and grievance submissions.</p>
                            </div>
                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">4. Technical Data</h3>
                                <p className="text-gray-600">IP address, browser type, device information, access times, pages viewed, and referring URL.</p>
                            </div>
                        </div>
                    </section>

                    <section id="data-usage" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">How We Use Your Data</h2>
                        <div className="grid md:grid-cols-2 gap-4">
                            {[
                                { title: "Account Management", desc: "To register and manage your account, verify identity, and maintain your business profile on the Platform." },
                                { title: "Order Fulfilment", desc: "To process orders, manage logistics, coordinate deliveries, handle payments and settlements between Buyers and Sellers." },
                                { title: "Communication", desc: "To send OTPs, order confirmations, delivery updates, payment notifications via email, SMS, WhatsApp, or in-app notifications." },
                                { title: "Legal & Tax Compliance", desc: "To comply with GST, TDS/TCS obligations, and other regulatory requirements under Indian law." },
                                { title: "Platform Improvement", desc: "To analyse usage patterns, improve services, develop new features, and enhance user experience." },
                                { title: "Security & Fraud Prevention", desc: "To detect and prevent fraud, unauthorized access, and other illegal activities on the Platform." },
                            ].map((item, i) => (
                                <div key={i} className="bg-white p-5 rounded-2xl border border-gray-200">
                                    <h3 className="font-semibold text-gray-800 mb-2">{item.title}</h3>
                                    <p className="text-sm text-gray-600">{item.desc}</p>
                                </div>
                            ))}
                        </div>
                    </section>

                    <section id="data-sharing" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Data Sharing & Disclosure</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 space-y-4">
                            <p>We do not sell your personal data. However, we may share data in the following circumstances:</p>
                            <ul className="space-y-3">
                                {[
                                    { label: "Between Buyers & Sellers", text: "Transaction-related information is shared between parties to facilitate orders, deliveries, and payments." },
                                    { label: "Third-Party Service Providers", text: "We engage logistics partners, payment processors, warehousing partners, and technology providers who process data on our behalf." },
                                    { label: "Verification Partners", text: "Identity and business verification services to validate your account information." },
                                    { label: "Legal Requirements", text: "We may disclose information if required by law, court order, government authority, or to protect our rights and safety." },
                                    { label: "With Your Consent", text: "Any other sharing will be done with your explicit consent." },
                                ].map((item, i) => (
                                    <li key={i} className="flex gap-3">
                                        <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-emerald-500 mt-2" />
                                        <span><strong>{item.label}:</strong> {item.text}</span>
                                    </li>
                                ))}
                            </ul>
                        </div>
                    </section>

                    <section id="security" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Data Security</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200">
                            <p className="text-gray-600 mb-4">We implement robust security measures to protect your data, including:</p>
                            <div className="grid md:grid-cols-3 gap-4 text-center">
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Lock className="w-8 h-8 text-green-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Encryption</h4>
                                    <p className="text-xs text-gray-500">Passwords are hashed. Data is encrypted in transit (SSL/TLS).</p>
                                </div>
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Shield className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Secure Access</h4>
                                    <p className="text-xs text-gray-500">Token-based authentication and role-based access controls.</p>
                                </div>
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Eye className="w-8 h-8 text-purple-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Monitoring</h4>
                                    <p className="text-xs text-gray-500">Regular security audits and infrastructure monitoring.</p>
                                </div>
                            </div>
                        </div>
                    </section>

                    <section id="cookies" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Cookies & Tracking</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 space-y-3">
                            <p>We use cookies and similar tracking technologies to enhance your experience:</p>
                            <ul className="list-disc pl-5 space-y-2">
                                <li><strong>Essential Cookies:</strong> Required for authentication, session management, and security.</li>
                                <li><strong>Analytics Cookies:</strong> Help us understand how users interact with the Platform to improve performance.</li>
                                <li><strong>Preference Cookies:</strong> Store your language and display preferences.</li>
                            </ul>
                            <p>You can manage cookie preferences through your browser settings. Disabling cookies may affect Platform functionality.</p>
                        </div>
                    </section>

                    <section id="rights" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Your Rights</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 space-y-3">
                            <p>Subject to applicable law, you have the right to:</p>
                            <ul className="list-disc pl-5 space-y-2">
                                <li><strong>Access:</strong> Request access to your personal data held by us.</li>
                                <li><strong>Correction:</strong> Request correction of inaccurate or incomplete data.</li>
                                <li><strong>Deletion:</strong> Request deletion of your account and associated data (subject to legal retention requirements).</li>
                                <li><strong>Withdraw Consent:</strong> Withdraw consent for data processing, where applicable.</li>
                                <li><strong>Data Portability:</strong> Request a copy of your data in a structured, machine-readable format.</li>
                            </ul>
                            <p>To exercise any of these rights, please contact our Grievance Officer using the details below.</p>
                        </div>
                    </section>

                    <section id="contact" className="scroll-mt-28 mb-20">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Contact & Grievance Officer</h2>
                        <div className="bg-slate-900 text-white p-8 rounded-3xl">
                            <p className="mb-6 text-slate-300">If you have questions about this Privacy Policy, wish to exercise your data rights, or have any grievance, please contact:</p>
                            <div className="space-y-4">
                                <div>
                                    <p className="font-bold text-lg">Arti Jadhav</p>
                                    <p className="text-slate-400 text-sm">Grievance Officer</p>
                                </div>
                                <div className="flex items-center gap-3">
                                    <Mail className="text-emerald-400" />
                                    <span>grievance@dealdirect.in</span>
                                </div>
                                <div className="flex items-start gap-3">
                                    <Server className="text-emerald-400 mt-1" />
                                    <div>
                                        <p className="font-semibold">Agrawal Business Network LLP</p>
                                        <p className="text-slate-400 text-sm">Growmore tower sector 2, plot no 5,<br />kharghar, Navi Mumbai 410210</p>
                                    </div>
                                </div>
                                <p className="text-slate-400 text-sm">Phone: +91 92-8963 8963 | Mon – Fri (10:00 AM – 06:00 PM)</p>
                            </div>
                        </div>
                    </section>
                </div>
            </div>
        </div>
    );
};

export default PrivacyPolicy;