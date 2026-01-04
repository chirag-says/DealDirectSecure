import React, { useEffect, useState } from "react";
import {
    Shield,
    Lock,
    Eye,
    FileText,
    Server,
    Share2,
    Cookie,
    Mail,
    ChevronRight
} from "lucide-react";

const PrivacyPolicy = () => {
    const [activeSection, setActiveSection] = useState("introduction");

    useEffect(() => {
        window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    }, []);

    const sections = [
        { id: "introduction", title: "Introduction", icon: Shield },
        { id: "information-collection", title: "Information We Collect", icon: FileText },
        { id: "data-usage", title: "How We Use Your Data", icon: Server },
        { id: "property-agreements", title: "Agreements & AI Services", icon: FileText },
        { id: "data-sharing", title: "Data Sharing & Disclosure", icon: Share2 },
        { id: "security", title: "Data Security", icon: Lock },
        { id: "cookies", title: "Cookies & Tracking", icon: Cookie },
        { id: "contact", title: "Contact Us", icon: Mail },
    ];

    const scrollToSection = (id) => {
        const element = document.getElementById(id);
        if (element) {
            const offset = 100; // Header height offset
            const bodyRect = document.body.getBoundingClientRect().top;
            const elementRect = element.getBoundingClientRect().top;
            const elementPosition = elementRect - bodyRect;
            const offsetPosition = elementPosition - offset;

            window.scrollTo({
                top: offsetPosition,
                behavior: "smooth"
            });
            setActiveSection(id);
        }
    };

    return (
        <div className="min-h-screen bg-slate-50 font-sans">

            {/* Header */}
            <div className="bg-slate-900 text-white py-16 px-6">
                <div className="max-w-7xl mx-auto text-center">
                    <div className="flex justify-center mb-6">
                        <div className="p-4 bg-white/10 rounded-full backdrop-blur-md">
                            <Shield className="w-12 h-12 text-blue-400" />
                        </div>
                    </div>
                    <h1 className="text-4xl md:text-5xl font-bold mb-4">Privacy Policy</h1>
                    <p className="text-slate-400 max-w-2xl mx-auto text-lg">
                        At DealDirect, we value your trust. This policy outlines how IshiSoftTech Pvt Ltd collects, uses, and protects your personal information.
                    </p>
                    <p className="text-slate-500 text-sm mt-4">Last Updated: December 2025</p>
                </div>
            </div>

            <div className="max-w-7xl mx-auto px-4 sm:px-6 py-12 flex flex-col lg:flex-row gap-12">

                {/* Sidebar Navigation (Sticky) */}
                <div className="lg:w-1/4 hidden lg:block">
                    <div className="sticky top-28 bg-white rounded-2xl shadow-sm border border-gray-200 p-2">
                        {sections.map((section) => (
                            <button
                                key={section.id}
                                onClick={() => scrollToSection(section.id)}
                                className={`w-full flex items-center justify-between p-3 rounded-xl text-sm font-medium transition-all duration-200 ${activeSection === section.id
                                    ? "bg-blue-50 text-blue-700 shadow-sm"
                                    : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"
                                    }`}
                            >
                                <div className="flex items-center gap-3">
                                    <section.icon className={`w-4 h-4 ${activeSection === section.id ? "text-blue-600" : "text-gray-400"}`} />
                                    {section.title}
                                </div>
                                {activeSection === section.id && <ChevronRight className="w-4 h-4" />}
                            </button>
                        ))}
                    </div>
                </div>

                {/* Content Area */}
                <div className="lg:w-3/4 space-y-12">

                    {/* Introduction */}
                    <section id="introduction" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                            Introduction
                        </h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 leading-relaxed">
                            <p className="mb-4">
                                Welcome to <strong>DealDirect</strong>, a venture by <strong>IshiSoftTech Pvt Ltd</strong>. We are committed to protecting your privacy and ensuring the security of your personal data.
                            </p>
                            <p>
                                This Privacy Policy explains how we collect, use, disclose, and safeguard your information when you visit our website, use our mobile application, or engage with our services such as property listings, chat systems, and agreement generation tools. By using DealDirect, you consent to the data practices described in this policy.
                            </p>
                        </div>
                    </section>

                    {/* Information We Collect */}
                    <section id="information-collection" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Information We Collect</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 space-y-6">

                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">1. Personal Information</h3>
                                <ul className="list-disc pl-5 text-gray-600 space-y-1">
                                    <li><strong>Identity Data:</strong> Name, email address, phone number, and profile photographs.</li>
                                    <li><strong>Verification Data:</strong> For property owners, we may collect ownership documents. For agreement generation, we collect details such as Age, Aadhaar Number (last 4 digits stored for reference), and permanent address.</li>
                                </ul>
                            </div>

                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">2. Property Data</h3>
                                <p className="text-gray-600">
                                    When you list a property, we collect details including physical address, photos (interior/exterior), pricing, amenities, and legal compliance details (RERA ID, Occupancy Certificate).
                                </p>
                            </div>

                            <div>
                                <h3 className="text-lg font-semibold text-gray-800 mb-2">3. Communications</h3>
                                <p className="text-gray-600">
                                    We store messages exchanged between buyers and sellers via our in-platform Chat System to ensure safety, prevent fraud, and improve service quality.
                                </p>
                            </div>
                        </div>
                    </section>

                    {/* How We Use Your Data */}
                    <section id="data-usage" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">How We Use Your Data</h2>
                        <div className="grid md:grid-cols-2 gap-4">
                            <div className="bg-white p-5 rounded-2xl border border-gray-200">
                                <h3 className="font-semibold text-gray-800 mb-2">Lead Generation</h3>
                                <p className="text-sm text-gray-600">
                                    To connect interested buyers with property owners. When you click "I'm Interested," your contact details are shared with the property owner.
                                </p>
                            </div>
                            <div className="bg-white p-5 rounded-2xl border border-gray-200">
                                <h3 className="font-semibold text-gray-800 mb-2">Service Delivery</h3>
                                <p className="text-sm text-gray-600">
                                    To manage your account, facilitate property listings, process chat messages, and calculate financial estimates (EMI).
                                </p>
                            </div>
                            <div className="bg-white p-5 rounded-2xl border border-gray-200">
                                <h3 className="font-semibold text-gray-800 mb-2">Communication</h3>
                                <p className="text-sm text-gray-600">
                                    To send you OTPs for verification, alerts about new leads, and updates regarding your property status.
                                </p>
                            </div>
                            <div className="bg-white p-5 rounded-2xl border border-gray-200">
                                <h3 className="font-semibold text-gray-800 mb-2">Security</h3>
                                <p className="text-sm text-gray-600">
                                    To detect and prevent fraud, spam, and abuse of our services.
                                </p>
                            </div>
                        </div>
                    </section>

                    {/* Agreement & AI Services */}
                    <section id="property-agreements" className="scroll-mt-28">
                        <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-100 p-6 rounded-2xl">
                            <h2 className="text-2xl font-bold text-gray-900 mb-4 flex items-center gap-2">
                                <FileText className="text-blue-600" />
                                Agreements & AI Services
                            </h2>
                            <p className="text-gray-700 mb-4">
                                DealDirect offers an AI-powered Agreement Generator. When using this feature:
                            </p>
                            <ul className="list-disc pl-5 text-gray-600 space-y-2">
                                <li>
                                    <strong>Data Processing:</strong> Information provided for agreements (Names, Addresses, Rent amounts) is processed using Google's Generative AI API to draft legal text.
                                </li>
                                <li>
                                    <strong>Data Retention:</strong> We do not permanently store the full text of generated agreements on our servers for privacy reasons. Users are encouraged to download PDFs immediately.
                                </li>
                                <li>
                                    <strong>Accuracy:</strong> While we strive for accuracy, AI-generated documents are for reference only. We recommend legal verification before signing.
                                </li>
                            </ul>
                        </div>
                    </section>

                    {/* Data Sharing */}
                    <section id="data-sharing" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Data Sharing & Disclosure</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200 text-gray-600 space-y-4">
                            <p>We do not sell your personal data. However, we may share data in the following circumstances:</p>
                            <ul className="space-y-3">
                                <li className="flex gap-3">
                                    <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-500 mt-2"></span>
                                    <span><strong>With Property Owners/Agents:</strong> If you express interest in a property, your name, email, and phone number are shared with the lister to facilitate the transaction.</span>
                                </li>
                                <li className="flex gap-3">
                                    <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-500 mt-2"></span>
                                    <span><strong>Service Providers:</strong> We use third-party services like Cloudinary (for image hosting) and Google (for maps and AI services). Data sent to these providers is strictly for functional purposes.</span>
                                </li>
                                <li className="flex gap-3">
                                    <span className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-500 mt-2"></span>
                                    <span><strong>Legal Requirements:</strong> We may disclose information if required by law, court order, or government regulation.</span>
                                </li>
                            </ul>
                        </div>
                    </section>

                    {/* Security */}
                    <section id="security" className="scroll-mt-28">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Data Security</h2>
                        <div className="bg-white p-6 rounded-2xl shadow-sm border border-gray-200">
                            <p className="text-gray-600 mb-4">
                                We implement robust security measures to protect your data, including:
                            </p>
                            <div className="grid md:grid-cols-3 gap-4 text-center">
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Lock className="w-8 h-8 text-green-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Encryption</h4>
                                    <p className="text-xs text-gray-500">Passwords are hashed using BCrypt.</p>
                                </div>
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Shield className="w-8 h-8 text-blue-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Secure Access</h4>
                                    <p className="text-xs text-gray-500">JWT Authentication for API access.</p>
                                </div>
                                <div className="p-4 bg-slate-50 rounded-xl">
                                    <Eye className="w-8 h-8 text-purple-500 mx-auto mb-2" />
                                    <h4 className="font-semibold text-gray-800">Monitoring</h4>
                                    <p className="text-xs text-gray-500">Regular audits of our infrastructure.</p>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* Contact */}
                    <section id="contact" className="scroll-mt-28 mb-20">
                        <h2 className="text-2xl font-bold text-gray-900 mb-4">Contact Us</h2>
                        <div className="bg-slate-900 text-white p-8 rounded-3xl">
                            <p className="mb-6 text-slate-300">
                                If you have questions about this Privacy Policy or wish to exercise your data rights, please contact our Data Protection Officer.
                            </p>
                            <div className="space-y-4">
                                <div className="flex items-center gap-3">
                                    <Mail className="text-blue-400" />
                                    <span>support@dealdirect.in</span>
                                </div>
                                <div className="flex items-start gap-3">
                                    <Server className="text-blue-400 mt-1" />
                                    <div>
                                        <p className="font-semibold">IshiSoftTech Pvt Ltd</p>
                                        <p className="text-slate-400 text-sm">
                                            123 Innovation Park, Tech Hub,<br />
                                            Mumbai, Maharashtra 400001
                                        </p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                </div>
            </div>
        </div>
    );
};

export default PrivacyPolicy;