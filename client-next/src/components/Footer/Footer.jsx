'use client';

import React, { useState } from "react";
import Link from "next/link";
import { toast } from "react-toastify";

import {
  AiOutlineMail,
  AiOutlinePhone,
  AiOutlineFacebook,
  AiOutlineTwitter,
  AiOutlineInstagram,
  AiOutlineLinkedin,
  AiOutlineEnvironment,
  AiOutlineYoutube
} from "react-icons/ai";
// Inline X/Twitter SVG to avoid importing the entire react-icons/fa6 bundle (~2.5MB)
const FaXTwitter = (props) => (
  <svg stroke="currentColor" fill="currentColor" strokeWidth="0" viewBox="0 0 512 512" height="1em" width="1em" {...props}>
    <path d="M389.2 48h70.6L305.6 224.2 487 464H345L233.7 318.6 106.5 464H35.8L200.7 275.5 26.8 48H172.4L272.9 180.9 389.2 48zM364.4 421.8h39.1L151.1 88h-42L364.4 421.8z" />
  </svg>
);
import logo from "../../assets/dealdirect_logo.png";

const Footer = () => {
  const currentYear = new Date().getFullYear();
  const [email, setEmail] = useState("");

  const handleSubscribe = (e) => {
    e.preventDefault();
    if (!email || !/\S+@\S+\.\S+/.test(email)) {
      toast.error("Please enter a valid email address.");
      return;
    }
    // Simulate API call
    setTimeout(() => {
      toast.success("Subscribed successfully!");
      setEmail("");
    }, 500);
  };

  const quickLinks = {
    "Buy": [
      { name: "Apartment / Flat", path: "/properties?search=Apartment&availableFor=Sell" },
      { name: "Independent House", path: "/properties?search=Independent House&availableFor=Sell" },
      { name: "Villa", path: "/properties?search=Villa&availableFor=Sell" },
      { name: "Builder Floor", path: "/properties?search=Builder Floor&availableFor=Sell" }
    ],
    "Rent": [
      { name: "Apartment / Flat", path: "/properties?search=Apartment&availableFor=Rent" },
      { name: "Independent House", path: "/properties?search=Independent House&availableFor=Rent" },
      { name: "Villa", path: "/properties?search=Villa&availableFor=Rent" },
      { name: "Builder Floor", path: "/properties?search=Builder Floor&availableFor=Rent" },
      { name: "PG / Hostel", path: "/properties?search=PG&availableFor=Rent" }
    ],
    "Company": [
      { name: "About Us", path: "/about" },
      { name: "Why Us?", path: "/why-us" },
      { name: "FAQs", path: "/faq" },
    ],
    "Support": [
      { name: "Contact Us", path: "/contact" },
      { name: "Privacy Policy", path: "/privacy" },
      { name: "Terms of Use", path: "/terms" }
    ]
  };

  const cities = ["Mumbai", "Delhi", "Bangalore", "Pune", "Hyderabad", "Chennai"];

  const socialLinks = [
    { icon: <AiOutlineFacebook />, name: "Facebook", url: "https://facebook.com/dealdirect" },
    { icon: <FaXTwitter />, name: "X", url: "https://x.com/dealdirect" },
    { icon: <AiOutlineInstagram />, name: "Instagram", url: "https://instagram.com/dealdirect" },
    { icon: <AiOutlineLinkedin />, name: "LinkedIn", url: "https://linkedin.com/company/dealdirect" },
    { icon: <AiOutlineYoutube />, name: "Youtube", url: "https://youtube.com/@dealdirect" }
  ];

  return (
    <footer className="bg-slate-950 text-white pt-16 pb-8 border-t border-slate-900">
      <div className="max-w-7xl mx-auto px-6">

        {/* Top Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 pb-12 border-b border-slate-800">

          {/* Brand & Contact */}
          <div className="space-y-6">
            <Link href="/" className="inline-block">
              <img
                src={logo.src}
                alt="DealDirect"
                className="h-12 w-auto object-contain"
              />
            </Link>
            <p className="text-gray-400 text-sm leading-relaxed max-w-xs">
              Bridging the gap between owners and seekers. No middlemen, just seamless property deals.
            </p>
            <div className="space-y-4 text-gray-300 text-sm">
              <a href="mailto:contact@dealdirect.in" className="flex items-center gap-3 hover:text-red-500 transition-colors">
                <AiOutlineMail className="text-red-500 text-lg flex-shrink-0" />
                <span>contact@dealdirect.in</span>
              </a>
              <a href="tel:+919289638963" className="flex items-center gap-3 hover:text-red-500 transition-colors">
                <AiOutlinePhone className="text-red-500 text-lg flex-shrink-0" />
                <span>+91 92 8963 8963</span>
              </a>
              <div className="flex items-start gap-3">
                <AiOutlineEnvironment className="text-red-500 text-lg flex-shrink-0 mt-0.5" />
                <div className="leading-relaxed">
                  <span className="font-medium text-gray-200">Agrawal Business Network LLP</span>
                  <p className="text-gray-400 mt-1">
                    Growmore Tower,<br />
                    Sector 2, Plot No. 5,<br />
                    Kharghar, Navi Mumbai 410210
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* Quick Links */}
          <div className="col-span-1 md:col-span-2 grid grid-cols-2 sm:grid-cols-4 gap-8">
            {Object.entries(quickLinks).map(([category, links]) => (
              <div key={category}>
                <h4 className="font-bold text-white text-base mb-6">{category}</h4>
                <div className="flex flex-col gap-3">
                  {links.map((link, idx) => (
                    <Link
                      key={idx}
                      href={link.path}
                      className="text-gray-400 text-sm hover:text-red-500 transition-colors"
                    >
                      {link.name}
                    </Link>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Newsletter */}
          <div className="space-y-6">
            <div>
              <h4 className="font-bold text-white text-base mb-6">Popular Cities</h4>
              <div className="flex flex-wrap gap-2">
                {cities.map((city, idx) => (
                  <Link
                    key={idx}
                    href={`/properties?city=${city}`}
                    className="text-gray-400 text-xs px-3 py-1.5 rounded-full bg-slate-900 border border-slate-800 hover:bg-red-600 hover:text-white hover:border-red-600 transition-all"
                  >
                    {city}
                  </Link>
                ))}
              </div>
            </div>

            <div>
              <h4 className="font-bold text-white text-base mb-4">Stay Updated</h4>
              <form onSubmit={handleSubscribe} className="flex flex-col space-y-3">
                <input
                  type="email"
                  placeholder="Your email address"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full px-4 py-3 rounded-xl bg-slate-900 text-white text-sm placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-red-600 border border-slate-800 transition-all"
                  required
                />
                <button
                  type="submit"
                  className="w-full bg-red-600 text-white px-4 py-3 rounded-xl text-sm font-semibold hover:bg-red-700 transition-all shadow-lg shadow-red-900/20"
                >
                  Subscribe
                </button>
              </form>
            </div>
          </div>
        </div>

        {/* Bottom Section */}
        <div className="mt-8 flex flex-col md:flex-row justify-between items-center gap-6 text-gray-500 text-sm">
          <p>&copy; {currentYear} Agrawal Business Network LLP. All rights reserved.</p>

          <div className="flex gap-4">
            {socialLinks.map((social, idx) => (
              <a
                key={idx}
                href={social.url}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={social.name}
                className="w-10 h-10 flex items-center justify-center rounded-full bg-slate-900 border border-slate-800 hover:bg-red-600 hover:border-red-600 hover:text-white transition-all text-lg"
              >
                {social.icon}
              </a>
            ))}
          </div>

          <div className="flex flex-wrap gap-6 text-sm">
            <Link href="/privacy" className="hover:text-red-500 transition-colors">Privacy Policy</Link>
            <Link href="/terms" className="hover:text-red-500 transition-colors">Terms of Use</Link>
            <Link href="/contact" className="hover:text-red-500 transition-colors">Contact</Link>
          </div>
        </div>

      </div>
    </footer>
  );
};

export default Footer;
