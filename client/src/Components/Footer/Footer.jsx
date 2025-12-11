import React, { useState } from "react";
import { Link } from "react-router-dom";
import { ToastContainer, toast } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";
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

    ],
    "Support": [
      { name: "Help Center", path: "/contact" },
      { name: "Contact Us", path: "/contact" },
      { name: "Privacy Policy", path: "/privacy" },
      { name: "Terms of Service", path: "/terms" }
    ]
  };

  const cities = ["Mumbai", "Delhi", "Bangalore", "Pune", "Hyderabad", "Chennai"];

  const socialLinks = [
    { icon: <AiOutlineFacebook />, name: "Facebook", url: "https://facebook.com" },
    { icon: <AiOutlineTwitter />, name: "Twitter", url: "https://twitter.com" },
    { icon: <AiOutlineInstagram />, name: "Instagram", url: "https://instagram.com" },
    { icon: <AiOutlineYoutube />, name: "Youtube", url: "https://youtube.com" }
  ];

  return (
    <footer className="bg-slate-950 text-white pt-16 pb-8 border-t border-slate-900">
      {/* Toast Container for notifications */}
      <ToastContainer position="bottom-right" theme="dark" />

      <div className="max-w-7xl mx-auto px-6">

        {/* Top Section */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-12 pb-12 border-b border-slate-800">

          {/* Brand & Contact */}
          <div className="space-y-6">
            <Link to="/" className="inline-block">
              <img
                src={logo}
                alt="DealDirect"
                className="h-12 w-auto object-contain"
              />
            </Link>
            <p className="text-gray-400 text-sm leading-relaxed max-w-xs">
              Bridging the gap between owners and seekers. No middlemen, just seamless property deals.
            </p>
            <div className="space-y-4 text-gray-300 text-sm">
              <a href="mailto:hello@dealdirect.com" className="flex items-center gap-3 hover:text-red-500 transition-colors">
                <AiOutlineMail className="text-red-500 text-lg flex-shrink-0" />
                <span>hello@dealdirect.com</span>
              </a>
              <a href="tel:+9118001234567" className="flex items-center gap-3 hover:text-red-500 transition-colors">
                <AiOutlinePhone className="text-red-500 text-lg flex-shrink-0" />
                <span>+91 1800-123-4567</span>
              </a>
              <div className="flex items-center gap-3">
                <AiOutlineEnvironment className="text-red-500 text-lg flex-shrink-0" />
                <span>Mumbai, India</span>
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
                      to={link.path}
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
                    to={`/properties?city=${city}`}
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
          <p>&copy; {currentYear} DealDirect. All rights reserved.</p>

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
            <Link to="/privacy" className="hover:text-red-500 transition-colors">Privacy Policy</Link>
            <Link to="/terms" className="hover:text-red-500 transition-colors">Terms of Service</Link>
            <Link to="/contact" className="hover:text-red-500 transition-colors">Contact</Link>
          </div>
        </div>

      </div>
    </footer>
  );
};

export default Footer;
