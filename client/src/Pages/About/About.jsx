import React, { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  FaBuilding,
  FaHandshake,
  FaUserShield,
  FaChartLine,
  FaUsers,
  FaCheckCircle,
  FaMapMarkerAlt,
  FaHeadset,
  FaSearch,
  FaRegCommentDots,
  FaKey,
  FaArrowRight
} from "react-icons/fa";
import { BsGraphUpArrow, BsHouseDoor } from "react-icons/bs";
import { useAuth } from "../../context/AuthContext";

export default function About() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();

  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
  }, []);

  // Navigate to login if not authenticated, otherwise to add-property
  const handleListProperty = () => {
    if (!isAuthenticated) {
      navigate('/login', { state: { from: '/add-property' } });
    } else {
      navigate('/add-property');
    }
  };

  return (
    <div className="font-sans text-gray-900 bg-white min-h-screen">

      {/* --- HERO SECTION --- */}
      <section className="relative py-16 md:py-24 bg-white overflow-hidden">
        <div className="relative z-10 max-w-6xl mx-auto px-6 text-center">
          <div className="inline-flex items-center gap-2 mb-6 px-5 py-2 rounded-full border border-red-200 bg-red-50 text-red-600 text-sm font-semibold tracking-wide uppercase">
            <FaBuilding className="text-red-500" />
            <span>India's Leading PropTech Platform</span>
          </div>

          <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight leading-tight mb-6 text-gray-900">
            About <span className="text-red-600">Deal Direct</span>
          </h1>

          <p className="text-lg md:text-xl text-gray-500 max-w-3xl mx-auto leading-relaxed mb-12">
            We're revolutionizing the way India buys, sells, and rents properties. By connecting you directly with verified property owners, we eliminate middlemen and save you lakhs in brokerage fees — making real estate transactions <strong className="text-gray-800">transparent, simple, and affordable</strong>.
          </p>

          {/* Key Metrics */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 md:gap-6 max-w-4xl mx-auto">
            {[
              { label: "Brokerage Saved", val: "₹50Cr+", icon: <BsGraphUpArrow className="text-green-500" /> },
              { label: "Happy Families", val: "10,000+", icon: <FaUsers className="text-blue-500" /> },
              { label: "Cities Covered", val: "12+", icon: <FaMapMarkerAlt className="text-orange-500" /> },
              { label: "Verified Listings", val: "100%", icon: <FaCheckCircle className="text-red-500" /> }
            ].map((stat, i) => (
              <div key={i} className="group bg-white border border-gray-100 p-5 rounded-2xl shadow-md hover:shadow-xl hover:-translate-y-1 transition-all duration-300 cursor-default">
                <div className="text-2xl mb-2">{stat.icon}</div>
                <div className="text-2xl md:text-3xl font-bold text-gray-900">{stat.val}</div>
                <div className="text-xs text-gray-500 uppercase tracking-wider mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* --- OUR STORY SECTION --- */}
      <section className="py-16 px-6 bg-gray-50 relative overflow-hidden">
        <div className="max-w-6xl mx-auto">
          <div className="grid md:grid-cols-2 gap-12 md:gap-16 items-center">
            {/* Left Content */}
            <div>
              <div className="inline-flex items-center gap-2 mb-4 px-4 py-1.5 rounded-full bg-orange-50 border border-orange-200 text-orange-600 text-sm font-medium">
                <BsHouseDoor className="text-sm" />
                Our Story
              </div>
              <h2 className="text-3xl md:text-4xl font-bold mb-6 leading-tight text-gray-900">
                Born from a Simple Question: <br />
                <span className="text-red-600">Why Pay Brokerage?</span>
              </h2>
              <div className="space-y-4 text-gray-600 leading-relaxed">
                <p>
                  Deal Direct was founded with a clear mission — to disrupt the traditional real estate brokerage model that has burdened Indian homebuyers and sellers for decades.
                </p>
                <p>
                  We realized that in an age of digital connectivity, paying 1-2% brokerage (often lakhs of rupees!) to a middleman was outdated. Property owners and buyers should be able to connect directly.
                </p>
                <p>
                  Today, we're proud to be India's fastest-growing PropTech platform, having helped thousands of families find their dream homes while saving them crores in brokerage fees.
                </p>
              </div>
            </div>

            {/* Right Visual */}
            <div className="relative">
              <div className="absolute -top-4 -left-4 w-full h-full bg-red-100 rounded-3xl"></div>
              <div className="relative bg-white rounded-3xl p-8 md:p-10 border border-gray-100 shadow-xl">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-16 h-16 rounded-2xl bg-red-600 flex items-center justify-center">
                    <BsHouseDoor className="text-3xl text-white" />
                  </div>
                  <div>
                    <h4 className="text-xl font-bold text-gray-900">Our Mission</h4>
                    <p className="text-gray-500 text-sm">What drives us every day</p>
                  </div>
                </div>
                <p className="text-gray-600 leading-relaxed text-lg italic border-l-4 border-red-500 pl-4">
                  "To make property transactions in India completely brokerage-free, transparent, and accessible to everyone — regardless of where they are or how much they have."
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* --- WHY DEAL DIRECT (VALUES) --- */}
      <section className="py-16 px-6 relative bg-white">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
              The Deal Direct <span className="text-red-600">Advantage</span>
            </h2>
            <p className="text-gray-500 text-lg max-w-2xl mx-auto">
              We're not just another property listing site. Here's what makes us different.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                icon: <FaUserShield className="text-3xl" />,
                title: "100% Verified Owners",
                desc: "Every property listing is verified. We ensure you deal only with genuine owners — no brokers, no fraud.",
                color: "bg-blue-600"
              },
              {
                icon: <FaHandshake className="text-3xl" />,
                title: "Zero Brokerage",
                desc: "Connect directly with owners and save lakhs in brokerage fees. Your money stays in your pocket.",
                color: "bg-purple-600"
              },
              {
                icon: <FaChartLine className="text-3xl" />,
                title: "Smart Insights",
                desc: "Get market trends, price history, and locality data to make informed property decisions.",
                color: "bg-green-600"
              },
              {
                icon: <FaHeadset className="text-3xl" />,
                title: "24/7 Support",
                desc: "Our dedicated support team is always ready to help you through your property journey.",
                color: "bg-orange-600"
              }
            ].map((item, i) => (
              <div
                key={i}
                className="group bg-white p-6 md:p-8 rounded-2xl border border-gray-100 shadow-md hover:shadow-xl hover:-translate-y-2 transition-all duration-300"
              >
                <div className={`w-14 h-14 rounded-2xl ${item.color} flex items-center justify-center text-white mb-5 group-hover:scale-110 transition-transform`}>
                  {item.icon}
                </div>
                <h3 className="text-lg font-bold mb-3 text-gray-900">{item.title}</h3>
                <p className="text-gray-500 text-sm leading-relaxed">{item.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* --- HOW IT WORKS --- */}
      <section className="py-16 px-6 bg-gray-50 relative overflow-hidden">
        <div className="max-w-5xl mx-auto relative z-10">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
              How <span className="text-red-600">Deal Direct</span> Works
            </h2>
            <p className="text-gray-500 text-lg max-w-2xl mx-auto">
              Three simple steps to find your perfect property or sell directly to buyers
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-10">
            {[
              {
                step: "01",
                title: "Search Properties",
                desc: "Browse thousands of verified properties. Filter by location, budget, type, and more.",
                icon: <FaSearch className="text-2xl" />,
                color: "bg-blue-600"
              },
              {
                step: "02",
                title: "Connect Directly",
                desc: "Get owner contact details instantly. No brokers, no middlemen — just direct conversation.",
                icon: <FaRegCommentDots className="text-2xl" />,
                color: "bg-purple-600"
              },
              {
                step: "03",
                title: "Close the Deal",
                desc: "Negotiate, visit, and finalize. Complete your transaction with confidence and transparency.",
                icon: <FaKey className="text-2xl" />,
                color: "bg-green-600"
              }
            ].map((item, i) => (
              <div key={i} className="group relative bg-white rounded-2xl p-8 shadow-lg hover:shadow-2xl transition-all duration-300 border border-gray-100 hover:-translate-y-2">
                <div className={`absolute -top-4 left-1/2 -translate-x-1/2 w-20 h-20 flex items-center justify-center ${item.color} rounded-2xl shadow-xl text-white group-hover:scale-110 transition-transform duration-300`}>
                  {item.icon}
                </div>
                <div className="mt-12 text-center">
                  <span className="text-xs font-bold text-gray-400 uppercase tracking-wider">Step {item.step}</span>
                  <h3 className="text-xl font-bold mt-2 mb-3 text-gray-900">{item.title}</h3>
                  <p className="text-gray-500 leading-relaxed">{item.desc}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* --- VISION SECTION --- */}
      <section className="py-16 px-6 relative bg-white overflow-hidden">
        <div className="max-w-4xl mx-auto text-center relative z-10">
          <h2 className="text-3xl md:text-4xl font-bold mb-6 leading-tight text-gray-900">
            Building a <span className="text-red-600">Brokerage-Free India</span>
          </h2>
          <p className="text-lg text-gray-600 leading-relaxed max-w-3xl mx-auto mb-10">
            We envision a future where every Indian can buy, sell, or rent property without paying a single rupee in brokerage. Through technology, transparency, and trust, we're making this vision a reality — one transaction at a time.
          </p>

          <div className="flex flex-wrap justify-center gap-3 text-sm">
            {["Transparent Pricing", "No Hidden Fees", "Verified Listings", "Direct Connections", "Secure Platform"].map((tag, i) => (
              <span key={i} className="px-4 py-2 bg-gray-50 border border-gray-200 rounded-full text-gray-600 hover:border-red-300 hover:text-red-600 transition-colors cursor-default">
                {tag}
              </span>
            ))}
          </div>
        </div>
      </section>

      {/* --- CTA SECTION --- */}
      <section className="py-16 px-6 relative overflow-hidden bg-gray-50">
        <div className="max-w-4xl mx-auto text-center relative z-10">
          <h2 className="text-3xl md:text-4xl font-bold mb-4 text-gray-900">
            Ready to Find Your <span className="text-red-600">Dream Home?</span>
          </h2>
          <p className="text-gray-500 text-lg mb-10 max-w-2xl mx-auto">
            Join thousands of happy families who found their perfect property through Deal Direct — without paying any brokerage.
          </p>
          <div className="flex flex-wrap justify-center gap-4">
            <button
              onClick={() => navigate('/properties')}
              className="bg-red-600 text-white px-8 py-4 rounded-full font-bold hover:bg-red-700 transition-all duration-300 shadow-lg hover:shadow-xl hover:scale-105 flex items-center gap-2"
            >
              Browse Properties <FaArrowRight className="text-sm" />
            </button>
            <button
              onClick={handleListProperty}
              className="bg-white text-gray-900 px-8 py-4 rounded-full font-bold border border-gray-200 hover:border-red-300 hover:text-red-600 transition-all duration-300 shadow-md hover:shadow-lg"
            >
              List Your Property
            </button>
            <button
              onClick={() => navigate('/contact')}
              className="border border-gray-300 text-gray-600 px-8 py-4 rounded-full font-bold hover:bg-white hover:border-gray-400 transition-all duration-300"
            >
              Contact Us
            </button>
          </div>
        </div>
      </section>

    </div>
  );
}