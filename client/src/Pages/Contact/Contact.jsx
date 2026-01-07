import React, { useEffect, useState } from "react";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import {
  FaMapMarkerAlt,
  FaPhoneAlt,
  FaEnvelope,
  FaClock,
  FaPaperPlane,
  FaBuilding,
  FaHeadset,
  FaLock
} from "react-icons/fa";



export default function Contact() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [formData, setFormData] = useState({
    name: "",
    email: "",
    subject: "",
    message: "",
    category: "general"
  });

  const { isAuthenticated, user } = useAuth();

  // Check if user is logged in and pre-fill form
  useEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });

    if (isAuthenticated && user) {
      setIsLoggedIn(true);
      setFormData(prev => ({
        ...prev,
        name: user.name || "",
        email: user.email || ""
      }));
    } else {
      setIsLoggedIn(false);
    }
  }, [isAuthenticated, user]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // Check if logged in
    if (!isLoggedIn) {
      toast.info("Please login to submit your inquiry");
      navigate("/login", { state: { from: "/contact" } });
      return;
    }

    setLoading(true);

    try {
      const response = await api.post(
        `/contact`,
        {
          subject: formData.subject,
          message: formData.message,
          category: formData.category
        }
      );

      if (response.data.success) {
        toast.success("Message sent! Our support team will contact you shortly.");
        setFormData(prev => ({
          ...prev,
          subject: "",
          message: "",
          category: "general"
        }));
      } else {
        toast.error(response.data.message || "Failed to send message");
      }
    } catch (error) {
      console.error("Contact form error:", error);
      const errorMsg = error.response?.data?.message || "Failed to send message. Please try again.";
      toast.error(errorMsg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="font-sans text-gray-900 bg-white min-h-screen">

      {/* --- HERO SECTION --- */}
      <section className="relative py-16 md:py-20 bg-white overflow-hidden">
        <div className="relative z-10 text-center px-6 max-w-4xl mx-auto">
          <div className="inline-flex items-center gap-2 mb-4 px-4 py-1.5 rounded-full border border-red-200 bg-red-50 text-red-600 text-xs font-bold uppercase tracking-widest">
            <FaHeadset /> 24/7 Support
          </div>
          <h1 className="text-4xl md:text-6xl font-extrabold tracking-tight mb-4 text-gray-900">
            Get in Touch with <br />
            <span className="text-red-600">Deal Direct</span>
          </h1>
          <p className="text-gray-500 text-lg md:text-xl max-w-2xl mx-auto leading-relaxed">
            Whether you're a buyer, seller, or just have a question, our team is here to help you navigate your property journey.
          </p>
        </div>
      </section>

      {/* --- MAIN CONTENT --- */}
      <section className="relative z-20 max-w-7xl mx-auto px-6 pb-20">
        <div className="bg-white rounded-3xl shadow-xl border border-gray-100 overflow-hidden flex flex-col lg:flex-row">

          {/* LEFT: Contact Info & Map */}
          <div className="lg:w-2/5 bg-red-600 text-white p-10 flex flex-col justify-between relative overflow-hidden">
            <div className="relative z-10">
              <h3 className="text-2xl font-bold mb-6 flex items-center gap-2">
                Contact Information
              </h3>
              <p className="text-white/80 mb-10 text-sm leading-relaxed">
                Reach out to our customer support team. We generally respond within 2 hours during business days.
              </p>

              <div className="space-y-8">
                {/* Address */}
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center flex-shrink-0 text-white">
                    <FaBuilding size={20} />
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Corporate Office</h4>
                    <p className="text-white/80 text-sm mt-1">
                      Deal Direct<br />
                      123 Innovation Park, Tech Hub,<br />
                      Mumbai, Maharashtra 400001
                    </p>
                  </div>
                </div>

                {/* Phone */}
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center flex-shrink-0 text-white">
                    <FaPhoneAlt size={20} />
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Call Us</h4>
                    <p className="text-white/80 text-sm mt-1">
                      +91 98765 43210 (Support)<br />
                      +91 22 1234 5678 (Office)
                    </p>
                  </div>
                </div>

                {/* Email */}
                <div className="flex items-start gap-4">
                  <div className="w-12 h-12 bg-white/20 rounded-xl flex items-center justify-center flex-shrink-0 text-white">
                    <FaEnvelope size={20} />
                  </div>
                  <div>
                    <h4 className="font-semibold text-white">Email Us</h4>
                    <p className="text-white/80 text-sm mt-1">
                      support@dealdirect.in<br />
                      business@dealdirect.in
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Embedded Map */}
            <div className="mt-12 rounded-2xl overflow-hidden border border-white/20 h-48 shadow-lg relative group">
              <iframe
                title="Office Location"
                src="https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3770.792556734796!2d72.87739281482195!3d19.07282778709007!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x3be7c6306644edc1%3A0x5da4ed8f8d648c69!2sMumbai%2C%20Maharashtra!5e0!3m2!1sen!2sin!4v1623918237920!5m2!1sen!2sin"
                className="w-full h-full transition-all duration-500 opacity-90 group-hover:opacity-100"
                allowFullScreen=""
                loading="lazy"
              ></iframe>
              <div className="absolute bottom-2 right-2 bg-white/90 backdrop-blur text-xs px-2 py-1 rounded text-gray-800 flex items-center gap-1 shadow-sm">
                <FaMapMarkerAlt className="text-red-500" /> View on Map
              </div>
            </div>
          </div>

          {/* RIGHT: Contact Form */}
          <div className="lg:w-3/5 p-10 lg:p-16">
            <h2 className="text-3xl font-bold text-gray-900 mb-2">Send us a Message</h2>
            <p className="text-gray-500 mb-8">
              Got a question about a property, or want to partner with us? Fill out the form below.
            </p>

            {/* Login Notice */}
            {!isLoggedIn && (
              <div className="mb-6 p-4 bg-amber-50 border border-amber-200 rounded-xl flex items-center gap-3">
                <FaLock className="text-amber-500 flex-shrink-0" />
                <div>
                  <p className="text-amber-800 text-sm font-medium">Login Required</p>
                  <p className="text-amber-600 text-xs">Please login to submit your inquiry. This helps us serve you better.</p>
                </div>
                <button
                  onClick={() => navigate("/login", { state: { from: "/contact" } })}
                  className="ml-auto px-4 py-2 bg-amber-500 text-white text-sm font-medium rounded-lg hover:bg-amber-600 transition-colors"
                >
                  Login
                </button>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-sm font-semibold text-gray-700">Your Name</label>
                  <input
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    placeholder="John Doe"
                    required
                    disabled={isLoggedIn}
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 transition-all outline-none bg-gray-50 focus:bg-white disabled:bg-gray-100 disabled:text-gray-600"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-semibold text-gray-700">Email Address</label>
                  <input
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="john@example.com"
                    required
                    disabled={isLoggedIn}
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 transition-all outline-none bg-gray-50 focus:bg-white disabled:bg-gray-100 disabled:text-gray-600"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <label className="text-sm font-semibold text-gray-700">Subject</label>
                  <input
                    type="text"
                    name="subject"
                    value={formData.subject}
                    onChange={handleChange}
                    placeholder="Regarding Property Listing / Partnership"
                    required
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 transition-all outline-none bg-gray-50 focus:bg-white"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-semibold text-gray-700">Category</label>
                  <select
                    name="category"
                    value={formData.category}
                    onChange={handleChange}
                    className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 transition-all outline-none bg-gray-50 focus:bg-white"
                  >
                    <option value="general">General Inquiry</option>
                    <option value="property">Property Related</option>
                    <option value="partnership">Partnership</option>
                    <option value="support">Technical Support</option>
                    <option value="feedback">Feedback</option>
                    <option value="complaint">Complaint</option>
                    <option value="other">Other</option>
                  </select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-semibold text-gray-700">Message</label>
                <textarea
                  name="message"
                  rows="5"
                  value={formData.message}
                  onChange={handleChange}
                  placeholder="How can we help you today?"
                  required
                  className="w-full px-4 py-3 rounded-xl border border-gray-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 transition-all outline-none bg-gray-50 focus:bg-white resize-none"
                ></textarea>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="w-full bg-red-600 text-white font-bold py-4 rounded-xl shadow-lg hover:bg-red-700 hover:shadow-xl hover:scale-[1.01] transition-all flex items-center justify-center gap-2 disabled:opacity-70 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>Processing...</>
                ) : (
                  <>
                    <FaPaperPlane /> Send Message
                  </>
                )}
              </button>
            </form>
          </div>

        </div>
      </section>

      {/* --- EXTRA: Support Hours Strip --- */}
      <section className="bg-gray-50 border-t border-gray-100 py-12">
        <div className="max-w-6xl mx-auto px-6 grid md:grid-cols-3 gap-8 text-center">
          <div className="p-4">
            <div className="w-12 h-12 bg-green-100 text-green-600 rounded-full flex items-center justify-center mx-auto mb-4 text-xl">
              <FaClock />
            </div>
            <h4 className="font-bold text-gray-900">Operating Hours</h4>
            <p className="text-gray-500 text-sm mt-1">Mon - Sat: 9:00 AM - 8:00 PM</p>
          </div>
          <div className="p-4 border-l border-r border-gray-200">
            <div className="w-12 h-12 bg-purple-100 text-purple-600 rounded-full flex items-center justify-center mx-auto mb-4 text-xl">
              <FaHeadset />
            </div>
            <h4 className="font-bold text-gray-900">Direct Support</h4>
            <p className="text-gray-500 text-sm mt-1">Dedicated team for premium listings</p>
          </div>
          <div className="p-4">
            <div className="w-12 h-12 bg-orange-100 text-orange-600 rounded-full flex items-center justify-center mx-auto mb-4 text-xl">
              <FaBuilding />
            </div>
            <h4 className="font-bold text-gray-900">Office Visits</h4>
            <p className="text-gray-500 text-sm mt-1">By Appointment Only</p>
          </div>
        </div>
      </section>

    </div>
  );
}