import React from "react";
import {
  FaDownload,
  FaFilePdf,
  FaShieldAlt,
  FaCheckCircle,
  FaLock,
  FaUserCheck,
  FaCertificate,
} from "react-icons/fa";

function SampleAgreement() {
  const agreements = [
    {
      title: "1 BHK Rent Agreement",
      file: "/agreements/1bhk.pdf",
      description:
        "A legally verified rental agreement template tailored for 1 BHK properties. Secure and ready to use.",
    },
    {
      title: "2 BHK Rent Agreement",
      file: "/agreements/2bhk.pdf",
      description:
        "A comprehensive 2 BHK rent agreement format with verified clauses to ensure transparency and protection.",
    },
    {
      title: "3 BHK Rent Agreement",
      file: "/agreements/3bhk.pdf",
      description:
        "A trusted 3 BHK rent agreement suitable for families or shared tenants — professional and reliable.",
    },
  ];

  const trustFeatures = [
    {
      icon: FaCertificate,
      text: "Legally Verified",
      subtext: "All documents comply with rental laws",
    },
    {
      icon: FaLock,
      text: "Secure & Protected",
      subtext: "Your data and privacy are safeguarded",
    },
    {
      icon: FaUserCheck,
      text: "Trusted by Thousands",
      subtext: "Used by property owners nationwide",
    },
    {
      icon: FaCheckCircle,
      text: "Professionally Drafted",
      subtext: "Created by legal experts",
    },
  ];

  return (
    <div className="min-h-screen mt-20 sm:mt-28 py-12 px-4 sm:px-8 lg:px-20 bg-white">
      {/* 🛡️ Header */}
      <div className="text-center mb-16">
        <div className="flex justify-center mb-6">
          <div className="relative">
            <div className="absolute inset-0 bg-blue-100 rounded-full blur-lg opacity-40"></div>
            <FaShieldAlt className="relative text-blue-600 text-4xl sm:text-5xl z-10" />
          </div>
        </div>

        <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold mb-4 text-gray-900">
          Verified Rent Agreements
        </h1>

        <p className="text-gray-700 max-w-3xl mx-auto text-sm sm:text-base leading-relaxed px-2">
          Professionally crafted, legally compliant rental agreements trusted by
          property owners and tenants nationwide. Every document is meticulously
          verified for your peace of mind.
        </p>

        {/* 🏅 Trust Badges */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 sm:gap-6 mt-10 sm:mt-12 max-w-5xl mx-auto">
          {trustFeatures.map((feature, index) => (
            <div
              key={index}
              className="bg-white rounded-xl p-4 sm:p-5 shadow-sm border border-gray-200 hover:shadow-md hover:border-blue-200 transition-all duration-300"
            >
              <div className="flex flex-col items-center text-center">
                <feature.icon className="text-blue-600 text-xl sm:text-2xl mb-3" />
                <h3 className="font-semibold text-gray-900 text-sm sm:text-base mb-1">
                  {feature.text}
                </h3>
                <p className="text-gray-600 text-xs sm:text-sm leading-snug">
                  {feature.subtext}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 📄 Agreement Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 sm:gap-8 max-w-7xl mx-auto">
        {agreements.map((agreement, index) => (
          <div
            key={index}
            className="group bg-white rounded-xl p-6 sm:p-8 flex flex-col items-center text-center shadow-sm hover:shadow-lg transition-all duration-300 border border-gray-200 hover:border-gray-300 relative overflow-hidden"
          >
            {/* Verified Badge */}
            <div className="absolute top-4 right-4 bg-green-500 text-white px-3 py-1 rounded-full text-[11px] sm:text-xs font-semibold flex items-center gap-1 shadow-sm">
              <FaCheckCircle className="text-white" />
              Verified
            </div>

            <div className="relative z-10">
              <div className="mb-6 relative">
                <div className="absolute inset-0 bg-red-50 rounded-full blur-md opacity-50"></div>
                <FaFilePdf className="relative text-red-500 text-5xl sm:text-6xl z-10" />
              </div>

              <h2 className="text-lg sm:text-xl font-bold text-gray-900 mb-4">
                {agreement.title}
              </h2>

              <p className="text-gray-600 text-sm sm:text-base leading-relaxed mb-8 px-1">
                {agreement.description}
              </p>

              {/* Buttons - Matching Website Style */}
              <div className="flex flex-col sm:flex-row gap-3 w-full">
                <a
                  href={agreement.file}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex-1 bg-gradient-to-r from-blue-600 to-indigo-600 text-white px-5 py-2.5 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 hover:from-blue-700 hover:to-indigo-700 hover:shadow-lg transform hover:scale-105 transition-all duration-300 shadow-md"
                >
                  <FaFilePdf className="text-white text-base" />
                  <span>Preview</span>
                </a>

                <a
                  href={agreement.file}
                  download
                  className="flex-1 bg-white text-gray-700 px-5 py-2.5 rounded-xl text-sm font-semibold flex items-center justify-center gap-2 hover:bg-gray-50 hover:shadow-md transform hover:scale-105 transition-all duration-300 border border-gray-300 hover:border-gray-400"
                >
                  <FaDownload className="text-gray-600 text-base" />
                  <span>Download</span>
                </a>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 🔒 Trust Footer */}
      <div className="mt-16 sm:mt-20 text-center">
        <div className="bg-white rounded-2xl p-6 sm:p-8 max-w-4xl mx-auto shadow-sm border border-gray-200">
          <div className="flex items-center justify-center gap-2 sm:gap-3 mb-4">
            <FaLock className="text-green-600 text-lg sm:text-xl" />
            <span className="text-xs sm:text-sm font-semibold text-green-600 uppercase tracking-wide">
              Secure & Trusted
            </span>
          </div>

          <h3 className="text-lg sm:text-xl font-bold text-gray-900 mb-3">
            Your Trust is Our Priority
          </h3>

          <p className="text-gray-700 text-sm sm:text-base leading-relaxed max-w-2xl mx-auto px-2">
            Every agreement is crafted by legal professionals and regularly
            updated to comply with rental laws. We maintain the highest
            standards to protect both property owners and tenants.
          </p>

          <div className="flex flex-wrap justify-center gap-4 sm:gap-6 mt-6 pt-6 border-t border-gray-200">
            {[
              "100% Legal Compliance",
              "Regularly Updated",
              "Professional Quality",
            ].map((text, i) => (
              <div
                key={i}
                className="flex items-center gap-2 text-xs sm:text-sm text-gray-700 font-medium"
              >
                <FaCheckCircle className="text-green-600" />
                <span>{text}</span>
              </div>
            ))}
          </div>
        </div>

        <p className="text-gray-500 text-xs sm:text-sm mt-8 max-w-2xl mx-auto px-2">
          ⚖️ All agreements provided here are professionally drafted templates.
          Please consult a certified legal advisor for specific legal advice.
        </p>
      </div>
    </div>
  );
}

export default SampleAgreement;
