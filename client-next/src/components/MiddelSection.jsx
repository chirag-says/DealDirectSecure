import React from "react";
import { FaMapMarkerAlt } from "react-icons/fa";

const MiddelSection = () => {
  return (
    <section className="relative h-[380px] sm:h-[550px] flex items-center justify-center text-center">

      {/* Background */}
      <div
        className="absolute inset-0 bg-cover bg-center"
        style={{
          backgroundImage: `url('https://images.unsplash.com/photo-1598928506311-c55ded91a20c?q=80&w=2000&auto=format&fit=crop')`,
          filter: "brightness(0.55)",
        }}
      ></div>

      {/* Red + Dark Blue Overlay */}
      <div className="absolute inset-0"></div>

      {/* Content */}
      <div className="relative z-10 max-w-3xl px-5">
        {/* Location Tag */}
        <div className="inline-flex items-center bg-white/90 px-5 py-2 rounded-full shadow-md mb-8">
          <FaMapMarkerAlt className="text-red-600" />
          <span className="text-sm font-medium ml-2 text-gray-800">Mumbai</span>
        </div>

        <h1 className="text-white text-4xl md:text-5xl font-extrabold mb-3">
          Get in Touch
        </h1>

        <p className="text-white/90 text-lg md:text-xl leading-relaxed">
          We're here to help you with any property-related inquiry.  
          Reach out for support, collaborations, or property assistance.
        </p>
      </div>
    </section>
  );
};

export default MiddelSection;
