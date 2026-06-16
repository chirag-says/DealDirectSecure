// src/Components/MiddelComp.jsx
import React from "react";

export default function Middel({ title, subtitle }) {
  return (
    <section className="relative h-[320px] md:h-[550px] flex items-center justify-center text-center">
      {/* Background */}
      <div
        className="absolute inset-0 bg-cover bg-center"
        style={{
          backgroundImage: `url('https://images.unsplash.com/photo-1598928506311-c55ded91a20c?q=80&w=2000&auto=format&fit=crop')`,
          filter: "brightness(0.55)",
        }}
      ></div>

      {/* Overlay */}
      <div className="absolute inset-0"></div>

      {/* Content */}
      <div className="relative z-10 px-5">
        <h1 className="text-white text-4xl md:text-5xl font-extrabold drop-shadow-lg">
          {title}
        </h1>
        {subtitle && (
          <p className="mt-3 text-lg md:text-xl text-gray-200 drop-shadow">
            {subtitle}
          </p>
        )}
      </div>
    </section>
  );
}
