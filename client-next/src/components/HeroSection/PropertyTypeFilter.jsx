'use client';

// src/Components/HeroSection/PropertyTypeFilter.jsx
import React, { useState } from "react";
import { propertyTypes } from "./filterConfig";

const PropertyTypeFilter = ({ 
  selectedPropertyTypes, 
  setSelectedPropertyTypes, 
  openDropdown, 
  setOpenDropdown, 
  dropdownRef 
}) => {
  const [propertyTypeTab, setPropertyTypeTab] = useState("Residential");

  const handleToggle = (type) => {
    setSelectedPropertyTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    );
  };

  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setOpenDropdown(openDropdown === 'propertyType' ? null : 'propertyType')}
        className="appearance-none bg-white rounded-xl px-4 py-2.5 pr-10 text-gray-700 font-medium focus:ring-2 focus:ring-blue-400 outline-none border border-gray-300 cursor-pointer text-sm shadow-sm flex items-center gap-2"
      >
        Property Type
        <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {openDropdown === 'propertyType' && (
        <div className="absolute top-full mt-2 bg-white rounded-xl shadow-2xl border border-gray-200 p-4 z-[70] w-72">
          <div className="flex border rounded-lg overflow-hidden mb-3">
            <button
              onClick={() => setPropertyTypeTab("Residential")}
              className={`flex-1 py-2 text-sm font-semibold transition ${
                propertyTypeTab === "Residential"
                  ? "bg-gray-900 text-white"
                  : "bg-white text-gray-700 hover:bg-gray-50"
              }`}
            >
              Residential
            </button>
            <button
              onClick={() => setPropertyTypeTab("Commercial")}
              className={`flex-1 py-2 text-sm font-semibold transition ${
                propertyTypeTab === "Commercial"
                  ? "bg-gray-900 text-white"
                  : "bg-white text-gray-700 hover:bg-gray-50"
              }`}
            >
              Commercial
            </button>
          </div>

          <div className="space-y-2">
            {propertyTypes[propertyTypeTab].map((type, idx) => (
              <label key={idx} className="flex items-center gap-2 cursor-pointer hover:bg-gray-50 p-2 rounded-lg">
                <input
                  type="checkbox"
                  checked={selectedPropertyTypes.includes(type)}
                  onChange={() => handleToggle(type)}
                  className="w-4 h-4 text-blue-600 border-gray-300 rounded focus:ring-blue-500"
                />
                <span className="text-sm text-gray-700">{type}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default PropertyTypeFilter;
