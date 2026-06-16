'use client';

import React, { useState, useEffect, useRef } from "react";
import Link from "next/link";
import { ChevronRight, ChevronLeft } from "lucide-react";

const MegaMenu = ({ title, sections, isOpen, onMouseEnter, onMouseLeave }) => {
  const [currentSlide, setCurrentSlide] = useState(0);
  const dropdownRef = useRef(null);
  const visibleColumns = 4;
  const maxSlide = sections.length - visibleColumns;

  useEffect(() => {
    if (isOpen) {
      console.log(`${title} Menu:`, {
        totalSections: sections.length,
        currentSlide,
        maxSlide,
        visibleSections: sections
          .slice(currentSlide, currentSlide + visibleColumns)
          .map((s) => s.title),
      });
    }
  }, [isOpen, currentSlide, title, sections, maxSlide]);

  const handleNext = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (currentSlide < maxSlide) {
      setCurrentSlide((prev) => prev + 1);
    }
  };

  const handlePrev = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (currentSlide > 0) {
      setCurrentSlide((prev) => prev - 1);
    }
  };

  const handleMouseLeave = (e) => {
    if (dropdownRef.current && !dropdownRef.current.contains(e.relatedTarget)) {
      setCurrentSlide(0);
      onMouseLeave();
    }
  };

  return (
    <div
      className="relative"
      onMouseEnter={onMouseEnter}
      onMouseLeave={handleMouseLeave}
    >
      <button
        className="flex items-center space-x-1 px-3 py-2 text-white hover:text-blue-700 font-medium transition text-[15px]"
        type="button"
      >
        <span>{title}</span>
        <svg
          className={`w-4 h-4 transition-transform ${isOpen ? "rotate-180" : ""}`}
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M19 9l-7 7-7-7"
          />
        </svg>
      </button>

      {isOpen && (
        <div
          ref={dropdownRef}
          className="absolute left-0 top-full mt-0 bg-white rounded-b-lg shadow-2xl border border-gray-200 z-50"
          style={{
            width: "900px", // Fixed width
            height: "450px", // Fixed height - same for both Buy and Rent
            paddingLeft: "3rem",
            paddingRight: "3rem",
            paddingTop: "1.5rem",
            paddingBottom: "1.5rem",
          }}
        >
          <div className="relative h-full flex flex-col">
            {/* Left Arrow */}
            {currentSlide > 0 && (
              <button
                type="button"
                onClick={handlePrev}
                onMouseDown={handlePrev}
                className="absolute -left-5 top-1/2 -translate-y-1/2 bg-white rounded-full p-3 shadow-xl hover:bg-gray-50 transition-all z-40 border-2 border-gray-300"
                aria-label="Previous"
                style={{ pointerEvents: "all" }}
              >
                <ChevronLeft size={24} className="text-gray-800" strokeWidth={2.5} />
              </button>
            )}

            {/* Sliding Container */}
            <div className="overflow-hidden relative flex-1">
              <div
                className="flex h-full transition-transform duration-500 ease-in-out"
                style={{
                  transform: `translateX(-${currentSlide * (100 / visibleColumns)}%)`,
                }}
              >
                {/* Render ALL sections in a single row */}
                {sections.map((section, idx) => (
                  <div
                    key={idx}
                    className="flex flex-col"
                    style={{
                      flex: `0 0 ${100 / visibleColumns}%`,
                      minWidth: 0,
                      padding: "0 1rem",
                      height: "100%",
                    }}
                  >
                    {/* Column Header - Sticky */}
                    <h3 className="font-bold text-gray-800 mb-3 text-sm border-b pb-2 flex-shrink-0">
                      {section.title}
                    </h3>

                    {/* Scrollable Content Area */}
                    <div
                      className="overflow-y-auto pr-2 flex-1"
                      style={{
                        scrollbarWidth: "thin",
                        scrollbarColor: "#cbd5e0 #f7fafc"
                      }}
                    >
                      <ul className="space-y-2">
                        {section.links.map((link, linkIdx) => (
                          <li key={linkIdx}>
                            <Link
                              href={link.url}
                              className="text-sm text-gray-600 hover:text-blue-600 hover:underline block transition-colors duration-150"
                            >
                              {link.label}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right Arrow */}
            {currentSlide < maxSlide && (
              <button
                type="button"
                onClick={handleNext}
                onMouseDown={handleNext}
                className="absolute -right-5 top-1/2 -translate-y-1/2 bg-white rounded-full p-3 shadow-xl hover:bg-gray-50 transition-all z-40 border-2 border-gray-300"
                aria-label="Next"
                style={{ pointerEvents: "all" }}
              >
                <ChevronRight size={24} className="text-gray-800" strokeWidth={2.5} />
              </button>
            )}

            {/* Page Indicator Dots */}
            {maxSlide > 0 && (
              <div className="flex justify-center mt-4 space-x-2 flex-shrink-0">
                {Array.from({ length: maxSlide + 1 }).map((_, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      setCurrentSlide(idx);
                    }}
                    className={`h-2 rounded-full transition-all duration-300 ${currentSlide === idx ? "bg-blue-600 w-6" : "bg-gray-300 w-2"
                      }`}
                    aria-label={`Go to position ${idx + 1}`}
                    style={{ pointerEvents: "all" }}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Custom Scrollbar Styles */}
      <style>{`
        /* Webkit browsers (Chrome, Safari, Edge) */
        div::-webkit-scrollbar {
          width: 6px;
        }
        
        div::-webkit-scrollbar-track {
          background: #f7fafc;
          border-radius: 3px;
        }
        
        div::-webkit-scrollbar-thumb {
          background: #cbd5e0;
          border-radius: 3px;
        }
        
        div::-webkit-scrollbar-thumb:hover {
          background: #a0aec0;
        }
      `}</style>
    </div>
  );
};

export default MegaMenu;
