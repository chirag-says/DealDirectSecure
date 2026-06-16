'use client';

// src/Components/HeroSection/BudgetFilter.jsx
import React from "react";
import { budgetOptions } from "./filterConfig";

const BudgetFilter = ({ 
  minBudget, 
  setMinBudget, 
  maxBudget, 
  setMaxBudget, 
  openDropdown, 
  setOpenDropdown, 
  dropdownRef 
}) => {
  return (
    <div className="relative" ref={dropdownRef}>
      <button
        onClick={() => setOpenDropdown(openDropdown === 'budget' ? null : 'budget')}
        className="appearance-none bg-white rounded-xl px-4 py-2.5 pr-10 text-gray-700 font-medium focus:ring-2 focus:ring-blue-400 outline-none border border-gray-300 cursor-pointer text-sm shadow-sm flex items-center gap-2 whitespace-nowrap"
      >
        {minBudget && maxBudget ? `${minBudget} - ${maxBudget}` : 'Budget'}
        <svg className="w-4 h-4 text-gray-500 ml-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {openDropdown === 'budget' && (
        <div className="absolute top-full mt-2 bg-white rounded-xl shadow-2xl border border-gray-200 p-4 z-[70] w-96">
          <div className="grid grid-cols-2 gap-4 mb-3">
            <div className="text-sm font-semibold text-gray-700">
              {minBudget || "Min"}
            </div>
            <div className="text-sm font-semibold text-gray-700">
              {maxBudget || "Max"}
            </div>
          </div>

          <div className="grid grid-cols-2 gap-4 max-h-64 overflow-y-auto border rounded-lg p-3">
            <div className="space-y-1">
              {budgetOptions.map((option, idx) => (
                <button
                  key={`min-${idx}`}
                  onClick={() => setMinBudget(option)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm transition ${
                    minBudget === option
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'hover:bg-gray-100 text-gray-700'
                  }`}
                >
                  {option}
                </button>
              ))}
            </div>

            <div className="space-y-1">
              {budgetOptions.map((option, idx) => (
                <button
                  key={`max-${idx}`}
                  onClick={() => setMaxBudget(option)}
                  className={`w-full text-left px-3 py-2 rounded-lg text-sm transition ${
                    maxBudget === option
                      ? 'bg-blue-600 text-white font-semibold'
                      : 'hover:bg-gray-100 text-gray-700'
                  }`}
                >
                  {option}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default BudgetFilter;
