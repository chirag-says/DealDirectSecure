import React from "react";

const PropertyFilter = ({ filters, setFilters }) => {
  const handleChange = (e) => {
    setFilters({ ...filters, [e.target.name]: e.target.value });
  };

  return (
    <div className="space-y-4">
      {/* Budget Filter */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Budget (Max)
        </label>
        <input
          type="number"
          name="budget"
          value={filters.budget}
          onChange={handleChange}
          placeholder="e.g. 10000000"
          className="w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500"
        />
      </div>

      {/* Property Type Filter */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          Property Type
        </label>
        <select
          name="type"
          value={filters.type}
          onChange={handleChange}
          className="w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500"
        >
          <option value="">All</option>
          <option value="Apartment">Apartment</option>
          <option value="Villa">Villa</option>
          <option value="Studio">Studio</option>
        </select>
      </div>

      {/* BHK Filter */}
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">
          BHK
        </label>
        <select
          name="bhk"
          value={filters.bhk}
          onChange={handleChange}
          className="w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500"
        >
          <option value="">All</option>
          <option value="1">1 BHK</option>
          <option value="2">2 BHK</option>
          <option value="3">3 BHK</option>
          <option value="4">4+ BHK</option>
        </select>
      </div>
    </div>
  );
};

export default PropertyFilter;
