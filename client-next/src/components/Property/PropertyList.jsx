import React from "react";
import { formatPrice } from "../../utils/formatPrice";

const PropertyList = ({ properties }) => {
  if (properties.length === 0) {
    return <p className="text-gray-500">No properties found.</p>;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {properties.map((property) => (
        <div
          key={property.id}
          className="bg-white rounded-lg shadow-md overflow-hidden hover:shadow-lg transition-shadow duration-300"
        >
          <img
            src={property.image}
            alt={property.title}
            className="w-full h-48 object-cover"
          />
          <div className="p-4">
            <h3 className="text-lg font-semibold text-gray-800">
              {property.title}
            </h3>
            <p className="text-gray-600">{property.location}</p>
            <p className="text-indigo-600 font-bold mt-2">
              {formatPrice(property.price)}
            </p>
            <p className="text-sm text-gray-500 mt-1">
              {property.bhk} BHK • {property.type}
            </p>
            <button className="mt-3 bg-indigo-600 text-white px-4 py-2 rounded-md hover:bg-indigo-700">
              View Details
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export default PropertyList;
