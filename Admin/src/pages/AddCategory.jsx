import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";

const API_URL = import.meta.env.VITE_API_BASE_URL;

const AddCategory = () => {
  const [name, setName] = useState("");
  const [propertyTypes, setPropertyTypes] = useState([]);
  const [selectedPropertyType, setSelectedPropertyType] = useState("");
  const [loading, setLoading] = useState(false);

  // Fetch property types for dropdown
  useEffect(() => {
    const fetchPropertyTypes = async () => {
      try {
        const res = await axios.get(`${API_URL}/api/propertyTypes/list-propertytype`);
        setPropertyTypes(res.data);
      } catch (error) {
        toast.error("Failed to load property types");
      }
    };
    fetchPropertyTypes();
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!selectedPropertyType) return toast.warn("Please select a property type");
    if (!name.trim()) return toast.warn("Please enter a category name");

    try {
      setLoading(true);
      // Using adminApi - cookies sent automatically
      const { data } = await adminApi.post(
        `/api/categories/add-category`,
        { name, propertyType: selectedPropertyType }
      );

      toast.success(data.message || "Category added successfully");
      setName("");
      setSelectedPropertyType("");
    } catch (error) {
      toast.error(error.response?.data?.message || "Error adding category");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="bg-gray-50 min-h-screen flex justify-center items-center">
      <div className="bg-white shadow-lg rounded-lg w-full max-w-lg p-8 border border-gray-200">
        <h2 className="text-2xl font-semibold text-gray-800 text-center mb-6">
          ➕ Add New Category
        </h2>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Property Type Dropdown */}
          <div>
            <label className="block text-gray-700 font-medium mb-2">
              Select Property Type
            </label>
            <select
              value={selectedPropertyType}
              onChange={(e) => setSelectedPropertyType(e.target.value)}
              className="w-full border border-gray-300 rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              <option value="">-- Select Property Type --</option>
              {propertyTypes.map((pt) => (
                <option key={pt._id} value={pt._id}>
                  {pt.name}
                </option>
              ))}
            </select>
          </div>

          {/* Category Name Input */}
          <div>
            <label className="block text-gray-700 font-medium mb-2">
              Category Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Enter category name"
              className="w-full border border-gray-300 rounded-lg p-3 outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className={`w-full py-3 rounded-lg text-white font-medium ${loading
                ? "bg-blue-400 cursor-not-allowed"
                : "bg-blue-600 hover:bg-blue-700"
              } transition`}
          >
            {loading ? "Adding..." : "Add Category"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default AddCategory;
