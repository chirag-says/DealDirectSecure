import React, { useState } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";


/**
 * Category is the TOP level of the taxonomy and has no parent.
 *
 * This screen used to ask for a property type to file the new category under,
 * which was the inverted model: it made a category a child of a type. It also
 * fetched that list with a bare `axios` it never imported, so the dropdown threw
 * on every render and only ever showed "Failed to load property types".
 *
 * Creating a property type, which does need a parent category, has no admin
 * screen. That is a gap rather than an oversight of this change.
 */
const AddCategory = () => {
  const [name, setName] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name.trim()) return toast.warn("Please enter a category name");

    try {
      setLoading(true);
      // Using adminApi - cookies sent automatically
      const { data } = await adminApi.post(
        `/api/categories/add-category`,
        { name }
      );

      toast.success(data.message || "Category added successfully");
      setName("");
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
