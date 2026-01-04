import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { Edit, Trash2, PlusCircle, X } from "lucide-react";
import { toast } from "react-toastify";

const API_URL = import.meta.env.VITE_API_BASE_URL;

const AllCategory = () => {
  const [propertyTypes, setPropertyTypes] = useState([]);
  const [categories, setCategories] = useState([]);
  const [subcategories, setSubcategories] = useState([]);

  const [loading, setLoading] = useState(true);
  const [editData, setEditData] = useState(null);
  const [isEditing, setIsEditing] = useState(false);

  // Auth handled by adminApi via cookies

  // Fetch all types, categories & subcategories
  const fetchAll = async () => {
    try {
      setLoading(true);

      const [ptRes, catRes, subRes] = await Promise.all([
        axios.get(`${API_URL}/api/propertyTypes/list-propertytype`),
        axios.get(`${API_URL}/api/categories/list-category`),
        axios.get(`${API_URL}/api/subcategories/list`)
      ]);

      setPropertyTypes(ptRes.data);
      setCategories(catRes.data);
      setSubcategories(subRes.data);

    } catch (err) {
      toast.error("Failed to load data");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAll();
  }, []);

  // Delete item
  const handleDelete = async (id, type) => {
    if (!window.confirm(`Delete this ${type}?`)) return;
    try {
      let endpoint = "";
      if (type === "propertyTypes") {
        endpoint = `${API_URL}/api/propertyTypes/delete/${id}`;
      } else if (type === "categories") {
        endpoint = `${API_URL}/api/categories/delete/${id}`;
      } else if (type === "subcategories") {
        endpoint = `${API_URL}/api/subcategories/delete/${id}`;
      }
      await adminApi.delete(endpoint);
      toast.success(`${type} deleted`);
      fetchAll();
    } catch (err) {
      toast.error("Delete failed");
    }
  };

  // Open edit modal
  const handleEdit = (item, type) => {
    setEditData({ ...item, type });
    setIsEditing(true);
  };

  // Save edits
  const handleSaveEdit = async () => {
    try {
      let endpoint = "";
      let payload = {};

      if (editData.type === "propertyTypes") {
        endpoint = `${API_URL}/api/propertyTypes/edit/${editData._id}`;
        payload = { name: editData.name };
      } else if (editData.type === "categories") {
        endpoint = `${API_URL}/api/categories/edit/${editData._id}`;
        payload = { name: editData.name };
      } else if (editData.type === "subcategories") {
        endpoint = `${API_URL}/api/subcategories/edit/${editData._id}`;
        payload = {
          name: editData.name,
          category: editData.category?._id || editData.category
        };
      }

      await adminApi.put(endpoint, payload);

      toast.success("Updated successfully");
      setIsEditing(false);
      fetchAll();

    } catch (err) {
      toast.error("Update failed");
    }
  };

  return (
    <div className="bg-gray-50 min-h-screen sm:p-4">

      <h2 className="text-xl sm:text-2xl font-bold mb-8 text-gray-800">
        📂 Manage All Categories
      </h2>

      {loading ? (
        <p className="text-center text-gray-500 text-lg">Loading...</p>
      ) : (
        <div className="space-y-8">

          {/* PROPERTY TYPES */}
          {propertyTypes.map((pt) => (
            <div
              key={pt._id}
              className="bg-white shadow-lg rounded-2xl p-6 hover:shadow-xl transition-all"
            >

              {/* MAIN TITLE */}
              <div className="flex justify-between items-center">
                <h3 className="text-xl font-semibold text-gray-800">
                  {pt.name}
                </h3>

                <div className="flex gap-4">
                  <Edit
                    className="text-blue-600 cursor-pointer hover:scale-110 transition"
                    onClick={() => handleEdit(pt, "propertyTypes")}
                  />
                  <Trash2
                    className="text-red-600 cursor-pointer hover:scale-110 transition"
                    onClick={() => handleDelete(pt._id, "propertyTypes")}
                  />
                </div>
              </div>

              {/* CATEGORIES */}
              <div className="mt-4 pl-4 space-y-4">

                {categories
                  .filter(c => c.propertyType?._id === pt._id)
                  .map(cat => (
                    <div
                      key={cat._id}
                      className="bg-gradient-to-r from-gray-50 to-gray-100 shadow-md rounded-xl p-4"
                    >
                      <div className="flex justify-between items-center">
                        <p className="font-semibold text-gray-800 text-lg">
                          {cat.name}
                        </p>

                        <div className="flex gap-3">
                          <Edit
                            className="text-blue-600 cursor-pointer hover:scale-110 transition"
                            onClick={() => handleEdit(cat, "categories")}
                          />
                          <Trash2
                            className="text-red-600 cursor-pointer hover:scale-110 transition"
                            onClick={() =>
                              handleDelete(cat._id, "categories")
                            }
                          />
                        </div>
                      </div>

                      {/* SUBCATEGORIES */}
                      <div className="flex flex-wrap gap-3 mt-3">

                        {subcategories
                          .filter(s => s.category?._id === cat._id)
                          .map(sub => (
                            <span
                              key={sub._id}
                              className="bg-white shadow px-4 py-2 rounded-full flex items-center gap-2 text-sm"
                            >
                              {sub.name}

                              <Edit
                                className="text-blue-500 cursor-pointer w-4 h-4 hover:scale-125 transition"
                                onClick={() =>
                                  handleEdit(sub, "subcategories")
                                }
                              />

                              <Trash2
                                className="text-red-500 cursor-pointer w-4 h-4 hover:scale-125 transition"
                                onClick={() =>
                                  handleDelete(sub._id, "subcategories")
                                }
                              />
                            </span>
                          ))}

                      </div>
                    </div>
                  ))}

              </div>
            </div>
          ))}

        </div>
      )}

      {/* EDIT MODAL */}
      {isEditing && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white w-full max-w-md p-6 rounded-2xl shadow-2xl relative">

            <button
              className="absolute top-4 right-4 text-gray-600 hover:text-black"
              onClick={() => setIsEditing(false)}
            >
              <X className="w-6 h-6" />
            </button>

            <h2 className="text-2xl font-semibold text-center mb-6 text-gray-800">
              Edit {editData.type.slice(0, -1)}
            </h2>

            <input
              type="text"
              className="w-full p-3 rounded-xl bg-gray-100 outline-none focus:ring-2 ring-blue-500"
              value={editData.name}
              onChange={(e) =>
                setEditData({ ...editData, name: e.target.value })
              }
            />

            <button
              onClick={handleSaveEdit}
              className="w-full mt-5 bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-xl text-lg shadow-md transition"
            >
              Save Changes
            </button>
          </div>
        </div>
      )}

    </div>
  );
};

export default AllCategory;
