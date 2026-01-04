// src/pages/Admin/AddProperty.jsx
import React, { useEffect, useState } from "react";
import axios from "axios";
import { toast } from "react-toastify";
import { Building2, Image as ImageIcon, Plus, XCircle, Loader2 } from "lucide-react";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "";

const toIdString = (value) => {
  if (!value) return "";
  if (typeof value === "object" && value._id) return String(value._id);
  return String(value);
};

const createInitialFormState = () => ({
  propertyType: "",
  category: "",
  subcategory: "",
  title: "",
  description: "",
  price: "",
  priceUnit: "Lac",
  area: { totalSqft: "", carpetSqft: "", builtUpSqft: "", pricePerSqft: "" },
  parking: { covered: "", open: "" },
  address: { line: "", area: "", city: "", state: "", pincode: "" },
  flooring: [],
});

const fileToBase64 = (file) =>
  new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(reader.result);
    reader.onerror = reject;
    reader.readAsDataURL(file);
  });

const AddProperty = () => {
  const [formData, setFormData] = useState(() => createInitialFormState());

  const [propertyTypes, setPropertyTypes] = useState([]);
  const [categories, setCategories] = useState([]);
  const [subcategories, setSubcategories] = useState([]);

  const [newPropertyType, setNewPropertyType] = useState("");
  const [newCategory, setNewCategory] = useState("");
  const [newSubcategory, setNewSubcategory] = useState("");

  const [images, setImages] = useState([]); // File objects
  const [errors, setErrors] = useState({});
  const [actionLoading, setActionLoading] = useState({
    propertyType: false,
    category: false,
    subcategory: false,
    submit: false,
  });

  // Utility - admin auth header
  const getAuthHeaders = () => {
    const token = localStorage.getItem("adminToken");
    return token ? { Authorization: `Bearer ${token}` } : {};
  };

  const runWithAction = async (key, task) => {
    setActionLoading((prev) => ({ ...prev, [key]: true }));
    try {
      await task();
    } finally {
      setActionLoading((prev) => ({ ...prev, [key]: false }));
    }
  };

  // Load property types
  useEffect(() => {
    loadPropertyTypes();
  }, []);

  const loadPropertyTypes = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/api/propertyTypes/list-propertytype`);
      setPropertyTypes(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error("loadPropertyTypes:", err?.response?.data || err.message);
      toast.error("Failed to load property types");
    }
  };

  // Load categories (all) and filter by propertyType client-side
  useEffect(() => {
    if (!formData.propertyType) {
      setCategories([]);
      setFormData((s) => ({ ...s, category: "", subcategory: "" }));
      return;
    }
    loadCategories();
  }, [formData.propertyType]);

  const loadCategories = async () => {
    try {
      const res = await axios.get(`${API_BASE_URL}/api/categories/list-category`);
      const list = Array.isArray(res.data) ? res.data : [];
      const activePropertyType = toIdString(formData.propertyType);
      const filtered = list.filter((c) => toIdString(c.propertyType?._id || c.propertyType) === activePropertyType);
      setCategories(filtered);
    } catch (err) {
      console.error("loadCategories:", err?.response?.data || err.message);
      toast.error("Failed to load categories");
    }
  };

  // Load subcategories for selected category
  useEffect(() => {
    if (!formData.category) {
      setSubcategories([]);
      setFormData((s) => ({ ...s, subcategory: "" }));
      return;
    }
    loadSubcategories();
  }, [formData.category]);

  const loadSubcategories = async () => {
    try {
      const categoryId = toIdString(formData.category);
      if (!categoryId) return;
      const res = await axios.get(`${API_BASE_URL}/api/subcategories/byCategory/${categoryId}`);
      setSubcategories(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      console.error("loadSubcategories:", err?.response?.data || err.message);
      toast.error("Failed to load subcategories");
    }
  };

  // -----------------------
  // Create helpers
  // -----------------------
  const handleAddPropertyType = async () => {
    if (!newPropertyType.trim()) return toast.error("Enter a property type name");
    await runWithAction("propertyType", async () => {
      try {
        const res = await axios.post(
          `${API_BASE_URL}/api/propertyTypes/add-property-type`,
          { name: newPropertyType.trim() },
          { headers: getAuthHeaders() }
        );

        const created = res.data;
        toast.success("Property type added");
        setNewPropertyType("");
        await loadPropertyTypes();
        if (created?._id)
          setFormData((s) => ({ ...s, propertyType: toIdString(created._id), category: "", subcategory: "" }));
      } catch (err) {
        console.error("handleAddPropertyType:", err?.response?.data || err.message);
        toast.error(err.response?.data?.message || "Failed to add property type");
      }
    });
  };

  const handleAddCategory = async () => {
    const propertyTypeId = toIdString(formData.propertyType);
    if (!propertyTypeId) return toast.error("Select a property type first");
    if (!newCategory.trim()) return toast.error("Enter a category name");
    await runWithAction("category", async () => {
      try {
        const res = await axios.post(
          `${API_BASE_URL}/api/categories/add-category`,
          { name: newCategory.trim(), propertyType: propertyTypeId },
          { headers: getAuthHeaders() }
        );

        const created = res.data;
        toast.success("Category added");
        setNewCategory("");
        await loadCategories();
        if (created?._id) setFormData((s) => ({ ...s, category: toIdString(created._id) }));
      } catch (err) {
        console.error("handleAddCategory:", err?.response?.data || err.message);
        toast.error(err.response?.data?.message || "Failed to add category");
      }
    });
  };

  const handleAddSubcategory = async () => {
    const categoryId = toIdString(formData.category);
    if (!categoryId) return toast.error("Select a category first");
    const propertyTypeId = toIdString(formData.propertyType);
    if (!newSubcategory.trim()) return toast.error("Enter a subcategory name");
    await runWithAction("subcategory", async () => {
      try {
        const res = await axios.post(
          `${API_BASE_URL}/api/subcategories/add`,
          { name: newSubcategory.trim(), category: categoryId, propertyType: propertyTypeId },
          { headers: getAuthHeaders() }
        );
        const created = res.data;
        toast.success("Subcategory added");
        setNewSubcategory("");
        await loadSubcategories();
        if (created?._id) setFormData((s) => ({ ...s, subcategory: toIdString(created._id) }));
      } catch (err) {
        console.error("handleAddSubcategory:", err?.response?.data || err.message);
        toast.error(err.response?.data?.message || "Failed to add subcategory");
      }
    });
  };

  // -----------------------
  // Form handlers
  // -----------------------
  const handleChange = (e) => setFormData({ ...formData, [e.target.name]: e.target.value });

  const handleNested = (section, key, value) =>
    setFormData((s) => ({ ...s, [section]: { ...(s[section] || {}), [key]: value } }));

  const handleFlooring = (e) =>
    setFormData((s) => ({ ...s, flooring: e.target.value.split(",").map((x) => x.trim()).filter(Boolean) }));

  const handleImageChange = (e) => {
    const files = Array.from(e.target.files || []);
    setImages((prev) => [...prev, ...files].slice(0, 10)); // limit 10
  };

  const removeImageAt = (idx) => setImages((prev) => prev.filter((_, i) => i !== idx));

  const resetFormState = () => {
    setFormData(createInitialFormState());
    setImages([]);
    setCategories([]);
    setSubcategories([]);
    setErrors({});
    setNewPropertyType("");
    setNewCategory("");
    setNewSubcategory("");
  };

  const handleResetForm = () => {
    resetFormState();
    toast.info("Form cleared");
  };

  // -----------------------
  // Validation
  // -----------------------
  const validate = () => {
    const err = {};
    if (!formData.propertyType) err.propertyType = "Required";
    if (!formData.category) err.category = "Required";
    if (!formData.subcategory) err.subcategory = "Required";
    if (!formData.title || !formData.title.trim()) err.title = "Required";
    if (!formData.price) err.price = "Required";
    if (!formData.address?.city || !String(formData.address.city).trim()) err.city = "Required";
    setErrors(err);
    return Object.keys(err).length === 0;
  };

  // -----------------------
  // Submit property
  // -----------------------
  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!validate()) return toast.error("Please fill required fields");

    await runWithAction("submit", async () => {
      try {
        const data = new FormData();

        const simpleKeys = ["propertyType", "category", "subcategory", "title", "description", "price", "priceUnit"];
        simpleKeys.forEach((k) => data.append(k, formData[k] ? String(formData[k]) : ""));

        // Add property type and normalized category names
        const selectedPropertyType = propertyTypes.find(pt => pt._id === formData.propertyType);
        const selectedCategory = categories.find(c => c._id === formData.category);

        if (selectedPropertyType) {
          data.append("propertyTypeName", selectedPropertyType.name);
        }

        if (selectedCategory) {
          const rawName = selectedCategory.name || "";
          const lower = rawName.toLowerCase();

          let normalizedCategory = rawName;
          if (lower.includes("residen")) normalizedCategory = "Residential";
          else if (lower.includes("commercial")) normalizedCategory = "Commercial";
          else if (selectedPropertyType?.name) {
            const typeLower = selectedPropertyType.name.toLowerCase();
            const isCommercialType = /office|shop|showroom|restaurant|cafe|warehouse|industrial|co-working|coworking|commercial/.test(typeLower);
            normalizedCategory = isCommercialType ? "Commercial" : "Residential";
          } else {
            normalizedCategory = "Residential";
          }

          data.append("categoryName", normalizedCategory);
        }

        ["area", "parking", "address", "flooring"].forEach((k) => {
          if (formData[k] !== undefined) data.append(k, JSON.stringify(formData[k]));
        });

        // Add images as files
        images.forEach((file) => data.append("images", file));

        await axios.post(`${API_BASE_URL}/api/properties/add`, data, {
          headers: getAuthHeaders(),
        });

        toast.success("Property added successfully");
        resetFormState();
      } catch (err) {
        console.error("addProperty:", err?.response?.data || err?.message);
        toast.error(err.response?.data?.message || "Failed to add property");
      }
    });
  };

  const invalid = (flag) => (flag ? "border-red-500 ring-red-200" : "border-gray-300");
  const canAddPropertyType = Boolean(newPropertyType.trim());
  const canAddCategory = Boolean(formData.propertyType && newCategory.trim());
  const canAddSubcategory = Boolean(formData.category && newSubcategory.trim());

  return (
    <div className="max-w-6xl mx-auto bg-white p-8 mt-6 rounded-2xl shadow">
      <div className="flex items-center gap-3 mb-6">
        <Building2 className="text-blue-600" />
        <h2 className="text-2xl font-semibold">Add Property</h2>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Property Type */}
        <div className="grid gap-2">
          <label className="font-medium">Property Type</label>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap gap-2">
              <select
                name="propertyType"
                value={formData.propertyType}
                onChange={handleChange}
                className={`flex-1 min-w-[200px] p-2 rounded border ${invalid(errors.propertyType)}`}
              >
                <option value="">Select Property Type</option>
                {propertyTypes.map((pt) => (
                  <option key={pt._id} value={pt._id}>
                    {pt.name}
                  </option>
                ))}
              </select>
              <input
                placeholder="Add new type"
                value={newPropertyType}
                onChange={(e) => setNewPropertyType(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleAddPropertyType();
                  }
                }}
                className="p-2 rounded border flex-1 min-w-[180px]"
              />
              <button
                type="button"
                onClick={handleAddPropertyType}
                disabled={!canAddPropertyType || actionLoading.propertyType}
                className={`flex items-center gap-1 px-4 rounded text-white text-sm font-medium ${!canAddPropertyType || actionLoading.propertyType
                    ? "bg-blue-300 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-700"
                  }`}
              >
                {actionLoading.propertyType ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4" />
                )}
                <span>Add Type</span>
              </button>
            </div>
            <p className="text-xs text-gray-500">
              Choose an existing type or create a new one to unlock category options.
            </p>
          </div>
        </div>

        {/* Category */}
        <div className="grid gap-2">
          <label className="font-medium">Category</label>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap gap-2">
              <select
                name="category"
                value={formData.category}
                onChange={handleChange}
                className={`flex-1 min-w-[200px] p-2 rounded border ${invalid(errors.category)}`}
                disabled={!formData.propertyType}
              >
                <option value="">{formData.propertyType ? "Select Category" : "Pick property type first"}</option>
                {categories.map((c) => (
                  <option key={c._id} value={c._id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <input
                placeholder="Add new category"
                value={newCategory}
                onChange={(e) => setNewCategory(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleAddCategory();
                  }
                }}
                className="p-2 rounded border flex-1 min-w-[180px]"
                disabled={!formData.propertyType}
              />
              <button
                type="button"
                onClick={handleAddCategory}
                disabled={!canAddCategory || actionLoading.category}
                className={`flex items-center gap-1 px-4 rounded text-white text-sm font-medium ${!canAddCategory || actionLoading.category
                    ? "bg-blue-300 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-700"
                  }`}
              >
                {actionLoading.category ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4" />
                )}
                <span>Add Category</span>
              </button>
            </div>
            <p className="text-xs text-gray-500">
              Categories are filtered by the selected property type.
            </p>
          </div>
        </div>

        {/* Subcategory */}
        <div className="grid gap-2">
          <label className="font-medium">Subcategory</label>
          <div className="flex flex-col gap-2">
            <div className="flex flex-wrap gap-2">
              <select
                name="subcategory"
                value={formData.subcategory}
                onChange={handleChange}
                className={`flex-1 min-w-[200px] p-2 rounded border ${invalid(errors.subcategory)}`}
                disabled={!formData.category}
              >
                <option value="">{formData.category ? "Select Subcategory" : "Pick category first"}</option>
                {subcategories.map((s) => (
                  <option key={s._id} value={s._id}>
                    {s.name}
                  </option>
                ))}
              </select>
              <input
                placeholder="Add new subcategory"
                value={newSubcategory}
                onChange={(e) => setNewSubcategory(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    handleAddSubcategory();
                  }
                }}
                className="p-2 rounded border flex-1 min-w-[180px]"
                disabled={!formData.category}
              />
              <button
                type="button"
                onClick={handleAddSubcategory}
                disabled={!canAddSubcategory || actionLoading.subcategory}
                className={`flex items-center gap-1 px-4 rounded text-white text-sm font-medium ${!canAddSubcategory || actionLoading.subcategory
                    ? "bg-blue-300 cursor-not-allowed"
                    : "bg-blue-600 hover:bg-blue-700"
                  }`}
              >
                {actionLoading.subcategory ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Plus className="h-4 w-4" />
                )}
                <span>Add Subcategory</span>
              </button>
            </div>
            <p className="text-xs text-gray-500">Subcategories depend on the selected category.</p>
          </div>
        </div>

        {/* Property Details */}
        <div className="grid gap-2">
          <label className="font-medium">Property Title</label>
          <input
            name="title"
            value={formData.title}
            onChange={handleChange}
            className={`p-2 rounded border ${invalid(errors.title)}`}
            placeholder="e.g. 2 BHK apartment near XYZ"
          />
          <label className="font-medium">Description</label>
          <textarea
            name="description"
            value={formData.description}
            onChange={handleChange}
            className="p-2 rounded border"
            rows={4}
            placeholder="Describe the property..."
          />
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="font-medium">Price</label>
              <input name="price" value={formData.price} onChange={handleChange} className={`p-2 rounded border ${invalid(errors.price)}`} placeholder="Price" />
            </div>
            <div>
              <label className="font-medium">Unit</label>
              <input name="priceUnit" value={formData.priceUnit} onChange={handleChange} className="p-2 rounded border" />
            </div>
          </div>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div className="border rounded-xl p-4 space-y-2">
            <h3 className="font-semibold text-gray-800">Area Details (sqft)</h3>
            <div className="grid grid-cols-2 gap-2">
              <input
                type="number"
                min="0"
                placeholder="Total"
                value={formData.area.totalSqft}
                onChange={(e) => handleNested("area", "totalSqft", e.target.value)}
                className="p-2 rounded border"
              />
              <input
                type="number"
                min="0"
                placeholder="Carpet"
                value={formData.area.carpetSqft}
                onChange={(e) => handleNested("area", "carpetSqft", e.target.value)}
                className="p-2 rounded border"
              />
              <input
                type="number"
                min="0"
                placeholder="Built-up"
                value={formData.area.builtUpSqft}
                onChange={(e) => handleNested("area", "builtUpSqft", e.target.value)}
                className="p-2 rounded border"
              />
              <input
                type="number"
                min="0"
                placeholder="Price / Sqft"
                value={formData.area.pricePerSqft}
                onChange={(e) => handleNested("area", "pricePerSqft", e.target.value)}
                className="p-2 rounded border"
              />
            </div>
          </div>

          <div className="border rounded-xl p-4 space-y-2">
            <h3 className="font-semibold text-gray-800">Parking & Flooring</h3>
            <div className="grid grid-cols-2 gap-2">
              <input
                type="text"
                placeholder="Covered parking"
                value={formData.parking.covered}
                onChange={(e) => handleNested("parking", "covered", e.target.value)}
                className="p-2 rounded border"
              />
              <input
                type="text"
                placeholder="Open parking"
                value={formData.parking.open}
                onChange={(e) => handleNested("parking", "open", e.target.value)}
                className="p-2 rounded border"
              />
            </div>
            <div>
              <label className="text-sm text-gray-600">Flooring Types (comma separated)</label>
              <input
                type="text"
                placeholder="Marble, Wooden"
                value={formData.flooring.join(", ")}
                onChange={handleFlooring}
                className="mt-1 p-2 rounded border w-full"
              />
            </div>
          </div>
        </div>

        {/* Location */}
        <div className="grid gap-2">
          <label className="font-medium">Location</label>
          <div className="grid md:grid-cols-2 gap-2">
            <input placeholder="City" value={formData.address.city} onChange={(e) => handleNested("address", "city", e.target.value)} className={`p-2 rounded border ${invalid(errors.city)}`} />
            <input placeholder="Area / Locality" value={formData.address.area} onChange={(e) => handleNested("address", "area", e.target.value)} className="p-2 rounded border" />
          </div>
          <div className="grid md:grid-cols-2 gap-2 mt-2">
            <input placeholder="Pincode" value={formData.address.pincode} onChange={(e) => handleNested("address", "pincode", e.target.value)} className="p-2 rounded border" />
            <input placeholder="State" value={formData.address.state} onChange={(e) => handleNested("address", "state", e.target.value)} className="p-2 rounded border" />
          </div>
        </div>

        {/* Images */}
        <div className="grid gap-2">
          <label className="font-medium flex items-center gap-2">
            <ImageIcon /> Property Images (max 10)
          </label>
          <input type="file" multiple accept="image/*" onChange={handleImageChange} />
          {images.length > 0 && (
            <div className="grid grid-cols-3 gap-3 mt-3">
              {images.map((file, idx) => (
                <div key={idx} className="relative h-28 border rounded overflow-hidden">
                  <img src={URL.createObjectURL(file)} alt="preview" className="w-full h-full object-cover" />
                  <button type="button" onClick={() => removeImageAt(idx)} className="absolute top-1 right-1 bg-white rounded-full p-1">
                    <XCircle size={16} />
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <button
            type="button"
            onClick={handleResetForm}
            className="px-4 py-2 border border-gray-300 rounded text-gray-700 hover:bg-gray-50"
          >
            Reset Form
          </button>
          <button
            type="submit"
            disabled={actionLoading.submit}
            className={`px-6 py-2 rounded text-white font-semibold flex items-center justify-center gap-2 ${actionLoading.submit ? "bg-blue-400 cursor-not-allowed" : "bg-blue-600 hover:bg-blue-700"
              }`}
          >
            {actionLoading.submit && <Loader2 className="h-4 w-4 animate-spin" />}
            Submit Property
          </button>
        </div>
      </form>
    </div>
  );
};

export default AddProperty;
