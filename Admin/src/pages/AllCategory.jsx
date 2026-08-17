import React, { useState, useEffect } from "react";
import adminApi from "../api/adminApi";
import { toast } from "react-toastify";

/**
 * The property taxonomy, as the API actually serves it.
 *
 * This page had three separate defects and had never rendered data:
 *
 * 1. It called `axios.get()` three times without importing `axios`, so every
 *    load threw a ReferenceError, hit the catch, and showed "Failed to load
 *    data". Identical to the bug in AddCategory.jsx next door.
 * 2. It fetched `/api/subcategories/list`, which is unmounted (decision D9),
 *    inside a `Promise.all`. That leg alone would have taken the whole page
 *    down even after the axios fix, because `Promise.all` rejects as a unit.
 * 3. It rendered the inverted hierarchy: property types on the outside,
 *    categories nested underneath, filtered on `c.propertyType`. That path no
 *    longer exists. Category is the top level; a property type belongs to one.
 *
 * READ-ONLY, and that is not a simplification.
 *
 * `list-category` and `list-propertytype` return the active taxonomy only, so
 * everything this page can display is canonical, and canonical documents are
 * immutable through the API: the server answers 409 TAXONOMY_PROTECTED. Renaming
 * `Residential` would not fail loudly, it would silently drop the category out
 * of every dropdown and start rejecting every listing that names it. Edit and
 * delete controls here would be buttons that always error.
 *
 * The nineteen obsolete rows the additive migration left behind are the ones
 * that genuinely need removing, and they are not returned by these endpoints.
 * Cleaning them up is the separate destructive stage in the cutover plan, which
 * needs its own confirmation and its own backup, not a trash icon.
 */
const AllCategory = () => {
  const [categories, setCategories] = useState([]);
  const [propertyTypes, setPropertyTypes] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        setLoading(true);
        // adminApi carries the base URL and the session cookie, so these are
        // relative. The old absolute `${API_URL}/api/...` strings bypassed the
        // instance's own configuration.
        const [catRes, typeRes] = await Promise.all([
          adminApi.get("/api/categories/list-category"),
          adminApi.get("/api/propertyTypes/list-propertytype"),
        ]);
        // Both endpoints answer { success, data }. The old code assigned
        // `res.data` straight into state, so `.map()` ran against an object.
        setCategories(catRes.data?.data || []);
        setPropertyTypes(typeRes.data?.data || []);
      } catch (err) {
        toast.error("Failed to load the taxonomy");
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const typesOf = (categoryId) =>
    propertyTypes.filter((t) => (t.category?._id || t.category) === categoryId);

  return (
    <div className="bg-gray-50 min-h-screen sm:p-4">
      <h2 className="text-xl sm:text-2xl font-bold mb-2 text-gray-800">
        Property Taxonomy
      </h2>
      <p className="text-sm text-gray-600 mb-8">
        The categories and property types every listing is filed under. This
        vocabulary is fixed in the application and cannot be edited here, because
        changing a name would stop existing listings from resolving against it.
      </p>

      {loading ? (
        <p className="text-center text-gray-500 text-lg">Loading...</p>
      ) : categories.length === 0 ? (
        <p className="text-center text-gray-500 text-lg">
          No taxonomy found. If this is unexpected, the seed migration has not run.
        </p>
      ) : (
        <div className="space-y-6">
          {categories.map((cat) => {
            const types = typesOf(cat._id);
            return (
              <div
                key={cat._id}
                className="bg-white shadow-lg rounded-2xl p-6 hover:shadow-xl transition-all"
              >
                <div className="flex justify-between items-baseline">
                  <h3 className="text-xl font-semibold text-gray-800">
                    {cat.name}
                  </h3>
                  <span className="text-sm text-gray-500">
                    {types.length} {types.length === 1 ? "type" : "types"}
                  </span>
                </div>

                <div className="flex flex-wrap gap-3 mt-4">
                  {types.map((type) => (
                    <span
                      key={type._id}
                      className="bg-gray-100 px-4 py-2 rounded-full text-sm text-gray-800"
                    >
                      {type.name}
                    </span>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export default AllCategory;
