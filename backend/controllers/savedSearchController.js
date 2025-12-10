import SavedSearch from "../models/SavedSearch.js";
import Notification from "../models/Notification.js";

// Create a new saved search for logged-in user
export const createSavedSearch = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const { name, filters, notifyEmail = true, notifyInApp = true } = req.body;

    if (!name || !filters) {
      return res.status(400).json({ success: false, message: "Name and filters are required" });
    }

    const hasAnyFilter =
      (filters.search && filters.search.trim()) ||
      filters.city ||
      filters.propertyType ||
      filters.priceRange ||
      filters.availableFor;

    if (!hasAnyFilter) {
      return res.status(400).json({
        success: false,
        message: "At least one filter (city, type, price, etc.) is required to save a search",
      });
    }

    const saved = await SavedSearch.create({
      user: userId,
      name,
      filters: {
        search: filters.search || "",
        city: filters.city || "",
        propertyType: filters.propertyType || "",
        priceRange: filters.priceRange || "",
        availableFor: filters.availableFor || "",
      },
      notifyEmail: Boolean(notifyEmail),
      notifyInApp: Boolean(notifyInApp),
    });

    // Create a simple notification for the user
    try {
      await Notification.create({
        user: userId,
        title: "Search saved",
        message: `We will alert you when new properties match: ${name}`,
        type: "saved-search",
        data: { savedSearchId: saved._id },
      });
    } catch (notifyErr) {
      console.error("Notification create error (saved search):", notifyErr);
    }

    return res.status(201).json({ success: true, savedSearch: saved });
  } catch (err) {
    console.error("createSavedSearch error:", err);
    return res.status(500).json({ success: false, message: "Failed to save search" });
  }
};

// Get current user's saved searches
export const getMySavedSearches = async (req, res) => {
  try {
    const userId = req.user?._id;
    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const searches = await SavedSearch.find({ user: userId, isActive: true })
      .sort({ updatedAt: -1 })
      .lean();

    return res.json({ success: true, searches });
  } catch (err) {
    console.error("getMySavedSearches error:", err);
    return res.status(500).json({ success: false, message: "Failed to fetch saved searches" });
  }
};

// Soft-disable a saved search (stop alerts)
export const toggleSavedSearchActive = async (req, res) => {
  try {
    const userId = req.user?._id;
    const { id } = req.params;

    if (!userId) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const search = await SavedSearch.findOne({ _id: id, user: userId });
    if (!search) {
      return res.status(404).json({ success: false, message: "Saved search not found" });
    }

    search.isActive = !search.isActive;
    await search.save();

    return res.json({ success: true, savedSearch: search });
  } catch (err) {
    console.error("toggleSavedSearchActive error:", err);
    return res.status(500).json({ success: false, message: "Failed to update saved search" });
  }
};
