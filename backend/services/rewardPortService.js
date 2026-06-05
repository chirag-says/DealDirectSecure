/**
 * RewardPort Service — DealDirect Rewards
 * Integration with RewardPort (catalogue.rewardzpromo.com) for product/voucher catalogue.
 *
 * Uses HTTP Basic Authentication and native fetch (Node 18+).
 * Env vars: REWARDPORT_USERNAME, REWARDPORT_PASSWORD
 */

const REWARDPORT_BASE_URL = "https://catalogue.rewardzpromo.com";

/**
 * Get Basic Auth header for RewardPort API
 */
const getAuthHeader = () => {
  const username = process.env.REWARDPORT_USERNAME;
  const password = process.env.REWARDPORT_PASSWORD;

  if (!username || !password) {
    throw new Error("RewardPort credentials not configured (REWARDPORT_USERNAME / REWARDPORT_PASSWORD)");
  }

  const encoded = Buffer.from(`${username}:${password}`).toString("base64");
  return `Basic ${encoded}`;
};

/**
 * Helper: make an authenticated request to RewardPort
 */
const rpFetch = async (path, options = {}) => {
  const url = `${REWARDPORT_BASE_URL}${path}`;
  const response = await fetch(url, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: getAuthHeader(),
      ...options.headers,
    },
    signal: AbortSignal.timeout(15000),
  });

  if (!response.ok) {
    throw new Error(`RewardPort API error: ${response.status} ${response.statusText}`);
  }

  return response.json();
};

// ============================================
// API METHODS
// ============================================

/**
 * Get all product categories
 * GET /api/productcategorylist
 */
export const getCategories = async () => {
  try {
    const data = await rpFetch("/api/productcategorylist");
    return {
      success: true,
      categories: data?.categories || [],
    };
  } catch (error) {
    console.error("[RewardPort] Failed to fetch categories:", error.message);
    return { success: false, error: error.message, categories: [] };
  }
};

/**
 * Get sub-categories by parent category ID
 * GET /api/productsubcategorylist/{categoryId}
 */
export const getSubCategories = async (categoryId) => {
  try {
    const data = await rpFetch(`/api/productsubcategorylist/${categoryId}`);
    return {
      success: true,
      subCategories: data?.subCategories || [],
    };
  } catch (error) {
    console.error("[RewardPort] Failed to fetch sub-categories:", error.message);
    return { success: false, error: error.message, subCategories: [] };
  }
};

/**
 * Get all products
 * GET /api/productlist
 */
export const getAllProducts = async () => {
  try {
    const data = await rpFetch("/api/productlist");
    return {
      success: true,
      products: data?.ProductList || [],
    };
  } catch (error) {
    console.error("[RewardPort] Failed to fetch products:", error.message);
    return { success: false, error: error.message, products: [] };
  }
};

/**
 * Filter & sort products
 * POST /api/products/getbycategory
 */
export const getProductsByCategory = async ({ categoryId = 0, subCategoryId = 0, sortBy = 1 } = {}) => {
  try {
    const data = await rpFetch("/api/products/getbycategory", {
      method: "POST",
      body: JSON.stringify({
        ProductCategoryId: categoryId,
        ProductSubCatId: subCategoryId,
        SortBy: sortBy,
      }),
    });
    return {
      success: true,
      products: data?.ProductList || [],
    };
  } catch (error) {
    console.error("[RewardPort] Failed to filter products:", error.message);
    return { success: false, error: error.message, products: [] };
  }
};

/**
 * Get product details by ID
 * POST /api/products/details
 */
export const getProductDetails = async (productId) => {
  try {
    const data = await rpFetch("/api/products/details", {
      method: "POST",
      body: JSON.stringify({ ProductId: String(productId) }),
    });
    return {
      success: true,
      product: data?.Product || null,
    };
  } catch (error) {
    console.error("[RewardPort] Failed to fetch product details:", error.message);
    return { success: false, error: error.message, product: null };
  }
};

/**
 * Check if RewardPort is configured
 */
export const isRewardPortConfigured = () => {
  return !!(process.env.REWARDPORT_USERNAME && process.env.REWARDPORT_PASSWORD);
};

export default {
  getCategories,
  getSubCategories,
  getAllProducts,
  getProductsByCategory,
  getProductDetails,
  isRewardPortConfigured,
};
