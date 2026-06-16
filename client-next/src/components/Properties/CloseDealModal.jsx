'use client';

import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  X,
  Upload,
  FileText,
  User,
  CheckCircle,
  AlertCircle,
  Loader2,
  Trash2,
  Key,
  Tag,
} from "lucide-react";
import api from "../../utils/api";
import { toast } from "react-toastify";

/**
 * CloseDealModal — Owner submits proof to close a deal.
 *
 * Props:
 *  - isOpen: boolean
 *  - onClose: () => void
 *  - property: object (the property being closed)
 *  - onSuccess: () => void (callback after successful submission)
 */
export default function CloseDealModal({ isOpen, onClose, property, onSuccess }) {
  const [step, setStep] = useState(1); // Step 1: type + documents, Step 2: buyer selection
  const [closingType, setClosingType] = useState("");
  const [documents, setDocuments] = useState([]);
  const [buyerId, setBuyerId] = useState("");
  const [interestedUsers, setInterestedUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [loadingUsers, setLoadingUsers] = useState(false);

  // Determine default closing type from listing type
  useEffect(() => {
    if (isOpen && property) {
      const lt = property.listingType?.toLowerCase();
      if (lt === "sell" || lt === "sale") {
        setClosingType("sold");
      } else if (lt === "rent" || lt === "lease") {
        setClosingType("rented");
      }
    }
  }, [property, isOpen]);

  // Load interested users from the property data (already populated by getMyProperties)
  useEffect(() => {
    if (isOpen && property) {
      const users = property.interestedUsers || [];
      setInterestedUsers(users);
      setLoadingUsers(false);
    }
  }, [isOpen, property]);

  const handleFileChange = (e) => {
    const files = Array.from(e.target.files);
    const validFiles = files.filter((f) => {
      const ext = f.name.split(".").pop().toLowerCase();
      const isValid = ["pdf", "jpg", "jpeg", "png", "webp"].includes(ext);
      const isSmallEnough = f.size <= 15 * 1024 * 1024; // 15MB
      if (!isValid) toast.error(`${f.name} is not a valid file type`);
      if (!isSmallEnough) toast.error(`${f.name} exceeds 15MB limit`);
      return isValid && isSmallEnough;
    });

    if (documents.length + validFiles.length > 5) {
      toast.error("Maximum 5 documents allowed");
      return;
    }

    setDocuments((prev) => [...prev, ...validFiles]);
  };

  const removeDocument = (idx) => {
    setDocuments((prev) => prev.filter((_, i) => i !== idx));
  };

  const handleNextStep = () => {
    if (!closingType) {
      toast.error("Please select how this property was closed");
      return;
    }
    if (documents.length === 0) {
      toast.error("Please upload at least one proof document");
      return;
    }
    setStep(2);
  };

  const handleSubmit = async () => {
    if (!buyerId) {
      toast.error("Please select the buyer/tenant");
      return;
    }

    setLoading(true);
    try {
      const formData = new FormData();
      formData.append("closingType", closingType);
      formData.append("buyerId", buyerId);
      documents.forEach((doc) => {
        formData.append("documents", doc);
      });

      const res = await api.post(`/properties/${property._id}/close-deal`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      if (res.data.success) {
        toast.success("Deal submitted for verification! You'll be notified once the admin approves it.");
        onSuccess?.();
        handleClose();
      }
    } catch (err) {
      const msg = err.response?.data?.message || "Failed to submit deal closure";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleClose = () => {
    setStep(1);
    setClosingType("");
    setDocuments([]);
    setBuyerId("");
    onClose();
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4"
        onClick={handleClose}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 20 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 20 }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="bg-white rounded-2xl shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto"
          onClick={(e) => e.stopPropagation()}
        >
          {/* Header */}
          <div className="sticky top-0 bg-white border-b border-gray-100 px-6 py-4 flex items-center justify-between z-10 rounded-t-2xl">
            <div>
              <h2 className="text-lg font-bold text-gray-900">Close Deal</h2>
              <p className="text-sm text-gray-500 mt-0.5">
                Step {step} of 2 — {step === 1 ? "Upload Proof" : "Select Buyer"}
              </p>
            </div>
            <button
              onClick={handleClose}
              className="p-2 rounded-lg hover:bg-gray-100 transition"
            >
              <X className="w-5 h-5 text-gray-500" />
            </button>
          </div>

          {/* Step Progress Bar */}
          <div className="px-6 pt-4">
            <div className="flex gap-2">
              <div className={`h-1.5 flex-1 rounded-full ${step >= 1 ? "bg-blue-600" : "bg-gray-200"}`} />
              <div className={`h-1.5 flex-1 rounded-full ${step >= 2 ? "bg-blue-600" : "bg-gray-200"}`} />
            </div>
          </div>

          <div className="px-6 py-5 space-y-5">
            {/* Property Info */}
            <div className="p-3 bg-gray-50 rounded-xl">
              <p className="text-sm font-medium text-gray-800">{property?.title}</p>
              <p className="text-xs text-gray-500 mt-1">
                {property?.locality || property?.address?.area || ""},{" "}
                {property?.city || property?.address?.city || ""}
              </p>
            </div>

            {step === 1 && (
              <>
                {/* Closing Type — auto-determined from listing type */}
                <div className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${closingType === "rented" ? "bg-purple-100" : "bg-blue-100"}`}>
                    {closingType === "rented"
                      ? <Key className="w-5 h-5 text-purple-600" />
                      : <Tag className="w-5 h-5 text-blue-600" />
                    }
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-800">
                      This property will be marked as{" "}
                      <span className={closingType === "rented" ? "text-purple-600" : "text-blue-600"}>
                        {closingType === "rented" ? "Rented" : "Sold"}
                      </span>
                    </p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      Based on listing type: {property?.listingType || "Sale"}
                    </p>
                  </div>
                </div>

                {/* Document Upload */}
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Upload Proof Documents
                  </label>
                  <p className="text-xs text-gray-500 mb-3">
                    Agreement, paperwork, or any sale proof. PDF and images accepted (max 5 files, 15MB each).
                  </p>

                  {/* Upload Zone */}
                  <label className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-gray-300 rounded-xl cursor-pointer hover:border-blue-400 hover:bg-blue-50/30 transition">
                    <Upload className="w-8 h-8 text-gray-400 mb-2" />
                    <span className="text-sm font-medium text-gray-600">Click to upload files</span>
                    <span className="text-xs text-gray-400 mt-1">PDF, JPG, PNG, WebP</span>
                    <input
                      type="file"
                      multiple
                      accept=".pdf,.jpg,.jpeg,.png,.webp"
                      onChange={handleFileChange}
                      className="hidden"
                    />
                  </label>

                  {/* Uploaded Files List */}
                  {documents.length > 0 && (
                    <div className="mt-3 space-y-2">
                      {documents.map((doc, idx) => (
                        <div
                          key={idx}
                          className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
                        >
                          <div className="flex items-center gap-2 min-w-0">
                            <FileText className="w-4 h-4 text-blue-600 flex-shrink-0" />
                            <span className="text-sm text-gray-700 truncate">{doc.name}</span>
                            <span className="text-xs text-gray-400 flex-shrink-0">
                              ({(doc.size / 1024 / 1024).toFixed(1)} MB)
                            </span>
                          </div>
                          <button
                            onClick={() => removeDocument(idx)}
                            className="p-1 rounded hover:bg-red-100 transition"
                          >
                            <Trash2 className="w-4 h-4 text-red-500" />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Next Button */}
                <button
                  onClick={handleNextStep}
                  className="w-full py-3 bg-blue-600 text-white rounded-xl font-semibold hover:bg-blue-700 transition"
                >
                  Next — Select Buyer
                </button>
              </>
            )}

            {step === 2 && (
              <>
                {/* Buyer Selection */}
                <div>
                  <label className="block text-sm font-semibold text-gray-700 mb-2">
                    Who {closingType === "rented" ? "rented" : "bought"} this property?
                  </label>
                  <p className="text-xs text-gray-500 mb-3">
                    Select from people who showed interest in this property.
                  </p>

                  {loadingUsers ? (
                    <div className="py-8 text-center">
                      <Loader2 className="w-6 h-6 text-blue-600 animate-spin mx-auto mb-2" />
                      <p className="text-sm text-gray-500">Loading interested users...</p>
                    </div>
                  ) : interestedUsers.length === 0 ? (
                    <div className="py-8 text-center bg-amber-50 rounded-xl">
                      <AlertCircle className="w-8 h-8 text-amber-500 mx-auto mb-2" />
                      <p className="text-sm font-medium text-amber-700">No interested users found</p>
                      <p className="text-xs text-amber-600 mt-1">
                        Only users who showed interest can be selected as the buyer.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-60 overflow-y-auto">
                      {interestedUsers.map((item) => {
                        const userId = item.user?._id || item.user;
                        const userName = item.user?.name || "User";
                        const userEmail = item.user?.email || "";
                        return (
                          <button
                            key={userId}
                            type="button"
                            onClick={() => setBuyerId(userId)}
                            className={`w-full flex items-center gap-3 p-3 rounded-xl border-2 transition text-left ${
                              buyerId === userId
                                ? "border-blue-600 bg-blue-50"
                                : "border-gray-200 hover:border-gray-300"
                            }`}
                          >
                            <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                              {userName.charAt(0).toUpperCase()}
                            </div>
                            <div className="min-w-0 flex-1">
                              <p className="text-sm font-medium text-gray-900 truncate">{userName}</p>
                              {userEmail && (
                                <p className="text-xs text-gray-500 truncate">{userEmail}</p>
                              )}
                            </div>
                            {buyerId === userId && (
                              <CheckCircle className="w-5 h-5 text-blue-600 flex-shrink-0" />
                            )}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>

                {/* Action Buttons */}
                <div className="flex gap-3">
                  <button
                    onClick={() => setStep(1)}
                    className="flex-1 py-3 border border-gray-300 text-gray-700 rounded-xl font-semibold hover:bg-gray-50 transition"
                  >
                    Back
                  </button>
                  <button
                    onClick={handleSubmit}
                    disabled={loading || !buyerId}
                    className="flex-1 py-3 bg-green-600 text-white rounded-xl font-semibold hover:bg-green-700 transition disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2"
                  >
                    {loading ? (
                      <>
                        <Loader2 className="w-4 h-4 animate-spin" /> Submitting...
                      </>
                    ) : (
                      <>
                        <CheckCircle className="w-4 h-4" /> Submit for Verification
                      </>
                    )}
                  </button>
                </div>

                {/* Info Banner */}
                <div className="p-3 bg-blue-50 rounded-xl text-xs text-blue-700 flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                  <span>
                    After submission, the admin will verify your documents. Once approved,
                    both you and the buyer will be notified to claim your rewards.
                  </span>
                </div>
              </>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
