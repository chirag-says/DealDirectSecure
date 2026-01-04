import React, { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { toast } from "react-toastify";
import ReactCrop, { centerCrop, makeAspectCrop } from "react-image-crop";
import "react-image-crop/dist/ReactCrop.css";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import {
  User,
  Mail,
  Phone,
  MapPin,
  Calendar,
  Camera,
  Save,
  Lock,
  Bell,
  Edit2,
  Check,
  X,
  Home,
  Building2,
  ChevronRight,
  Crop,
  RotateCw,
  ZoomIn,
  ZoomOut,
  Settings,
  Shield,
  Trash2,
  LogOut,
  HelpCircle,
  FileText,
  Heart,
} from "lucide-react";

// Note: API_BASE is no longer needed - api.js handles this

// Helper function to create centered aspect crop
function centerAspectCrop(mediaWidth, mediaHeight, aspect) {
  return centerCrop(
    makeAspectCrop(
      {
        unit: "%",
        width: 90,
      },
      aspect,
      mediaWidth,
      mediaHeight
    ),
    mediaWidth,
    mediaHeight
  );
}

const Profile = () => {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [activeTab, setActiveTab] = useState(searchParams.get("tab") || "profile");
  const [isEditing, setIsEditing] = useState(false);
  const [user, setUser] = useState(null);
  const [profileImage, setProfileImage] = useState(null);
  const [previewImage, setPreviewImage] = useState(null);

  // Update URL when tab changes
  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setSearchParams({ tab });
  };

  // Image cropping states
  const [showCropModal, setShowCropModal] = useState(false);
  const [imageSrc, setImageSrc] = useState("");
  const [crop, setCrop] = useState();
  const [completedCrop, setCompletedCrop] = useState();
  const imgRef = useRef(null);
  const [scale, setScale] = useState(1);
  const [rotate, setRotate] = useState(0);

  const [formData, setFormData] = useState({
    name: "",
    email: "",
    phone: "",
    alternatePhone: "",
    address: {
      line1: "",
      line2: "",
      city: "",
      state: "",
      pincode: "",
    },
    dateOfBirth: "",
    gender: "",
    bio: "",
    preferences: {
      emailNotifications: true,
      smsNotifications: false,
    },
  });

  const [passwordData, setPasswordData] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  const { isAuthenticated, loading: authLoading, updateUser } = useAuth();

  // Check auth and fetch profile
  useEffect(() => {
    if (!authLoading) {
      if (!isAuthenticated) {
        toast.error("Please login to view your profile");
        navigate("/login");
        return;
      }
      fetchProfile();
    }
  }, [navigate, authLoading, isAuthenticated]);

  const fetchProfile = async () => {
    try {
      setLoading(true);
      const response = await api.get('/users/profile');

      const userData = response.data.user;
      setUser(userData);
      updateUser(userData); // Sync global auth state
      setFormData({
        name: userData.name || "",
        email: userData.email || "",
        phone: userData.phone || "",
        alternatePhone: userData.alternatePhone || "",
        address: {
          line1: userData.address?.line1 || "",
          line2: userData.address?.line2 || "",
          city: userData.address?.city || "",
          state: userData.address?.state || "",
          pincode: userData.address?.pincode || "",
        },
        dateOfBirth: userData.dateOfBirth
          ? new Date(userData.dateOfBirth).toISOString().split("T")[0]
          : "",
        gender: userData.gender || "",
        bio: userData.bio || "",
        preferences: {
          emailNotifications: userData.preferences?.emailNotifications ?? true,
          smsNotifications: userData.preferences?.smsNotifications ?? false,
        },
      });
      setPreviewImage(userData.profileImage || null);
    } catch (error) {
      // 401 errors are handled by api interceptor
      if (error.response?.status !== 401) {
        console.error("Error fetching profile:", error);
        toast.error("Failed to load profile");
      }
    } finally {
      setLoading(false);
    }
  };

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;

    if (name.startsWith("address.")) {
      const field = name.split(".")[1];
      setFormData((prev) => ({
        ...prev,
        address: { ...prev.address, [field]: value },
      }));
    } else if (name.startsWith("preferences.")) {
      const field = name.split(".")[1];
      setFormData((prev) => ({
        ...prev,
        preferences: { ...prev.preferences, [field]: checked },
      }));
    } else {
      setFormData((prev) => ({
        ...prev,
        [name]: type === "checkbox" ? checked : value,
      }));
    }
  };

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      if (file.size > 10 * 1024 * 1024) {
        toast.error("Image size should be less than 10MB");
        return;
      }

      // Read file and open crop modal
      const reader = new FileReader();
      reader.addEventListener("load", () => {
        setImageSrc(reader.result?.toString() || "");
        setShowCropModal(true);
        setScale(1);
        setRotate(0);
      });
      reader.readAsDataURL(file);
    }
    // Reset input so same file can be selected again
    e.target.value = "";
  };

  // When image loads in crop modal, set initial crop
  const onImageLoad = useCallback((e) => {
    const { width, height } = e.currentTarget;
    setCrop(centerAspectCrop(width, height, 1)); // 1:1 aspect ratio for profile
  }, []);

  // Generate cropped image blob
  const getCroppedImg = useCallback(async () => {
    const image = imgRef.current;
    if (!image || !completedCrop) return null;

    const canvas = document.createElement("canvas");
    const ctx = canvas.getContext("2d");
    if (!ctx) return null;

    const scaleX = image.naturalWidth / image.width;
    const scaleY = image.naturalHeight / image.height;

    // Set canvas size to desired output size
    const outputSize = 400; // 400x400 for profile image
    canvas.width = outputSize;
    canvas.height = outputSize;

    // Calculate the crop dimensions in natural image coordinates
    const cropX = completedCrop.x * scaleX;
    const cropY = completedCrop.y * scaleY;
    const cropWidth = completedCrop.width * scaleX;
    const cropHeight = completedCrop.height * scaleY;

    // Handle rotation
    const rotateRads = (rotate * Math.PI) / 180;
    const centerX = outputSize / 2;
    const centerY = outputSize / 2;

    ctx.save();
    ctx.translate(centerX, centerY);
    ctx.rotate(rotateRads);
    ctx.scale(scale, scale);
    ctx.translate(-centerX, -centerY);

    // Draw the cropped portion
    ctx.drawImage(
      image,
      cropX,
      cropY,
      cropWidth,
      cropHeight,
      0,
      0,
      outputSize,
      outputSize
    );

    ctx.restore();

    // Convert canvas to blob
    return new Promise((resolve) => {
      canvas.toBlob(
        (blob) => {
          if (blob) {
            const file = new File([blob], "profile-image.jpg", { type: "image/jpeg" });
            resolve(file);
          } else {
            resolve(null);
          }
        },
        "image/jpeg",
        0.95
      );
    });
  }, [completedCrop, rotate, scale]);

  // Handle crop confirm
  const handleCropConfirm = async () => {
    const croppedFile = await getCroppedImg();
    if (croppedFile) {
      setProfileImage(croppedFile);
      setPreviewImage(URL.createObjectURL(croppedFile));
      setShowCropModal(false);
      setImageSrc("");
      toast.success("Image cropped successfully!");
    } else {
      toast.error("Failed to crop image. Please try again.");
    }
  };

  // Handle crop cancel
  const handleCropCancel = () => {
    setShowCropModal(false);
    setImageSrc("");
    setCrop(undefined);
    setCompletedCrop(undefined);
    setScale(1);
    setRotate(0);
  };

  const handleSaveProfile = async () => {
    try {
      setSaving(true);

      const submitData = new FormData();
      submitData.append("name", formData.name);
      submitData.append("phone", formData.phone || "");
      submitData.append("alternatePhone", formData.alternatePhone || "");
      submitData.append("address", JSON.stringify(formData.address));
      submitData.append("dateOfBirth", formData.dateOfBirth || "");
      submitData.append("gender", formData.gender || "");
      submitData.append("bio", formData.bio || "");
      submitData.append("preferences", JSON.stringify(formData.preferences));

      if (profileImage) {
        submitData.append("profileImage", profileImage);
      }

      const response = await api.put('/users/profile', submitData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
      });

      // Update in AuthContext and localStorage
      const updatedUser = response.data.user;
      updateUser(updatedUser);

      setUser(updatedUser);
      // Update preview image with the Cloudinary URL from server
      setPreviewImage(updatedUser.profileImage || null);
      setIsEditing(false);
      setProfileImage(null);
      toast.success("Profile updated successfully!");
    } catch (error) {
      console.error("Error updating profile:", error);
      toast.error(error.response?.data?.message || "Failed to update profile");
    } finally {
      setSaving(false);
    }
  };

  const handleChangePassword = async (e) => {
    e.preventDefault();

    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast.error("New passwords don't match");
      return;
    }

    if (passwordData.newPassword.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }

    try {
      setSaving(true);

      await api.put('/users/change-password', {
        currentPassword: passwordData.currentPassword,
        newPassword: passwordData.newPassword,
      });

      setPasswordData({
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
      });
      toast.success("Password changed successfully!");
    } catch (error) {
      console.error("Error changing password:", error);
      toast.error(error.response?.data?.message || "Failed to change password");
    } finally {
      setSaving(false);
    }
  };

  const cancelEdit = () => {
    setIsEditing(false);
    setProfileImage(null);
    setPreviewImage(user?.profileImage || null);
    // Reset form to original user data
    if (user) {
      setFormData({
        name: user.name || "",
        email: user.email || "",
        phone: user.phone || "",
        alternatePhone: user.alternatePhone || "",
        address: {
          line1: user.address?.line1 || "",
          line2: user.address?.line2 || "",
          city: user.address?.city || "",
          state: user.address?.state || "",
          pincode: user.address?.pincode || "",
        },
        dateOfBirth: user.dateOfBirth
          ? new Date(user.dateOfBirth).toISOString().split("T")[0]
          : "",
        gender: user.gender || "",
        bio: user.bio || "",
        preferences: {
          emailNotifications: user.preferences?.emailNotifications ?? true,
          smsNotifications: user.preferences?.smsNotifications ?? false,
        },
      });
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 pt-20 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-red-600 mx-auto"></div>
          <p className="mt-4 text-slate-600">Loading profile...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 pb-10">
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Breadcrumb */}
        <nav className="flex items-center gap-2 text-sm text-slate-500 mb-6">
          <button onClick={() => navigate("/")} className="hover:text-red-600 flex items-center gap-1">
            <Home size={14} />
            Home
          </button>
          <ChevronRight size={14} />
          <span className="text-slate-800 font-medium">My Profile</span>
        </nav>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden static lg:sticky lg:top-24">
              {/* Profile Header */}
              <div className="bg-gradient-to-br from-red-500 to-rose-600 p-6 text-center">
                <div className="relative inline-block">
                  <div className="w-24 h-24 rounded-full bg-white p-1 mx-auto">
                    {previewImage ? (
                      <img
                        src={previewImage}
                        alt={formData.name}
                        className="w-full h-full rounded-full object-cover"
                      />
                    ) : (
                      <div className="w-full h-full rounded-full bg-slate-100 flex items-center justify-center text-slate-400">
                        <User size={40} />
                      </div>
                    )}
                  </div>
                  {isEditing && (
                    <label className="absolute bottom-0 right-0 bg-white rounded-full p-2 shadow-lg cursor-pointer hover:bg-slate-50 transition group" title="Upload & Crop Photo">
                      <Camera size={16} className="text-slate-600" />
                      <input
                        type="file"
                        accept="image/jpeg,image/png,image/webp,image/gif"
                        onChange={handleImageChange}
                        className="hidden"
                      />
                      {/* Tooltip */}
                      <span className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-2 py-1 text-xs text-white bg-slate-800 rounded-md whitespace-nowrap opacity-0 group-hover:opacity-100 transition pointer-events-none">
                        Upload & Crop
                      </span>
                    </label>
                  )}
                </div>
                <h2 className="mt-3 text-white font-bold text-lg">{formData.name}</h2>
                <p className="text-white/80 text-sm">{formData.email}</p>
                <span className="inline-block mt-2 px-3 py-1 bg-white/20 rounded-full text-xs text-white capitalize">
                  {user?.role || "User"}
                </span>
              </div>

              {/* Navigation Tabs */}
              <nav className="p-4 flex flex-row lg:flex-col overflow-x-auto lg:overflow-visible gap-3 lg:gap-0 space-y-0 lg:space-y-1 scrollbar-hide">
                <button
                  onClick={() => handleTabChange("profile")}
                  className={`flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition whitespace-nowrap ${activeTab === "profile"
                    ? "bg-red-50 text-red-600"
                    : "text-slate-600 hover:bg-slate-50"
                    }`}
                >
                  <User size={18} />
                  <span className="font-medium">Profile Info</span>
                </button>
                <button
                  onClick={() => handleTabChange("security")}
                  className={`flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition whitespace-nowrap ${activeTab === "security"
                    ? "bg-red-50 text-red-600"
                    : "text-slate-600 hover:bg-slate-50"
                    }`}
                >
                  <Lock size={18} />
                  <span className="font-medium">Security</span>
                </button>
                <button
                  onClick={() => handleTabChange("preferences")}
                  className={`flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition whitespace-nowrap ${activeTab === "preferences"
                    ? "bg-red-50 text-red-600"
                    : "text-slate-600 hover:bg-slate-50"
                    }`}
                >
                  <Bell size={18} />
                  <span className="font-medium">Notifications</span>
                </button>
                <button
                  onClick={() => handleTabChange("settings")}
                  className={`flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left transition whitespace-nowrap ${activeTab === "settings"
                    ? "bg-red-50 text-red-600"
                    : "text-slate-600 hover:bg-slate-50"
                    }`}
                >
                  <Settings size={18} />
                  <span className="font-medium">Settings</span>
                </button>

                {/* Divider */}
                <div className="hidden lg:block border-t border-slate-100 my-2"></div>

                {(user?.role === 'owner' || user?.role === 'agent') && (
                  <Link
                    to="/my-properties"
                    className="flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left text-slate-600 hover:bg-slate-50 transition whitespace-nowrap"
                  >
                    <Building2 size={18} />
                    <span className="font-medium">My Properties</span>
                  </Link>
                )}
                <Link
                  to="/saved-properties"
                  className="flex-shrink-0 lg:w-full flex items-center gap-3 px-4 py-3 rounded-xl text-left text-slate-600 hover:bg-slate-50 transition whitespace-nowrap"
                >
                  <Heart size={18} />
                  <span className="font-medium">Saved Properties</span>
                </Link>
              </nav>
            </div>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            {/* Profile Info Tab */}
            {activeTab === "profile" && (
              <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-6 border-b border-slate-100 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
                  <div>
                    <h3 className="text-xl font-bold text-slate-800">Personal Information</h3>
                    <p className="text-slate-500 text-sm mt-1">Manage your profile details</p>
                  </div>
                  {!isEditing ? (
                    <button
                      onClick={() => setIsEditing(true)}
                      className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition font-medium text-sm"
                    >
                      <Edit2 size={16} />
                      Edit Profile
                    </button>
                  ) : (
                    <div className="flex gap-2">
                      <button
                        onClick={cancelEdit}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-slate-100 text-slate-600 rounded-lg hover:bg-slate-200 transition font-medium text-sm"
                      >
                        <X size={16} />
                        Cancel
                      </button>
                      <button
                        onClick={handleSaveProfile}
                        disabled={saving}
                        className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 transition font-medium text-sm disabled:opacity-50"
                      >
                        {saving ? (
                          <>
                            <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                            Saving...
                          </>
                        ) : (
                          <>
                            <Check size={16} />
                            Save Changes
                          </>
                        )}
                      </button>
                    </div>
                  )}
                </div>

                <div className="p-6 space-y-6">
                  {/* Basic Info */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <User size={14} className="inline mr-2" />
                        Full Name
                      </label>
                      <input
                        type="text"
                        name="name"
                        value={formData.name}
                        onChange={handleChange}
                        disabled={!isEditing}
                        className={`w-full px-4 py-3 rounded-xl border ${isEditing
                          ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                          : "border-transparent bg-slate-50"
                          } outline-none transition`}
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <Mail size={14} className="inline mr-2" />
                        Email Address
                      </label>
                      <input
                        type="email"
                        name="email"
                        value={formData.email}
                        disabled
                        className="w-full px-4 py-3 rounded-xl border border-transparent bg-slate-50 text-slate-500 cursor-not-allowed"
                      />
                      <p className="text-xs text-slate-400 mt-1">Email cannot be changed</p>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <Phone size={14} className="inline mr-2" />
                        Phone Number
                      </label>
                      <input
                        type="tel"
                        name="phone"
                        value={formData.phone}
                        onChange={handleChange}
                        disabled={!isEditing}
                        placeholder="+91 9876543210"
                        className={`w-full px-4 py-3 rounded-xl border ${isEditing
                          ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                          : "border-transparent bg-slate-50"
                          } outline-none transition`}
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <Phone size={14} className="inline mr-2" />
                        Alternate Phone
                      </label>
                      <input
                        type="tel"
                        name="alternatePhone"
                        value={formData.alternatePhone}
                        onChange={handleChange}
                        disabled={!isEditing}
                        placeholder="+91 9876543210"
                        className={`w-full px-4 py-3 rounded-xl border ${isEditing
                          ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                          : "border-transparent bg-slate-50"
                          } outline-none transition`}
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        <Calendar size={14} className="inline mr-2" />
                        Date of Birth
                      </label>
                      <input
                        type="date"
                        name="dateOfBirth"
                        value={formData.dateOfBirth}
                        onChange={handleChange}
                        disabled={!isEditing}
                        className={`w-full px-4 py-3 rounded-xl border ${isEditing
                          ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                          : "border-transparent bg-slate-50"
                          } outline-none transition`}
                      />
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-slate-700 mb-2">
                        Gender
                      </label>
                      <select
                        name="gender"
                        value={formData.gender}
                        onChange={handleChange}
                        disabled={!isEditing}
                        className={`w-full px-4 py-3 rounded-xl border ${isEditing
                          ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                          : "border-transparent bg-slate-50"
                          } outline-none transition`}
                      >
                        <option value="">Select Gender</option>
                        <option value="Male">Male</option>
                        <option value="Female">Female</option>
                        <option value="Other">Other</option>
                      </select>
                    </div>
                  </div>

                  {/* Bio */}
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      About Me
                    </label>
                    <textarea
                      name="bio"
                      value={formData.bio}
                      onChange={handleChange}
                      disabled={!isEditing}
                      rows={3}
                      placeholder="Tell us a little about yourself..."
                      className={`w-full px-4 py-3 rounded-xl border ${isEditing
                        ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                        : "border-transparent bg-slate-50"
                        } outline-none transition resize-none`}
                    />
                  </div>

                  {/* Address */}
                  <div>
                    <h4 className="font-semibold text-slate-800 mb-4 flex items-center gap-2">
                      <MapPin size={16} />
                      Address
                    </h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="md:col-span-2">
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          Address Line 1
                        </label>
                        <input
                          type="text"
                          name="address.line1"
                          value={formData.address.line1}
                          onChange={handleChange}
                          disabled={!isEditing}
                          placeholder="House/Flat No., Building Name"
                          className={`w-full px-4 py-3 rounded-xl border ${isEditing
                            ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                            : "border-transparent bg-slate-50"
                            } outline-none transition`}
                        />
                      </div>

                      <div className="md:col-span-2">
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          Address Line 2
                        </label>
                        <input
                          type="text"
                          name="address.line2"
                          value={formData.address.line2}
                          onChange={handleChange}
                          disabled={!isEditing}
                          placeholder="Street, Area, Landmark"
                          className={`w-full px-4 py-3 rounded-xl border ${isEditing
                            ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                            : "border-transparent bg-slate-50"
                            } outline-none transition`}
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          City
                        </label>
                        <input
                          type="text"
                          name="address.city"
                          value={formData.address.city}
                          onChange={handleChange}
                          disabled={!isEditing}
                          placeholder="Mumbai"
                          className={`w-full px-4 py-3 rounded-xl border ${isEditing
                            ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                            : "border-transparent bg-slate-50"
                            } outline-none transition`}
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          State
                        </label>
                        <input
                          type="text"
                          name="address.state"
                          value={formData.address.state}
                          onChange={handleChange}
                          disabled={!isEditing}
                          placeholder="Maharashtra"
                          className={`w-full px-4 py-3 rounded-xl border ${isEditing
                            ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                            : "border-transparent bg-slate-50"
                            } outline-none transition`}
                        />
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-slate-700 mb-2">
                          PIN Code
                        </label>
                        <input
                          type="text"
                          name="address.pincode"
                          value={formData.address.pincode}
                          onChange={handleChange}
                          disabled={!isEditing}
                          placeholder="400001"
                          maxLength={6}
                          className={`w-full px-4 py-3 rounded-xl border ${isEditing
                            ? "border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100"
                            : "border-transparent bg-slate-50"
                            } outline-none transition`}
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Security Tab */}
            {activeTab === "security" && (
              <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-6 border-b border-slate-100">
                  <h3 className="text-xl font-bold text-slate-800">Security Settings</h3>
                  <p className="text-slate-500 text-sm mt-1">Manage your password and security</p>
                </div>

                <form onSubmit={handleChangePassword} className="p-6 space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Current Password
                    </label>
                    <input
                      type="password"
                      value={passwordData.currentPassword}
                      onChange={(e) =>
                        setPasswordData((prev) => ({ ...prev, currentPassword: e.target.value }))
                      }
                      required
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 outline-none transition"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      New Password
                    </label>
                    <input
                      type="password"
                      value={passwordData.newPassword}
                      onChange={(e) =>
                        setPasswordData((prev) => ({ ...prev, newPassword: e.target.value }))
                      }
                      required
                      minLength={6}
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 outline-none transition"
                    />
                    <p className="text-xs text-slate-400 mt-1">Minimum 6 characters</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-slate-700 mb-2">
                      Confirm New Password
                    </label>
                    <input
                      type="password"
                      value={passwordData.confirmPassword}
                      onChange={(e) =>
                        setPasswordData((prev) => ({ ...prev, confirmPassword: e.target.value }))
                      }
                      required
                      className="w-full px-4 py-3 rounded-xl border border-slate-200 focus:border-red-500 focus:ring-2 focus:ring-red-100 outline-none transition"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={saving}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 text-white rounded-xl hover:bg-red-700 transition font-medium disabled:opacity-50"
                  >
                    {saving ? (
                      <>
                        <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                        Updating...
                      </>
                    ) : (
                      <>
                        <Lock size={18} />
                        Change Password
                      </>
                    )}
                  </button>
                </form>

                {/* Account Info */}
                <div className="p-6 border-t border-slate-100 bg-slate-50">
                  <h4 className="font-semibold text-slate-800 mb-4">Account Information</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-slate-500">Account Created:</span>
                      <p className="font-medium text-slate-800">
                        {user?.createdAt
                          ? new Date(user.createdAt).toLocaleDateString("en-IN", {
                            day: "numeric",
                            month: "long",
                            year: "numeric",
                          })
                          : "N/A"}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-500">Last Updated:</span>
                      <p className="font-medium text-slate-800">
                        {user?.updatedAt
                          ? new Date(user.updatedAt).toLocaleDateString("en-IN", {
                            day: "numeric",
                            month: "long",
                            year: "numeric",
                          })
                          : "N/A"}
                      </p>
                    </div>
                    <div>
                      <span className="text-slate-500">Account Type:</span>
                      <p className="font-medium text-slate-800 capitalize">{user?.role || "User"}</p>
                    </div>
                    <div>
                      <span className="text-slate-500">Email Verified:</span>
                      <p className="font-medium text-green-600">Verified ✓</p>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* Preferences Tab */}
            {activeTab === "preferences" && (
              <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                <div className="p-6 border-b border-slate-100">
                  <h3 className="text-xl font-bold text-slate-800">Notification Preferences</h3>
                  <p className="text-slate-500 text-sm mt-1">
                    Manage how you receive notifications
                  </p>
                </div>

                <div className="p-6 space-y-6">
                  <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                    <div>
                      <h4 className="font-medium text-slate-800">Email Notifications</h4>
                      <p className="text-sm text-slate-500">
                        Receive property alerts and updates via email
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        name="preferences.emailNotifications"
                        checked={formData.preferences.emailNotifications}
                        onChange={handleChange}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-300 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-red-100 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-red-600"></div>
                    </label>
                  </div>

                  <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                    <div>
                      <h4 className="font-medium text-slate-800">SMS Notifications</h4>
                      <p className="text-sm text-slate-500">
                        Receive important alerts via SMS
                      </p>
                    </div>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input
                        type="checkbox"
                        name="preferences.smsNotifications"
                        checked={formData.preferences.smsNotifications}
                        onChange={handleChange}
                        className="sr-only peer"
                      />
                      <div className="w-11 h-6 bg-slate-300 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-red-100 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-red-600"></div>
                    </label>
                  </div>

                  <button
                    onClick={handleSaveProfile}
                    disabled={saving}
                    className="inline-flex items-center gap-2 px-6 py-3 bg-red-600 text-white rounded-xl hover:bg-red-700 transition font-medium disabled:opacity-50"
                  >
                    {saving ? (
                      <>
                        <div className="animate-spin h-4 w-4 border-2 border-white border-t-transparent rounded-full"></div>
                        Saving...
                      </>
                    ) : (
                      <>
                        <Save size={18} />
                        Save Preferences
                      </>
                    )}
                  </button>
                </div>
              </div>
            )}

            {/* Settings Tab */}
            {activeTab === "settings" && (
              <div className="space-y-6">
                {/* Account Settings */}
                <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                  <div className="p-6 border-b border-slate-100">
                    <h3 className="text-xl font-bold text-slate-800">Account Settings</h3>
                    <p className="text-slate-500 text-sm mt-1">
                      Manage your account preferences and data
                    </p>
                  </div>

                  <div className="p-6 space-y-4">
                    {/* Account Type */}
                    <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                      <div className="flex items-center gap-4">
                        <div className="p-3 bg-blue-100 rounded-xl">
                          <Shield size={20} className="text-blue-600" />
                        </div>
                        <div>
                          <h4 className="font-medium text-slate-800">Account Type</h4>
                          <p className="text-sm text-slate-500">
                            {user?.role === 'owner' ? 'Property Owner - Can list properties' :
                              user?.role === 'agent' ? 'Agent - Full access' :
                                'Buyer - Browse and save properties'}
                          </p>
                        </div>
                      </div>
                      <span className={`px-3 py-1.5 rounded-full text-sm font-medium ${user?.role === 'owner' ? 'bg-blue-100 text-blue-700' :
                        user?.role === 'agent' ? 'bg-purple-100 text-purple-700' :
                          'bg-gray-100 text-gray-700'
                        }`}>
                        {user?.role === 'owner' ? '🏠 Owner' : user?.role === 'agent' ? '👔 Agent' : '👤 Buyer'}
                      </span>
                    </div>

                    {/* Email Verification */}
                    <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                      <div className="flex items-center gap-4">
                        <div className="p-3 bg-green-100 rounded-xl">
                          <Mail size={20} className="text-green-600" />
                        </div>
                        <div>
                          <h4 className="font-medium text-slate-800">Email Verification</h4>
                          <p className="text-sm text-slate-500">{formData.email}</p>
                        </div>
                      </div>
                      <span className="px-3 py-1.5 rounded-full text-sm font-medium bg-green-100 text-green-700">
                        ✓ Verified
                      </span>
                    </div>

                    {/* Member Since */}
                    <div className="flex items-center justify-between p-4 bg-slate-50 rounded-xl">
                      <div className="flex items-center gap-4">
                        <div className="p-3 bg-amber-100 rounded-xl">
                          <Calendar size={20} className="text-amber-600" />
                        </div>
                        <div>
                          <h4 className="font-medium text-slate-800">Member Since</h4>
                          <p className="text-sm text-slate-500">
                            {user?.createdAt ? new Date(user.createdAt).toLocaleDateString('en-IN', {
                              day: 'numeric',
                              month: 'long',
                              year: 'numeric'
                            }) : 'N/A'}
                          </p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Quick Links */}
                <div className="bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden">
                  <div className="p-6 border-b border-slate-100">
                    <h3 className="text-xl font-bold text-slate-800">Quick Links</h3>
                    <p className="text-slate-500 text-sm mt-1">
                      Helpful resources and support
                    </p>
                  </div>

                  <div className="p-4 space-y-2">
                    <Link
                      to="/about"
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-slate-50 transition group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-slate-200 transition">
                          <HelpCircle size={18} className="text-slate-600" />
                        </div>
                        <span className="font-medium text-slate-700">About DealDirect</span>
                      </div>
                      <ChevronRight size={18} className="text-slate-400" />
                    </Link>

                    <Link
                      to="/contact"
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-slate-50 transition group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-slate-200 transition">
                          <Phone size={18} className="text-slate-600" />
                        </div>
                        <span className="font-medium text-slate-700">Contact Support</span>
                      </div>
                      <ChevronRight size={18} className="text-slate-400" />
                    </Link>

                    <Link
                      to="/agreements"
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-slate-50 transition group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-slate-200 transition">
                          <FileText size={18} className="text-slate-600" />
                        </div>
                        <span className="font-medium text-slate-700">Rent Agreements</span>
                      </div>
                      <ChevronRight size={18} className="text-slate-400" />
                    </Link>

                    <a
                      href="#"
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-slate-50 transition group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-slate-200 transition">
                          <Shield size={18} className="text-slate-600" />
                        </div>
                        <span className="font-medium text-slate-700">Privacy Policy</span>
                      </div>
                      <ChevronRight size={18} className="text-slate-400" />
                    </a>

                    <a
                      href="#"
                      className="flex items-center justify-between p-4 rounded-xl hover:bg-slate-50 transition group"
                    >
                      <div className="flex items-center gap-4">
                        <div className="p-2 bg-slate-100 rounded-lg group-hover:bg-slate-200 transition">
                          <FileText size={18} className="text-slate-600" />
                        </div>
                        <span className="font-medium text-slate-700">Terms of Service</span>
                      </div>
                      <ChevronRight size={18} className="text-slate-400" />
                    </a>
                  </div>
                </div>

                {/* Danger Zone */}
                <div className="bg-white rounded-2xl shadow-sm border border-red-100 overflow-hidden">
                  <div className="p-6 border-b border-red-100 bg-red-50">
                    <h3 className="text-xl font-bold text-red-800">Danger Zone</h3>
                    <p className="text-red-600 text-sm mt-1">
                      Irreversible actions - proceed with caution
                    </p>
                  </div>

                  <div className="p-6 space-y-4">
                    <div className="flex items-center justify-between p-4 border border-slate-200 rounded-xl">
                      <div>
                        <h4 className="font-medium text-slate-800">Log out of all devices</h4>
                        <p className="text-sm text-slate-500">
                          This will log you out from all active sessions
                        </p>
                      </div>
                      <button className="px-4 py-2 text-amber-600 border border-amber-200 rounded-lg hover:bg-amber-50 font-medium text-sm transition">
                        Log Out All
                      </button>
                    </div>

                    <div className="flex items-center justify-between p-4 border border-red-200 rounded-xl bg-red-50/50">
                      <div>
                        <h4 className="font-medium text-red-800">Delete Account</h4>
                        <p className="text-sm text-red-600">
                          Permanently delete your account and all data
                        </p>
                      </div>
                      <button className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 font-medium text-sm transition flex items-center gap-2">
                        <Trash2 size={16} />
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Image Crop Modal */}
      {showCropModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in duration-200">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-red-100 rounded-lg">
                  <Crop size={20} className="text-red-600" />
                </div>
                <div>
                  <h3 className="font-bold text-slate-800">Crop Profile Photo</h3>
                  <p className="text-xs text-slate-500">Adjust the crop area for your profile picture</p>
                </div>
              </div>
              <button
                onClick={handleCropCancel}
                className="p-2 hover:bg-slate-100 rounded-lg transition"
              >
                <X size={20} className="text-slate-500" />
              </button>
            </div>

            {/* Crop Area */}
            <div className="p-6 bg-slate-50">
              <div className="flex justify-center items-center bg-slate-900 rounded-xl overflow-hidden" style={{ minHeight: "300px" }}>
                {imageSrc && (
                  <ReactCrop
                    crop={crop}
                    onChange={(_, percentCrop) => setCrop(percentCrop)}
                    onComplete={(c) => setCompletedCrop(c)}
                    aspect={1}
                    circularCrop
                    className="max-h-[400px]"
                  >
                    <img
                      ref={imgRef}
                      alt="Crop preview"
                      src={imageSrc}
                      style={{
                        transform: `scale(${scale}) rotate(${rotate}deg)`,
                        maxHeight: "400px",
                        maxWidth: "100%",
                      }}
                      onLoad={onImageLoad}
                    />
                  </ReactCrop>
                )}
              </div>

              {/* Controls */}
              <div className="mt-4 space-y-4">
                {/* Zoom Control */}
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2 text-sm text-slate-600">
                    <ZoomOut size={16} />
                    <span>Zoom</span>
                  </div>
                  <input
                    type="range"
                    min="0.5"
                    max="3"
                    step="0.1"
                    value={scale}
                    onChange={(e) => setScale(Number(e.target.value))}
                    className="flex-1 h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-red-600"
                  />
                  <ZoomIn size={16} className="text-slate-600" />
                </div>

                {/* Rotate Control */}
                <div className="flex items-center gap-4">
                  <div className="flex items-center gap-2 text-sm text-slate-600">
                    <RotateCw size={16} />
                    <span>Rotate</span>
                  </div>
                  <input
                    type="range"
                    min="-180"
                    max="180"
                    step="1"
                    value={rotate}
                    onChange={(e) => setRotate(Number(e.target.value))}
                    className="flex-1 h-2 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-red-600"
                  />
                  <span className="text-sm text-slate-500 w-12 text-right">{rotate}°</span>
                </div>

                {/* Reset Button */}
                <button
                  onClick={() => {
                    setScale(1);
                    setRotate(0);
                  }}
                  className="text-sm text-red-600 hover:text-red-700 font-medium"
                >
                  Reset Adjustments
                </button>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="px-6 py-4 border-t border-slate-100 flex justify-end gap-3">
              <button
                onClick={handleCropCancel}
                className="px-5 py-2.5 text-slate-600 bg-slate-100 hover:bg-slate-200 rounded-xl font-medium transition"
              >
                Cancel
              </button>
              <button
                onClick={handleCropConfirm}
                className="px-5 py-2.5 bg-red-600 text-white hover:bg-red-700 rounded-xl font-medium transition flex items-center gap-2"
              >
                <Check size={18} />
                Apply Crop
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Profile;
