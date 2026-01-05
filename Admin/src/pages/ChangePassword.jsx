import React, { useState } from "react";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import { Lock, KeyRound, AlertTriangle } from "lucide-react";
import { adminAuthApi } from "../api/adminApi";

const ChangePassword = () => {
    const navigate = useNavigate();
    const [loading, setLoading] = useState(false);
    const [formData, setFormData] = useState({
        currentPassword: "",
        newPassword: "",
        confirmPassword: "",
    });

    const handleChange = (e) => {
        setFormData({ ...formData, [e.target.name]: e.target.value });
    };

    const getPasswordStrength = (password) => {
        if (password.length < 12) return "Too Short";
        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNum = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        const count = [hasUpper, hasLower, hasNum, hasSpecial].filter(Boolean).length;
        if (count < 3) return "Weak";
        if (count === 3) return "Medium";
        return "Strong";
    };

    const handleSubmit = async (e) => {
        e.preventDefault();

        if (formData.newPassword !== formData.confirmPassword) {
            return toast.warn("New passwords do not match");
        }

        if (formData.newPassword.length < 12) {
            return toast.warn("Password must be at least 12 characters");
        }

        // Check strength locally before sending
        const strength = getPasswordStrength(formData.newPassword);
        if (strength === "Too Short" || strength === "Weak") {
            return toast.warn("Password is not strong enough. Use uppercase, lowercase, numbers, and symbols.");
        }

        try {
            setLoading(true);
            await adminAuthApi.changePassword(formData.currentPassword, formData.newPassword);

            toast.success("Password changed successfully!");
            toast.info("Please log in with your new password.");

            // Force logout and redirect to login
            await adminAuthApi.logout();
            navigate("/admin/login");

        } catch (error) {
            const message = error.response?.data?.message || "Failed to change password";
            toast.error(message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <div className="bg-white shadow-xl rounded-2xl w-full max-w-md p-8 border border-gray-100">

                <div className="text-center mb-8">
                    <div className="mx-auto w-16 h-16 bg-orange-100 rounded-full flex items-center justify-center mb-4">
                        <KeyRound className="w-8 h-8 text-orange-600" />
                    </div>
                    <h2 className="text-2xl font-bold text-gray-800">Change Password</h2>
                    <div className="flex items-center justify-center mt-2 text-amber-600 bg-amber-50 px-3 py-1 rounded-full text-xs font-semibold w-fit mx-auto border border-amber-200">
                        <AlertTriangle className="w-3 h-3 mr-1" />
                        Security Requirement
                    </div>
                    <p className="text-gray-500 mt-3 text-sm">
                        For security, new accounts must update their password on first login.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-5">
                    {/* Current Password */}
                    <div>
                        <label className="block text-gray-700 font-medium mb-1 text-sm">
                            Current Password
                        </label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3.5 text-gray-400 w-4 h-4" />
                            <input
                                type="password"
                                name="currentPassword"
                                value={formData.currentPassword}
                                onChange={handleChange}
                                placeholder="Enter current password"
                                className="w-full border border-gray-300 pl-10 rounded-lg p-3 text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                                required
                            />
                        </div>
                    </div>

                    {/* New Password */}
                    <div>
                        <div className="flex justify-between items-center mb-1">
                            <label className="block text-gray-700 font-medium text-sm">
                                New Password
                            </label>
                            {formData.newPassword && (
                                <span className={`text-xs font-bold ${getPasswordStrength(formData.newPassword) === "Strong" ? "text-green-600" :
                                        getPasswordStrength(formData.newPassword) === "Medium" ? "text-yellow-600" : "text-red-500"
                                    }`}>
                                    {getPasswordStrength(formData.newPassword)}
                                </span>
                            )}
                        </div>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3.5 text-gray-400 w-4 h-4" />
                            <input
                                type="password"
                                name="newPassword"
                                value={formData.newPassword}
                                onChange={handleChange}
                                placeholder="Min 12 chars, mixed case, numbers, symbols"
                                className="w-full border border-gray-300 pl-10 rounded-lg p-3 text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                                required
                            />
                        </div>
                    </div>

                    {/* Confirm Password */}
                    <div>
                        <label className="block text-gray-700 font-medium mb-1 text-sm">
                            Confirm New Password
                        </label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3.5 text-gray-400 w-4 h-4" />
                            <input
                                type="password"
                                name="confirmPassword"
                                value={formData.confirmPassword}
                                onChange={handleChange}
                                placeholder="Re-enter new password"
                                className="w-full border border-gray-300 pl-10 rounded-lg p-3 text-sm focus:ring-2 focus:ring-orange-500 focus:border-orange-500 outline-none"
                                required
                            />
                        </div>
                    </div>

                    <button
                        type="submit"
                        disabled={loading}
                        className={`w-full py-3 rounded-lg text-white font-semibold transition-all ${loading
                                ? "bg-gray-400 cursor-not-allowed"
                                : "bg-orange-600 hover:bg-orange-700 shadow-md"
                            }`}
                    >
                        {loading ? "Updating..." : "Update Password"}
                    </button>
                </form>

            </div>
        </div>
    );
};

export default ChangePassword;
