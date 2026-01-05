import React, { useState, useEffect } from "react";
import { toast } from "react-toastify";
import { useNavigate, useLocation } from "react-router-dom";
import { Lock, Mail } from "lucide-react";
import { adminAuthApi } from "../api/adminApi";
import { useAdmin } from "../context/AdminContext";

const AdminLogin = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { login, isAuthenticated, isLoading } = useAdmin();

  const [form, setForm] = useState({ email: "", password: "" });
  const [loading, setLoading] = useState(false);

  // Redirect if already authenticated
  useEffect(() => {
    if (isAuthenticated && !isLoading) {
      const from = location.state?.from || "/dashboard";
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, isLoading, navigate, location.state]);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!form.email || !form.password) {
      return toast.warn("Please fill all fields");
    }

    try {
      setLoading(true);

      // Use the adminAuthApi for login - cookies are handled automatically
      const data = await adminAuthApi.login(form.email, form.password);

      toast.success("Login successful!");

      // Check for MFA requirement
      if (data.requiresMfa) {
        navigate("/admin/mfa-verify");
        return;
      }

      // Check for MFA setup requirement (FIRST LOGIN)
      if (data.requiresMfaSetup) {
        toast.info("Please setup multi-factor authentication.");
        navigate("/admin/mfa-setup");
        return; // CRITICAL: Return here so we DON'T update context 'isAuthenticated' yet
      }

      // Update context with admin data ONLY if fully authenticated
      await login(data.admin);

      // Check for password change requirement
      if (data.mustChangePassword) {
        toast.info("You must change your password before continuing.");
        navigate("/admin/change-password");
        return;
      }

      // Navigate to intended destination or dashboard
      const from = location.state?.from || "/dashboard";
      navigate(from, { replace: true });
    } catch (error) {
      const message = error.response?.data?.message || "Login failed";
      toast.error(message);

      // Handle specific error codes
      if (error.response?.data?.code === "ACCOUNT_LOCKED") {
        const lockoutUntil = error.response?.data?.lockoutUntil;
        if (lockoutUntil) {
          const minutes = Math.ceil((new Date(lockoutUntil) - Date.now()) / 60000);
          toast.error(`Account locked. Try again in ${minutes} minutes.`);
        }
      }
    } finally {
      setLoading(false);
    }
  };

  // Show loading state while checking initial auth
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="w-10 h-10 border-4 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center ">
      <div className="bg-white shadow-xl rounded-2xl w-full max-w-md p-8 border border-gray-100">
        <h2 className="text-2xl font-bold text-gray-800 text-center mb-6">
          👨‍💼 Admin Login
        </h2>

        <form onSubmit={handleSubmit} className="space-y-5">
          {/* Email */}
          <div>
            <label className="block text-gray-700 font-medium mb-1">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-3.5 text-gray-400 w-5 h-5" />
              <input
                type="email"
                name="email"
                value={form.email}
                onChange={handleChange}
                placeholder="admin@example.com"
                className="w-full border border-gray-300 pl-10 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 rounded-lg p-3 text-gray-800 outline-none transition-all"
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="block text-gray-700 font-medium mb-1">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-3.5 text-gray-400 w-5 h-5" />
              <input
                type="password"
                name="password"
                value={form.password}
                onChange={handleChange}
                placeholder="Enter your password"
                className="w-full border border-gray-300 pl-10 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 rounded-lg p-3 text-gray-800 outline-none transition-all"
              />
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className={`w-full py-3 rounded-lg text-white font-semibold transition-all ${loading
              ? "bg-blue-400 cursor-not-allowed"
              : "bg-blue-600 hover:bg-blue-700 shadow-md"
              }`}
          >
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>

        <p className="text-center text-sm text-gray-500 mt-6">
          © {new Date().getFullYear()} PropertyDeal Admin Panel
        </p>
      </div>
    </div>
  );
};

export default AdminLogin;
