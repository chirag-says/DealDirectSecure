// src/pages/Auth/Register.jsx
import React, { useState, useEffect } from "react";
import api from "../../utils/api";
import { toast } from "react-toastify";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { User, Mail, Lock, Eye, EyeOff, Loader2, CheckCircle, ShieldCheck, RefreshCw, Home, Search, Phone, ArrowLeft, KeyRound } from "lucide-react";
import dealDirectLogo from "../../assets/dealdirect_logo.png";
import { useAuth } from "../../context/AuthContext";



export default function Register() {
  const [formData, setFormData] = useState({ name: "", email: "", password: "", phone: "", agree: false });
  const [userType, setUserType] = useState("buyer"); // "buyer" or "owner"
  const [otp, setOtp] = useState("");
  const [step, setStep] = useState(1); // 1: Details, 2: OTP (only for owners)
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendTimer, setResendTimer] = useState(0);
  const navigate = useNavigate();
  const location = useLocation();
  const {
    register: authRegister,
    updateUser,
    requiresMfa,
    requiresPasswordChange,
    verifyMfa,
    changePasswordOnLogin,
    cancelPendingAuth,
    pendingAuthData
  } = useAuth();
  const redirectPath = location.state?.from || "/";

  // MFA state
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);

  // Password change state
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmNewPassword, setShowConfirmNewPassword] = useState(false);
  const [passwordChangeLoading, setPasswordChangeLoading] = useState(false);

  // Countdown timer for resend OTP
  useEffect(() => {
    let interval;
    if (resendTimer > 0) {
      interval = setInterval(() => {
        setResendTimer((prev) => prev - 1);
      }, 1000);
    }
    return () => clearInterval(interval);
  }, [resendTimer]);

  // Reset MFA/password states when component unmounts
  useEffect(() => {
    return () => {
      cancelPendingAuth?.();
    };
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    let newValue = type === "checkbox" ? checked : value;

    if (name === "phone") {
      newValue = newValue.replace(/[^0-9]/g, "").slice(0, 10);
    }

    setFormData((f) => ({ ...f, [name]: newValue }));
  };

  // Handle registration - different flow for buyer vs owner
  const handleRegister = async (e) => {
    e.preventDefault();
    if (!formData.agree) return toast.error("Please accept the Terms & Privacy Policy");

    if (!formData.phone) {
      toast.error("Please enter your phone number");
      return;
    }

    if (!/^[6-9]\d{9}$/.test(formData.phone.trim())) {
      toast.error("Please enter a valid 10-digit phone number");
      return;
    }

    setIsLoading(true);
    try {
      if (userType === "buyer") {
        // Buyers: Direct registration without OTP
        const res = await api.post('/users/register-direct', {
          name: formData.name,
          email: formData.email,
          password: formData.password,
          role: "user",
          phone: formData.phone,
        });

        // Check for MFA requirement
        if (res.data.requiresMfa || res.data.code === 'REQUIRES_MFA') {
          // Let AuthContext handle this
          const result = await authRegister({
            name: formData.name,
            email: formData.email,
            password: formData.password,
            role: "user",
            phone: formData.phone,
          });

          if (result.requiresMfa) {
            toast.info(result.message || "Please complete MFA verification");
            setIsLoading(false);
            return;
          }
        }

        // Check for password change requirement
        if (res.data.passwordChangeRequired || res.data.code === 'PASSWORD_CHANGE_REQUIRED') {
          const result = await authRegister({
            name: formData.name,
            email: formData.email,
            password: formData.password,
            role: "user",
            phone: formData.phone,
          });

          if (result.passwordChangeRequired) {
            toast.warning(result.message || "Please set a new password");
            setIsLoading(false);
            return;
          }
        }

        const { user } = res.data;
        updateUser(user);

        toast.success("Registration successful! Welcome to DealDirect.");
        navigate(redirectPath);
      } else {
        // Owners: Require OTP verification
        await api.post('/users/register', {
          name: formData.name,
          email: formData.email,
          password: formData.password,
          role: "owner",
          phone: formData.phone,
        });

        toast.success("OTP sent to your email! Please verify to complete registration.");
        setStep(2);
        setResendTimer(60);
      }
    } catch (err) {
      const errorData = err.response?.data;

      // Handle MFA requirement from error response
      if (errorData?.requiresMfa || errorData?.code === 'REQUIRES_MFA') {
        // Use AuthContext to handle MFA
        await authRegister({
          name: formData.name,
          email: formData.email,
          password: formData.password,
          role: userType === "buyer" ? "user" : "owner",
          phone: formData.phone,
        });
        toast.info(errorData.message || "Please complete MFA verification");
        setIsLoading(false);
        return;
      }

      // Handle password change requirement from error response
      if (errorData?.passwordChangeRequired || errorData?.code === 'PASSWORD_CHANGE_REQUIRED') {
        await authRegister({
          name: formData.name,
          email: formData.email,
          password: formData.password,
          role: userType === "buyer" ? "user" : "owner",
          phone: formData.phone,
        });
        toast.warning(errorData.message || "Please set a new password");
        setIsLoading(false);
        return;
      }

      toast.error(errorData?.message || "Registration failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOtp = async () => {
    if (resendTimer > 0) return;

    setResendLoading(true);
    try {
      await api.post('/users/resend-otp', {
        email: formData.email
      });
      toast.success("New OTP sent to your email!");
      setResendTimer(60); // Reset countdown
      setOtp(""); // Clear old OTP input
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to resend OTP. Please try again.");
    } finally {
      setResendLoading(false);
    }
  };

  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const res = await api.post('/users/verify-otp', {
        email: formData.email,
        otp
      });

      // Check for MFA requirement after OTP verification
      if (res.data.requiresMfa || res.data.code === 'REQUIRES_MFA') {
        await authRegister({
          email: formData.email,
        });
        toast.info(res.data.message || "Please complete MFA verification");
        setIsLoading(false);
        return;
      }

      // Check for password change requirement after OTP verification
      if (res.data.passwordChangeRequired || res.data.code === 'PASSWORD_CHANGE_REQUIRED') {
        await authRegister({
          email: formData.email,
        });
        toast.warning(res.data.message || "Please set a new password");
        setIsLoading(false);
        return;
      }

      const { user } = res.data;
      updateUser(user);

      toast.success("Registration successful! Welcome aboard.");
      navigate(redirectPath);
    } catch (err) {
      toast.error(err.response?.data?.message || "Invalid OTP. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  // Handle MFA verification
  const handleMfaVerify = async (e) => {
    e.preventDefault();
    if (!mfaCode || mfaCode.length !== 6) {
      toast.error("Please enter a valid 6-digit MFA code");
      return;
    }

    setMfaLoading(true);
    try {
      const result = await verifyMfa(mfaCode);

      if (result.success) {
        toast.success(`Welcome, ${result.user.name || 'User'}!`);
        navigate(redirectPath);
      } else {
        toast.error(result.message || "MFA verification failed");
      }
    } catch (err) {
      toast.error(err.response?.data?.message || "MFA verification failed");
    } finally {
      setMfaLoading(false);
    }
  };

  // Handle password change on registration
  const handlePasswordChange = async (e) => {
    e.preventDefault();

    if (newPassword.length < 8) {
      toast.error("Password must be at least 8 characters");
      return;
    }

    if (newPassword !== confirmNewPassword) {
      toast.error("Passwords do not match");
      return;
    }

    setPasswordChangeLoading(true);
    try {
      const result = await changePasswordOnLogin(newPassword);

      if (result.success) {
        toast.success("Password set successfully! Welcome aboard.");
        navigate(redirectPath);
      } else {
        toast.error(result.message || "Password change failed");
      }
    } catch (err) {
      toast.error(err.response?.data?.message || "Password change failed");
    } finally {
      setPasswordChangeLoading(false);
    }
  };

  // Cancel MFA or password change flow
  const handleCancelFlow = () => {
    cancelPendingAuth();
    setMfaCode("");
    setNewPassword("");
    setConfirmNewPassword("");
    setStep(1);
  };

  // Render MFA verification form
  if (requiresMfa) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 font-sans">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden p-8">
          <div className="text-center mb-8">
            <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
              <ShieldCheck className="w-8 h-8 text-blue-600" />
            </div>
            <h2 className="text-2xl font-bold text-slate-800">Two-Factor Authentication</h2>
            <p className="text-slate-500 mt-2">
              Enter the 6-digit code from your authenticator app
            </p>
            {pendingAuthData?.email && (
              <p className="text-sm text-slate-400 mt-1">for {pendingAuthData.email}</p>
            )}
          </div>

          <form onSubmit={handleMfaVerify} className="space-y-6">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 block text-center">MFA Code</label>
              <input
                type="text"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                placeholder="000000"
                required
                autoFocus
                className="w-full text-center text-2xl tracking-[0.5em] py-4 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800 font-mono"
              />
            </div>

            <button
              type="submit"
              disabled={mfaLoading || mfaCode.length !== 6}
              className="w-full bg-slate-900 text-white py-3.5 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center disabled:opacity-50"
            >
              {mfaLoading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  Verifying...
                </>
              ) : (
                "Verify Code"
              )}
            </button>

            <button
              type="button"
              onClick={handleCancelFlow}
              className="w-full text-slate-500 text-sm hover:text-slate-700 py-2"
            >
              <ArrowLeft className="w-4 h-4 inline mr-1" />
              Back to Register
            </button>
          </form>
        </div>
      </div>
    );
  }

  // Render password change requirement form
  if (requiresPasswordChange) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50 font-sans">
        <div className="w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden p-8">
          <div className="text-center mb-8">
            <div className="mx-auto w-16 h-16 bg-amber-100 rounded-full flex items-center justify-center mb-4">
              <KeyRound className="w-8 h-8 text-amber-600" />
            </div>
            <h2 className="text-2xl font-bold text-slate-800">Set Your Password</h2>
            <p className="text-slate-500 mt-2">
              Please set a secure password for your account
            </p>
          </div>

          <form onSubmit={handlePasswordChange} className="space-y-5">
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 block">New Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-400" />
                </div>
                <input
                  type={showNewPassword ? "text" : "password"}
                  placeholder="Enter new password (min 8 characters)"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                  className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                />
                <button
                  type="button"
                  onClick={() => setShowNewPassword(!showNewPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                >
                  {showNewPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
            </div>

            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 block">Confirm New Password</label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                  <Lock className="h-5 w-5 text-slate-400" />
                </div>
                <input
                  type={showConfirmNewPassword ? "text" : "password"}
                  placeholder="Confirm new password"
                  value={confirmNewPassword}
                  onChange={(e) => setConfirmNewPassword(e.target.value)}
                  required
                  minLength={8}
                  className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmNewPassword(!showConfirmNewPassword)}
                  className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                >
                  {showConfirmNewPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                </button>
              </div>
              {confirmNewPassword && newPassword !== confirmNewPassword && (
                <p className="text-xs text-red-500">Passwords do not match</p>
              )}
            </div>

            <button
              type="submit"
              disabled={passwordChangeLoading || newPassword !== confirmNewPassword || newPassword.length < 8}
              className="w-full bg-slate-900 text-white py-3.5 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center disabled:opacity-50"
            >
              {passwordChangeLoading ? (
                <>
                  <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                  Setting Password...
                </>
              ) : (
                "Set Password & Continue"
              )}
            </button>

            <button
              type="button"
              onClick={handleCancelFlow}
              className="w-full text-slate-500 text-sm hover:text-slate-700 py-2"
            >
              <ArrowLeft className="w-4 h-4 inline mr-1" />
              Back to Register
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 font-sans pb-10 px-4">
      <div className="w-full max-w-5xl bg-white rounded-2xl shadow-2xl overflow-hidden flex flex-col md:flex-row md:min-h-[600px]">

        {/* LEFT SIDE - IMAGE & BRANDING */}
        <div className="md:w-1/2 relative hidden md:flex flex-col justify-between p-12 text-white">
          {/* Background Image with Overlay */}
          <div className="absolute inset-0 bg-cover bg-center z-0"
            style={{ backgroundImage: "url('https://images.unsplash.com/photo-1560518883-ce09059eeffa?q=80&w=1973&auto=format&fit=crop')" }}>
          </div>
          <div className="absolute inset-0 bg-slate-900/70 z-10"></div>

          {/* Header Branding */}
          <div className="relative z-20 flex items-center gap-2 mb-6">
            <img src={dealDirectLogo} alt="DealDirect" className="h-12 w-auto" />
          </div>

          {/* Main Text */}
          <div className="relative z-20 mb-8">
            <h2 className="text-4xl font-bold leading-tight mb-6">
              Start your journey <br /> to <span className="text-blue-400">home ownership.</span>
            </h2>

            <ul className="space-y-4 text-gray-300">
              <li className="flex items-center gap-3">
                <CheckCircle className="w-5 h-5 text-blue-400" />
                <span>Direct connections with sellers</span>
              </li>
              <li className="flex items-center gap-3">
                <CheckCircle className="w-5 h-5 text-blue-400" />
                <span>Zero brokerage fees</span>
              </li>
              <li className="flex items-center gap-3">
                <CheckCircle className="w-5 h-5 text-blue-400" />
                <span>Verified property listings</span>
              </li>
            </ul>
          </div>

          <div className="relative z-20 text-sm text-gray-400">
            © 2025 DealDirect. Building Trust.
          </div>
        </div>

        {/* RIGHT SIDE - FORM */}
        <div className="md:w-1/2 w-full p-8 md:p-12 flex flex-col justify-center">
          <div className="max-w-md mx-auto w-full">

            {step === 1 ? (
              <>
                <div className="text-center mb-8">
                  <h2 className="text-3xl font-bold text-slate-800">Create Account</h2>
                  <p className="text-slate-500 mt-2">Join us to unlock exclusive property deals.</p>
                </div>

                {/* User Type Selector */}
                <div className="mb-6">
                  <label className="text-sm font-medium text-slate-700 block mb-3">I want to</label>
                  <div className="grid grid-cols-2 gap-3">
                    <button
                      type="button"
                      onClick={() => setUserType("buyer")}
                      className={`flex flex-col items-center p-4 rounded-xl border-2 transition-all ${userType === "buyer"
                        ? "border-blue-600 bg-blue-50 text-blue-700"
                        : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                        }`}
                    >
                      <Search className={`w-6 h-6 mb-2 ${userType === "buyer" ? "text-blue-600" : "text-slate-400"}`} />
                      <span className="font-semibold text-sm">Find Property</span>
                      <span className="text-xs mt-1 opacity-70">Browse & Buy</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setUserType("owner")}
                      className={`flex flex-col items-center p-4 rounded-xl border-2 transition-all ${userType === "owner"
                        ? "border-blue-600 bg-blue-50 text-blue-700"
                        : "border-slate-200 bg-white text-slate-600 hover:border-slate-300"
                        }`}
                    >
                      <Home className={`w-6 h-6 mb-2 ${userType === "owner" ? "text-blue-600" : "text-slate-400"}`} />
                      <span className="font-semibold text-sm">List Property</span>
                      <span className="text-xs mt-1 opacity-70">Sell or Rent</span>
                    </button>
                  </div>
                  {userType === "owner" && (
                    <p className="text-xs text-amber-600 mt-2 flex items-center gap-1">
                      <ShieldCheck className="w-3.5 h-3.5" />
                      Email verification required to list properties
                    </p>
                  )}
                </div>

                <form onSubmit={handleRegister} className="space-y-5">
                  {/* Name Input */}
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Full Name</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <User className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        name="name"
                        placeholder="John Doe"
                        value={formData.name}
                        onChange={handleChange}
                        required
                        className="w-full pl-10 pr-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                    </div>
                  </div>

                  {/* Phone Input */}
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Phone Number</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Phone className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type="tel"
                        name="phone"
                        placeholder="10-digit mobile number"
                        value={formData.phone}
                        onChange={handleChange}
                        required
                        className="w-full pl-10 pr-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                    </div>
                    <p className="text-xs text-slate-500">
                      Used for important updates about your account and visits.
                    </p>
                  </div>

                  {/* Email Input */}
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Email Address</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Mail className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type="email"
                        name="email"
                        placeholder="name@company.com"
                        value={formData.email}
                        onChange={handleChange}
                        required
                        className="w-full pl-10 pr-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                    </div>
                  </div>

                  {/* Password Input */}
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Password</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Lock className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type={showPassword ? "text" : "password"}
                        name="password"
                        placeholder="Create a strong password"
                        value={formData.password}
                        onChange={handleChange}
                        required
                        minLength={8}
                        className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                      >
                        {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                      </button>
                    </div>
                    <p className="text-xs text-slate-500">
                      Min 8 characters with uppercase, lowercase, number & special character (@$!%*?&#^()-_=+)
                    </p>
                  </div>

                  {/* Terms Checkbox */}
                  <div className="flex items-start">
                    <div className="flex items-center h-5">
                      <input
                        id="agree"
                        name="agree"
                        type="checkbox"
                        checked={formData.agree}
                        onChange={handleChange}
                        className="w-4 h-4 text-blue-900 border-slate-300 rounded focus:ring-blue-900 cursor-pointer"
                      />
                    </div>
                    <div className="ml-3 text-sm">
                      <label htmlFor="agree" className="text-slate-600 cursor-pointer">
                        I agree to the <a href="#" className="text-blue-900 font-medium hover:underline">Terms of Service</a> and <a href="#" className="text-blue-900 font-medium hover:underline">Privacy Policy</a>
                      </label>
                    </div>
                  </div>

                  {/* Submit Button */}
                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-slate-900 text-white py-3.5 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                        {userType === "owner" ? "Sending OTP..." : "Creating Account..."}
                      </>
                    ) : (
                      userType === "owner" ? "Verify & Create Account" : "Create Account"
                    )}
                  </button>
                </form>

                {/* Footer */}
                <div className="mt-8 text-center text-sm text-slate-500">
                  Already have an account?{" "}
                  <Link to="/login" className="font-bold text-blue-900 hover:underline">
                    Log in here
                  </Link>
                </div>
              </>
            ) : (
              <>
                {/* OTP STEP */}
                <div className="text-center mb-8">
                  <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                    <ShieldCheck className="w-8 h-8 text-blue-600" />
                  </div>
                  <h2 className="text-3xl font-bold text-slate-800">Verify Email</h2>
                  <p className="text-slate-500 mt-2">
                    We've sent a verification code to <br /> <span className="font-semibold text-slate-800">{formData.email}</span>
                  </p>
                </div>

                <form onSubmit={handleVerifyOtp} className="space-y-6">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block text-center">Enter 6-Digit OTP</label>
                    <input
                      type="text"
                      value={otp}
                      onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, '').slice(0, 6))}
                      placeholder="123456"
                      required
                      className="w-full text-center text-2xl tracking-widest py-4 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isLoading}
                    className="w-full bg-slate-900 text-white py-3.5 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center"
                  >
                    {isLoading ? (
                      <>
                        <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                        Verifying...
                      </>
                    ) : (
                      "Verify & Register"
                    )}
                  </button>

                  {/* Resend OTP Section */}
                  <div className="text-center space-y-2">
                    <p className="text-sm text-slate-500">Didn't receive the code?</p>
                    <button
                      type="button"
                      onClick={handleResendOtp}
                      disabled={resendTimer > 0 || resendLoading}
                      className={`inline-flex items-center text-sm font-medium transition-colors ${resendTimer > 0
                        ? 'text-slate-400 cursor-not-allowed'
                        : 'text-blue-900 hover:text-blue-700 hover:underline cursor-pointer'
                        }`}
                    >
                      {resendLoading ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-1.5 animate-spin" />
                          Sending...
                        </>
                      ) : resendTimer > 0 ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-1.5" />
                          Resend in {resendTimer}s
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-4 h-4 mr-1.5" />
                          Resend OTP
                        </>
                      )}
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={() => setStep(1)}
                    className="w-full text-slate-500 text-sm hover:text-slate-700"
                  >
                    Change Email / Go Back
                  </button>
                </form>
              </>
            )}

          </div>
        </div>

      </div>
    </div>
  );
}