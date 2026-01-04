// src/pages/Auth/Login.jsx
import React, { useState, useEffect } from "react";
import api from "../../utils/api";
import { toast } from "react-toastify";
import { useNavigate, Link, useLocation } from "react-router-dom";
import { Mail, Lock, Eye, EyeOff, Loader2, X, ArrowLeft, KeyRound, CheckCircle, AlertTriangle, Phone, ShieldCheck } from "lucide-react";
import dealDirectLogo from "../../assets/dealdirect_logo.png";
import { useAuth } from "../../context/AuthContext";



export default function Login() {
  const [formData, setFormData] = useState({ email: "", password: "", phone: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const {
    login: authLogin,
    updateUser,
    requiresMfa,
    requiresPasswordChange,
    verifyMfa,
    changePasswordOnLogin,
    cancelPendingAuth,
    pendingAuthData
  } = useAuth();

  // Get the redirect path and any pending action from state (if user was redirected here)
  const redirectPath = location.state?.from || "/";
  const pendingAction = location.state?.pendingAction;
  const pendingPropertyId = location.state?.propertyId;

  // Blocked user state
  const [blockedError, setBlockedError] = useState(null);

  // MFA state
  const [mfaCode, setMfaCode] = useState("");
  const [mfaLoading, setMfaLoading] = useState(false);

  // Password change state
  const [newPassword, setNewPassword] = useState("");
  const [confirmNewPassword, setConfirmNewPassword] = useState("");
  const [showNewPassword, setShowNewPassword] = useState(false);
  const [showConfirmNewPassword, setShowConfirmNewPassword] = useState(false);
  const [passwordChangeLoading, setPasswordChangeLoading] = useState(false);

  // Forgot Password Modal State
  const [showForgotModal, setShowForgotModal] = useState(false);
  const [forgotStep, setForgotStep] = useState(1); // 1: email, 2: otp+password, 3: success
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotOtp, setForgotOtp] = useState("");
  const [forgotNewPassword, setForgotNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [showForgotNewPassword, setShowForgotNewPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [forgotLoading, setForgotLoading] = useState(false);

  // Reset MFA/password states when component unmounts
  useEffect(() => {
    return () => {
      cancelPendingAuth?.();
    };
  }, []);

  const handleChange = (e) => {
    const { name, value } = e.target;
    let newValue = value;

    if (name === "phone") {
      newValue = newValue.replace(/[^0-9]/g, "").slice(0, 10);
    }

    setFormData((f) => ({ ...f, [name]: newValue }));
  };

  const isValidPhone = (phone) => {
    const cleaned = (phone || "").trim();
    if (!cleaned) return false;
    return /^[6-9]\d{9}$/.test(cleaned);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (formData.phone && !isValidPhone(formData.phone)) {
      toast.error("Please enter a valid 10-digit phone number");
      return;
    }
    setIsLoading(true);
    setBlockedError(null);

    try {
      const result = await authLogin(formData.email, formData.password);

      // Handle MFA requirement
      if (result.requiresMfa) {
        toast.info(result.message || "Please enter your MFA code");
        setIsLoading(false);
        return;
      }

      // Handle password change requirement
      if (result.passwordChangeRequired) {
        toast.warning(result.message || "Please change your password to continue");
        setIsLoading(false);
        return;
      }

      if (result.success && result.user) {
        toast.success(`Welcome back, ${result.user.name || 'User'}!`);

        let navigationState = location.state ? { ...location.state } : undefined;

        // If user was trying to express interest, complete it
        if (pendingAction === "interest" && pendingPropertyId) {
          try {
            await api.post(`/properties/interested/${pendingPropertyId}`, {});
            toast.success("Interest registered! The owner will be notified.");
            navigationState = { ...navigationState, interestedPropertyId: pendingPropertyId };
          } catch (interestErr) {
            const msg = interestErr.response?.data?.message || "Failed to register interest";
            toast.error(msg);
          }
        }

        if (navigationState) {
          delete navigationState.pendingAction;
          delete navigationState.propertyId;
        }

        navigate(redirectPath, { state: navigationState });
      } else {
        // Check for blocked account
        if (result.errorData?.isBlocked || result.errorData?.code === 'ACCOUNT_BLOCKED') {
          setBlockedError({
            message: result.errorData.message,
            reason: result.errorData.blockReason || 'No reason provided',
            blockedAt: result.errorData.blockedAt
          });
        } else {
          toast.error(result.message || "Invalid credentials. Please try again.");
        }
      }
    } catch (err) {
      const errorData = err.response?.data;
      if (errorData?.isBlocked || errorData?.code === 'ACCOUNT_BLOCKED') {
        setBlockedError({
          message: errorData.message,
          reason: errorData.blockReason || 'No reason provided',
          blockedAt: errorData.blockedAt
        });
      } else {
        toast.error(errorData?.message || "Invalid credentials. Please try again.");
      }
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
        toast.success(`Welcome back, ${result.user.name || 'User'}!`);
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

  // Handle password change on login
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
        toast.success("Password changed successfully! Welcome back.");
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
  };

  // Forgot Password Handlers
  const openForgotModal = (e) => {
    e.preventDefault();
    setShowForgotModal(true);
    setForgotStep(1);
    setForgotEmail("");
    setForgotOtp("");
    setForgotNewPassword("");
    setConfirmPassword("");
  };

  const closeForgotModal = () => {
    setShowForgotModal(false);
    setForgotStep(1);
    setForgotEmail("");
    setForgotOtp("");
    setForgotNewPassword("");
    setConfirmPassword("");
  };

  const handleSendOtp = async (e) => {
    e.preventDefault();
    if (!forgotEmail) {
      toast.error("Please enter your email address");
      return;
    }

    setForgotLoading(true);
    try {
      await api.post('/users/forgot-password', { email: forgotEmail });
      toast.success("OTP sent to your email!");
      setForgotStep(2);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to send OTP. Please try again.");
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResetPassword = async (e) => {
    e.preventDefault();

    if (!forgotOtp || forgotOtp.length !== 6) {
      toast.error("Please enter a valid 6-digit OTP");
      return;
    }

    if (forgotNewPassword.length < 6) {
      toast.error("Password must be at least 6 characters");
      return;
    }

    if (forgotNewPassword !== confirmPassword) {
      toast.error("Passwords do not match");
      return;
    }

    setForgotLoading(true);
    try {
      await api.post('/users/reset-password', {
        email: forgotEmail,
        otp: forgotOtp,
        newPassword: forgotNewPassword,
      });
      toast.success("Password reset successful!");
      setForgotStep(3);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to reset password. Please try again.");
    } finally {
      setForgotLoading(false);
    }
  };

  const handleResendOtp = async () => {
    setForgotLoading(true);
    try {
      await api.post('/users/forgot-password', { email: forgotEmail });
      toast.success("New OTP sent to your email!");
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to resend OTP");
    } finally {
      setForgotLoading(false);
    }
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
              Back to Login
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
            <h2 className="text-2xl font-bold text-slate-800">Password Change Required</h2>
            <p className="text-slate-500 mt-2">
              For security reasons, you must change your password before continuing
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
                  Changing Password...
                </>
              ) : (
                "Change Password & Continue"
              )}
            </button>

            <button
              type="button"
              onClick={handleCancelFlow}
              className="w-full text-slate-500 text-sm hover:text-slate-700 py-2"
            >
              <ArrowLeft className="w-4 h-4 inline mr-1" />
              Back to Login
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 font-sans">
      <div className="w-full max-w-5xl bg-white rounded-2xl shadow-2xl overflow-hidden flex flex-col md:flex-row min-h-[600px]">

        {/* LEFT SIDE - IMAGE & BRANDING */}
        <div className="md:w-1/2 relative hidden md:flex flex-col justify-between p-12 text-white">
          {/* Background Image with Overlay */}
          <div className="absolute inset-0 bg-cover bg-center z-0"
            style={{ backgroundImage: "url('https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?q=80&w=2070&auto=format&fit=crop')" }}>
          </div>
          <div className="absolute inset-0 bg-slate-900/60 z-10"></div>

          {/* Content over image */}
          <div className="relative z-20 flex items-center gap-2 mb-6">
            <img src={dealDirectLogo} alt="DealDirect" className="h-12 w-auto" />
          </div>

          <div className="relative z-20 mb-8">
            <h2 className="text-4xl font-bold leading-tight mb-4">
              Find your dream property, <br /> <span className="text-blue-400">Broker-free.</span>
            </h2>
            <p className="text-gray-300 text-lg">
              Join thousands of buyers and sellers connecting directly on the world's most transparent real estate platform.
            </p>
          </div>

          <div className="relative z-20 text-sm text-gray-400">
            © 2025 DealDirect. All rights reserved.
          </div>
        </div>

        {/* RIGHT SIDE - FORM */}
        <div className="md:w-1/2 w-full p-8 md:p-12 flex flex-col justify-center">
          <div className="max-w-md mx-auto w-full">
            <div className="text-center mb-10">
              <h2 className="text-3xl font-bold text-slate-800">Welcome Back</h2>
              <p className="text-slate-500 mt-2">Please enter your details to sign in.</p>
            </div>

            {/* Blocked User Error */}
            {blockedError && (
              <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-xl">
                <div className="flex items-start gap-3">
                  <div className="flex-shrink-0">
                    <AlertTriangle className="h-6 w-6 text-red-600" />
                  </div>
                  <div className="flex-1">
                    <h3 className="text-red-800 font-semibold text-lg">Account Blocked</h3>
                    <p className="text-red-700 text-sm mt-1">{blockedError.message}</p>
                    <div className="mt-3 p-3 bg-red-100 rounded-lg">
                      <p className="text-red-800 text-sm">
                        <strong>Reason:</strong> {blockedError.reason}
                      </p>
                    </div>
                    <p className="text-red-600 text-xs mt-3">
                      If you believe this is a mistake, please contact our support team.
                    </p>
                  </div>
                </div>
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-6">

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

              {/* Phone Input (Optional) */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-700 block">
                  Phone Number <span className="text-xs text-slate-400">(optional)</span>
                </label>
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
                    placeholder="••••••••"
                    value={formData.password}
                    onChange={handleChange}
                    required
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
              </div>

              {/* Remember Me / Forgot Password */}
              <div className="flex items-center justify-between text-sm">
                <label className="flex items-center cursor-pointer">
                  <input type="checkbox" className="w-4 h-4 text-blue-900 border-slate-300 rounded focus:ring-blue-900" />
                  <span className="ml-2 text-slate-600">Remember me</span>
                </label>
                <button
                  type="button"
                  onClick={openForgotModal}
                  className="font-medium text-blue-900 hover:underline"
                >
                  Forgot password?
                </button>
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
                    Signing in...
                  </>
                ) : (
                  "Sign in"
                )}
              </button>
            </form>

            {/* Footer */}
            <div className="mt-8 text-center text-sm text-slate-500">
              Don't have an account?{" "}
              <Link to="/register" state={{ from: redirectPath }} className="font-bold text-blue-900 hover:underline">
                Create an account
              </Link>
            </div>
          </div>
        </div>

      </div>

      {/* Forgot Password Modal */}
      {showForgotModal && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-md w-full overflow-hidden animate-in fade-in zoom-in duration-200">
            {/* Modal Header */}
            <div className="bg-gradient-to-r from-slate-900 to-slate-800 p-6 text-white relative">
              <button
                onClick={closeForgotModal}
                className="absolute top-4 right-4 text-white/70 hover:text-white transition-colors"
              >
                <X className="w-6 h-6" />
              </button>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 bg-white/10 rounded-xl flex items-center justify-center">
                  <KeyRound className="w-6 h-6" />
                </div>
                <div>
                  <h3 className="text-xl font-bold">
                    {forgotStep === 1 && "Forgot Password"}
                    {forgotStep === 2 && "Reset Password"}
                    {forgotStep === 3 && "Success!"}
                  </h3>
                  <p className="text-sm text-white/70">
                    {forgotStep === 1 && "Enter your email to receive OTP"}
                    {forgotStep === 2 && "Enter OTP and new password"}
                    {forgotStep === 3 && "Password changed successfully"}
                  </p>
                </div>
              </div>
            </div>

            {/* Modal Body */}
            <div className="p-6">
              {/* Step 1: Email */}
              {forgotStep === 1 && (
                <form onSubmit={handleSendOtp} className="space-y-5">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Email Address</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Mail className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type="email"
                        placeholder="name@company.com"
                        value={forgotEmail}
                        onChange={(e) => setForgotEmail(e.target.value)}
                        required
                        className="w-full pl-10 pr-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                    </div>
                    <p className="text-xs text-slate-500">
                      We'll send a 6-digit OTP to your registered email address.
                    </p>
                  </div>

                  <button
                    type="submit"
                    disabled={forgotLoading}
                    className="w-full bg-slate-900 text-white py-3 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center"
                  >
                    {forgotLoading ? (
                      <>
                        <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                        Sending OTP...
                      </>
                    ) : (
                      "Send OTP"
                    )}
                  </button>
                </form>
              )}

              {/* Step 2: OTP + New Password */}
              {forgotStep === 2 && (
                <form onSubmit={handleResetPassword} className="space-y-5">
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Enter OTP</label>
                    <input
                      type="text"
                      placeholder="Enter 6-digit OTP"
                      value={forgotOtp}
                      onChange={(e) => setForgotOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                      maxLength={6}
                      required
                      className="w-full px-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800 text-center text-2xl tracking-[0.5em] font-mono"
                    />
                    <div className="flex items-center justify-between text-xs">
                      <span className="text-slate-500">OTP sent to {forgotEmail}</span>
                      <button
                        type="button"
                        onClick={handleResendOtp}
                        disabled={forgotLoading}
                        className="text-blue-900 hover:underline font-medium"
                      >
                        Resend OTP
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">New Password</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Lock className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type={showForgotNewPassword ? "text" : "password"}
                        placeholder="Enter new password"
                        value={forgotNewPassword}
                        onChange={(e) => setForgotNewPassword(e.target.value)}
                        required
                        minLength={6}
                        className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                      <button
                        type="button"
                        onClick={() => setShowForgotNewPassword(!showForgotNewPassword)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                      >
                        {showForgotNewPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                      </button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Confirm Password</label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Lock className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type={showConfirmPassword ? "text" : "password"}
                        placeholder="Confirm new password"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        required
                        minLength={6}
                        className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                      />
                      <button
                        type="button"
                        onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                        className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                      >
                        {showConfirmPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                      </button>
                    </div>
                    {confirmPassword && forgotNewPassword !== confirmPassword && (
                      <p className="text-xs text-red-500">Passwords do not match</p>
                    )}
                  </div>

                  <div className="flex gap-3">
                    <button
                      type="button"
                      onClick={() => setForgotStep(1)}
                      className="flex-1 border border-slate-300 text-slate-700 py-3 rounded-lg font-medium hover:bg-slate-50 transition-all flex items-center justify-center"
                    >
                      <ArrowLeft className="w-4 h-4 mr-2" />
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={forgotLoading || forgotNewPassword !== confirmPassword}
                      className="flex-1 bg-slate-900 text-white py-3 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {forgotLoading ? (
                        <>
                          <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                          Resetting...
                        </>
                      ) : (
                        "Reset Password"
                      )}
                    </button>
                  </div>
                </form>
              )}

              {/* Step 3: Success */}
              {forgotStep === 3 && (
                <div className="text-center py-6">
                  <div className="w-20 h-20 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                    <CheckCircle className="w-10 h-10 text-green-600" />
                  </div>
                  <h4 className="text-xl font-bold text-slate-800 mb-2">Password Reset Successful!</h4>
                  <p className="text-slate-500 mb-6">
                    Your password has been changed successfully. You can now login with your new password.
                  </p>
                  <button
                    onClick={closeForgotModal}
                    className="w-full bg-slate-900 text-white py-3 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all"
                  >
                    Back to Login
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}