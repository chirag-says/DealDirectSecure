// src/Components/EmailVerificationModal/EmailVerificationModal.jsx
import React, { useState, useEffect } from "react";
// eslint-disable-next-line no-unused-vars
import { motion, AnimatePresence } from "framer-motion";
import { X, Mail, ShieldCheck, Loader2, RefreshCw, CheckCircle, Home } from "lucide-react";
import { toast } from "react-toastify";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";

export default function EmailVerificationModal({ isOpen, onClose, user, onVerified }) {
  const [step, setStep] = useState(1); // 1: Confirm email, 2: Enter OTP
  const [otp, setOtp] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendTimer, setResendTimer] = useState(0);

  // Use AuthContext to update user after verification
  const { updateUser } = useAuth();

  // Reset state when modal opens
  useEffect(() => {
    if (isOpen) {
      setStep(1);
      setOtp("");
      setResendTimer(0);
    }
  }, [isOpen]);

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

  const handleSendOtp = async () => {
    setIsLoading(true);
    try {
      await api.post('/users/send-upgrade-otp', { email: user?.email });
      toast.success("OTP sent to your email!");
      setStep(2);
      setResendTimer(60);
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to send OTP. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleResendOtp = async () => {
    if (resendTimer > 0) return;

    setResendLoading(true);
    try {
      await api.post('/users/send-upgrade-otp', { email: user?.email });
      toast.success("New OTP sent to your email!");
      setResendTimer(60);
      setOtp("");
    } catch (err) {
      toast.error(err.response?.data?.message || "Failed to resend OTP. Please try again.");
    } finally {
      setResendLoading(false);
    }
  };

  const handleVerifyOtp = async () => {
    if (otp.length !== 6) {
      toast.error("Please enter a valid 6-digit OTP");
      return;
    }

    setIsLoading(true);
    try {
      const res = await api.post('/users/verify-upgrade-otp', { email: user?.email, otp });

      // Update user in AuthContext (handles localStorage and cookie refresh)
      const { user: updatedUser } = res.data;
      updateUser(updatedUser);

      toast.success("Email verified! You can now list properties.");
      onVerified && onVerified();
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.message || "Invalid OTP. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
          />

          {/* Modal */}
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ type: "spring", duration: 0.5 }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4"
          >
            <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">
              {/* Header */}
              <div className="bg-gradient-to-r from-blue-600 to-blue-700 px-6 py-5 text-white relative">
                <button
                  onClick={onClose}
                  className="absolute right-4 top-4 p-1 hover:bg-white/20 rounded-full transition"
                >
                  <X className="w-5 h-5" />
                </button>
                <div className="flex items-center gap-3">
                  <div className="p-2 bg-white/20 rounded-lg">
                    <Home className="w-6 h-6" />
                  </div>
                  <div>
                    <h2 className="text-xl font-bold">List Your Property</h2>
                    <p className="text-blue-100 text-sm">Verify email to become a property owner</p>
                  </div>
                </div>
              </div>

              {/* Body */}
              <div className="p-6">
                {step === 1 ? (
                  <>
                    {/* Step 1: Confirm Email */}
                    <div className="text-center mb-6">
                      <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                        <Mail className="w-8 h-8 text-blue-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-gray-800 mb-2">
                        Verify Your Email
                      </h3>
                      <p className="text-gray-500 text-sm">
                        To list properties, we need to verify your email address for security.
                      </p>
                    </div>

                    {/* Email Display */}
                    <div className="bg-gray-50 border border-gray-200 rounded-xl p-4 mb-6">
                      <label className="text-xs font-medium text-gray-500 block mb-1">
                        Verification will be sent to
                      </label>
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center">
                          <Mail className="w-5 h-5 text-blue-600" />
                        </div>
                        <div>
                          <p className="font-semibold text-gray-800">{user?.email}</p>
                          <p className="text-xs text-gray-500">Registered email</p>
                        </div>
                      </div>
                    </div>

                    {/* Benefits */}
                    <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 mb-6">
                      <p className="text-sm text-amber-800 font-medium mb-2">
                        🏠 Why verify?
                      </p>
                      <ul className="text-xs text-amber-700 space-y-1">
                        <li>• List unlimited properties for free</li>
                        <li>• Connect directly with buyers</li>
                        <li>• Access owner dashboard</li>
                      </ul>
                    </div>

                    {/* Send OTP Button */}
                    <button
                      onClick={handleSendOtp}
                      disabled={isLoading}
                      className="w-full bg-blue-600 text-white py-3.5 rounded-xl font-semibold hover:bg-blue-700 focus:ring-4 focus:ring-blue-200 transition-all flex items-center justify-center gap-2"
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="w-5 h-5 animate-spin" />
                          Sending OTP...
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-5 h-5" />
                          Send Verification OTP
                        </>
                      )}
                    </button>
                  </>
                ) : (
                  <>
                    {/* Step 2: Enter OTP */}
                    <div className="text-center mb-6">
                      <div className="mx-auto w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mb-4">
                        <ShieldCheck className="w-8 h-8 text-green-600" />
                      </div>
                      <h3 className="text-lg font-semibold text-gray-800 mb-2">
                        Enter Verification Code
                      </h3>
                      <p className="text-gray-500 text-sm">
                        We've sent a 6-digit code to<br />
                        <span className="font-semibold text-gray-800">{user?.email}</span>
                      </p>
                    </div>

                    {/* OTP Input */}
                    <div className="mb-6">
                      <input
                        type="text"
                        value={otp}
                        onChange={(e) => setOtp(e.target.value.replace(/[^0-9]/g, "").slice(0, 6))}
                        placeholder="Enter 6-digit OTP"
                        className="w-full text-center text-2xl tracking-[0.5em] py-4 border-2 border-gray-200 rounded-xl focus:ring-2 focus:ring-blue-500 focus:border-blue-500 transition outline-none text-gray-800 font-mono"
                        maxLength={6}
                      />
                    </div>

                    {/* Verify Button */}
                    <button
                      onClick={handleVerifyOtp}
                      disabled={isLoading || otp.length !== 6}
                      className="w-full bg-green-600 text-white py-3.5 rounded-xl font-semibold hover:bg-green-700 focus:ring-4 focus:ring-green-200 transition-all flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {isLoading ? (
                        <>
                          <Loader2 className="w-5 h-5 animate-spin" />
                          Verifying...
                        </>
                      ) : (
                        <>
                          <CheckCircle className="w-5 h-5" />
                          Verify & Continue
                        </>
                      )}
                    </button>

                    {/* Resend OTP */}
                    <div className="mt-4 text-center">
                      <p className="text-sm text-gray-500 mb-2">Didn't receive the code?</p>
                      <button
                        type="button"
                        onClick={handleResendOtp}
                        disabled={resendTimer > 0 || resendLoading}
                        className={`inline-flex items-center text-sm font-medium transition-colors ${resendTimer > 0
                          ? "text-gray-400 cursor-not-allowed"
                          : "text-blue-600 hover:text-blue-700 hover:underline cursor-pointer"
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

                    {/* Go Back */}
                    <button
                      type="button"
                      onClick={() => setStep(1)}
                      className="w-full mt-3 text-gray-500 text-sm hover:text-gray-700 transition"
                    >
                      ← Change email / Go back
                    </button>
                  </>
                )}
              </div>
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
