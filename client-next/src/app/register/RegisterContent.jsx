'use client';
import { useRouter, usePathname, useSearchParams } from 'next/navigation';
import Link from 'next/link';

// src/pages/Auth/Register.jsx
import React, { useState, useEffect } from "react";
import api from "../../utils/api";
import { toast } from "react-toastify";
import { User, Mail, Lock, Eye, EyeOff, Loader2, CheckCircle, Gift } from "lucide-react";
import dealDirectLogo from "../../assets/dealdirect_logo.png";
import { useAuth } from "../../context/AuthContext";
import GoogleAuthPanel from "../../components/Auth/GoogleAuthPanel";

/**
 * Registration. One form, for everyone.
 *
 * WHAT USED TO BE HERE
 *
 * This page opened with "I want to: Find Property / List Property", and that
 * choice decided everything after it. "List Property" ran an SMS OTP before the
 * account existed and added a second step to the form; "Find Property" did not.
 *
 * Both are gone. The choice was asked at the worst moment — before anyone has
 * seen a listing, they are made to declare which kind of person they are — and
 * it was wrong as often as not, since most owners browse before they list. And
 * the OTP was a toll gate on a stranger who had not yet been given a reason to
 * spend one.
 *
 * Neither fact is asked for here now. The account is created immediately, and
 * both are established later, at the moment they matter:
 *
 *   - the ROLE is granted server-side the first time the account posts a
 *     listing (`ensureOwnerRole`)
 *   - the PHONE is verified by the modal the API layer raises when a gated
 *     action is refused (`PhoneVerificationModal`)
 *
 * The phone field is gone from this form entirely. Collecting a number here and
 * verifying it later would be asking for the same thing twice.
 */
export default function Register() {
  const [formData, setFormData] = useState({ name: "", email: "", password: "", agree: false, referralCode: "" });

  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const {
    register: authRegister,
    updateUser,
  } = useAuth();
  const redirectPath = searchParams.get("from") || "/";

  // Auto-fill referral code from URL param ?ref=XXXX
  useEffect(() => {
    const refCode = searchParams.get("ref");
    if (refCode) {
      setFormData((f) => ({ ...f, referralCode: refCode.toUpperCase().trim() }));
    }
  }, [searchParams]);



  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((f) => ({ ...f, [name]: type === "checkbox" ? checked : value }));
  };

  // Password validation helper
  const validatePassword = (password) => {
    if (!password || password.length < 8) {
      return { valid: false, message: 'Password must be at least 8 characters long' };
    }
    if (!/[a-z]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one lowercase letter' };
    }
    if (!/[A-Z]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one uppercase letter' };
    }
    if (!/\d/.test(password)) {
      return { valid: false, message: 'Password must contain at least one number' };
    }
    if (!/[@$!%*?&#^()\-_=+]/.test(password)) {
      return { valid: false, message: 'Password must contain at least one special character (@$!%*?&#^()-_=+)' };
    }
    return { valid: true };
  };

  /**
   * One registration path: create the account and the session in a single call.
   *
   * `/users/register-direct`, never `/users/register`. No OTP, no phone number,
   * no role — see the note at the top of this file for why none of the three is
   * asked for at signup any more.
   */
  const handleRegister = async (e) => {
    e.preventDefault();
    if (!formData.agree) return toast.error("Please accept the Terms & Privacy Policy");

    const passwordCheck = validatePassword(formData.password);
    if (!passwordCheck.valid) {
      toast.error(passwordCheck.message);
      return;
    }

    setIsLoading(true);
    try {
      const res = await api.post('/users/register-direct', {
        name: formData.name,
        email: formData.email,
        password: formData.password,
        referralCode: formData.referralCode || undefined,
      });

      updateUser(res.data.user);
      toast.success("Registration successful! Welcome to DealDirect.");
      router.push(redirectPath);
    } catch (err) {
      const errorData = err.response?.data;

      // An email that already signs in with Google cannot take a password here.
      // Point at the door that works instead of at the refusal.
      if (errorData?.code === 'USE_GOOGLE_SIGNIN') {
        toast.error("This email already signs in with Google. Use the Google button above.");
        return;
      }

      toast.error(errorData?.message || err.message || "Registration failed. Please check your details and try again.");
      console.error("Registration error:", err.response?.status, errorData);
    } finally {
      setIsLoading(false);
    }
  };

  // The MFA and forced-password-change screens were removed here (Phase 5.3).
  //
  // Neither could ever render: the user API emits no requiresMfa or
  // passwordChangeRequired flag, and /users/verify-mfa and
  // /users/change-password-required are not routes. MFA is an admin feature and
  // lives in the Admin app.
  //
  // The OTP step, its resend timer and `handleVerifyOtp` went in the auth
  // unification. The phone OTP is no longer part of registration at all; it
  // fires just in time, from PhoneVerificationModal, at the first action that
  // needs a real number.

  // Render password change requirement form
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
            <img src={dealDirectLogo.src} alt="DealDirect" className="h-12 w-auto" />
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
            </ul>
          </div>

          <div className="relative z-20 text-sm text-gray-400">
            © 2025 DealDirect. Building Trust.
          </div>
        </div>

        {/* RIGHT SIDE - FORM */}
        <div className="md:w-1/2 w-full p-8 md:p-12 flex flex-col justify-center">
          <div className="max-w-md mx-auto w-full">

            <div className="text-center mb-8">
              <h2 className="text-3xl font-bold text-slate-800">Create Account</h2>
              <p className="text-slate-500 mt-2">Join us to unlock exclusive property deals.</p>
            </div>

            <GoogleAuthPanel
              referralCode={formData.referralCode || undefined}
              onSuccess={() => router.push(redirectPath)}
              dividerLabel="or sign up with email"
            />

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

                  {/* Referral Code Input (Optional) */}
                  <div className="space-y-2">
                    <label className="text-sm font-medium text-slate-700 block">Referral Code <span className="text-slate-400 font-normal">(optional)</span></label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
                        <Gift className="h-5 w-5 text-slate-400" />
                      </div>
                      <input
                        type="text"
                        name="referralCode"
                        placeholder="e.g. DDAB12"
                        value={formData.referralCode}
                        onChange={handleChange}
                        maxLength={6}
                        className="w-full pl-10 pr-4 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800 uppercase tracking-wider"
                      />
                    </div>
                    {formData.referralCode && (
                      <p className="text-xs text-green-600 flex items-center gap-1">
                        <CheckCircle className="w-3.5 h-3.5" />
                        Referral code applied — you and your friend will both earn bonus points!
                      </p>
                    )}
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
                        I agree to the <Link href="/terms" target="_blank" className="text-blue-900 font-medium hover:underline">Terms of Use</Link> and <Link href="/privacy" target="_blank" className="text-blue-900 font-medium hover:underline">Privacy Policy</Link>
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
                        Creating Account...
                      </>
                    ) : (
                      "Create Account"
                    )}
                  </button>
                </form>

                {/* Footer */}
                <div className="mt-8 text-center text-sm text-slate-500">
                  Already have an account?{" "}
                  <Link href="/login" className="font-bold text-blue-900 hover:underline">
                    Log in here
                  </Link>
                </div>
          </div>
        </div>

      </div>
    </div>
  );
}