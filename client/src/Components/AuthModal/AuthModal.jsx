import React, { useState } from "react";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import { FaTimes } from "react-icons/fa";
import { User, Mail, Lock, Eye, EyeOff, Loader2, CheckCircle, ShieldCheck } from "lucide-react";
import api from "../../utils/api";
import { useAuth } from "../../context/AuthContext";
import dealDirectLogo from "../../assets/dealdirect_logo.png";

const AuthModal = ({ isOpen, onClose }) => {
    const [isLogin, setIsLogin] = useState(true);
    const [formData, setFormData] = useState({
        name: "",
        email: "",
        password: "",
        agree: false,
    });
    const [otp, setOtp] = useState("");
    const [step, setStep] = useState(1); // 1: Details, 2: OTP (Only for Register)
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    // Use AuthContext for login/register
    const { login, updateUser } = useAuth();

    if (!isOpen) return null;

    const handleChange = (e) => {
        const { name, value, type, checked } = e.target;
        setFormData((f) => ({
            ...f,
            [name]: type === "checkbox" ? checked : value,
        }));
    };

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            // Use AuthContext login method (handles cookies)
            await login(formData.email, formData.password);

            toast.success("Welcome back!");
            onClose();
            navigate("/add-property");
        } catch (err) {
            toast.error(err.response?.data?.message || "Login failed");
        } finally {
            setIsLoading(false);
        }
    };

    const handleRegisterStep1 = async (e) => {
        e.preventDefault();
        if (!formData.agree) return toast.error("Please accept Terms & Privacy Policy");

        setIsLoading(true);
        try {
            // Seller registration should create an owner-style account (with OTP)
            await api.post('/users/register', {
                name: formData.name,
                email: formData.email,
                password: formData.password,
                role: "owner",
            });
            toast.success("OTP sent to your email!");
            setStep(2);
        } catch (err) {
            toast.error(err.response?.data?.message || "Failed to send OTP");
        } finally {
            setIsLoading(false);
        }
    };

    const handleVerifyOtp = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        try {
            const res = await api.post('/users/verify-otp', {
                email: formData.email,
                otp,
            });

            // The server sets HttpOnly cookie, just store user data for UI
            const { user } = res.data;
            updateUser(user);
            // window.dispatchEvent(new Event("auth-change"));

            toast.success("Registration successful! Welcome aboard.");
            onClose();
            navigate("/add-property");
        } catch (err) {
            toast.error(err.response?.data?.message || "Invalid OTP");
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 font-sans">
            <div className="relative w-full max-w-5xl bg-white rounded-2xl shadow-2xl overflow-hidden flex flex-col md:flex-row min-h-[600px] animate-fadeIn">

                {/* Close Button */}
                <button
                    onClick={onClose}
                    className="absolute top-4 right-4 z-30 p-2 bg-white/20 hover:bg-gray-100 rounded-full text-gray-600 transition-colors"
                >
                    <FaTimes size={20} />
                </button>

                {/* LEFT SIDE - IMAGE & BRANDING */}
                <div className="md:w-1/2 relative hidden md:flex flex-col justify-between p-12 text-white">
                    {/* Background Image with Overlay */}
                    <div className="absolute inset-0 bg-cover bg-center z-0"
                        style={{
                            backgroundImage: isLogin
                                ? "url('https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?q=80&w=2070&auto=format&fit=crop')"
                                : "url('https://images.unsplash.com/photo-1560518883-ce09059eeffa?q=80&w=1973&auto=format&fit=crop')"
                        }}>
                    </div>
                    <div className={`absolute inset-0 z-10 ${isLogin ? 'bg-slate-900/60' : 'bg-slate-900/70'}`}></div>

                    {/* Header Branding */}
                    <div className="relative z-20 flex items-center gap-2 mb-6">
                        <img src={dealDirectLogo} alt="DealDirect" className="h-12 w-auto" />
                    </div>

                    {/* Main Text */}
                    <div className="relative z-20 mb-8">
                        {isLogin ? (
                            <>
                                <h2 className="text-4xl font-bold leading-tight mb-4">
                                    Reach serious buyers <br /> <span className="text-blue-400">directly.</span>
                                </h2>
                                <p className="text-gray-300 text-lg">
                                    List your property for free and manage every lead in one seller dashboard - no middlemen required.
                                </p>
                            </>
                        ) : (
                            <>
                                <h2 className="text-4xl font-bold leading-tight mb-6">
                                    Start listing with <br /> <span className="text-blue-400">DealDirect.</span>
                                </h2>
                                <ul className="space-y-4 text-gray-300">
                                    <li className="flex items-center gap-3">
                                        <CheckCircle className="w-5 h-5 text-blue-400" />
                                        <span>Connect with verified, high-intent buyers</span>
                                    </li>
                                    <li className="flex items-center gap-3">
                                        <CheckCircle className="w-5 h-5 text-blue-400" />
                                        <span>Track inquiries, calls, and visits from one place</span>
                                    </li>
                                    <li className="flex items-center gap-3">
                                        <CheckCircle className="w-5 h-5 text-blue-400" />
                                        <span>Close deals faster with zero brokerage</span>
                                    </li>
                                </ul>
                            </>
                        )}
                    </div>

                    <div className="relative z-20 text-sm text-gray-400">
                        © 2025 DealDirect. All rights reserved.
                    </div>
                </div>

                {/* RIGHT SIDE - FORM */}
                <div className="md:w-1/2 w-full p-8 md:p-12 flex flex-col justify-center relative z-20 bg-white">
                    <div className="max-w-md mx-auto w-full">

                        {/* LOGIN FORM */}
                        {isLogin && (
                            <>
                                <div className="text-center mb-10">
                                    <h2 className="text-3xl font-bold text-slate-800">Seller Sign In</h2>
                                    <p className="text-slate-500 mt-2">Access your dashboard to manage property listings.</p>
                                </div>

                                <form onSubmit={handleLogin} className="space-y-6">
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

                                    <div className="flex items-center justify-between text-sm">
                                        <label className="flex items-center cursor-pointer">
                                            <input type="checkbox" className="w-4 h-4 text-blue-900 border-slate-300 rounded focus:ring-blue-900" />
                                            <span className="ml-2 text-slate-600">Remember me</span>
                                        </label>
                                        <a href="#" className="font-medium text-blue-900 hover:underline">Forgot password?</a>
                                    </div>

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
                            </>
                        )}

                        {/* REGISTER FORM - STEP 1 */}
                        {!isLogin && step === 1 && (
                            <>
                                <div className="text-center mb-8">
                                    <h2 className="text-3xl font-bold text-slate-800">Create Seller Account</h2>
                                    <p className="text-slate-500 mt-2">Tell us a few details to start posting your listings.</p>
                                </div>

                                <form onSubmit={handleRegisterStep1} className="space-y-5">
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
                                                className="w-full pl-10 pr-12 py-3 border border-slate-300 rounded-lg focus:ring-2 focus:ring-blue-900 focus:border-blue-900 transition-colors outline-none text-slate-800"
                                            />
                                            <button
                                                type="button"
                                                onClick={() => setShowPassword((prev) => !prev)}
                                                className="absolute inset-y-0 right-0 pr-3 flex items-center text-slate-400 hover:text-slate-600"
                                            >
                                                {showPassword ? <EyeOff className="h-5 w-5" /> : <Eye className="h-5 w-5" />}
                                            </button>
                                        </div>
                                    </div>

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
                                                I agree to the{' '}
                                                <a href="#" className="text-blue-900 font-medium hover:underline">Terms of Service</a>{' '}
                                                and{' '}
                                                <a href="#" className="text-blue-900 font-medium hover:underline">Privacy Policy</a>
                                            </label>
                                        </div>
                                    </div>

                                    <button
                                        type="submit"
                                        disabled={isLoading}
                                        className="w-full bg-slate-900 text-white py-3.5 rounded-lg font-semibold hover:bg-slate-800 focus:ring-4 focus:ring-slate-200 transition-all flex items-center justify-center"
                                    >
                                        {isLoading ? (
                                            <>
                                                <Loader2 className="w-5 h-5 mr-2 animate-spin" />
                                                Sending OTP...
                                            </>
                                        ) : (
                                            "Create Seller Account"
                                        )}
                                    </button>
                                </form>
                            </>
                        )}

                        {/* REGISTER FORM - STEP 2 (OTP) */}
                        {!isLogin && step === 2 && (
                            <>
                                <div className="text-center mb-8">
                                    <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                                        <ShieldCheck className="w-8 h-8 text-blue-600" />
                                    </div>
                                    <h2 className="text-3xl font-bold text-slate-800">Verify Seller Email</h2>
                                    <p className="text-slate-500 mt-2">
                                        We've sent a verification code to <br /> <span className="font-semibold text-slate-800">{formData.email}</span> to activate your seller account.
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
                                            "Verify & Start Listing"
                                        )}
                                    </button>

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

                        {/* FOOTER TOGGLE */}
                        <div className="mt-8 text-center text-sm text-slate-500">
                            {isLogin ? "Don't have an account? " : "Already have an account? "}
                            <button
                                onClick={() => {
                                    setIsLogin(!isLogin);
                                    setStep(1);
                                }}
                                className="font-bold text-blue-900 hover:underline"
                            >
                                {isLogin ? "Create an account" : "Log in here"}
                            </button>
                        </div>

                    </div>
                </div>

            </div>
        </div>
    );
};

export default AuthModal;
