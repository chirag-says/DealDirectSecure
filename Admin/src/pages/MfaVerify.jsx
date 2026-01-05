import React, { useState } from "react";
import { toast } from "react-toastify";
import { useNavigate, useLocation } from "react-router-dom";
import { ShieldCheck, ArrowRight } from "lucide-react";
import { mfaApi } from "../api/adminApi";
import { useAdmin } from "../context/AdminContext";

const MfaVerify = () => {
    const navigate = useNavigate();
    const location = useLocation();
    const { login } = useAdmin();
    const [code, setCode] = useState("");
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!code || code.length !== 6) {
            return toast.warn("Please enter a valid 6-digit code");
        }

        try {
            setLoading(true);
            const data = await mfaApi.verify(code);

            if (data.success) {
                toast.success("Verification Successful!");

                // Update global context with the now fully-authenticated admin profile
                await login(data.admin);

                // Navigate to dashboard or intended page
                const from = location.state?.from || "/dashboard";
                navigate(from, { replace: true });
            }
        } catch (error) {
            const msg = error.response?.data?.message || "Invalid code. Please try again.";
            toast.error(msg);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <div className="bg-white shadow-xl rounded-2xl w-full max-w-sm p-8 border border-gray-100">

                <div className="text-center mb-6">
                    <div className="mx-auto w-14 h-14 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                        <ShieldCheck className="w-7 h-7 text-blue-600" />
                    </div>
                    <h2 className="text-xl font-bold text-gray-800">Security Verification</h2>
                    <p className="text-gray-500 mt-2 text-sm">
                        Please enter the 6-digit code from your authenticator app.
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-5">
                    <div>
                        <input
                            type="text"
                            maxLength="6"
                            value={code}
                            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} // Numeric only
                            placeholder="000 000"
                            className="w-full text-center text-3xl tracking-[0.5em] font-mono border-b-2 border-gray-300 focus:border-blue-600 outline-none py-2 transition-colors bg-transparent text-gray-800 placeholder-gray-300"
                            autoFocus
                        />
                    </div>

                    <button
                        type="submit"
                        disabled={loading || code.length !== 6}
                        className={`w-full py-3 rounded-lg text-white font-semibold flex items-center justify-center gap-2 transition-all ${loading || code.length !== 6
                                ? "bg-gray-400 cursor-not-allowed"
                                : "bg-blue-600 hover:bg-blue-700 shadow-md"
                            }`}
                    >
                        {loading ? "Verifying..." : "Verify"}
                        {!loading && <ArrowRight className="w-4 h-4" />}
                    </button>
                </form>

                <div className="text-center mt-6">
                    <button
                        onClick={() => navigate("/admin/login")}
                        className="text-xs text-gray-400 hover:text-gray-600 underline"
                    >
                        Back to Login
                    </button>
                </div>

            </div>
        </div>
    );
};

export default MfaVerify;
