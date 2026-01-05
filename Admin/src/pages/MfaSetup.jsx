import React, { useState } from "react";
import { toast } from "react-toastify";
import { useNavigate } from "react-router-dom";
import { ShieldCheck, Copy, CheckCircle, Smartphone } from "lucide-react";
import { mfaApi } from "../api/adminApi";

const MfaSetup = () => {
    const navigate = useNavigate();
    const [step, setStep] = useState("init"); // init, scan, verify
    const [qrCode, setQrCode] = useState("");
    const [secret, setSecret] = useState("");
    const [verificationCode, setVerificationCode] = useState("");
    const [loading, setLoading] = useState(false);
    const [backupCodes, setBackupCodes] = useState([]);

    // Step 1: Initialize Setup and Get QR
    const startSetup = async () => {
        try {
            setLoading(true);
            const data = await mfaApi.setup();

            if (data.success) {
                setQrCode(data.qrCode);
                setSecret(data.manualEntry);
                setBackupCodes(data.backupCodes || []);
                setStep("scan");
                toast.success("MFA Setup Initiated");
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Failed to start MFA setup");
        } finally {
            setLoading(false);
        }
    };

    // Step 2: Verify Code
    const verifyCode = async (e) => {
        e.preventDefault();
        if (!verificationCode || verificationCode.length !== 6) {
            return toast.warn("Please enter a valid 6-digit code");
        }

        try {
            setLoading(true);
            const data = await mfaApi.confirm(verificationCode);

            if (data.success) {
                toast.success("MFA Enabled Successfully!");
                // Redirect to dashboard (this time authentication works fully)
                // We reload to force a fresh auth check
                window.location.href = "/dashboard";
            }
        } catch (error) {
            toast.error(error.response?.data?.message || "Verification failed. Try again.");
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text) => {
        navigator.clipboard.writeText(text);
        toast.info("Copied to clipboard");
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 p-4">
            <div className="bg-white shadow-xl rounded-2xl w-full max-w-lg p-8 border border-gray-100">

                {/* Header */}
                <div className="text-center mb-8">
                    <div className="mx-auto w-16 h-16 bg-blue-100 rounded-full flex items-center justify-center mb-4">
                        <ShieldCheck className="w-8 h-8 text-blue-600" />
                    </div>
                    <h2 className="text-2xl font-bold text-gray-800">Secure Your Account</h2>
                    <p className="text-gray-500 mt-2">Set up Multi-Factor Authentication (MFA)</p>
                </div>

                {/* Step 1: Start */}
                {step === "init" && (
                    <div className="text-center space-y-6">
                        <p className="text-gray-600">
                            To protect your admin account, you must set up MFA. You will need an authenticator app like Google Authenticator or Authy.
                        </p>
                        <button
                            onClick={startSetup}
                            disabled={loading}
                            className="w-full py-3 bg-blue-600 text-white rounded-lg font-semibold hover:bg-blue-700 transition-colors shadow-lg"
                        >
                            {loading ? "Initializing..." : "Start Setup"}
                        </button>
                    </div>
                )}

                {/* Step 2: Scan QR */}
                {step === "scan" && (
                    <div className="space-y-6">
                        <div className="bg-gray-50 p-4 rounded-xl border border-gray-200 text-center">
                            <p className="text-sm font-semibold text-gray-700 mb-4">1. Scan this QR Code with your app</p>
                            {qrCode ? (
                                <img src={qrCode} alt="MFA QR Code" className="mx-auto w-48 h-48 border-4 border-white shadow-sm rounded-lg" />
                            ) : (
                                <div className="w-48 h-48 mx-auto bg-gray-200 animate-pulse rounded-lg"></div>
                            )}
                        </div>

                        <div className="bg-gray-50 p-4 rounded-xl border border-gray-200">
                            <p className="text-sm font-semibold text-gray-700 mb-2">Or enter manual key:</p>
                            <div className="flex items-center justify-between bg-white p-3 rounded border border-gray-200">
                                <code className="text-blue-600 font-mono text-sm break-all">{secret}</code>
                                <button onClick={() => copyToClipboard(secret)} className="ml-2 text-gray-400 hover:text-gray-600">
                                    <Copy className="w-4 h-4" />
                                </button>
                            </div>
                        </div>

                        <form onSubmit={verifyCode} className="space-y-4">
                            <div className="text-center">
                                <p className="text-sm font-semibold text-gray-700 mb-2">2. Enter the 6-digit code from your app</p>
                                <div className="relative">
                                    <Smartphone className="absolute left-3 top-3.5 text-gray-400 w-5 h-5" />
                                    <input
                                        type="text"
                                        maxLength="6"
                                        value={verificationCode}
                                        onChange={(e) => setVerificationCode(e.target.value.replace(/\D/g, ''))}
                                        placeholder="000 000"
                                        className="w-full border border-gray-300 pl-10 text-center text-2xl tracking-widest font-mono rounded-lg p-3 text-gray-800 focus:ring-2 focus:ring-blue-500 outline-none"
                                    />
                                </div>
                            </div>

                            <button
                                type="submit"
                                disabled={loading || verificationCode.length !== 6}
                                className={`w-full py-3 rounded-lg text-white font-semibold transition-all ${loading || verificationCode.length !== 6
                                        ? "bg-gray-400 cursor-not-allowed"
                                        : "bg-green-600 hover:bg-green-700 shadow-md"
                                    }`}
                            >
                                {loading ? "Verifying..." : "Verify & Enable"}
                            </button>
                        </form>
                    </div>
                )}

                {/* Backup Codes Modal (Simplified for now - user should see them) */}
                {backupCodes.length > 0 && (
                    <div className="mt-6 pt-6 border-t border-gray-100">
                        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4">
                            <h4 className="font-bold text-yellow-800 flex items-center mb-2">
                                <CheckCircle className="w-4 h-4 mr-2" />
                                Save these Backup Codes!
                            </h4>
                            <p className="text-xs text-yellow-700 mb-2">If you lose your phone, these are the only way to recover your account.</p>
                            <div className="grid grid-cols-2 gap-2">
                                {backupCodes.slice(0, 4).map((code, i) => (
                                    <code key={i} className="text-xs font-mono bg-white px-2 py-1 rounded border border-yellow-100 text-center">
                                        {code}
                                    </code>
                                ))}
                            </div>
                            <p className="text-xs text-center mt-2 text-yellow-600 italic">...and {backupCodes.length - 4} more</p>
                        </div>
                    </div>
                )}

            </div>
        </div>
    );
};

export default MfaSetup;
