import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { ChevronDownIcon, Bars3Icon, ArrowLeftStartOnRectangleIcon, KeyIcon } from "@heroicons/react/24/outline";
import logoSrc from "../assets/dd.jpg";
import { useAdmin } from "../context/AdminContext";

const Header = ({ toggleSidebar }) => {
    const [menuOpen, setMenuOpen] = useState(false);
    const dropdownRef = useRef(null);
    const { admin, logout } = useAdmin();

    // Handle clicks outside dropdown
    useEffect(() => {
        function handleClickOutside(event) {
            if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
                setMenuOpen(false);
            }
        }
        document.addEventListener("mousedown", handleClickOutside);
        return () => {
            document.removeEventListener("mousedown", handleClickOutside);
        };
    }, [dropdownRef]);

    // Logout Function - now uses context
    const handleLogout = async () => {
        await logout();
        window.location.href = "/admin/login";
    };

    // Get admin info from context
    const adminName = admin?.name || "Admin";
    const adminEmail = admin?.email || "N/A";
    const adminRole = admin?.role?.displayName || admin?.role?.name || "Administrator";

    // Get Avatar Text (e.g., 'A' for Admin)
    const getAvatarText = (name) => {
        return name.charAt(0).toUpperCase();
    };

    // Get role badge color based on role
    const getRoleBadgeColor = (role) => {
        const roleName = (role || "").toLowerCase();
        if (roleName.includes("super")) return "bg-purple-100 text-purple-700";
        if (roleName.includes("admin")) return "bg-blue-100 text-blue-700";
        if (roleName.includes("manager")) return "bg-green-100 text-green-700";
        return "bg-gray-100 text-gray-700"; // Viewer or default
    };

    return (
        <header className="sticky top-0 z-40 bg-white border-b border-gray-100 p-3 sm:p-4 flex justify-between items-center shadow-md">
            {/* Left Side: Toggle & Logo */}
            <div className="flex items-center px-5 space-x-3 sm:space-x-4 flex-shrink-0">
                <button
                    onClick={toggleSidebar}
                    className="lg:hidden p-1.5 sm:p-2 text-gray-600 hover:bg-gray-100 rounded-lg focus:outline-none transition"
                    aria-label="Toggle Sidebar"
                >
                    <Bars3Icon className="h-6 w-6" />
                </button>
                <img src={logoSrc} alt="DealDirect Logo" className="h-7 sm:h-10 w-auto object-contain" />
            </div>

            {/* Right Side */}
            <div className="flex items-center space-x-3 sm:space-x-5 relative flex-shrink-1 min-w-0">

                {/* Admin Profile + Dropdown */}
                <div ref={dropdownRef} className="relative flex-shrink-1">
                    <button
                        onClick={() => setMenuOpen(!menuOpen)}
                        className="flex items-center space-x-1 sm:space-x-2 p-1.5 rounded-full bg-gray-50 hover:bg-gray-100 transition focus:outline-none"
                        aria-expanded={menuOpen}
                        aria-controls="profile-menu"
                    >
                        {/* Profile Avatar */}
                        <div className="flex-shrink-0 h-9 w-9 sm:h-10 sm:w-10 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-lg shadow-md">
                            {getAvatarText(adminName)}
                        </div>

                        {/* Info and Chevron */}
                        <div className="hidden md:flex flex-col items-start min-w-0">
                            <span className="text-sm font-semibold text-gray-800 truncate max-w-[120px]">
                                {adminName}
                            </span>
                            <span className="text-xs text-gray-500 truncate max-w-[120px]">
                                {adminRole}
                            </span>
                        </div>

                        <ChevronDownIcon className="h-4 w-4 text-gray-500 flex-shrink-0" />
                    </button>

                    {/* Dropdown Menu */}
                    {menuOpen && (
                        <div
                            id="profile-menu"
                            className="absolute right-0 top-full mt-2 w-64 bg-white border border-gray-100 rounded-lg shadow-xl z-50 origin-top-right animate-fade-in-down"
                        >
                            <div className="p-4 border-b border-gray-100">
                                <p className="font-bold text-gray-800 truncate">{adminName}</p>
                                <p className="text-sm text-gray-500 truncate">{adminEmail}</p>
                                <span className={`mt-2 inline-block text-xs font-semibold px-2 py-0.5 rounded-full ${getRoleBadgeColor(adminRole)}`}>
                                    {adminRole}
                                </span>
                            </div>

                            <ul className="py-2">
                                {/* Change Password */}
                                <li>
                                    <Link
                                        to="/admin/change-password"
                                        onClick={() => setMenuOpen(false)}
                                        className="w-full flex items-center space-x-3 px-4 py-2 text-sm text-gray-700 hover:bg-gray-50 transition"
                                    >
                                        <KeyIcon className="h-5 w-5 text-gray-400" />
                                        <span>Change Password</span>
                                    </Link>
                                </li>

                                <div className="border-t border-gray-100 my-1"></div>

                                {/* Logout Button */}
                                <li>
                                    <button
                                        onClick={handleLogout}
                                        className="w-full flex items-center space-x-3 px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition"
                                    >
                                        <ArrowLeftStartOnRectangleIcon className="h-5 w-5" />
                                        <span>Logout</span>
                                    </button>
                                </li>
                            </ul>
                        </div>
                    )}
                </div>
            </div>
        </header>
    );
};

export default Header;