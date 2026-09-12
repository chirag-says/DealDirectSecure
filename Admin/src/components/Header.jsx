import React, { useState, useEffect, useRef } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, LockKeyhole, LogOut, PanelLeft, PanelLeftClose } from "lucide-react";
import logoSrc from "../assets/dd.jpg";
import ddAdminPfp from "../assets/dealdirectadminpfp.png";
import { useAdmin } from "../context/AdminContext";

const Header = ({ toggleSidebar, isSidebarOpen }) => {
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

    // Escape closes the menu. A dropdown you can only dismiss with the mouse
    // is a trap for anyone driving the panel from the keyboard.
    useEffect(() => {
        if (!menuOpen) return;
        const onKeyDown = (e) => e.key === "Escape" && setMenuOpen(false);
        document.addEventListener("keydown", onKeyDown);
        return () => document.removeEventListener("keydown", onKeyDown);
    }, [menuOpen]);

    // Logout Function - now uses context
    const handleLogout = async () => {
        await logout();
        window.location.href = "/admin/login";
    };

    // Get admin info from context
    const adminName = admin?.name || "Admin";
    const adminEmail = admin?.email || "N/A";
    const adminRole = admin?.role?.displayName || admin?.role?.name || "Administrator";

    return (
        // One header, one border, no shadow. This element used to be wrapped in
        // a second <header> in App.jsx that carried its own shadow, stacking two
        // elevations on the same edge.
        <header className="shrink-0 z-40 bg-surface border-b border-line h-14 px-3 sm:px-4 flex items-center justify-between">
            <div className="flex items-center gap-2.5 min-w-0">
                {/*
                  The collapse control lives here, not in the sidebar.
                  In the sidebar it occupied a 48px row of its own above the
                  first nav item — a whole row of chrome to hold one 18px
                  icon. Here it sits with the other global controls, and the
                  navigation starts at the top of its own panel.
                */}
                <button
                    type="button"
                    onClick={toggleSidebar}
                    className="p-1.5 -ml-1 text-ink-muted hover:bg-surface-hover hover:text-ink rounded-control transition-colors"
                    aria-label={isSidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
                    aria-expanded={isSidebarOpen}
                >
                    {isSidebarOpen ? (
                        <PanelLeftClose className="h-4.5 w-4.5" />
                    ) : (
                        <PanelLeft className="h-4.5 w-4.5" />
                    )}
                </button>
                <img
                    src={logoSrc}
                    alt="DealDirect"
                    className="h-7 w-auto object-contain"
                />
            </div>

            <div ref={dropdownRef} className="relative">
                <button
                    type="button"
                    onClick={() => setMenuOpen(!menuOpen)}
                    className="flex items-center gap-2 py-1 pl-1 pr-2 rounded-control hover:bg-surface-hover transition-colors"
                    aria-expanded={menuOpen}
                    aria-haspopup="menu"
                    aria-controls="profile-menu"
                >
                    <img
                        src={ddAdminPfp}
                        alt=""
                        className="h-7 w-7 rounded-full object-cover shrink-0"
                    />
                    <span className="hidden md:block type-body font-medium text-ink truncate max-w-[140px]">
                        {adminName}
                    </span>
                    <ChevronDown className="h-4 w-4 text-ink-faint shrink-0" />
                </button>

                {menuOpen && (
                    <div
                        id="profile-menu"
                        role="menu"
                        className="absolute right-0 top-full mt-1.5 w-60 bg-surface border border-line rounded-card shadow-popover z-50 origin-top-right animate-fadeIn overflow-hidden"
                    >
                        <div className="px-3 py-2.5 border-b border-line">
                            <p className="type-body font-medium text-ink truncate">{adminName}</p>
                            <p className="type-label text-ink-muted truncate">{adminEmail}</p>
                            {/*
                              One neutral badge. The old version tinted this
                              purple / blue / green by substring-matching the
                              role name, which implied a hierarchy the product
                              does not have — there is a single admin role.
                            */}
                            <span className="mt-1.5 inline-flex items-center rounded-control border border-neutral-line bg-neutral-soft px-1.5 py-0.5 type-micro text-ink-muted">
                                {adminRole}
                            </span>
                        </div>

                        <div className="p-1">
                            <Link
                                to="/admin/change-password"
                                role="menuitem"
                                onClick={() => setMenuOpen(false)}
                                className="flex items-center gap-2.5 px-2.5 py-2 rounded-control type-body text-ink-body hover:bg-surface-hover transition-colors"
                            >
                                <LockKeyhole className="h-4 w-4 text-ink-faint" />
                                Change password
                            </Link>

                            <button
                                type="button"
                                role="menuitem"
                                onClick={handleLogout}
                                className="w-full flex items-center gap-2.5 px-2.5 py-2 rounded-control type-body text-danger hover:bg-danger-soft transition-colors"
                            >
                                <LogOut className="h-4 w-4" />
                                Log out
                            </button>
                        </div>
                    </div>
                )}
            </div>
        </header>
    );
};

export default Header;
