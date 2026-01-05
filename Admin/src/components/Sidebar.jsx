import React from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Home,
  Users,
  Briefcase,
  BarChart3,
  Settings,
  Menu,
  X,
  Mail,
  Flag
} from "lucide-react";
import { CiLogout } from "react-icons/ci";
import { useAdmin } from "../context/AdminContext";

const Sidebar = ({ isOpen, toggleSidebar }) => {
  const { admin, logout, roleName, roleLevel } = useAdmin();

  // All menu items available to all authenticated admins
  // Backend handles permission enforcement
  const menuItems = [
    {
      path: "/dashboard",
      name: "Dashboard",
      icon: <LayoutDashboard className="h-5 w-5" />,
    },
    {
      path: "/all-clients",
      name: "All Clients",
      icon: <BarChart3 className="h-5 w-5" />,
    },
    {
      path: "/all-owners",
      name: "All Owners",
      icon: <BarChart3 className="h-5 w-5" />,
    },
    {
      path: "/owners-projects",
      name: "Owner's Project",
      icon: <BarChart3 className="h-5 w-5" />,
    },
    {
      path: "/all-properties",
      name: "All Properties",
      icon: <BarChart3 className="h-5 w-5" />,
    },

    {
      path: "/lead-monitoring",
      name: "Lead Monitoring",
      icon: <BarChart3 className="h-5 w-5" />,
    },
    {
      path: "/contact-inquiries",
      name: "Contact Inquiries",
      icon: <Mail className="h-5 w-5" />,
    },
    {
      path: "/reported-messages",
      name: "Reported Messages",
      icon: <Flag className="h-5 w-5" />,
    },
    {
      path: "/property-reports",
      name: "Property Reports",
      icon: <Flag className="h-5 w-5" />,
    },
  ];

  /**
   * Logout handler - calls the context logout which:
   * 1. Calls /api/admin/logout to invalidate the session cookie
   * 2. Clears the admin state
   * 3. App will redirect to login automatically
   */
  const handleLogout = async () => {
    await logout();
    // Navigation is handled by AdminProtectedRoute based on auth state
    window.location.href = "/admin/login";
  };

  return (
    <>
      <div className="flex border-r border-gray-100 flex-col h-full">
        {/* Top section with Toggle/Close */}
        <div className={`flex items-center ${isOpen ? 'justify-end' : 'justify-center'} p-4`}>
          <button
            className="text-gray-600 hover:text-gray-600"
            onClick={toggleSidebar}
          >
            {isOpen ? <X size={25} /> : <Menu size={25} className="mr-5" />}
          </button>
        </div>

        {/* Admin Info (when sidebar is open) */}
        {isOpen && admin && (
          <div className="px-4 pb-4 border-b border-gray-100">
            <div className="text-sm font-medium text-gray-800 truncate">
              {admin.name}
            </div>
            <div className="text-xs text-gray-500 truncate">
              {admin.email}
            </div>
            {roleName && (
              <span className="inline-block mt-1 px-2 py-0.5 text-xs bg-blue-100 text-blue-700 rounded-full">
                {admin.role?.displayName || roleName}
              </span>
            )}
          </div>
        )}

        {/* Menu items */}
        <nav className="flex-1 overflow-auto mt-2 px-2">
          <ul className="space-y-1">
            {menuItems.map((item, idx) => (
              <li key={idx}>
                <NavLink
                  to={item.path}
                  onClick={() => isOpen && toggleSidebar()}
                  className={({ isActive }) =>
                    `flex items-center gap-3 p-2 rounded-md transition-all duration-200 ${isActive
                      ? "bg-gray-100 text-gray-600 font-medium"
                      : "text-gray-700 hover:bg-gray-100"
                    }`
                  }
                >
                  {item.icon}
                  {isOpen && (
                    <span className="text-sm font-medium">{item.name}</span>
                  )}
                </NavLink>
              </li>
            ))}

            {/* Logout */}
            <li>
              <button
                className="w-full flex items-center gap-3 p-2 rounded-md text-gray-700 hover:bg-gray-100 transition-all duration-200"
                onClick={handleLogout}
              >
                <CiLogout className="h-5 w-5" />
                {isOpen && <span className="text-sm font-medium">Logout</span>}
              </button>
            </li>
          </ul>
        </nav>
      </div>
    </>
  );
};

export default Sidebar;
