import React, { useMemo } from "react";
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

const Sidebar = ({ isOpen, toggleSidebar }) => {
  const adminInfo = useMemo(() => {
    try {
      const stored = localStorage.getItem("adminInfo");
      return stored ? JSON.parse(stored) : null;
    } catch (error) {
      console.error("Failed to parse adminInfo", error);
      return null;
    }
  }, []);

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
      path: "/add-property",
      name: "Add Property",
      icon: <Home className="h-5 w-5" />,
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

  const handleLogout = () => {
    localStorage.removeItem("adminToken");
    localStorage.removeItem("adminInfo");
    localStorage.removeItem("adminName");
    localStorage.removeItem("adminRole");
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
