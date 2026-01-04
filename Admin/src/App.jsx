import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";

import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import AddProperty from "./pages/AddProperty";
import AddCategory from "./pages/AddCategory";
import AddSubCategory from "./pages/AddSubCategory";
import AllClients from "./pages/AllClients";
import AllProperty from "./pages/AllProperty";
import AllCategory from "./pages/AllCategory";
import AdminLogin from "./pages/AdminLogin";
import LeadMonitoring from "./pages/LeadMonitoring";
import BuilderVerification from "./pages/BuilderVerification";
import BuilderProjects from "./pages/BuilderProjects";
import ContactInquiries from "./pages/ContactInquiries";
import ReportedMessages from "./pages/ReportedMessages";
import PropertyReports from "./pages/PropertyReports";

const getStoredAdminInfo = () => {
  try {
    const stored = localStorage.getItem("adminInfo");
    return stored ? JSON.parse(stored) : null;
  } catch (error) {
    console.error("Failed to parse adminInfo", error);
    return null;
  }
};

/**
 * Protected Route Component
 * All authenticated admins have full access - no role-based restrictions on frontend
 * (Authorization is handled by backend permissions)
 */
const ProtectedRoute = ({ children }) => {
  const token = localStorage.getItem("adminToken");
  if (!token) return <Navigate to="/admin/login" replace />;
  return children;
};

const Layout = ({ isSidebarOpen, toggleSidebar, children }) => {
  const location = useLocation();

  // Hide header + sidebar on login page
  const isLoginPage = location.pathname === "/admin/login";

  // Determine sidebar width classes based on isSidebarOpen
  const sidebarClasses = isSidebarOpen
    ? "w-64 translate-x-0" // Open: full width, no translate
    : "w-64 -translate-x-full lg:w-20 lg:translate-x-0"; // Closed: hidden on mobile, mini on desktop

  return (
    <div className="h-screen flex flex-col font-sans text-gray-800 bg-gray-50 relative overflow-hidden">
      {/* Header */}
      {!isLoginPage && (
        <header className="w-full shadow bg-white z-40 relative">
          <Header toggleSidebar={toggleSidebar} />
        </header>
      )}

      {/* Main content area */}
      <div className="flex flex-1 h-full overflow-hidden relative">
        {/* Sidebar */}
        {!isLoginPage && (
          <>
            {/* Mobile Overlay */}
            <div
              className={`fixed inset-0 bg-black/50 z-40 lg:hidden transition-opacity duration-300 ${isSidebarOpen ? "opacity-100 visible" : "opacity-0 invisible"
                }`}
              onClick={toggleSidebar}
            />

            {/* Sidebar Component */}
            <aside
              className={`bg-white shadow-md transition-all duration-300 ease-in-out z-50
                fixed lg:static inset-y-0 left-0 h-full ${sidebarClasses} 
              `}
            >
              <Sidebar isOpen={isSidebarOpen} toggleSidebar={toggleSidebar} />
            </aside>
          </>
        )}

        {/* Main Content Area/Pages */}
        <main
          className="flex-1 transition-all duration-300 ease-in-out overflow-y-auto overflow-x-hidden p-4 sm:p-6 w-full"
        >
          {children}
          {/* Footer */}
          {!isLoginPage && (
            <footer className="w-full bg-white p-4 shadow-md mt-6 border-t border-gray-200">
              <div className="flex flex-col md:flex-row items-center justify-center text-sm text-gray-500">
                {/* Copyright Section */}
                <p className="mb-2 md:mb-0">
                  &copy; {new Date().getFullYear()}{" "}
                  <strong className="text-blue-600">Admin Panel</strong>. All
                  rights reserved.
                </p>
              </div>
            </footer>
          )}
        </main>
      </div>
    </div>
  );
};

// Function to determine initial state based on screen size
const getInitialSidebarState = () => {
  if (typeof window !== 'undefined' && window.innerWidth >= 1024) {
    return true; // Desktop: Start Open
  }
  return false; // Mobile/Tablet: Start Closed
};


function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(getInitialSidebarState);

  const toggleSidebar = () => setIsSidebarOpen((prev) => !prev);

  // Update state on resize for dynamic behavior
  useEffect(() => {
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setIsSidebarOpen(true);
      } else {
        setIsSidebarOpen(false);
      }
    };

    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return (
    <Router>
      <Layout isSidebarOpen={isSidebarOpen} toggleSidebar={toggleSidebar}>
        <Routes>
          {/* Public Route */}
          <Route path="/admin/login" element={<AdminLogin />} />

          {/* Protected Routes - All admins have access (backend handles permissions) */}
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />
          <Route
            path="/add-property"
            element={
              <ProtectedRoute>
                <AddProperty />
              </ProtectedRoute>
            }
          />
          <Route
            path="/lead-monitoring"
            element={
              <ProtectedRoute>
                <LeadMonitoring />
              </ProtectedRoute>
            }
          />
          <Route
            path="/add-category"
            element={
              <ProtectedRoute>
                <AddCategory />
              </ProtectedRoute>
            }
          />
          <Route
            path="/add-subcategory"
            element={
              <ProtectedRoute>
                <AddSubCategory />
              </ProtectedRoute>
            }
          />
          <Route
            path="/all-owners"
            element={
              <ProtectedRoute>
                <BuilderVerification />
              </ProtectedRoute>
            }
          />
          <Route
            path="/owners-projects"
            element={
              <ProtectedRoute>
                <BuilderProjects />
              </ProtectedRoute>
            }
          />
          <Route
            path="/all-clients"
            element={
              <ProtectedRoute>
                <AllClients />
              </ProtectedRoute>
            }
          />
          <Route
            path="/all-properties"
            element={
              <ProtectedRoute>
                <AllProperty />
              </ProtectedRoute>
            }
          />
          <Route
            path="/all-category"
            element={
              <ProtectedRoute>
                <AllCategory />
              </ProtectedRoute>
            }
          />
          <Route
            path="/contact-inquiries"
            element={
              <ProtectedRoute>
                <ContactInquiries />
              </ProtectedRoute>
            }
          />
          <Route
            path="/reported-messages"
            element={
              <ProtectedRoute>
                <ReportedMessages />
              </ProtectedRoute>
            }
          />
          <Route
            path="/property-reports"
            element={
              <ProtectedRoute>
                <PropertyReports />
              </ProtectedRoute>
            }
          />


          {/* Redirect all other routes */}
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default App;