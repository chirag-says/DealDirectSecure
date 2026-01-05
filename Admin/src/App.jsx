import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";

import { AdminProvider } from "./context/AdminContext";
import Header from "./components/Header";
import Sidebar from "./components/Sidebar";
import AdminProtectedRoute from "./components/AdminProtectedRoute";
import Dashboard from "./pages/Dashboard";

import AddCategory from "./pages/AddCategory";
import AddSubCategory from "./pages/AddSubCategory";
import AllClients from "./pages/AllClients";
import AllProperty from "./pages/AllProperty";
import AllCategory from "./pages/AllCategory";
import AdminLogin from "./pages/AdminLogin";
import MfaSetup from "./pages/MfaSetup";
import ChangePassword from "./pages/ChangePassword";
import MfaVerify from "./pages/MfaVerify";
import LeadMonitoring from "./pages/LeadMonitoring";
import BuilderVerification from "./pages/BuilderVerification";
import BuilderProjects from "./pages/BuilderProjects";
import ContactInquiries from "./pages/ContactInquiries";
import ReportedMessages from "./pages/ReportedMessages";
import PropertyReports from "./pages/PropertyReports";

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


function AppContent() {
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
    <Layout isSidebarOpen={isSidebarOpen} toggleSidebar={toggleSidebar}>
      <Routes>
        {/* Public Route */}
        <Route path="/admin/login" element={<AdminLogin />} />
        {/* MFA Setup - Public route (protected by partial session on backend) */}
        <Route path="/admin/mfa-setup" element={<MfaSetup />} />
        {/* Change Password - Public route (backend enforces access) */}
        <Route path="/admin/change-password" element={<ChangePassword />} />
        {/* MFA Verify - Public route (protected by partial session on backend) */}
        <Route path="/admin/mfa-verify" element={<MfaVerify />} />

        {/* Protected Routes - Cookie-based auth verification */}
        <Route
          path="/dashboard"
          element={
            <AdminProtectedRoute>
              <Dashboard />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/lead-monitoring"
          element={
            <AdminProtectedRoute>
              <LeadMonitoring />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/add-category"
          element={
            <AdminProtectedRoute>
              <AddCategory />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/add-subcategory"
          element={
            <AdminProtectedRoute>
              <AddSubCategory />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/all-owners"
          element={
            <AdminProtectedRoute>
              <BuilderVerification />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/owners-projects"
          element={
            <AdminProtectedRoute>
              <BuilderProjects />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/all-clients"
          element={
            <AdminProtectedRoute>
              <AllClients />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/all-properties"
          element={
            <AdminProtectedRoute>
              <AllProperty />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/all-category"
          element={
            <AdminProtectedRoute>
              <AllCategory />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/contact-inquiries"
          element={
            <AdminProtectedRoute>
              <ContactInquiries />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/reported-messages"
          element={
            <AdminProtectedRoute>
              <ReportedMessages />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/property-reports"
          element={
            <AdminProtectedRoute>
              <PropertyReports />
            </AdminProtectedRoute>
          }
        />


        {/* Redirect all other routes */}
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  );
}

function App() {
  return (
    <Router>
      <AdminProvider>
        <AppContent />
      </AdminProvider>
    </Router>
  );
}

export default App;