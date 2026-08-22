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
import BookingManagement from "./pages/BookingManagement";

import AddCategory from "./pages/AddCategory";
import AllClients from "./pages/AllClients";
import AllProperty from "./pages/AllProperty";
import AllCategory from "./pages/AllCategory";
import AdminLogin from "./pages/AdminLogin";
import MfaSetup from "./pages/MfaSetup";
import ChangePassword from "./pages/ChangePassword";
import MfaVerify from "./pages/MfaVerify";
import LeadMonitoring from "./pages/LeadMonitoring";
import BuilderVerification from "./pages/BuilderVerification";
import ContactInquiries from "./pages/ContactInquiries";
import ReportedMessages from "./pages/ReportedMessages";
import PropertyReports from "./pages/PropertyReports";
import BlogManagement from "./pages/BlogManagement";
import AdminBlogEditor from "./pages/AdminBlogEditor";
import RewardsManagement from "./pages/RewardsManagement";
import DealVerifications from "./pages/DealVerifications";
import PopularProperties from "./pages/PopularProperties";
import GroupBuyManagement from "./pages/GroupBuyManagement";
import BuilderManagement from "./pages/BuilderManagement";
import BuilderDetail from "./pages/BuilderDetail";
import BuilderProjectsList from "./pages/BuilderProjectsList";
import AdminAddProperty from "./pages/AdminAddProperty";
import CreateProject from "./pages/CreateProject";
import ProjectDetail from "./pages/ProjectDetail";
import CreateUnitType from "./pages/CreateUnitType";
import CreateCampaign from "./pages/CreateCampaign";

/**
 * Routes that render without panel chrome.
 *
 * Login and the two MFA steps run before the admin holds a full session, so a
 * navigation sidebar there advertises pages they cannot open yet. Change
 * password is NOT in this set: it is reachable from the header menu by an
 * admin who is already signed in, and stripping their navigation would strand
 * them on it.
 */
const CHROMELESS_ROUTES = new Set([
  "/admin/login",
  "/admin/mfa-setup",
  "/admin/mfa-verify",
]);

const Layout = ({ isSidebarOpen, toggleSidebar, children }) => {
  const location = useLocation();
  const chromeless = CHROMELESS_ROUTES.has(location.pathname);

  // Open: full width. Closed: off-canvas on mobile, icon rail on desktop.
  const sidebarClasses = isSidebarOpen
    ? "w-60 translate-x-0"
    : "w-60 -translate-x-full lg:w-16 lg:translate-x-0";

  if (chromeless) {
    return (
      <div className="min-h-screen bg-canvas font-sans text-ink-body">
        {children}
      </div>
    );
  }

  return (
    <div className="h-screen flex flex-col font-sans text-ink-body bg-canvas overflow-hidden">
      {/*
        Header renders its own <header> element, so this is a plain wrapper.
        It used to be a second <header> with its own shadow, which stacked two
        elevations on one edge and nested a landmark inside a landmark.
      */}
      <Header toggleSidebar={toggleSidebar} isSidebarOpen={isSidebarOpen} />

      <div className="flex flex-1 min-h-0 relative">
        {/* Mobile scrim */}
        <div
          className={`fixed inset-0 bg-ink/40 z-40 lg:hidden transition-opacity duration-200 ${isSidebarOpen ? "opacity-100 visible" : "opacity-0 invisible"
            }`}
          onClick={toggleSidebar}
          aria-hidden="true"
        />

        <aside
          className={`bg-sidebar border-r border-line transition-[width,transform] duration-200 ease-out z-50
            fixed lg:static inset-y-0 left-0 h-full ${sidebarClasses}`}
        >
          <Sidebar isOpen={isSidebarOpen} toggleSidebar={toggleSidebar} />
        </aside>

        {/*
          The only scroll container and the only page padding in the app.
          Pages render their content directly — no page should open its own
          <main>, set its own background, or add its own outer padding.
        */}
        <main className="flex-1 min-w-0 overflow-y-auto overflow-x-hidden p-4 sm:p-6">
          {children}
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
          path="/all-owners"
          element={
            <AdminProtectedRoute>
              <BuilderVerification />
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
        <Route
          path="/blog-management"
          element={
            <AdminProtectedRoute>
              <BlogManagement />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/blog-editor"
          element={
            <AdminProtectedRoute>
              <AdminBlogEditor />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/blog-editor/:id"
          element={
            <AdminProtectedRoute>
              <AdminBlogEditor />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/rewards-management"
          element={
            <AdminProtectedRoute>
              <RewardsManagement />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/deal-verifications"
          element={
            <AdminProtectedRoute>
              <DealVerifications />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/popular-properties"
          element={
            <AdminProtectedRoute>
              <PopularProperties />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/group-buy"
          element={
            <AdminProtectedRoute>
              <GroupBuyManagement />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/builder-management"
          element={
            <AdminProtectedRoute>
              <BuilderManagement />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/builder/:builderId"
          element={
            <AdminProtectedRoute>
              <BuilderDetail />
            </AdminProtectedRoute>
          }
        />

        <Route
          path="/admin-add-property"
          element={
            <AdminProtectedRoute>
              <AdminAddProperty />
            </AdminProtectedRoute>
          }
        />

        {/* ── Builder Project Flow ───────────────────────────── */}
        <Route
          path="/create-project"
          element={
            <AdminProtectedRoute>
              <CreateProject />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/project/:id"
          element={
            <AdminProtectedRoute>
              <ProjectDetail />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/builder/:builderId/projects"
          element={
            <AdminProtectedRoute>
              <BuilderProjectsList />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/project/:projectId/add-unit-type"
          element={
            <AdminProtectedRoute>
              <CreateUnitType />
            </AdminProtectedRoute>
          }
        />
        <Route
          path="/project/:projectId/campaign/new"
          element={
            <AdminProtectedRoute>
              <CreateCampaign />
            </AdminProtectedRoute>
          }
        />


        <Route
          path="/bookings"
          element={
            <AdminProtectedRoute>
              <BookingManagement />
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