import React from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import Navbar from "../src/Components/Navbar/Navbar.jsx";
import Home from "./Pages/Home/Home.jsx";
import Footer from "./Components/Footer/Footer.jsx";
import PropertyPage from "./Pages/PropertyList/PropertyList.jsx";
import PropertyDetails from "./Pages/Property Details/PropertyDetails.jsx";
import Login from "./Pages/Login/Login.jsx";
import Register from "./Pages/Register/Register.jsx";
import About from "./Pages/About/About.jsx";
import Contact from "./Pages/Contact/Contact.jsx";
import AgreementGenerator from "./Components/SampleAgreement/AgreementGenerator.jsx";
import AddProperty from "./Pages/AddProperty/AddProperty.jsx";
import EditProperty from "./Pages/EditProperty/EditProperty.jsx";
import Profile from "./Pages/Profile/Profile.jsx";
import MyProperties from "./Pages/MyProperties/MyProperties.jsx";
import SavedProperties from "./Pages/SavedProperties/SavedProperties.jsx";
import Notifications from "./Pages/Notifications/Notifications.jsx";
import PrivacyPolicy from "./Pages/Privacy/Privacy.jsx";
import TermsAndConditions from "./Pages/Terms&Conditions/Terms&Conditions.jsx";
import WhyUs from "./Pages/WhyUs/WhyUs.jsx";
import Pricing from "./Pages/Pricing/Pricing.jsx";
import ScrollToTop from "./Components/ScrollToTop/ScrollToTop.jsx";
import { ChatProvider } from "./context/ChatContext.jsx";
import { AuthProvider, ProtectedRoute } from "./context/AuthContext.jsx";
import ChatWidget from "./Components/Chat/ChatWidget.jsx";
import ChatButton from "./Components/Chat/ChatButton.jsx";

function App() {
  return (
    <div className="w-full min-h-screen overflow-x-hidden bg-white pt-16 lg:pt-20">
      <Router>
        <AuthProvider>
          <ChatProvider>
            <ScrollToTop />
            <Navbar />
            <Routes>
              {/* Public Routes */}
              <Route path="/" element={<Home />} />
              <Route path="/contact" element={<Contact />} />
              <Route path="/properties" element={<PropertyPage />} />
              <Route path="/properties/:id" element={<PropertyDetails />} />
              <Route path="/login" element={<Login />} />
              <Route path="/about" element={<About />} />
              <Route path="/register" element={<Register />} />
              <Route path="/privacy" element={<PrivacyPolicy />} />
              <Route path="/terms" element={<TermsAndConditions />} />
              <Route path="/why-us" element={<WhyUs />} />
              <Route path="/pricing" element={<Pricing />} />

              {/* Protected Routes - Any authenticated user */}
              <Route path="/profile" element={
                <ProtectedRoute>
                  <Profile />
                </ProtectedRoute>
              } />
              <Route path="/saved-properties" element={
                <ProtectedRoute>
                  <SavedProperties />
                </ProtectedRoute>
              } />
              <Route path="/notifications" element={
                <ProtectedRoute>
                  <Notifications />
                </ProtectedRoute>
              } />
              <Route path="/agreements" element={
                <ProtectedRoute>
                  <AgreementGenerator />
                </ProtectedRoute>
              } />

              {/* Add Property - Allows any authenticated user, role check happens in AddProperty page */}
              <Route path="/add-property" element={
                <ProtectedRoute>
                  <AddProperty />
                </ProtectedRoute>
              } />

              {/* Owner-only Routes */}
              <Route path="/edit-property/:id" element={
                <ProtectedRoute requiredRole="owner">
                  <EditProperty />
                </ProtectedRoute>
              } />
              <Route path="/my-properties" element={
                <ProtectedRoute requiredRole="owner">
                  <MyProperties />
                </ProtectedRoute>
              } />
            </Routes>
            <Footer />
            <ChatButton />
            <ChatWidget />
          </ChatProvider>
        </AuthProvider>
      </Router>
    </div>
  );
}

export default App;
