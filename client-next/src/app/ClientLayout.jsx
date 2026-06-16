'use client';

/**
 * ClientLayout - Provider wrapper for client-side global state
 * 
 * This component wraps the entire application with:
 * - AuthProvider (authentication state)
 * - ScrollToTop (scroll reset on route change, wrapped in Suspense for useSearchParams)
 * - Navbar (fixed navigation)
 * - Footer (site footer)
 * - ToastContainer (notifications)
 */

import { Suspense } from 'react';
import { AuthProvider } from '../context/AuthContext';
import ScrollToTop from '../components/ScrollToTop/ScrollToTop';
import Navbar from '../components/Navbar/Navbar';
import Footer from '../components/Footer/Footer';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

export default function ClientLayout({ children }) {
    return (
        <AuthProvider>
            <Suspense fallback={null}>
                <ScrollToTop />
            </Suspense>
            <div className="w-full min-h-screen overflow-x-hidden bg-white pt-16 lg:pt-20">
                <Suspense fallback={null}>
                    <Navbar />
                </Suspense>
                <main>{children}</main>
                <Footer />
            </div>
            <ToastContainer
                position="bottom-right"
                autoClose={4000}
                hideProgressBar={false}
                newestOnTop
                closeOnClick
                rtl={false}
                pauseOnFocusLoss
                draggable
                pauseOnHover
                theme="light"
            />
        </AuthProvider>
    );
}
