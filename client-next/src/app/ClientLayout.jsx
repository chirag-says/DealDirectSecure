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
 * - PhoneVerificationModal (the just-in-time phone gate)
 */

import { Suspense } from 'react';
import { AuthProvider } from '../context/AuthContext';
import ScrollToTop from '../components/ScrollToTop/ScrollToTop';
import Navbar from '../components/Navbar/Navbar';
import Footer from '../components/Footer/Footer';
import { ToastContainer } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import PhoneVerificationModal from '../components/Auth/PhoneVerificationModal';

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
            {/*
                The just-in-time phone gate. Mounted once, here, because the
                axios interceptor raises it rather than any page: a gated
                request opens it, waits, and then replays itself.

                Inside AuthProvider because it calls the phone endpoints through
                it, and outside the page container so it paints over whatever
                the visitor was doing. It must never be a route — navigating
                away would lose the listing they were standing on, which is the
                exact failure this design prevents. Renders nothing until the
                backend refuses a gated action.
            */}
            <PhoneVerificationModal />
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
