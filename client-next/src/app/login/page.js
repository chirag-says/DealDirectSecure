import { Suspense } from 'react';
import LoginContent from './LoginContent';

export const metadata = {
    title: 'Login',
    description: 'Log in to your DealDirect account to manage properties, view listings, and contact owners directly.',
};

export default function LoginPage() {
    return (
        <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Loading login...</div>}>
            <LoginContent />
        </Suspense>
    );
}
