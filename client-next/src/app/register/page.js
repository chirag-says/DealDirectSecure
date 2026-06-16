import { Suspense } from 'react';
import RegisterContent from './RegisterContent';

export const metadata = {
    title: 'Sign Up',
    description: 'Create a free account on DealDirect to list your properties, save searches, and contact property owners directly.',
};

export default function RegisterPage() {
    return (
        <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Loading sign up...</div>}>
            <RegisterContent />
        </Suspense>
    );
}
