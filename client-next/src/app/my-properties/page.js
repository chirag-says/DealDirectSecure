import { Suspense } from 'react';
import MyPropertiesContent from './MyPropertiesContent';

export const metadata = {
    title: 'My Properties',
    description: 'Manage your listed properties, view leads, and track performance on DealDirect.',
    robots: { index: false, follow: false },
};

export default function MyPropertiesPage() {
    return (
        <Suspense fallback={<div className="min-h-screen bg-gray-50 pt-24 flex items-center justify-center text-gray-600">Loading your dashboard...</div>}>
            <MyPropertiesContent />
        </Suspense>
    );
}
