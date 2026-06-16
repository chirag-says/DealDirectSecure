import { Suspense } from 'react';
import ProfileContent from './ProfileContent';

export const metadata = {
    title: 'My Profile',
    description: 'Manage your DealDirect profile, update your information, and change your password.',
    robots: { index: false, follow: false },
};

export default function ProfilePage() {
    return (
        <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-600"></div></div>}>
            <ProfileContent />
        </Suspense>
    );
}
