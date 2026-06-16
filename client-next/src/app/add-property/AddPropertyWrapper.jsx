'use client';

import dynamic from 'next/dynamic';

// Dynamic import with ssr:false to avoid "window is not defined" from leaflet
const AddPropertyContent = dynamic(() => import('./AddPropertyContent'), {
    ssr: false,
    loading: () => (
        <div className="min-h-screen flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-600"></div>
        </div>
    ),
});

export default function AddPropertyWrapper() {
    return <AddPropertyContent />;
}
