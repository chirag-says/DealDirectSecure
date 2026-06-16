'use client';
import dynamic from 'next/dynamic';

const PropertyListContent = dynamic(() => import('./PropertyListContent'), {
    ssr: false,
    loading: () => <div className="min-h-screen flex items-center justify-center text-slate-500">Loading properties...</div>
});

export default function ClientPropertyList({ initialProperties, initialCategories }) {
    return <PropertyListContent initialProperties={initialProperties} initialCategories={initialCategories} />;
}
