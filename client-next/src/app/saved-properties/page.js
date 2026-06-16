import SavedPropertiesContent from './SavedPropertiesContent';

export const metadata = {
    title: 'Saved Properties',
    description: 'View and manage your saved properties on DealDirect.',
    robots: { index: false, follow: false },
};

export default function SavedPropertiesPage() {
    return <SavedPropertiesContent />;
}
