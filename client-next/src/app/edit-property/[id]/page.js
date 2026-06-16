import EditPropertyWrapper from './EditPropertyWrapper';

export const metadata = {
    title: 'Edit Property',
    description: 'Edit your property listing on DealDirect.',
    robots: { index: false, follow: false },
};

export default function EditPropertyPage() {
    return <EditPropertyWrapper />;
}
