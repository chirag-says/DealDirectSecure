import AgreementsContent from './AgreementsContent';

export const metadata = {
    title: 'Agreement Generator',
    description: 'Generate professional property agreements with AI on DealDirect.',
    robots: { index: false, follow: false },
};

export default function AgreementsPage() {
    return <AgreementsContent />;
}
