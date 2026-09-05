import ShortlistContent from './ShortlistContent';

export const metadata = {
    // Private by definition — there is nothing here for a crawler, and
    // robots.js disallows the path as well.
    title: 'Your shortlist',
    description: 'Homes you have saved on DealDirect. Private to you.',
    robots: { index: false, follow: false },
};

export default function ShortlistPage() {
    return <ShortlistContent />;
}
