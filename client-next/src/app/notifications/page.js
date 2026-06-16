import NotificationsContent from './NotificationsContent';

export const metadata = {
    title: 'Notifications',
    description: 'View your notifications, saved search alerts, and property matches on DealDirect.',
    robots: { index: false, follow: false },
};

export default function NotificationsPage() {
    return <NotificationsContent />;
}
