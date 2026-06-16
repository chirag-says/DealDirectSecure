import { Suspense } from 'react';
import MyBookingsContent from './MyBookingsContent';

export const metadata = {
  title: 'My Bookings | DealDirect',
  description: 'Track your project unit bookings and payment verification status.',
};

export default function MyBookingsPage() {
  return (
    <Suspense fallback={null}>
      <MyBookingsContent />
    </Suspense>
  );
}
