import { Suspense } from 'react';
import MyBookingsContent from './MyBookingsContent';

export const metadata = {
  title: 'My Enquiries | DealDirect',
  description: 'See the enquiries you have sent about builder project units and where each one stands.',
};

export default function MyBookingsPage() {
  return (
    <Suspense fallback={null}>
      <MyBookingsContent />
    </Suspense>
  );
}
