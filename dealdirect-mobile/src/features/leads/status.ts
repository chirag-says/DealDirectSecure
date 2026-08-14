import type { BadgeTone } from '@/ui';
import type { LeadStatus } from '@/types/backend/lead';

export const LEAD_STATUSES: LeadStatus[] = [
  'new',
  'contacted',
  'interested',
  'negotiating',
  'converted',
  'lost',
];

export function statusLabel(status: LeadStatus): string {
  return status.charAt(0).toUpperCase() + status.slice(1);
}

export function statusTone(status: LeadStatus): BadgeTone {
  switch (status) {
    case 'new':
      return 'accent';
    case 'converted':
      return 'success';
    case 'lost':
      return 'danger';
    case 'negotiating':
      return 'warning';
    default:
      return 'neutral';
  }
}
