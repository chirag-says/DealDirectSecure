/**
 * The buyer, in aggregate.
 *
 * `buyerContext` is four numbers the server computes across ALL of a buyer's
 * activity, never a history: how long they have been active, how many owners
 * they have enquired to, how many visits they have completed, and whether
 * this listing sits inside the budget they have been looking at. It is what
 * lets an owner tell a serious buyer from a curious one without being shown
 * anything about the other listings.
 *
 * Rendered as one muted line on the lead row and as four labelled numbers on
 * the deal page. Both read this file so the wording cannot drift.
 */

import type { BuyerContext } from '@/types/backend/deal';

export function budgetFitLabel(fit: BuyerContext['budgetFit']): string | null {
  switch (fit) {
    case 'within':
      return 'Budget fits';
    case 'above':
      return 'Above their budget';
    case 'below':
      return 'Below their budget';
    default:
      return null;
  }
}

/** "3 weeks on DealDirect · 4 enquiries · 2 visits · Budget fits" */
export function buyerContextLine(context: BuyerContext): string {
  const parts: string[] = [];

  if (context.activeWeeks !== null && context.activeWeeks >= 0) {
    parts.push(
      context.activeWeeks === 0
        ? 'New this week'
        : `${context.activeWeeks} ${context.activeWeeks === 1 ? 'week' : 'weeks'} on DealDirect`
    );
  }
  parts.push(`${context.enquiries} ${context.enquiries === 1 ? 'enquiry' : 'enquiries'}`);
  parts.push(`${context.visitsDone} ${context.visitsDone === 1 ? 'visit' : 'visits'}`);

  const fit = budgetFitLabel(context.budgetFit);
  if (fit) parts.push(fit);

  return parts.join(' · ');
}

/** The four facts with a one-line meaning each, for the deal page card. */
export function buyerContextFacts(context: BuyerContext): Array<{
  label: string;
  value: string;
  meaning: string;
}> {
  return [
    {
      label: 'Active',
      value:
        context.activeWeeks === null
          ? '—'
          : context.activeWeeks === 0
            ? '< 1 wk'
            : `${context.activeWeeks} wk`,
      meaning: 'Time since their first action on DealDirect',
    },
    {
      label: 'Enquiries',
      value: String(context.enquiries),
      meaning: 'Owners they have contacted, including you',
    },
    {
      label: 'Visits',
      value: String(context.visitsDone),
      meaning: 'Site visits both sides confirmed happened',
    },
    {
      label: 'Budget',
      value: budgetFitLabel(context.budgetFit) ?? 'Unknown',
      meaning: 'Your price against the range they have been enquiring in',
    },
  ];
}
