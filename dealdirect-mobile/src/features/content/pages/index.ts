import { WEB_URL } from '@/config/env';

import { aboutPage } from './about';
import { contactPage } from './contact';
import { faqPage } from './faq';
import type { ContentPage, IconName } from './model';
import { privacyPage } from './privacy';
import { rewardsTermsPage } from './rewardsTerms';
import { termsPage } from './terms';
import { whyUsPage } from './whyUs';

/**
 * The pages the app carries, in the order the Support screen lists them.
 *
 * `group` is the Support screen's list heading. `label` is the row text and
 * is short where the page title is long ("Rewards terms" for "Rewards: Terms &
 * Fair Play"). Contact is not in this list: it has a form, so it has its own
 * route (`app/legal/contact.tsx`) and its row sits under "Talk to us".
 */
export type ContentGroup = 'help' | 'about' | 'legal';

export interface ContentPageEntry {
  page: ContentPage;
  group: ContentGroup;
  icon: IconName;
  label: string;
}

export const CONTENT_PAGES: readonly ContentPageEntry[] = [
  { page: faqPage, group: 'help', icon: 'help-circle-outline', label: 'FAQ' },
  { page: aboutPage, group: 'about', icon: 'information-circle-outline', label: 'About DealDirect' },
  { page: whyUsPage, group: 'about', icon: 'sparkles-outline', label: 'Why DealDirect' },
  { page: privacyPage, group: 'legal', icon: 'shield-checkmark-outline', label: 'Privacy policy' },
  { page: termsPage, group: 'legal', icon: 'document-text-outline', label: 'Terms of use' },
  { page: rewardsTermsPage, group: 'legal', icon: 'gift-outline', label: 'Rewards terms' },
];

export const CONTENT_GROUP_TITLES: Record<ContentGroup, string> = {
  help: 'Help',
  about: 'About',
  legal: 'Legal',
};

/** The Support screen's groups, in display order, each with its rows. */
export function contentPagesByGroup(): { group: ContentGroup; title: string; entries: ContentPageEntry[] }[] {
  const order: ContentGroup[] = ['help', 'about', 'legal'];
  return order
    .map((group) => ({
      group,
      title: CONTENT_GROUP_TITLES[group],
      entries: CONTENT_PAGES.filter((entry) => entry.group === group),
    }))
    .filter((group) => group.entries.length > 0);
}

export function getContentPage(id: string | undefined): ContentPageEntry | undefined {
  if (!id) return undefined;
  return CONTENT_PAGES.find((entry) => entry.page.id === id);
}

/** The website page carrying the same text, for "Open on website". */
export function webUrlFor(page: ContentPage): string {
  return `${WEB_URL}${page.webPath}`;
}

export { contactPage };
