import { PropertyRail, clearRecentlyViewed, useRecentlyViewed } from '@/features/properties';
import { Section } from './Section';

/**
 * "Recently viewed", the first row on Home.
 *
 * ---------------------------------------------------------------------------
 * WHY IT IS FIRST, AHEAD OF THE CURATED ROWS
 *
 * Every large portal puts this near the top of a returning user's home screen,
 * and the reason is not sentiment: on the second and every subsequent session,
 * the listing someone wants is far more often one they already looked at than
 * one an algorithm picked. Property search runs over weeks, and the thing a
 * buyer does when they reopen the app is go back to the two flats they are
 * deciding between.
 *
 * It is also the only row on Home that can be first without costing anything.
 * Everything else here is gated behind `Reveal` because `/properties/search`
 * allows 20 requests a minute across everyone behind a carrier NAT, and each
 * rail is one of them. This row makes NO request at all — it replays a snapshot
 * from disk, which is the whole point of how `recentlyViewed.ts` stores it, so
 * it paints instantly on a cold start and takes nothing from the budget the
 * rows below it are competing for.
 *
 * That module has been complete since M12 — snapshot storage, an external-store
 * subscription so it updates when a listing is opened on any screen, and a
 * deliberate refusal to refetch because `GET /properties/:id` increments the
 * view counter. Its own docstring refers to "the Recently Viewed row on Home".
 * Until now that row did not exist.
 *
 * ---------------------------------------------------------------------------
 * ONE ENTRY IS ENOUGH TO RENDER
 *
 * A rail holding a single card does not fill the width, and the instinct is to
 * hide it until there are three. That is backwards for this row specifically:
 * a user with exactly one viewed listing is a user in their first session who
 * looked at one thing, and putting that one thing back in front of them when
 * they return is the most useful the row will ever be.
 *
 * ---------------------------------------------------------------------------
 * CLEARING DOES NOT CONFIRM
 *
 * The app confirms destructive actions elsewhere — removing an interest emails
 * nobody but frees one of five capped slots, deleting a saved search stops an
 * alert. Both have consequences outside the tap. This has none: it is
 * device-local history, nothing on the server changes, and the way back is to
 * open a listing. A confirmation dialog here would be ceremony that teaches
 * users to dismiss the ones that matter.
 */
export interface RecentlyViewedProps {
  onSelectProperty: (id: string) => void;
}

export function RecentlyViewed({ onSelectProperty }: RecentlyViewedProps) {
  const items = useRecentlyViewed();

  if (items.length === 0) return null;

  return (
    <Section
      title="Recently viewed"
      subtitle="Pick up where you left off"
      actionLabel="Clear"
      onAction={clearRecentlyViewed}
    >
      <PropertyRail
        items={items}
        onSelect={onSelectProperty}
        accessibilityLabel="Recently viewed properties"
      />
    </Section>
  );
}
