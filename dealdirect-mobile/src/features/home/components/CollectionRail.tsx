import { PropertyRail } from '@/features/properties';
import type { PropertySearchParams } from '@/types/backend/property';
import type { Collection } from '../collections';
import { useCollection } from '../useCollection';
import { Section } from './Section';

/**
 * One curated row: heading, rail, and the decision to exist at all.
 *
 * This is the whole of Home's editorial half. Every collection in the registry
 * renders through this one component, which is what makes fifteen curated rows
 * a table edit rather than fifteen things to keep working.
 *
 * ---------------------------------------------------------------------------
 * IT RETURNS NULL, AND THAT IS THE FEATURE
 *
 * A collection that does not clear its `minResults` renders nothing: no
 * heading, no empty state, no "0 properties", no skeleton left behind. The user
 * never learns the row was considered.
 *
 * That is what lets the registry hold aspirational collections. "Sea View" and
 * "Homes with a Private Pool" match nothing today and are therefore invisible
 * today; the hour someone lists a sea-facing flat the row appears by itself
 * with no deploy. Without this rule those entries would be six broken headings
 * and the whole screen would read as unfinished.
 *
 * It is also the honest handling of failure. A rail whose request failed has
 * nothing to show, and a red error box inside a discovery row asks the user to
 * care about a problem they did not cause and cannot fix. The row simply is not
 * there, and the sections around it close the gap.
 */

export interface CollectionRailProps {
  collection: Collection;
  /** Opens the browse screen with this collection's filters applied. */
  onViewAll: (params: PropertySearchParams) => void;
  onSelectProperty: (id: string) => void;
}

export function CollectionRail({
  collection,
  onViewAll,
  onSelectProperty,
}: CollectionRailProps) {
  const { items, visible, isLoading } = useCollection(collection);

  /*
   * The loading pass still renders the heading and skeletons. Withholding both
   * until data lands would make the row appear from nothing and push everything
   * below it down the screen mid-scroll, which moves whatever the user was
   * reaching for out from under their thumb.
   *
   * The gamble is that a row which turns out to be under `minResults` showed a
   * heading for a moment and then vanished. That is the right trade: it happens
   * once per collection per cache window, and the alternative is layout shift
   * on every one of them, every time.
   */
  if (!visible && !isLoading) return null;

  return (
    <Section
      title={collection.title}
      subtitle={collection.subtitle}
      actionLabel="View all"
      onAction={() => onViewAll(collection.params)}
    >
      <PropertyRail
        items={items}
        loading={isLoading}
        onSelect={onSelectProperty}
        accessibilityLabel={collection.title}
      />
    </Section>
  );
}
