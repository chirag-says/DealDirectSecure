import { useState } from 'react';
import { View } from 'react-native';

import { useThemePreference, type ThemePreference } from '@/theme';
import {
  Avatar,
  Badge,
  Button,
  Card,
  Chip,
  EmptyState,
  ErrorState,
  Input,
  PriceLabel,
  RangeSlider,
  Refreshable,
  Screen,
  Select,
  Sheet,
  Skeleton,
  SkeletonList,
  Tag,
  Text,
  formatPrice,
} from '@/ui';

/**
 * Primitive gallery.
 *
 * Reachable at /gallery in development. Every primitive is rendered in its real
 * states, which is how a design system stays honest: a component that only ever
 * appears inside a feature gets its edge cases discovered by users.
 *
 * It doubles as the light/dark check, since the scheme toggle at the top
 * re-renders everything on screen at once.
 *
 * ---------------------------------------------------------------------------
 * PRODUCTION GUARD
 *
 * This comment used to claim the route was "excluded from production builds
 * along with the rest of src/dev". It was not: Expo Router builds its route
 * tree from the filesystem and nothing filtered this file, so a release build
 * shipped an internal component gallery, deep-linkable at
 * `dealdirect://gallery`.
 *
 * The claim is now enforced rather than asserted — `__DEV__` is false in
 * release builds, and the route renders nothing there. Metro still bundles
 * the module (excluding it properly needs a resolver rule), so this is a
 * reachability guard, not a size optimisation.
 */

const THEME_OPTIONS: readonly { label: string; value: ThemePreference }[] = [
  { label: 'Follow system', value: 'system' },
  { label: 'Light', value: 'light' },
  { label: 'Dark', value: 'dark' },
];

const SORT_OPTIONS = [
  { label: 'Newest first', value: 'newest' },
  { label: 'Price: low to high', value: 'priceAsc' },
  { label: 'Price: high to low', value: 'priceDesc' },
] as const;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <View className="mb-2xl">
      <Text variant="overline" tone="muted" className="mb-md">
        {title}
      </Text>
      <View className="gap-md">{children}</View>
    </View>
  );
}

export default function GalleryScreen() {
  // Hooks still run above this: a conditional return before them would break
  // the rules of hooks. The guard sits after state is declared and before
  // anything is painted.
  const { preference, setPreference } = useThemePreference();
  const [sheetOpen, setSheetOpen] = useState(false);
  const [sort, setSort] = useState<string>('newest');
  const [chips, setChips] = useState<string[]>(['2 BHK']);
  const [priceRange, setPriceRange] = useState<[number, number]>([500_000, 25_000_000]);

  const toggleChip = (label: string) =>
    setChips((current) =>
      current.includes(label) ? current.filter((c) => c !== label) : [...current, label]
    );

  if (!__DEV__) return null;

  return (
    <Screen>
      <Refreshable contentContainerStyle={{ padding: 16 }}>
        <Text variant="display" className="mb-lg">
          Primitives
        </Text>

        <Section title="Theme">
          <View className="flex-row flex-wrap gap-sm">
            {THEME_OPTIONS.map((option) => (
              <Chip
                key={option.value}
                label={option.label}
                selected={preference === option.value}
                onPress={() => setPreference(option.value)}
              />
            ))}
          </View>
        </Section>

        <Section title="Typography">
          <Text variant="display">Display 34</Text>
          <Text variant="title1">Title 1 · 28</Text>
          <Text variant="title2">Title 2 · 22</Text>
          <Text variant="title3">Title 3 · 18</Text>
          <Text variant="body">Body 16. Tracking sits at neutral for reading sizes.</Text>
          <Text variant="callout" tone="secondary">Callout 15, secondary tone.</Text>
          <Text variant="footnote" tone="muted">Footnote 13, positive tracking.</Text>
          <Text variant="overline" tone="muted">OVERLINE 11</Text>
        </Section>

        <Section title="Buttons">
          <Button label="Primary" fullWidth />
          <Button label="Secondary" variant="secondary" fullWidth />
          <Button label="Ghost" variant="ghost" fullWidth />
          <Button label="Danger" variant="danger" fullWidth />
          <Button label="Loading" loading fullWidth />
          <Button label="Disabled" disabled fullWidth />
          <View className="flex-row gap-sm">
            <Button label="Small" size="sm" />
            <Button label="Large" size="lg" />
          </View>
        </Section>

        <Section title="Inputs">
          <Input label="Email" placeholder="you@example.com" keyboardType="email-address" />
          <Input label="Password" placeholder="••••••••" secureTextEntry />
          <Input label="Phone" placeholder="10-digit number" error="Enter a valid 10-digit number" />
          <Input label="Locality" placeholder="Andheri West" hint="Used to rank nearby listings" />
          <Select
            label="Sort"
            value={sort}
            options={SORT_OPTIONS}
            onChange={(value) => setSort(value)}
          />
        </Section>

        <Section title="Range slider">
          <RangeSlider
            label="Price"
            min={100_000}
            max={50_000_000}
            step={100_000}
            value={priceRange}
            onChange={setPriceRange}
            format={formatPrice}
          />
        </Section>

        <Section title="Chips">
          <View className="flex-row flex-wrap gap-sm">
            {['1 BHK', '2 BHK', '3 BHK', 'Furnished'].map((label) => (
              <Chip
                key={label}
                label={label}
                selected={chips.includes(label)}
                onPress={() => toggleChip(label)}
              />
            ))}
          </View>
        </Section>

        {/* The chips above are controls; these are labels. Same family, no role. */}
        <Section title="Tags">
          <View className="flex-row flex-wrap gap-sm">
            <Tag label="Lift" />
            <Tag label="Power backup" />
            <Tag label="Metro station" icon="location-outline" />
          </View>
        </Section>

        <Section title="Badges">
          <View className="flex-row flex-wrap gap-sm">
            <Badge label="Active" tone="success" />
            <Badge label="Pending" tone="warning" />
            <Badge label="Rejected" tone="danger" />
            <Badge label="Draft" tone="neutral" />
            <Badge label="Verified" tone="accent" />
          </View>
        </Section>

        <Section title="Price">
          <PriceLabel price={4_500_000} />
          <PriceLabel price={70_000_000} />
          <PriceLabel price={18_000} suffix="/month" />
          <Text variant="caption" tone="muted">
            Always rupees. `priceUnit` is the schema default on most listings and
            is never applied as a multiplier.
          </Text>
        </Section>

        <Section title="Card and avatar">
          <Card>
            <View className="flex-row items-center gap-md">
              <Avatar name="Chirag Sharma" />
              <View className="flex-1">
                <Text variant="bodyEmphasis">Chirag Sharma</Text>
                <Text variant="footnote" tone="muted">Owner · 3 listings</Text>
              </View>
              <Badge label="Owner" tone="accent" />
            </View>
          </Card>
          <Card raised={false}>
            <Text variant="body">Flat card, for grouped rows.</Text>
          </Card>
        </Section>

        <Section title="Loading">
          <Skeleton height={20} width="60%" />
          <SkeletonList count={3} />
        </Section>

        <Section title="Sheet">
          <Button label="Open sheet" variant="secondary" onPress={() => setSheetOpen(true)} />
          <Text variant="caption" tone="muted">
            Drag it. Release mid-flight and grab it again to check interruption.
          </Text>
        </Section>

        <Section title="Empty and error">
          <Card raised={false} className="h-2xl">
            <EmptyState
              title="No saved listings"
              description="Listings you save appear here."
              actionLabel="Browse properties"
              onAction={() => undefined}
            />
          </Card>
          <Card raised={false} className="h-2xl">
            <ErrorState
              description="We could not load your listings."
              requestId="1738291-8f2a1c"
              onRetry={() => undefined}
            />
          </Card>
        </Section>
      </Refreshable>

      <Sheet visible={sheetOpen} onClose={() => setSheetOpen(false)} title="Filters">
        <Text variant="body">
          Tracks the finger 1:1, rubber-bands upward, and uses the release velocity to decide
          between settling and dismissing.
        </Text>
        <Button
          label="Done"
          fullWidth
          className="mt-lg"
          onPress={() => setSheetOpen(false)}
        />
      </Sheet>
    </Screen>
  );
}
