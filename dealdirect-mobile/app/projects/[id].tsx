import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { FlatList, useWindowDimensions, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { useProjectDetail, useUnitTypesForProject } from '@/features/projects';
import { gesture, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import type { UnitType } from '@/types/backend/project';
import {
  Avatar,
  Badge,
  Card,
  ErrorState,
  Image,
  PressableScale,
  PriceLabel,
  Refreshable,
  Screen,
  Skeleton,
  Tag,
  Text,
} from '@/ui';

/**
 * The gallery's height, derived from the width rather than fixed.
 *
 * Same reasoning as `DetailHero.heroHeight`: a fixed height over a variable
 * width is a fixed CROP over a variable one, so the same project showed more
 * sky on a larger phone. Clamped so a tablet-width device does not hand the
 * photo two thirds of the page.
 */
function galleryHeight(width: number): number {
  return Math.round(Math.min(Math.max(width * 0.72, 240), 360));
}

export default function ProjectDetailScreen() {
  const router = useRouter();
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const { width } = useWindowDimensions();
  const { id } = useLocalSearchParams<{ id: string }>();
  const { project, isLoading, error, refresh } = useProjectDetail(id);
  const { unitTypes, isLoading: unitTypesLoading } = useUnitTypesForProject(id);

  /**
   * Pull-to-refresh used to pass `refreshing={false}` unconditionally, so the
   * gesture fired the request and showed nothing — the one thing a refresh
   * control exists to communicate. `useProjectDetail` exposes no in-flight
   * flag, so this screen owns one for the duration of the refetch.
   */
  const [refreshing, setRefreshing] = useState(false);
  const handleRefresh = useCallback(async () => {
    setRefreshing(true);
    try {
      await refresh();
    } finally {
      setRefreshing(false);
    }
  }, [refresh]);

  const height = galleryHeight(width);

  if (isLoading) {
    return (
      <Screen edges={['bottom']}>
        <Skeleton height={galleryHeight(width)} radius={0} />
        <View className="p-base">
          <Skeleton height={28} className="mb-base" />
          <Skeleton height={120} radius={12} />
        </View>
      </Screen>
    );
  }

  if (error || !project) {
    return (
      <Screen>
        <ErrorState title="Could not load this project" onRetry={refresh} />
      </Screen>
    );
  }

  const images = [
    ...(project.media?.exteriorImages ?? []),
    ...(project.media?.droneImages ?? []),
  ];
  const builder = typeof project.builder === 'object' ? project.builder : undefined;
  const amenities = (project.amenities ?? []).filter((a): a is string => typeof a === 'string');
  const priceMin = project.priceRange?.min;
  const priceMax = project.priceRange?.max;

  return (
    <Screen unsafe>
      <Refreshable
        refreshing={refreshing}
        onRefresh={handleRefresh}
        contentContainerStyle={{ paddingBottom: scrollBottomPadding }}
      >
        <View style={{ height }}>
          {images.length > 0 ? (
            /*
              A windowed `FlatList`, not a mapped `ScrollView`.

              The ScrollView this replaces mounted every image at once, so a
              project with a full set of exterior and drone shots decoded all
              of them before first paint. Three at a time, recycled, is the
              same choice `DetailHero` documents at length and for the same
              reason. `size="medium"` rather than `full` for the same budget:
              this is a 300pt-tall carousel, not a full-screen viewer.
            */
            <FlatList
              data={images}
              horizontal
              pagingEnabled
              showsHorizontalScrollIndicator={false}
              keyExtractor={(uri, index) => `${uri}-${index}`}
              initialNumToRender={1}
              windowSize={3}
              removeClippedSubviews
              getItemLayout={(_, i) => ({ length: width, offset: width * i, index: i })}
              renderItem={({ item }) => (
                <Image uri={item} size="medium" style={{ width, height }} />
              )}
            />
          ) : (
            <View className="h-full w-full items-center justify-center bg-surface-muted">
              <Ionicons name="business-outline" size={40} color={theme.colors.textMuted} />
            </View>
          )}

          {/*
            A floating disc rather than a nav bar, because it sits over the
            gallery. `insets.top` rather than the 48 this used to hard-code:
            that number was right on exactly one device and put the control
            under the status bar on any phone with a taller notch.
          */}
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Go back"
            onPress={() => (router.canGoBack() ? router.back() : router.replace('/(tabs)'))}
            hitSlop={gesture.hitSlop}
            className="absolute left-base h-10 w-10 items-center justify-center rounded-full bg-black/45"
            style={{ top: insets.top + spacing.sm }}
          >
            <Ionicons name="chevron-back" size={22} color="#fff" />
          </PressableScale>
        </View>

        <View style={{ padding: screenPadding }}>
          {project.basics?.status ? <Badge label={project.basics.status} tone="accent" className="mb-sm" /> : null}
          <Text variant="title1">{project.basics?.name ?? 'Project'}</Text>

          {project.location?.locality || project.location?.city ? (
            <View className="mt-xs flex-row items-center">
              <Ionicons name="location-outline" size={16} color={theme.colors.brand} />
              <Text variant="callout" tone="secondary" className="ml-xs">
                {[project.location?.locality, project.location?.city].filter(Boolean).join(', ')}
              </Text>
            </View>
          ) : null}

          {priceMin ? (
            <View className="mt-base flex-row items-baseline">
              <PriceLabel price={priceMin} variant="title2" />
              {priceMax && priceMax > priceMin ? (
                <>
                  <Text variant="body" tone="secondary" className="mx-xs">
                    –
                  </Text>
                  <PriceLabel price={priceMax} variant="title2" />
                </>
              ) : null}
            </View>
          ) : null}

          {builder ? (
            <Card className="mt-lg flex-row items-center">
              <Avatar uri={builder.logoUrl ?? builder.logo} name={builder.company ?? builder.name} />
              <View className="ml-base flex-1">
                <Text variant="bodyEmphasis">{builder.company ?? builder.name}</Text>
                {builder.city ? (
                  <Text variant="footnote" tone="secondary">
                    {builder.city}
                  </Text>
                ) : null}
              </View>
            </Card>
          ) : null}

          {project.basics?.description ? (
            <View className="mt-lg">
              <Text variant="title3" className="mb-sm">
                About
              </Text>
              <Text variant="body" tone="secondary">
                {project.basics.description}
              </Text>
            </View>
          ) : null}

          {amenities.length > 0 ? (
            <View className="mt-lg">
              <Text variant="title3" className="mb-sm">
                Amenities
              </Text>
              {/*
                `Tag`, not `Badge` — and not `Chip`. Matching the property
                detail screen, where the same decision is documented: `Chip`
                renders a Pressable with `accessibilityRole="button"`, so a
                screen reader announces every amenity as a dead control.
              */}
              <View className="flex-row flex-wrap gap-sm">
                {amenities.map((amenity) => (
                  <Tag key={amenity} label={amenity} />
                ))}
              </View>
            </View>
          ) : null}

          <View className="mt-lg">
            <Text variant="title3" className="mb-sm">
              Unit types
            </Text>
            {unitTypesLoading ? (
              <Skeleton height={80} radius={12} />
            ) : unitTypes.length === 0 ? (
              <Text variant="callout" tone="secondary">
                No unit types published yet.
              </Text>
            ) : (
              unitTypes.map((unitType) => (
                <UnitTypeRow
                  key={unitType._id}
                  unitType={unitType}
                  onPress={() => router.push(`/projects/unit/${unitType._id}`)}
                />
              ))
            )}
          </View>
        </View>
      </Refreshable>
    </Screen>
  );
}

function UnitTypeRow({ unitType, onPress }: { unitType: UnitType; onPress: () => void }) {
  const theme = useTheme();
  const price = unitType.pricing?.effectivePrice ?? unitType.pricing?.basePrice;
  const available = unitType.inventory?.available;

  // `Card`'s own `onPress`, not a wrapping `Pressable` — that one carried no
  // `style` callback, so the row acknowledged a touch with nothing at all.
  return (
    <Card onPress={onPress} className="mb-base flex-row items-center justify-between">
      <View className="flex-1 pr-base">
        <Text variant="bodyEmphasis">{unitType.config?.name ?? 'Unit type'}</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {[
            unitType.config?.bedrooms ? `${unitType.config.bedrooms} BHK` : undefined,
            typeof available === 'number' ? `${available} available` : undefined,
          ]
            .filter(Boolean)
            .join(' · ')}
        </Text>
        {price ? <PriceLabel price={price} variant="callout" className="mt-xs" /> : null}
      </View>
      <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
    </Card>
  );
}
