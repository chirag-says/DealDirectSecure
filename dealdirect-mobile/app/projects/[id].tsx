import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { Dimensions, ScrollView, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { useProjectDetail, useUnitTypesForProject } from '@/features/projects';
import { gesture, spacing, useTheme } from '@/theme';
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
  Text,
} from '@/ui';

const GALLERY_HEIGHT = 260;
const SCREEN_WIDTH = Dimensions.get('window').width;

export default function ProjectDetailScreen() {
  const router = useRouter();
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const { id } = useLocalSearchParams<{ id: string }>();
  const { project, isLoading, error, refresh } = useProjectDetail(id);
  const { unitTypes, isLoading: unitTypesLoading } = useUnitTypesForProject(id);

  if (isLoading) {
    return (
      <Screen edges={['bottom']}>
        <Skeleton height={GALLERY_HEIGHT} radius={0} />
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
      <Refreshable refreshing={false} onRefresh={refresh} contentContainerStyle={{ paddingBottom: 48 }}>
        <View style={{ height: GALLERY_HEIGHT }}>
          {images.length > 0 ? (
            <ScrollView horizontal pagingEnabled showsHorizontalScrollIndicator={false}>
              {images.map((uri, index) => (
                <Image
                  key={`${uri}-${index}`}
                  uri={uri}
                  size="full"
                  style={{ width: SCREEN_WIDTH, height: GALLERY_HEIGHT }}
                />
              ))}
            </ScrollView>
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

        <View className="p-base">
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
              <View className="flex-row flex-wrap">
                {amenities.map((amenity) => (
                  <Badge key={amenity} label={amenity} className="mb-sm mr-sm" />
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
