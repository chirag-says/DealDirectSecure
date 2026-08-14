import Ionicons from '@expo/vector-icons/Ionicons';
import { memo, useCallback } from 'react';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { Image, PressableScale, PriceLabel, Scrim, Text } from '@/ui';
import type { ProjectSummary } from '../types';

/**
 * A builder project card.
 *
 * Deliberately NOT the property card with different fields. The two are
 * different objects and the hierarchy has to differ to match:
 *
 * A property is bought as a unit, so its price is the fact you scan for and it
 * gets the largest type. A project is not one thing at a price — it is a
 * development with several unit types spanning a range, and what identifies it
 * is its NAME. "Satyam Metro Codename Waterfalls" is the thing being recalled
 * and recognised; the ₹1.35 Cr is a qualifier on it. So the name leads here and
 * the price sits below in a supporting weight, which is the reverse of
 * `PropertyRailCard`.
 *
 * The status badge carries real schema data ("New Launch", "Under
 * Construction") and is genuinely decision-relevant: whether you can move in
 * next month or in three years changes whether the listing is for you at all.
 * That is worth a badge in a way that a generic "Featured" ribbon is not.
 */

const IMAGE_HEIGHT = 150;

export interface ProjectCardProps {
  project: ProjectSummary;
  width: number;
  onPress: (id: string) => void;
}

/**
 * Status to a tone.
 *
 * Only "New Launch" earns colour. It is the one status that is time-sensitive,
 * and colouring all four would turn the rail into a set of traffic lights where
 * every card competes. The rest read as neutral metadata, which is what they
 * are.
 */
function isNewLaunch(status?: string): boolean {
  return status?.toLowerCase() === 'new launch';
}

function ProjectCardComponent({ project, width, onPress }: ProjectCardProps) {
  const theme = useTheme();
  const handlePress = useCallback(() => onPress(project.id), [onPress, project.id]);

  const hasRange =
    project.priceMin !== undefined &&
    project.priceMax !== undefined &&
    project.priceMax > project.priceMin;

  return (
    <PressableScale
      accessibilityLabel={`${project.name}${project.builderName ? ` by ${project.builderName}` : ''}`}
      onPress={handlePress}
      style={{
        width,
        borderRadius: radius.lg,
        backgroundColor: theme.colors.surface,
        // Shadow, not a border — matched to `PropertyCard` so the same object
        // does not change its construction between Home and the browse list.
        // The page is dark enough now (`palette.canvas`) for a shadow to read;
        // when this card was written it was not, which is why it outlined
        // itself instead.
        shadowColor: '#000',
        shadowOpacity: 0.07,
        shadowRadius: 12,
        shadowOffset: { width: 0, height: 4 },
        elevation: 3,
        overflow: 'hidden',
      }}
    >
      <View style={{ height: IMAGE_HEIGHT }}>
        {project.coverImage ? (
          <Image uri={project.coverImage} size="thumb" style={{ width: '100%', height: '100%' }} />
        ) : (
          <View className="h-full w-full items-center justify-center bg-surface-muted">
            <Ionicons name="business-outline" size={26} color={theme.colors.textMuted} />
          </View>
        )}

        <Scrim variant="tile" />

        {project.status ? (
          <View
            className="absolute"
            style={{
              left: spacing.md,
              top: spacing.md,
              paddingHorizontal: spacing.sm + 2,
              paddingVertical: spacing.xs,
              borderRadius: radius.full,
              backgroundColor: isNewLaunch(project.status)
                ? theme.colors.success
                : 'rgba(0,0,0,0.55)',
            }}
          >
            <Text variant="overline" style={{ color: '#FFFFFF' }}>
              {project.status.toUpperCase()}
            </Text>
          </View>
        ) : null}

        {/*
          The builder mark sits on the image, bottom-right, where it reads as a
          maker's stamp rather than as another row of text competing with the
          project name below.
        */}
        {project.builderLogo ? (
          <View
            className="absolute overflow-hidden bg-white"
            style={{
              right: spacing.md,
              bottom: spacing.md,
              width: 34,
              height: 34,
              borderRadius: radius.full,
              padding: 3,
            }}
          >
            <Image
              uri={project.builderLogo}
              size="thumb"
              contentFit="contain"
              style={{ width: '100%', height: '100%' }}
            />
          </View>
        ) : null}
      </View>

      <View style={{ padding: spacing.md }}>
        <Text variant="bodyEmphasis" numberOfLines={1}>
          {project.name}
        </Text>

        {project.builderName ? (
          <Text variant="caption" tone="muted" numberOfLines={1} className="mt-xs">
            by {project.builderName}
          </Text>
        ) : null}

        <View className="mt-sm flex-row items-center" style={{ gap: spacing.xs }}>
          <Ionicons name="location-outline" size={13} color={theme.colors.brand} />
          <Text variant="footnote" tone="secondary" numberOfLines={1} className="flex-1">
            {project.locationLabel}
          </Text>
        </View>

        {project.priceMin !== undefined ? (
          <View className="mt-sm flex-row items-baseline" style={{ gap: spacing.xs }}>
            <PriceLabel price={project.priceMin} variant="callout" />
            {/*
              "onwards" only when the range is genuinely a range. Several live
              projects carry min === max, and printing "₹47 Lac onwards" for a
              single fixed price overstates what is on offer.
            */}
            <Text variant="caption" tone="muted">
              {hasRange ? 'onwards' : ''}
            </Text>
          </View>
        ) : null}
      </View>
    </PressableScale>
  );
}

export const ProjectCard = memo(ProjectCardComponent);
