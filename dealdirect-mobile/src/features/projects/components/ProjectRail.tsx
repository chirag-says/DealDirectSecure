import { useCallback } from 'react';
import { View } from 'react-native';

import { radius, spacing } from '@/theme';
import { Rail, Skeleton, useRailItemWidth } from '@/ui';
import type { ProjectSummary } from '../types';
import { ProjectCard } from './ProjectCard';

/**
 * A horizontal row of builder projects.
 *
 * Uses the `medium` rail size rather than `large`. Project cards carry less
 * per-card information than a property card — no BHK, no area, no per-unit
 * price — so a narrower card stays legible while showing more of the row, and
 * with only a handful of live projects a wider card would leave the rail
 * looking half empty after two swipes.
 *
 * Renders nothing when empty, matching every other discovery row on Home.
 */

export interface ProjectRailProps {
  items: readonly ProjectSummary[];
  loading?: boolean;
  onSelect: (id: string) => void;
  accessibilityLabel?: string;
}

const SKELETON_COUNT = 3;

export function ProjectRail({
  items,
  loading = false,
  onSelect,
  accessibilityLabel,
}: ProjectRailProps) {
  const width = useRailItemWidth('medium');

  const renderItem = useCallback(
    (project: ProjectSummary, itemWidth: number) => (
      <ProjectCard project={project} width={itemWidth} onPress={onSelect} />
    ),
    [onSelect]
  );

  if (loading) {
    return (
      <View
        className="flex-row px-base"
        style={{ gap: spacing.md }}
        accessibilityLabel="Loading projects"
      >
        {Array.from({ length: SKELETON_COUNT }, (_, index) => (
          // 150pt image plus roughly 110pt of text, matching the real card so
          // the row does not resize when data lands.
          <Skeleton key={index} width={width} height={260} radius={radius.lg} />
        ))}
      </View>
    );
  }

  if (items.length === 0) return null;

  return (
    <Rail
      data={items}
      size="medium"
      keyExtractor={(item) => item.id}
      renderItem={renderItem}
      accessibilityLabel={accessibilityLabel}
    />
  );
}
