import React from 'react';
import { RefreshControl, ScrollView, type ScrollViewProps } from 'react-native';

import { useTheme } from '@/theme';

/**
 * Scroll container with pull-to-refresh.
 *
 * Every list in the app is refreshable, so the wiring lives here once. Long
 * lists use FlashList with its own `refreshControl`; this is for scroll views
 * of bounded content such as detail screens and forms.
 */

export interface RefreshableProps extends ScrollViewProps {
  refreshing?: boolean;
  onRefresh?: () => void;
  className?: string;
}

export function Refreshable({
  refreshing = false,
  onRefresh,
  children,
  ...rest
}: RefreshableProps) {
  const theme = useTheme();

  return (
    <ScrollView
      keyboardShouldPersistTaps="handled"
      refreshControl={
        onRefresh ? (
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            tintColor={theme.colors.textMuted}
            colors={[theme.colors.accent]}
            progressBackgroundColor={theme.colors.surface}
          />
        ) : undefined
      }
      {...rest}
    >
      {children}
    </ScrollView>
  );
}
