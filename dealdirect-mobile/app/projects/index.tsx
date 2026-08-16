import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo, useState } from 'react';
import { Pressable, ScrollView, View } from 'react-native';

import { ProjectList, useProjectFeed } from '@/features/projects';
import { gesture, screenPadding, spacing, useTheme } from '@/theme';
import { Chip, Input, Screen, ScreenHeader } from '@/ui';

const CATEGORIES = ['Residential', 'Commercial', 'Mixed Use'] as const;

/**
 * Builder projects, full list. `GET /projects` runs a Mongo `$text` search —
 * whole words only, no prefix matching like the property search regex — so
 * search here is submit-on-enter, not live suggestions.
 */
export default function ProjectsScreen() {
  const theme = useTheme();
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState<string | undefined>(undefined);

  const params = useMemo(
    () => ({ search: search || undefined, category, limit: 20 }),
    [search, category]
  );

  const feed = useProjectFeed(params);

  return (
    <Screen>
      <ScreenHeader title="Projects" backTo="/(tabs)" />

      <View className="px-base pb-sm">
        <Input
          placeholder="Search projects…"
          value={searchInput}
          onChangeText={setSearchInput}
          onSubmitEditing={() => setSearch(searchInput.trim())}
          returnKeyType="search"
          trailing={
            searchInput ? (
              <Pressable
                accessibilityRole="button"
                accessibilityLabel="Clear search"
                onPress={() => {
                  setSearchInput('');
                  setSearch('');
                }}
                hitSlop={gesture.hitSlop}
              >
                <Ionicons name="close-circle" size={18} color={theme.colors.textMuted} />
              </Pressable>
            ) : undefined
          }
        />
      </View>

      {/*
        A scrolling rail, not a fixed row. Three chips fit across 375pt at the
        default text size with about 30pt to spare - and clip with no way to
        reach the third at large accessibility sizes, which is exactly the
        reader who can least afford a control to go missing. The Properties
        screen's quick-filter rail scrolls for the same reason.
      */}
      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={{
          paddingHorizontal: screenPadding,
          paddingBottom: spacing.sm,
          gap: spacing.sm,
        }}
        keyboardShouldPersistTaps="handled"
      >
        {CATEGORIES.map((c) => (
          <Chip
            key={c}
            label={c}
            selected={category === c}
            onPress={() => setCategory((prev) => (prev === c ? undefined : c))}
          />
        ))}
      </ScrollView>

      <ProjectList feed={feed} />
    </Screen>
  );
}
