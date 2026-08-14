import Ionicons from '@expo/vector-icons/Ionicons';
import { useMemo, useState } from 'react';
import { Pressable, View } from 'react-native';

import { ProjectList, useProjectFeed } from '@/features/projects';
import { useTheme } from '@/theme';
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

      <View className="px-lg pb-sm">
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
                hitSlop={8}
              >
                <Ionicons name="close-circle" size={18} color={theme.colors.textMuted} />
              </Pressable>
            ) : undefined
          }
        />
      </View>

      <View className="flex-row px-lg pb-sm">
        {CATEGORIES.map((c) => (
          <Chip
            key={c}
            label={c}
            selected={category === c}
            onPress={() => setCategory((prev) => (prev === c ? undefined : c))}
            className="mr-sm"
          />
        ))}
      </View>

      <ProjectList feed={feed} />
    </Screen>
  );
}
