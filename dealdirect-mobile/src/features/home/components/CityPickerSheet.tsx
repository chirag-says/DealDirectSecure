import Ionicons from '@expo/vector-icons/Ionicons';
import { ScrollView, View } from 'react-native';

import { radius, screenPadding, spacing, useTheme } from '@/theme';
import { PressableScale, Sheet, Text } from '@/ui';
import { CITIES, type City } from '../cities';

/**
 * Which city the session is scoped to.
 *
 * A sheet rather than a screen: choosing a city is a modifier on what you were
 * already doing, and a full push would take the hero off screen to change one
 * word in it.
 *
 * "All cities" is a first-class row, not an escape hatch buried at the bottom.
 * DealDirect's inventory is thin enough in some cities that scoping to one can
 * empty the results, and a user who cannot get back to everything reads that as
 * the app having nothing.
 */

export interface CityPickerSheetProps {
  visible: boolean;
  selected: City | null;
  onSelect: (city: City | null) => void;
  onClose: () => void;
}

export function CityPickerSheet({ visible, selected, onSelect, onClose }: CityPickerSheetProps) {
  const theme = useTheme();

  const choose = (city: City | null) => {
    onSelect(city);
    onClose();
  };

  return (
    <Sheet visible={visible} onClose={onClose} title="Where are you looking?" heightRatio={0.7}>
      <ScrollView
        contentContainerStyle={{ paddingHorizontal: screenPadding, paddingBottom: spacing['2xl'] }}
        showsVerticalScrollIndicator={false}
      >
        <Row label="All cities" selected={selected === null} onPress={() => choose(null)} />

        {CITIES.map((city) => (
          <Row
            key={city.id}
            label={city.label}
            selected={selected?.id === city.id}
            onPress={() => choose(city)}
          />
        ))}

        <Text variant="caption" tone="muted" className="mt-lg">
          Your city is remembered on this device and scopes the search field and
          the Buy, Rent and Projects shortcuts above it.
        </Text>
      </ScrollView>

      <View style={{ height: 1, backgroundColor: theme.colors.border }} />
    </Sheet>
  );
}

function Row({
  label,
  selected,
  onPress,
}: {
  label: string;
  selected: boolean;
  onPress: () => void;
}) {
  const theme = useTheme();

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={label}
      accessibilityState={{ selected }}
      onPress={onPress}
      activeScale={0.99}
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        justifyContent: 'space-between',
        paddingVertical: spacing.md,
        paddingHorizontal: spacing.base,
        borderRadius: radius.lg,
        backgroundColor: selected ? theme.colors.accentMuted : 'transparent',
        marginBottom: spacing.xs,
      }}
    >
      <Text variant="body" tone={selected ? 'accent' : 'primary'}>
        {label}
      </Text>
      {selected ? (
        <Ionicons name="checkmark" size={18} color={theme.colors.accent} />
      ) : null}
    </PressableScale>
  );
}
