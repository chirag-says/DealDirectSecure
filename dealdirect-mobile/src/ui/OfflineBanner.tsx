import { View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { useIsOffline } from '@/lib';
import { useTheme } from '@/theme';
import { Text } from './Text';

/**
 * Global offline indicator (M12).
 *
 * Mounted once in `app/_layout.tsx`, above the route stack. Every screen
 * already renders cached content when offline — that is what the persisted
 * query cache (`src/api/persistence.ts`) is for — and every write already
 * fails with a clear "No connection" message (`src/api/errors.ts`'s
 * `network` kind). What was missing is telling the user BEFORE they tap
 * something that it will not work; this banner is that, and nothing more.
 */
export function OfflineBanner() {
  const offline = useIsOffline();
  const insets = useSafeAreaInsets();
  const theme = useTheme();

  if (!offline) return null;

  return (
    <View
      pointerEvents="none"
      style={{
        position: 'absolute',
        top: insets.top,
        left: 0,
        right: 0,
        zIndex: 50,
        alignItems: 'center',
        paddingVertical: 6,
        backgroundColor: theme.colors.warning,
      }}
    >
      <Text variant="footnote" style={{ color: '#1A1200' }}>
        You&apos;re offline — showing saved content, some actions won&apos;t work
      </Text>
    </View>
  );
}
