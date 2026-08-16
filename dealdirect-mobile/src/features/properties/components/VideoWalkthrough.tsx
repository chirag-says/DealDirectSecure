import Ionicons from '@expo/vector-icons/Ionicons';
import { Linking, Pressable, View } from 'react-native';

import { useTheme } from '@/theme';
import { Text, useToast } from '@/ui';

/**
 * Video walkthrough — opens externally rather than embedding.
 *
 * `videoUrl` has been typed and adapted since M4 (`types.ts`, `adapters.ts`)
 * but never rendered. The website embeds it as a YouTube iframe
 * (`getVideoEmbedUrl` in `PropertyDetailsContent.jsx`); that needs a WebView,
 * and `react-native-webview` is not installed — it is the exact dependency
 * the property-detail map is blocked on (docs/HANDOFF.md §5.1), and adding it
 * just for this would trigger the same dev-client rebuild the map is waiting
 * for, for a much smaller feature. `Linking.openURL` gets the same content in
 * front of the user today, in the platform's own YouTube app or browser,
 * with no new native module.
 */
export interface VideoWalkthroughProps {
  videoUrl: string;
}

export function VideoWalkthrough({ videoUrl }: VideoWalkthroughProps) {
  const toast = useToast();
  const theme = useTheme();

  const handlePress = async () => {
    const supported = await Linking.canOpenURL(videoUrl);
    if (!supported) {
      // A toast, not a modal: there is nothing to decide and nothing to copy —
      // the listing simply has a bad link, and the user's next move is to
      // carry on reading the page they are already on.
      toast.show('That video link looks invalid.', 'danger');
      return;
    }
    await Linking.openURL(videoUrl);
  };

  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel="Watch video walkthrough"
      onPress={() => void handlePress()}
      className="flex-row items-center rounded-xl border border-border bg-surface-muted p-md active:opacity-70"
    >
      <View
        className="h-11 w-11 items-center justify-center rounded-full"
        style={{ backgroundColor: theme.colors.accentMuted }}
      >
        <Ionicons name="play" size={18} color={theme.colors.accent} />
      </View>
      <View className="ml-md flex-1">
        <Text variant="bodyEmphasis">Video walkthrough</Text>
        <Text variant="footnote" tone="secondary">
          Opens in your browser or video app
        </Text>
      </View>
      <Ionicons name="open-outline" size={18} color={theme.colors.textMuted} />
    </Pressable>
  );
}
