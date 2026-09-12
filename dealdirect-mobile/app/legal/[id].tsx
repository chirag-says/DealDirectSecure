import { useLocalSearchParams } from 'expo-router';
import { View } from 'react-native';

import { ContentPageView, getContentPage } from '@/features/content';
import { screenPadding } from '@/theme';
import { Screen, ScreenHeader, Text } from '@/ui';

/**
 * A help or legal page, rendered natively: privacy policy, terms, FAQ, about.
 *
 * Until 2026-09-12 this was a WebView of the website. See the module doc in
 * `features/content/index.ts` for why the copy now lives in the app and how
 * drift against the website is kept in check. `/legal/contact` is NOT served
 * here: it has a form, so it is a static route beside this one, and
 * expo-router prefers the static file over the dynamic segment.
 *
 * Public, with no sign-in. Both stores want the privacy policy reachable
 * without an account, and Support links to it from the signed-out profile.
 */
export default function ContentPageScreen() {
  const { id } = useLocalSearchParams<{ id: string }>();
  const entry = getContentPage(id);

  if (!entry) {
    return (
      <Screen>
        <ScreenHeader title="Page" backTo="/support" />
        <View style={{ padding: screenPadding }}>
          <Text variant="body" tone="secondary">
            This page is not available.
          </Text>
        </View>
      </Screen>
    );
  }

  return <ContentPageView page={entry.page} />;
}
