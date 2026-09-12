import Constants from 'expo-constants';
import { router } from 'expo-router';
import { Linking, ScrollView } from 'react-native';

import { SUPPORT_CONTACT, contentPagesByGroup } from '@/features/content';
import { screenPadding, scrollBottomPadding } from '@/theme';
import { ListGroup, ListRow, Screen, ScreenHeader, Text } from '@/ui';

/**
 * Help & support — how to reach a human, the help and legal pages, the build.
 *
 * ---------------------------------------------------------------------------
 * THE FAQ AND THE LEGAL PAGES ARE BACK, AS SCREENS — 2026-09-12
 *
 * On 2026-08-24 this screen lost its FAQ (the app answers those questions on
 * the screens where they arise) and kept only two links out to the website's
 * privacy policy and terms. That was the right shape for an app and the wrong
 * shape for a store submission: review wants the policy, the terms and the
 * help content INSIDE the binary, in the app's own theme, with no network
 * between the reader and the text. The owner asked for exactly that.
 *
 * So the website's help and legal pages are rendered natively now, from data,
 * and this screen lists them. The rows come from `features/content/pages`, so
 * adding a page there adds a row here. What has not changed: reaching a human
 * comes first, works signed out, and needs no page at all.
 *
 * Press & impressions is still not offered. It is aimed at journalists, and
 * nothing about it belongs in a buyer's or owner's app.
 */
export default function SupportScreen() {
  const appVersion = Constants.expoConfig?.version ?? null;

  return (
    // Both safe-area edges: this is a stack screen with no tab bar beneath it,
    // and with only the top edge the version caption sat under the gesture bar.
    <Screen>
      <ScreenHeader title="Help & support" backTo="/(tabs)/profile" />

      <ScrollView
        contentContainerStyle={{
          padding: screenPadding,
          paddingBottom: scrollBottomPadding,
        }}
      >
        <ListGroup
          title="Talk to us"
          footer="Something wrong with a listing, or stuck on your account? Reach us directly."
        >
          <ListRow
            icon="mail-outline"
            label={SUPPORT_CONTACT.email}
            chevron={false}
            onPress={() => void Linking.openURL(`mailto:${SUPPORT_CONTACT.email}`)}
          />
          <ListRow
            icon="call-outline"
            label={SUPPORT_CONTACT.phone}
            chevron={false}
            onPress={() => void Linking.openURL(`tel:${SUPPORT_CONTACT.phone}`)}
          />
          <ListRow
            icon="chatbubble-ellipses-outline"
            label="Send us a message"
            detail="Office address, hours, and a contact form"
            onPress={() => router.push('/legal/contact')}
          />
        </ListGroup>

        {contentPagesByGroup().map(({ group, title, entries }) => (
          <ListGroup key={group} title={title} className="mt-lg">
            {entries.map((entry) => (
              <ListRow
                key={entry.page.id}
                icon={entry.icon}
                label={entry.label}
                onPress={() => router.push(`/legal/${entry.page.id}`)}
              />
            ))}
          </ListGroup>
        ))}

        {appVersion ? (
          <Text variant="caption" tone="muted" className="mt-2xl text-center">
            DealDirect {appVersion}
          </Text>
        ) : null}
      </ScrollView>
    </Screen>
  );
}
