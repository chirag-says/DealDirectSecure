import Ionicons from '@expo/vector-icons/Ionicons';
import Constants from 'expo-constants';
import { Linking, ScrollView } from 'react-native';

import { LEGAL_LINKS, SUPPORT_CONTACT } from '@/features/content';
import { screenPadding, scrollBottomPadding, useTheme } from '@/theme';
import { ListGroup, ListRow, Screen, ScreenHeader, Text } from '@/ui';

/**
 * Help & support — how to reach a human, the legal links, and the build.
 *
 * ---------------------------------------------------------------------------
 * THE FAQ IS GONE — 2026-08-24
 *
 * This screen carried eleven questions in four collapsible categories, copied
 * verbatim from the website's `/faq` page. Reproducing the copy was the right
 * call at the time and the wrong artefact: an FAQ is what a website builds
 * when it cannot answer a question at the moment the question occurs. An app
 * can.
 *
 * Every entry was checked before it was deleted rather than after:
 *
 *   "What is DealDirect?" and "Is it really broker-free?" are the pitch. The
 *   person reading them has installed the app. They belong on the website,
 *   which still has them.
 *
 *   "Can I edit or delete my post?", "How do I report a listing?" and "How do
 *   I refer someone?" are answered by the interface — the buttons exist, on
 *   the screens where those things happen. A help entry describing a visible
 *   control is a symptom, not documentation.
 *
 *   "Why can I only post one property?" was the one entry carrying information
 *   the app never showed. It has moved to `owner/properties`, which is where
 *   an owner is standing when they wonder. See the note there.
 *
 *   "How do I earn rewards?" and "What can I do with my points?" are already
 *   stated on the Rewards screen, in its empty state and its redemption card.
 *
 *   "Is my data safe?" is a privacy question with a legal answer, and the
 *   privacy policy is linked below. A paraphrase in a binary that cannot be
 *   corrected without a store release is the exact hazard `content/index.ts`
 *   describes for terms.
 *
 * What is left is what an app's help screen is for: reaching a human, the
 * legal source of truth, and which build you are on when you do.
 *
 * The website's seven content routes (`/about`, `/why-us`, `/faq`, `/contact`,
 * `/privacy`, `/terms`, `/press-impressions`) remain the website's. The two
 * legal ones open there — see `features/content/pages.ts` for why legal text
 * is deliberately not copied into the binary. Press & impressions is not
 * offered at all: it is aimed at journalists, and nothing about it belongs in
 * a buyer's or owner's app.
 */
export default function SupportScreen() {
  const theme = useTheme();
  const legalLinks = LEGAL_LINKS();

  const appVersion = Constants.expoConfig?.version ?? null;

  return (
    <Screen edges={['top']}>
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
        </ListGroup>

        {/* Omitted entirely when no web origin is configured, rather than
            rendering links that would open nothing. */}
        {legalLinks.length > 0 ? (
          <ListGroup title="More" className="mt-lg">
            {legalLinks.map(({ page, url }) => (
              <ListRow
                key={page.id}
                label={page.label}
                detail="Opens in your browser"
                chevron={false}
                trailing={
                  <Ionicons name="open-outline" size={17} color={theme.colors.textMuted} />
                }
                onPress={() => void Linking.openURL(url)}
              />
            ))}
          </ListGroup>
        ) : null}

        {appVersion ? (
          <Text variant="caption" tone="muted" className="mt-2xl text-center">
            DealDirect {appVersion}
          </Text>
        ) : null}
      </ScrollView>
    </Screen>
  );
}
