import Ionicons from '@expo/vector-icons/Ionicons';
import Constants from 'expo-constants';
import { useState } from 'react';
import { Linking, Pressable, ScrollView, View } from 'react-native';

import { FAQ_CATEGORIES, LEGAL_LINKS, SUPPORT_CONTACT, type FaqEntry } from '@/features/content';
import { screenPadding, scrollBottomPadding, useTheme } from '@/theme';
import {
  Card,
  ListGroup,
  ListRow,
  Screen,
  ScreenHeader,
  SectionLabel,
  Text,
} from '@/ui';

/**
 * Help & about — the FAQ, how to reach a human, and the links out to the
 * website's legal pages.
 *
 * One screen rather than the website's seven (`/about`, `/why-us`, `/faq`,
 * `/contact`, `/privacy`, `/terms`, `/press-impressions`). Seven separate
 * routes carrying a paragraph each is a website's information architecture,
 * not an app's: on a phone this is one place you go when you are stuck or
 * curious. The two pages with real substance behind them (About, Why
 * DealDirect) and the two legal ones open on the web — see
 * `features/content/pages.ts` for why legal text is deliberately not copied
 * into the binary.
 *
 * Press & impressions is not offered at all. It is a marketing surface aimed
 * at journalists, and nothing about it belongs in a buyer's or owner's app.
 */
export default function SupportScreen() {
  const theme = useTheme();
  const legalLinks = LEGAL_LINKS();

  const appVersion = Constants.expoConfig?.version ?? null;

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="Help & about" backTo="/(tabs)/profile" />

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

        <Text variant="title3" className="mb-base mt-2xl">
          Frequently asked
        </Text>

        {FAQ_CATEGORIES.map((category) => (
          <View key={category.title} className="mb-lg">
            <SectionLabel>{category.title}</SectionLabel>
            <Card>
              {category.questions.map((entry, index) => (
                <FaqRow
                  key={entry.q}
                  entry={entry}
                  isLast={index === category.questions.length - 1}
                />
              ))}
            </Card>
          </View>
        ))}

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

/** Collapsed by default: the questions are the index, the answers are the detail. */
function FaqRow({ entry, isLast }: { entry: FaqEntry; isLast: boolean }) {
  const theme = useTheme();
  const [open, setOpen] = useState(false);

  return (
    <View className={isLast ? '' : 'border-b border-border'}>
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded: open }}
        accessibilityLabel={entry.q}
        onPress={() => setOpen((current) => !current)}
        className="flex-row items-center py-md active:opacity-60"
      >
        <Text variant="body" className="flex-1 pr-md">
          {entry.q}
        </Text>
        <Ionicons
          name={open ? 'chevron-up' : 'chevron-down'}
          size={17}
          color={theme.colors.textMuted}
        />
      </Pressable>

      {open ? (
        <Text variant="callout" tone="secondary" className="pb-md">
          {entry.a}
        </Text>
      ) : null}
    </View>
  );
}
