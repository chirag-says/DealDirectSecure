import Ionicons from '@expo/vector-icons/Ionicons';
import { router } from 'expo-router';
import { useState, type ReactNode } from 'react';
import { Linking, Pressable, ScrollView, StyleSheet, View } from 'react-native';
import Animated, { LinearTransition, useReducedMotion } from 'react-native-reanimated';

import { radius, screenPadding, scrollBottomPadding, spacing, touchTarget, useTheme } from '@/theme';
import {
  Button,
  Card,
  HeaderAction,
  KeyboardAvoider,
  Screen,
  ScreenHeader,
  Segmented,
  Text,
  useFontFamily,
  type TextVariant,
} from '@/ui';

import { webUrlFor } from '../pages';
import {
  parseRichText,
  type Block,
  type CalloutTone,
  type CardItem,
  type ContentPage,
  type ContentPart,
  type FaqItem,
  type IconName,
  type RichText,
  type Section,
} from '../pages/model';

/**
 * Renders a `ContentPage`: the one screen behind every help and legal page.
 *
 * ---------------------------------------------------------------------------
 * THE LAYOUT IS THE PROPERTY PAGE'S — 2026-09-12
 *
 * The first version put every run of prose in a white card and every section
 * title behind an icon tile. On a phone that read as a stack of boxes, and the
 * owner said so. The property details screen is the reference for how this
 * app lays out long content, and it uses no cards for text at all: a hairline
 * rule, a heading, the copy, and 32pt before the next section. That is what
 * this does now. The only surface left is the stats grid, which is a fact
 * strip and gets the same treatment as the property page's facts.
 *
 * Three type levels, and only three, so the hierarchy is legible at a glance:
 *
 *   title2  22pt  a section ("Information We Collect", "Earning Rewards")
 *   title3  18pt  a sub-heading inside it, an accordion row, a feature title
 *   body    16pt  everything a person reads; secondary tone, bold runs primary
 *
 * Nothing here knows which page it is rendering. A page that needs a new kind
 * of block gets a new `Block` variant and a case below, not a special screen.
 */

export interface ContentPageViewProps {
  page: ContentPage;
  /** Where the header's back control goes. */
  backTo?: string;
  /** Rendered after the page's own content, inside the scroll: the contact form. */
  children?: ReactNode;
}

export function ContentPageView({ page, backTo = '/support', children }: ContentPageViewProps) {
  return (
    <Screen>
      <ScreenHeader
        title={page.title}
        backTo={backTo}
        tight
        actions={
          <HeaderAction
            icon="open-outline"
            label="Open on website"
            onPress={() => void Linking.openURL(webUrlFor(page))}
          />
        }
      />

      <KeyboardAvoider className="flex-1">
        <ScrollView
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingTop: spacing.md,
            paddingBottom: scrollBottomPadding,
          }}
          keyboardShouldPersistTaps="handled"
        >
          <PageIntro page={page} />
          {page.parts ? <Parts parts={page.parts} /> : <Sections sections={page.sections} />}
          {children ? <View style={{ marginTop: spacing['2xl'] }}>{children}</View> : null}
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}

function PageIntro({ page }: { page: ContentPage }) {
  return (
    <View style={{ gap: spacing.sm }}>
      <Text variant="overline" tone="accent">
        {page.eyebrow.toUpperCase()}
      </Text>
      {page.intro ? <Rich text={page.intro} /> : null}
      {page.meta ? (
        <Text variant="footnote" tone="muted">
          {page.meta}
        </Text>
      ) : null}
    </View>
  );
}

/* ---------------------------------------------------------------- parts */

function Parts({ parts }: { parts: ContentPart[] }) {
  const [activeId, setActiveId] = useState(() => parts[0]?.id ?? '');
  const active = parts.find((part) => part.id === activeId) ?? parts[0];
  if (!active) return null;

  return (
    <>
      <View style={{ marginTop: spacing.xl }}>
        <Segmented
          options={parts.map((part) => ({ label: part.label, value: part.id }))}
          value={active.id}
          onChange={setActiveId}
          accessibilityLabel="Part of the terms"
        />
      </View>
      {/* Keyed so switching parts resets every accordion to its own default
          rather than carrying one part's open state into another's clauses. */}
      <View key={active.id}>
        {active.blocks?.length ? (
          <View style={{ marginTop: spacing.xl }}>
            <BlockList blocks={active.blocks} />
          </View>
        ) : null}
        <Sections sections={active.sections} />
      </View>
    </>
  );
}

/* ------------------------------------------------------------- sections */

function Sections({ sections }: { sections: Section[] }) {
  const theme = useTheme();
  // Accordion rows read as a list: one rule above the first, one under each.
  const allCollapsible = sections.every((section) => section.collapsible);

  return (
    <View
      style={
        allCollapsible
          ? {
              marginTop: spacing.xl,
              borderTopWidth: StyleSheet.hairlineWidth,
              borderTopColor: theme.colors.border,
            }
          : undefined
      }
    >
      {sections.map((section) =>
        section.collapsible ? (
          <Accordion key={section.id} section={section} />
        ) : (
          <OpenSection key={section.id} section={section} />
        )
      )}
    </View>
  );
}

/** The property page's `Section`: a rule, a heading, the content. */
function OpenSection({ section }: { section: Section }) {
  const theme = useTheme();
  return (
    <View style={{ marginTop: spacing['2xl'] }}>
      {section.title ? (
        <>
          <View
            style={{
              height: StyleSheet.hairlineWidth,
              backgroundColor: theme.colors.border,
              marginBottom: spacing.lg,
            }}
          />
          <View style={{ marginBottom: spacing.base, gap: spacing.xs }}>
            <Text variant="title2">{section.title}</Text>
            {section.blurb ? (
              <Text variant="callout" tone="muted">
                {section.blurb}
              </Text>
            ) : null}
          </View>
        </>
      ) : null}
      <BlockList blocks={section.blocks} />
    </View>
  );
}

function Accordion({ section }: { section: Section }) {
  const theme = useTheme();
  const reduceMotion = useReducedMotion();
  const [expanded, setExpanded] = useState(section.defaultOpen ?? false);

  return (
    <Animated.View
      layout={reduceMotion ? undefined : LinearTransition}
      style={{ borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: theme.colors.border }}
    >
      <Pressable
        accessibilityRole="button"
        accessibilityState={{ expanded }}
        accessibilityLabel={section.title}
        onPress={() => setExpanded((value) => !value)}
        style={{
          flexDirection: 'row',
          alignItems: 'center',
          gap: spacing.md,
          paddingVertical: spacing.base,
          minHeight: touchTarget.min,
        }}
      >
        <Text variant="title3" style={{ flex: 1 }}>
          {section.title}
        </Text>
        <Ionicons
          name={expanded ? 'chevron-up' : 'chevron-down'}
          size={20}
          color={theme.colors.textMuted}
        />
      </Pressable>

      {expanded ? (
        <View style={{ paddingBottom: spacing.xl }}>
          <BlockList blocks={section.blocks} />
        </View>
      ) : null}
    </Animated.View>
  );
}

/* --------------------------------------------------------------- blocks */

function BlockList({ blocks }: { blocks: Block[] }) {
  return (
    <View style={{ gap: spacing.base }}>
      {blocks.map((block, index) => (
        <BlockView key={index} block={block} />
      ))}
    </View>
  );
}

function BlockView({ block }: { block: Block }) {
  switch (block.type) {
    case 'paragraph':
      return <Rich text={block.text} />;
    case 'heading':
      // A sub-heading sits closer to what follows it than to what precedes it.
      return (
        <Text variant="title3" style={{ marginTop: spacing.sm, marginBottom: -spacing.xs }}>
          {block.text}
        </Text>
      );
    case 'bullets':
      return <Bullets items={block.items} />;
    case 'callout':
      return <Callout tone={block.tone} title={block.title} text={block.text} items={block.items} />;
    case 'cards':
      return <Features items={block.items} />;
    case 'stats':
      return <Stats items={block.items} />;
    case 'quote':
      return <Quote text={block.text} />;
    case 'tags':
      return <Tags items={block.items} />;
    case 'faq':
      return <Faq items={block.items} />;
    case 'contact':
      return <Contact {...block} />;
    case 'actions':
      return (
        <View style={{ gap: spacing.sm, marginTop: spacing.xs }}>
          {block.items.map((action) => (
            <Button
              key={action.label}
              label={action.label}
              variant={action.variant ?? 'secondary'}
              fullWidth
              onPress={() => router.push(action.href)}
            />
          ))}
        </View>
      );
  }
}

/* ------------------------------------------------------------ rich text */

/**
 * A paragraph with bold runs. Bold takes the primary tone at the same size:
 * emphasis by weight and colour, never by growing.
 */
function Rich({
  text,
  variant = 'body',
  tone = 'secondary',
}: {
  text: RichText;
  variant?: TextVariant;
  tone?: 'primary' | 'secondary' | 'muted';
}) {
  const runs = parseRichText(text);
  // The app's typeface is loaded one file per weight, so a `fontWeight` style
  // on its own changes nothing on Android: the bold FACE has to be named.
  // `useFontFamily` gives the 600 face under the app's font override and
  // nothing under the system font, where the weight style is what works.
  const boldFamily = useFontFamily('600');
  const bold = boldFamily ? { fontFamily: boldFamily } : { fontWeight: '600' as const };
  return (
    <Text variant={variant} tone={tone}>
      {runs.map((run, index) =>
        run.bold ? (
          <Text key={index} variant={variant} tone="primary" style={bold}>
            {run.text}
          </Text>
        ) : (
          run.text
        )
      )}
    </Text>
  );
}

function Bullets({ items, color }: { items: RichText[]; color?: string }) {
  const theme = useTheme();
  return (
    <View style={{ gap: spacing.sm }}>
      {items.map((item, index) => (
        <View key={index} style={{ flexDirection: 'row', gap: spacing.md }}>
          <View
            style={{
              width: 6,
              height: 6,
              borderRadius: 3,
              marginTop: 9,
              backgroundColor: color ?? theme.colors.accent,
            }}
          />
          <View style={{ flex: 1 }}>
            <Rich text={item} />
          </View>
        </View>
      ))}
    </View>
  );
}

function Callout({
  tone,
  title,
  text,
  items,
}: {
  tone: CalloutTone;
  title?: string;
  text?: RichText;
  items?: RichText[];
}) {
  const theme = useTheme();
  const palette: Record<CalloutTone, { fill: string; ink: string }> = {
    info: { fill: theme.colors.accentMuted, ink: theme.colors.accent },
    success: { fill: theme.colors.successMuted, ink: theme.colors.success },
    warning: { fill: theme.colors.warningMuted, ink: theme.colors.warning },
    danger: { fill: theme.colors.dangerMuted, ink: theme.colors.danger },
    neutral: { fill: theme.colors.surfaceMuted, ink: theme.colors.textSecondary },
  };
  const { fill, ink } = palette[tone];

  return (
    <View
      style={{
        backgroundColor: fill,
        borderRadius: radius.lg,
        padding: spacing.base,
        gap: spacing.sm,
      }}
    >
      {title ? (
        <Text variant="bodyEmphasis" style={{ color: ink }}>
          {title}
        </Text>
      ) : null}
      {text ? <Rich text={text} tone="primary" /> : null}
      {items?.length ? <Bullets items={items} color={ink} /> : null}
    </View>
  );
}

/** Feature and plan lists: a glyph, a title, the copy. No surfaces. */
function Features({ items }: { items: CardItem[] }) {
  const theme = useTheme();
  return (
    <View style={{ gap: spacing.xl }}>
      {items.map((item) => (
        <View key={item.title} style={{ flexDirection: 'row', gap: spacing.md }}>
          {item.icon ? (
            <Ionicons
              name={item.icon}
              size={22}
              color={theme.colors.accent}
              // Centred on the title's first line (title3 leading is 23).
              style={{ marginTop: 1 }}
            />
          ) : null}
          <View style={{ flex: 1, gap: spacing.sm }}>
            <View>
              <Text variant="title3">{item.title}</Text>
              {item.meta ? (
                <Text variant="footnote" tone="muted" style={{ marginTop: spacing.xs }}>
                  {item.meta}
                </Text>
              ) : null}
            </View>
            {item.text.split('\n\n').map((paragraph, index) => (
              <Rich key={index} text={paragraph} />
            ))}
            {item.footnote ? (
              <Text variant="footnote" tone="muted">
                {item.footnote}
              </Text>
            ) : null}
          </View>
        </View>
      ))}
    </View>
  );
}

/** A fact strip, like the property page's: one surface, hairlines between cells. */
function Stats({ items }: { items: { value: string; label: string }[] }) {
  const theme = useTheme();
  const perRow = 2;
  return (
    <Card radius="xl" padded={false}>
      <View style={{ flexDirection: 'row', flexWrap: 'wrap' }}>
        {items.map((item, index) => {
          const firstInRow = index % perRow === 0;
          const firstRow = index < perRow;
          return (
            <View
              key={item.label}
              style={{
                width: `${100 / perRow}%`,
                paddingVertical: spacing.base,
                paddingHorizontal: spacing.base,
                borderLeftWidth: firstInRow ? 0 : StyleSheet.hairlineWidth,
                borderTopWidth: firstRow ? 0 : StyleSheet.hairlineWidth,
                borderColor: theme.colors.border,
              }}
            >
              <Text variant="title2" tone="accent" numberOfLines={1}>
                {item.value}
              </Text>
              <Text variant="caption" tone="muted" numberOfLines={1} style={{ marginTop: 2 }}>
                {item.label.toUpperCase()}
              </Text>
            </View>
          );
        })}
      </View>
    </Card>
  );
}

function Quote({ text }: { text: string }) {
  const theme = useTheme();
  return (
    <View
      style={{
        borderLeftWidth: 3,
        borderLeftColor: theme.colors.brand,
        paddingLeft: spacing.base,
        marginTop: spacing.xs,
      }}
    >
      <Text variant="body" style={{ fontStyle: 'italic' }}>
        “{text}”
      </Text>
    </View>
  );
}

function Tags({ items }: { items: string[] }) {
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: spacing.sm }}>
      {items.map((item) => (
        <View
          key={item}
          className="rounded-full bg-surface-muted"
          style={{ paddingHorizontal: spacing.md, paddingVertical: spacing.xs }}
        >
          <Text variant="footnote" tone="secondary">
            {item}
          </Text>
        </View>
      ))}
    </View>
  );
}

function Faq({ items }: { items: FaqItem[] }) {
  const theme = useTheme();
  const reduceMotion = useReducedMotion();
  const [open, setOpen] = useState<ReadonlySet<string>>(() => new Set());

  const toggle = (id: string) =>
    setOpen((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  return (
    <Animated.View
      layout={reduceMotion ? undefined : LinearTransition}
      style={{ borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: theme.colors.border }}
    >
      {items.map((item) => {
        const expanded = open.has(item.id);
        return (
          <View
            key={item.id}
            style={{ borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: theme.colors.border }}
          >
            <Pressable
              accessibilityRole="button"
              accessibilityState={{ expanded }}
              onPress={() => toggle(item.id)}
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                gap: spacing.md,
                paddingVertical: spacing.base,
                minHeight: touchTarget.min,
              }}
            >
              <Text variant="bodyEmphasis" style={{ flex: 1 }}>
                {item.question}
              </Text>
              <Ionicons
                name={expanded ? 'chevron-up' : 'chevron-down'}
                size={20}
                color={theme.colors.textMuted}
              />
            </Pressable>
            {expanded ? (
              <View style={{ paddingBottom: spacing.lg }}>
                <Rich text={item.answer} />
              </View>
            ) : null}
          </View>
        );
      })}
    </Animated.View>
  );
}

function Contact({
  name,
  role,
  org,
  address,
  email,
  phone,
  hours,
}: Extract<Block, { type: 'contact' }>) {
  // A person: name, then their role, then the organisation. An office with no
  // named person: the organisation first, and the role ("Corporate office")
  // describes it.
  const roleLine = role ? (
    <Text variant="footnote" tone="muted">
      {role}
    </Text>
  ) : null;

  return (
    <View style={{ gap: spacing.xs }}>
      {name ? <Text variant="title3">{name}</Text> : null}
      {name ? roleLine : null}
      {org ? (
        <Text variant="bodyEmphasis" style={name ? { marginTop: spacing.sm } : undefined}>
          {org}
        </Text>
      ) : null}
      {!name ? roleLine : null}
      {address ? (
        <Text variant="body" tone="secondary">
          {address}
        </Text>
      ) : null}
      <View style={{ marginTop: spacing.sm }}>
        {email ? <ContactRow icon="mail-outline" label={email} url={`mailto:${email}`} /> : null}
        {phone ? (
          <ContactRow icon="call-outline" label={phone} url={`tel:${phone.replace(/[^\d+]/g, '')}`} />
        ) : null}
      </View>
      {hours ? (
        <Text variant="footnote" tone="muted">
          {hours}
        </Text>
      ) : null}
    </View>
  );
}

function ContactRow({ icon, label, url }: { icon: IconName; label: string; url: string }) {
  const theme = useTheme();
  return (
    <Pressable
      accessibilityRole="link"
      onPress={() => void Linking.openURL(url)}
      style={{
        flexDirection: 'row',
        alignItems: 'center',
        gap: spacing.sm,
        minHeight: touchTarget.min,
      }}
    >
      <Ionicons name={icon} size={18} color={theme.colors.accent} />
      <Text variant="body" tone="accent">
        {label}
      </Text>
    </Pressable>
  );
}
