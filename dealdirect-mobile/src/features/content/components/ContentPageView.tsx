import Ionicons from '@expo/vector-icons/Ionicons';
import { router } from 'expo-router';
import { useState, type ReactNode } from 'react';
import { Linking, Pressable, ScrollView, View } from 'react-native';
import Animated, { LinearTransition, useReducedMotion } from 'react-native-reanimated';

import {
  radius,
  screenPadding,
  scrollBottomPadding,
  spacing,
  touchTarget,
  typography,
  useTheme,
} from '@/theme';
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
 * LAYOUT RULES, SO EVERY PAGE READS THE SAME
 *
 * Prose blocks (paragraphs, headings, bullets, callouts, quotes, contacts, FAQ
 * rows) sit on a white surface; a run of them shares one card. Structural
 * blocks (card grids, stats, tags, actions) sit directly on the page, because
 * a card inside a card states its edge twice. Inside an accordion everything
 * is flat: the accordion is the surface.
 *
 * Bold runs inside a paragraph inherit the paragraph's size and take the
 * primary tone, so a defined term stands out by weight and colour and never
 * by growing.
 *
 * Nothing here knows which page it is rendering. A page that needs a new kind
 * of block gets a new `Block` variant and a case below, not a special screen.
 */

const STRUCTURAL: ReadonlySet<Block['type']> = new Set(['cards', 'stats', 'tags', 'actions']);

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
            padding: screenPadding,
            paddingBottom: scrollBottomPadding,
            gap: spacing.xl,
          }}
          keyboardShouldPersistTaps="handled"
        >
          <PageIntro page={page} />
          {page.parts ? <Parts parts={page.parts} /> : <Sections sections={page.sections} />}
          {children}
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}

function PageIntro({ page }: { page: ContentPage }) {
  if (!page.intro && !page.meta) return null;
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
      <Segmented
        options={parts.map((part) => ({ label: part.label, value: part.id }))}
        value={active.id}
        onChange={setActiveId}
        accessibilityLabel="Part of the terms"
      />
      {/* Keyed so switching parts resets every accordion to its own default
          rather than carrying one part's open state into another's clauses. */}
      <View key={active.id} style={{ gap: spacing.xl }}>
        {/* Flat, like the page intro above it: the preamble is callouts and a
            paragraph, and a tinted box inside a white card is a box in a box. */}
        {active.blocks?.length ? <BlockList blocks={active.blocks} nested /> : null}
        <Sections sections={active.sections} />
      </View>
    </>
  );
}

/* ------------------------------------------------------------- sections */

function Sections({ sections }: { sections: Section[] }) {
  // Accordions stack tight, like rows; open sections need air between them.
  const allCollapsible = sections.every((section) => section.collapsible);
  return (
    <View style={{ gap: allCollapsible ? spacing.sm : spacing.xl }}>
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

function OpenSection({ section }: { section: Section }) {
  return (
    <View style={{ gap: spacing.md }}>
      {section.title ? (
        // Top-aligned, with the icon nudged to sit centred on the title's
        // FIRST line. Centring on the whole block sent the icon drifting
        // down whenever a title wrapped.
        <View style={{ flexDirection: 'row', alignItems: 'flex-start', gap: spacing.md }}>
          {section.icon ? (
            <View style={{ marginTop: (typography.title3.lineHeight - ICON_BOX) / 2 }}>
              <IconBox name={section.icon} />
            </View>
          ) : null}
          <View style={{ flex: 1 }}>
            <Text variant="title3">{section.title}</Text>
            {section.blurb ? (
              <Text variant="footnote" tone="muted">
                {section.blurb}
              </Text>
            ) : null}
          </View>
        </View>
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
    <Animated.View layout={reduceMotion ? undefined : LinearTransition}>
      <Card radius="xl" padded={false}>
        <Pressable
          accessibilityRole="button"
          accessibilityState={{ expanded }}
          accessibilityLabel={section.title}
          onPress={() => setExpanded((value) => !value)}
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            gap: spacing.md,
            padding: spacing.base,
            minHeight: touchTarget.min,
          }}
        >
          {section.icon ? <IconBox name={section.icon} /> : null}
          <Text variant="bodyEmphasis" style={{ flex: 1 }}>
            {section.title}
          </Text>
          <Ionicons
            name={expanded ? 'chevron-up' : 'chevron-down'}
            size={18}
            color={theme.colors.textMuted}
          />
        </Pressable>

        {expanded ? (
          <View
            style={{
              paddingHorizontal: spacing.base,
              paddingBottom: spacing.base,
              paddingTop: spacing.md,
              borderTopWidth: 1,
              borderTopColor: theme.colors.border,
            }}
          >
            <BlockList blocks={section.blocks} nested />
          </View>
        ) : null}
      </Card>
    </Animated.View>
  );
}

const ICON_BOX = 32;

function IconBox({ name }: { name: IconName }) {
  const theme = useTheme();
  return (
    <View
      style={{
        width: ICON_BOX,
        height: ICON_BOX,
        borderRadius: radius.md,
        backgroundColor: theme.colors.accentMuted,
        alignItems: 'center',
        justifyContent: 'center',
      }}
    >
      <Ionicons name={name} size={17} color={theme.colors.accent} />
    </View>
  );
}

/* --------------------------------------------------------------- blocks */

/**
 * Lays out a section's blocks. Consecutive prose blocks share one card;
 * structural blocks stand on the page. `nested` (inside an accordion) drops
 * the cards and renders everything flat.
 */
function BlockList({ blocks, nested = false }: { blocks: Block[]; nested?: boolean }) {
  if (nested) {
    return (
      <View style={{ gap: spacing.md }}>
        {blocks.map((block, index) => (
          <BlockView key={index} block={block} nested />
        ))}
      </View>
    );
  }

  type Group = { prose: true; blocks: Block[] } | { prose: false; block: Block };
  const groups: Group[] = [];
  for (const block of blocks) {
    const last = groups[groups.length - 1];
    if (STRUCTURAL.has(block.type)) groups.push({ prose: false, block });
    else if (last?.prose) last.blocks.push(block);
    else groups.push({ prose: true, blocks: [block] });
  }

  return (
    <View style={{ gap: spacing.md }}>
      {groups.map((group, index) =>
        group.prose ? (
          <Card key={index} radius="xl">
            <View style={{ gap: spacing.md }}>
              {group.blocks.map((block, blockIndex) => (
                <BlockView key={blockIndex} block={block} nested />
              ))}
            </View>
          </Card>
        ) : (
          <BlockView key={index} block={group.block} />
        )
      )}
    </View>
  );
}

function BlockView({ block, nested = false }: { block: Block; nested?: boolean }) {
  switch (block.type) {
    case 'paragraph':
      return <Rich text={block.text} />;
    case 'heading':
      return <Text variant="bodyEmphasis">{block.text}</Text>;
    case 'bullets':
      return <Bullets items={block.items} />;
    case 'callout':
      return <Callout tone={block.tone} title={block.title} text={block.text} items={block.items} />;
    case 'cards':
      return <Cards items={block.items} nested={nested} />;
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
        <View style={{ gap: spacing.sm }}>
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
    <View style={{ backgroundColor: fill, borderRadius: radius.lg, padding: spacing.base, gap: spacing.sm }}>
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

function Cards({ items, nested }: { items: CardItem[]; nested: boolean }) {
  return (
    <View style={{ gap: spacing.md }}>
      {items.map((item) => {
        const body = (
          <View style={{ gap: spacing.sm }}>
            <View style={{ flexDirection: 'row', alignItems: 'center', gap: spacing.md }}>
              {item.icon ? <IconBox name={item.icon} /> : null}
              <View style={{ flex: 1 }}>
                <Text variant="bodyEmphasis">{item.title}</Text>
                {item.meta ? (
                  <Text variant="caption" tone="muted">
                    {item.meta}
                  </Text>
                ) : null}
              </View>
            </View>
            {item.text.split('\n\n').map((paragraph, index) => (
              <Rich key={index} text={paragraph} variant="callout" />
            ))}
            {item.footnote ? (
              <Text variant="footnote" tone="muted">
                {item.footnote}
              </Text>
            ) : null}
          </View>
        );
        return nested ? (
          <View
            key={item.title}
            className="rounded-lg bg-surface-muted"
            style={{ padding: spacing.base }}
          >
            {body}
          </View>
        ) : (
          <Card key={item.title} radius="lg">
            {body}
          </Card>
        );
      })}
    </View>
  );
}

function Stats({ items }: { items: { value: string; label: string }[] }) {
  return (
    <View style={{ flexDirection: 'row', flexWrap: 'wrap', gap: spacing.md }}>
      {items.map((item) => (
        <Card key={item.label} radius="lg" style={{ flexBasis: '46%', flexGrow: 1 }}>
          <Text variant="title2" tone="accent">
            {item.value}
          </Text>
          <Text variant="caption" tone="muted">
            {item.label.toUpperCase()}
          </Text>
        </Card>
      ))}
    </View>
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
          className="rounded-full border border-border bg-surface"
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
    <Animated.View layout={reduceMotion ? undefined : LinearTransition}>
      {items.map((item, index) => {
        const expanded = open.has(item.id);
        return (
          <View
            key={item.id}
            style={
              index < items.length - 1
                ? { borderBottomWidth: 1, borderBottomColor: theme.colors.border }
                : undefined
            }
          >
            <Pressable
              accessibilityRole="button"
              accessibilityState={{ expanded }}
              onPress={() => toggle(item.id)}
              style={{
                flexDirection: 'row',
                alignItems: 'center',
                gap: spacing.md,
                paddingVertical: spacing.md,
                minHeight: touchTarget.min,
              }}
            >
              <Text variant="bodyEmphasis" style={{ flex: 1 }}>
                {item.question}
              </Text>
              <Ionicons
                name={expanded ? 'chevron-up' : 'chevron-down'}
                size={18}
                color={theme.colors.textMuted}
              />
            </Pressable>
            {expanded ? (
              <View style={{ paddingBottom: spacing.base }}>
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
  return (
    <View style={{ gap: spacing.sm }}>
      {name ? <Text variant="title3">{name}</Text> : null}
      {role ? (
        <Text variant="footnote" tone="muted">
          {role}
        </Text>
      ) : null}
      {org ? <Text variant="bodyEmphasis">{org}</Text> : null}
      {address ? (
        <Text variant="body" tone="secondary">
          {address}
        </Text>
      ) : null}
      {email ? <ContactRow icon="mail-outline" label={email} url={`mailto:${email}`} /> : null}
      {phone ? (
        <ContactRow icon="call-outline" label={phone} url={`tel:${phone.replace(/[^\d+]/g, '')}`} />
      ) : null}
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
