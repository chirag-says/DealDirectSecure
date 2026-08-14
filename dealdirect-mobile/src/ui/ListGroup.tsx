import Ionicons from '@expo/vector-icons/Ionicons';
import React, { Children, isValidElement } from 'react';
import { View, type ViewProps } from 'react-native';

import { radius, spacing, touchTarget, useTheme } from '@/theme';
import { PressableScale } from './PressableScale';
import { Text } from './Text';

/**
 * The grouped list: a rounded container of rows, on the page background.
 *
 * This is the single most common shape in the app — settings, profile, support,
 * every "here are your options" screen — and until 2026-08-13 each of those
 * screens built it by hand out of a `Card` with `p-0` and a local `MenuRow`
 * that only that file could use.
 *
 * ---------------------------------------------------------------------------
 * SEPARATORS ARE INSET, AND THAT IS THE WHOLE POINT
 *
 * A separator that runs the full width of the container turns a list into a
 * data table. Inset to the leading edge of the row's TEXT — past the icon, if
 * there is one — and the rows read as a group of related things instead. This
 * is the detail that most distinguishes a native-feeling list from a web one,
 * and it costs nothing.
 *
 * The separator is drawn by the row, not by the group, because only the row
 * knows whether it has a leading icon and therefore how far to inset. The
 * group tells the last row to skip it: a line under the final row draws a
 * boundary the container's own edge already draws.
 */

export interface ListGroupProps extends ViewProps {
  /** Uppercase label above the group. Optional; many groups need no name. */
  title?: string;
  /** Explanatory text below the group, in the manner of iOS settings. */
  footer?: string;
  className?: string;
}

export function ListGroup({ title, footer, className = '', children, ...rest }: ListGroupProps) {
  const items = Children.toArray(children).filter(Boolean);
  const lastIndex = items.length - 1;

  return (
    <View className={className} {...rest}>
      {title ? <SectionLabel>{title}</SectionLabel> : null}

      <View
        className="overflow-hidden bg-surface"
        style={{ borderRadius: radius.lg }}
      >
        {items.map((child, index) =>
          isValidElement<{ isLast?: boolean }>(child)
            ? React.cloneElement(child, { isLast: index === lastIndex })
            : child
        )}
      </View>

      {footer ? (
        <Text
          variant="footnote"
          tone="muted"
          style={{ marginTop: spacing.sm, paddingHorizontal: spacing.xs }}
        >
          {footer}
        </Text>
      ) : null}
    </View>
  );
}

/**
 * The label above a group or a section of a screen.
 *
 * Sentence case at `subhead`, not uppercase at `overline`. Uppercase is louder
 * than a group name needs to be when there are four of them down one screen,
 * and it costs legibility at 13px for no gain in hierarchy that weight and
 * colour do not already provide.
 */
export function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <Text
      variant="subhead"
      tone="secondary"
      style={{ marginBottom: spacing.sm, paddingHorizontal: spacing.xs }}
    >
      {children}
    </Text>
  );
}

export interface ListRowProps {
  label: string;
  /** Second line, for context or current value. */
  detail?: string;
  /** Right-aligned value, for a setting that has one. */
  value?: string;
  icon?: keyof typeof Ionicons.glyphMap;
  onPress?: () => void;
  /** Shows the disclosure chevron. Defaults to true when pressable. */
  chevron?: boolean;
  /** Renders the label in the danger tone, for destructive rows. */
  destructive?: boolean;
  /** Replaces the trailing accessory entirely — a Switch, a Badge, a spinner. */
  trailing?: React.ReactNode;
  /** Set by `ListGroup`. Suppresses the separator on the final row. */
  isLast?: boolean;
}

export function ListRow({
  label,
  detail,
  value,
  icon,
  onPress,
  chevron,
  destructive = false,
  trailing,
  isLast = false,
}: ListRowProps) {
  const theme = useTheme();
  const showChevron = chevron ?? Boolean(onPress);

  // The separator starts where the text starts, so it clears the icon when
  // there is one. See the module doc.
  const separatorInset = icon ? spacing.base + 22 + spacing.md : spacing.base;

  const body = (
    <View style={{ paddingLeft: spacing.base }}>
      <View
        className="flex-row items-center"
        style={{
          minHeight: touchTarget.min,
          paddingVertical: spacing.md,
          paddingRight: spacing.base,
        }}
      >
        {icon ? (
          <Ionicons
            name={icon}
            size={22}
            color={destructive ? theme.colors.danger : theme.colors.textSecondary}
            style={{ marginRight: spacing.md }}
          />
        ) : null}

        <View className="flex-1">
          <Text variant="body" tone={destructive ? 'danger' : 'primary'} numberOfLines={1}>
            {label}
          </Text>
          {detail ? (
            <Text variant="footnote" tone="secondary" numberOfLines={2} style={{ marginTop: 2 }}>
              {detail}
            </Text>
          ) : null}
        </View>

        {trailing ?? (
          <>
            {value ? (
              <Text variant="callout" tone="secondary" numberOfLines={1} style={{ marginLeft: spacing.sm }}>
                {value}
              </Text>
            ) : null}
            {showChevron ? (
              <Ionicons
                name="chevron-forward"
                size={18}
                color={theme.colors.textMuted}
                style={{ marginLeft: spacing.xs }}
              />
            ) : null}
          </>
        )}
      </View>

      {!isLast ? (
        <View
          style={{
            height: 1,
            backgroundColor: theme.colors.border,
            marginLeft: separatorInset - spacing.base,
          }}
        />
      ) : null}
    </View>
  );

  if (!onPress) return body;

  return (
    <PressableScale
      accessibilityRole="button"
      accessibilityLabel={label}
      onPress={onPress}
      // Barely there. A row inside a group is not a floating object, so it
      // should acknowledge the touch without appearing to lift off the page.
      activeScale={0.995}
    >
      {body}
    </PressableScale>
  );
}
