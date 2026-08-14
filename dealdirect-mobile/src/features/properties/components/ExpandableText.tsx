import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useState } from 'react';
import {
  Pressable,
  Text as RNText,
  type NativeSyntheticEvent,
  type TextLayoutEventData,
} from 'react-native';
import Animated, { LinearTransition, useReducedMotion } from 'react-native-reanimated';

import { typography, useTheme } from '@/theme';
import { Text } from '@/ui';

/**
 * Body copy that clamps until asked to open.
 *
 * Owner-written descriptions run from one line to fifteen paragraphs, and the
 * long ones sit directly above the attribute table, the EMI calculator and the
 * owner block. Letting one listing push all of that three screens further down
 * than another makes the page's shape depend on how talkative its owner was.
 *
 * The toggle appears only when it would do something. A control that collapses
 * a four-line paragraph to four lines is a control that lies about having an
 * effect, so the line count is measured first and the toggle is conditional
 * on it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE MEASUREMENT IS A SEPARATE HIDDEN COPY
 *
 * `onTextLayout` on a clamped `Text` does not agree across platforms about
 * whether it reports the lines it drew or the lines it would have drawn, so
 * reading the count off the visible element gives the right answer on one
 * platform and "exactly the clamp, always" on the other.
 *
 * An unclamped copy is unambiguous on both. It is laid out once, never painted,
 * and hidden from the accessibility tree so the description is not announced
 * twice. The cost is a second text layout pass on mount, which is the price of
 * an answer that is the same on both platforms.
 *
 * ---------------------------------------------------------------------------
 * The expansion animates the CONTAINER, not the text. Everything below has to
 * move by the same amount at the same time, or the paragraph grows into its
 * neighbours and the page appears to break for a frame. `LinearTransition` on
 * the wrapper animates that relationship; under reduced motion the layout
 * simply lands, which is a jump the user asked for by pressing.
 */

const COLLAPSED_LINES = 6;

export interface ExpandableTextProps {
  text: string;
  /** Lines shown before expanding. */
  collapsedLines?: number;
  /** Matches the tone of the copy it replaces. */
  tone?: 'primary' | 'secondary';
}

export function ExpandableText({
  text,
  collapsedLines = COLLAPSED_LINES,
  tone = 'secondary',
}: ExpandableTextProps) {
  const theme = useTheme();
  const reduceMotion = useReducedMotion();

  const [expanded, setExpanded] = useState(false);
  const [lineCount, setLineCount] = useState<number | null>(null);

  const handleMeasure = useCallback(
    (event: NativeSyntheticEvent<TextLayoutEventData>) => {
      setLineCount(event.nativeEvent.lines.length);
    },
    []
  );

  const overflows = lineCount !== null && lineCount > collapsedLines;

  return (
    <Animated.View layout={reduceMotion ? undefined : LinearTransition}>
      {lineCount === null ? (
        <RNText
          onTextLayout={handleMeasure}
          accessibilityElementsHidden
          importantForAccessibility="no-hide-descendants"
          style={{
            position: 'absolute',
            opacity: 0,
            left: 0,
            right: 0,
            fontSize: typography.body.fontSize,
            lineHeight: typography.body.lineHeight,
            letterSpacing: typography.body.letterSpacing,
          }}
        >
          {text}
        </RNText>
      ) : null}

      <Text
        variant="body"
        tone={tone}
        numberOfLines={expanded || !overflows ? undefined : collapsedLines}
      >
        {text}
      </Text>

      {overflows ? (
        <Pressable
          accessibilityRole="button"
          accessibilityState={{ expanded }}
          accessibilityLabel={expanded ? 'Show less of the description' : 'Show the full description'}
          onPress={() => setExpanded((value) => !value)}
          hitSlop={12}
          className="mt-sm flex-row items-center self-start"
          style={({ pressed }) => (pressed ? { opacity: 0.6 } : undefined)}
        >
          <Text variant="bodyEmphasis" tone="accent">
            {expanded ? 'Show less' : 'Read more'}
          </Text>
          <Ionicons
            name={expanded ? 'chevron-up' : 'chevron-down'}
            size={15}
            color={theme.colors.accent}
            style={{ marginLeft: 4 }}
          />
        </Pressable>
      ) : null}
    </Animated.View>
  );
}
