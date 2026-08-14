import Ionicons from '@expo/vector-icons/Ionicons';
import { View } from 'react-native';

import { radius, spacing, useTheme } from '@/theme';
import { PressableScale, Text } from '@/ui';

/**
 * The research tools, as two cards on Home.
 *
 * ---------------------------------------------------------------------------
 * TWO, NOT SIX
 *
 * Housing.com's home carries six — EMI, Eligibility, Affordability, Area,
 * Valuation, Rent Value — and shipping six because they ship six would be
 * copying the inventory rather than the idea. Three of theirs (Valuation, Rent
 * Value, Area) need data or a model we do not have, and Eligibility is
 * Affordability asked backwards.
 *
 * So: the two that a buyer on this app can actually use, at a size where the
 * label is readable, rather than six tiles of which four lead somewhere
 * disappointing. The row goes in the day another one has something behind it.
 *
 * ---------------------------------------------------------------------------
 * WHY IT SITS BETWEEN INVENTORY AND THE PITCH
 *
 * A user who has scrolled past the popular listings and the builder projects
 * has seen what things cost and is, at that exact moment, wondering whether
 * they can afford any of it. That is the question these answer. Higher up they
 * would interrupt browsing with homework; lower down, past the marketing
 * copy, they would be read as more marketing.
 */

/**
 * The literal union, not `string`. Expo Router types every route in the app,
 * so a `string` here would not satisfy `router.push` at the call site and
 * would need a cast — which is exactly the check that stops a renamed file
 * from silently becoming a dead tile.
 */
export type ToolRoute = '/tools/affordability' | '/tools/emi';

interface Tool {
  icon: keyof typeof Ionicons.glyphMap;
  title: string;
  body: string;
  route: ToolRoute;
}

const TOOLS: readonly Tool[] = [
  {
    icon: 'wallet-outline',
    title: 'What can I afford?',
    body: 'Turn your income and savings into a budget',
    route: '/tools/affordability',
  },
  {
    icon: 'calculator-outline',
    title: 'EMI calculator',
    body: 'Work out the monthly payment on a loan',
    route: '/tools/emi',
  },
];

export interface ToolsRowProps {
  onOpen: (route: ToolRoute) => void;
}

export function ToolsRow({ onOpen }: ToolsRowProps) {
  const theme = useTheme();

  return (
    <View className="px-base" style={{ gap: spacing.md }}>
      {TOOLS.map((tool) => (
        <PressableScale
          key={tool.route}
          accessibilityRole="button"
          accessibilityLabel={`${tool.title}. ${tool.body}`}
          onPress={() => onOpen(tool.route)}
          activeScale={0.99}
          style={{
            flexDirection: 'row',
            alignItems: 'center',
            padding: spacing.base,
            borderRadius: radius.lg,
            backgroundColor: theme.colors.surface,
            shadowColor: '#000',
            shadowOpacity: 0.05,
            shadowRadius: 8,
            shadowOffset: { width: 0, height: 2 },
            elevation: 2,
          }}
        >
          <View
            style={{
              width: 42,
              height: 42,
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: radius.full,
              backgroundColor: theme.colors.accentMuted,
            }}
          >
            <Ionicons name={tool.icon} size={21} color={theme.colors.accent} />
          </View>

          <View className="ml-base flex-1">
            <Text variant="bodyEmphasis">{tool.title}</Text>
            <Text variant="footnote" tone="secondary" className="mt-xs">
              {tool.body}
            </Text>
          </View>

          <Ionicons name="chevron-forward" size={18} color={theme.colors.textMuted} />
        </PressableScale>
      ))}
    </View>
  );
}
