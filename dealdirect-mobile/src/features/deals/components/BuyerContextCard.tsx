import { View } from 'react-native';

import { buyerContextFacts } from '@/features/leads';
import { spacing } from '@/theme';
import type { BuyerContext } from '@/types/backend/deal';
import { Card, Text } from '@/ui';

/**
 * Owner only: the buyer in four aggregate numbers, each with its meaning.
 *
 * Aggregates, never a history. The server computes these across everything
 * the buyer has done on DealDirect and hands over only the totals, so an
 * owner can weigh seriousness without being shown which other listings the
 * buyer looked at. The meaning line under each number is what keeps the
 * number honest: "4" is a figure, "owners they have contacted" is a fact.
 */

export interface BuyerContextCardProps {
  context: BuyerContext;
  /** The owner's own note on the lead, read-only here. */
  notes?: string;
}

export function BuyerContextCard({ context, notes }: BuyerContextCardProps) {
  const facts = buyerContextFacts(context);

  return (
    <Card>
      <Text variant="bodyEmphasis">About this buyer</Text>
      <Text variant="caption" tone="muted" className="mt-xs">
        Totals across DealDirect. Only you see this.
      </Text>

      <View className="mt-base flex-row flex-wrap" style={{ rowGap: spacing.base }}>
        {facts.map((fact) => (
          <View key={fact.label} style={{ width: '50%', paddingRight: spacing.sm }}>
            <Text variant="title3" numberOfLines={1}>
              {fact.value}
            </Text>
            <Text variant="footnote" tone="secondary">
              {fact.label}
            </Text>
            <Text variant="caption" tone="muted" className="mt-xs">
              {fact.meaning}
            </Text>
          </View>
        ))}
      </View>

      {notes?.trim() ? (
        <View className="mt-base border-t border-border pt-base">
          <Text variant="footnote" tone="secondary">
            Your notes
          </Text>
          <Text variant="body" className="mt-xs">
            {notes.trim()}
          </Text>
        </View>
      ) : null}
    </Card>
  );
}
