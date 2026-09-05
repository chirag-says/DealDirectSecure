import Ionicons from '@expo/vector-icons/Ionicons';
import { Linking, View } from 'react-native';

import { WEB_URL } from '@/config/env';
import { relativeDay } from '@/lib';
import { useTheme } from '@/theme';
import type { DealDetail } from '@/types/backend/deal';
import { Button, Card, Text } from '@/ui';
import { isStageAtLeast } from '../stage';

/**
 * The agreement, as far as the app goes with it.
 *
 * D1 (HANDOFF §9.1) withdrew agreements from mobile; Phase 2 re-opens the
 * feature on the server behind `AGREEMENTS_ENABLED`, and the deal says so
 * with `agreementsEnabled`. When it is off this renders NOTHING, not a
 * "coming soon": a feature the server has switched off is not a feature.
 *
 * When it is on, the app still does not generate or sign. That is the
 * website's flow (a Gemini draft, HMAC signatures, a payment webhook) and
 * porting it is its own decision. So this card states what exists and sends
 * the user to the website for the act itself, in plain words.
 */

export interface AgreementCardProps {
  deal: Pick<DealDetail, 'agreementsEnabled' | 'agreement' | 'stage'>;
}

export function AgreementCard({ deal }: AgreementCardProps) {
  const theme = useTheme();

  if (!deal.agreementsEnabled) return null;

  const open = () => void Linking.openURL(`${WEB_URL}/agreements`);

  if (deal.agreement) {
    const when = relativeDay(deal.agreement.at);
    return (
      <Card>
        <View className="flex-row items-center">
          <Ionicons name="document-text-outline" size={18} color={theme.colors.success} />
          <Text variant="bodyEmphasis" className="ml-sm">
            Agreement generated
          </Text>
        </View>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {when ? `Drafted ${when}. ` : ''}Signing happens on the website for now.
        </Text>
        <View className="mt-base">
          <Button
            label="Open on the website"
            variant="secondary"
            size="sm"
            onPress={open}
            leading={<Ionicons name="open-outline" size={15} color={theme.colors.textPrimary} />}
          />
        </View>
      </Card>
    );
  }

  if (isStageAtLeast(deal.stage, 'visited')) {
    return (
      <Card>
        <Text variant="bodyEmphasis">Agreement</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          Both sides visited. An agreement can be drafted on the website; it appears here once it
          exists.
        </Text>
        <View className="mt-base">
          <Button
            label="Generate agreement on the website"
            variant="secondary"
            size="sm"
            onPress={open}
            leading={<Ionicons name="open-outline" size={15} color={theme.colors.textPrimary} />}
          />
        </View>
      </Card>
    );
  }

  return (
    <Card>
      <Text variant="bodyEmphasis">Agreement</Text>
      <Text variant="footnote" tone="muted" className="mt-xs">
        Available after a visit both sides confirm.
      </Text>
    </Card>
  );
}
