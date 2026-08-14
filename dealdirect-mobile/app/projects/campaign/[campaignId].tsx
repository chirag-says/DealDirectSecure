import type * as ImagePickerModule from 'expo-image-picker';
import { useLocalSearchParams } from 'expo-router';
import { useState } from 'react';
import { Alert, ScrollView, View } from 'react-native';

import { ApiError } from '@/api';
import { optionalNativeModule } from '@/config/optionalNative';
import {
  useCampaignDetail,
  useExitCampaign,
  useJoinCampaign,
  useUploadPaymentProof,
} from '@/features/projects';
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * Optional: absent in Expo Go. A top-level import would throw while Expo
 * Router evaluates this route file to build its route tree, which breaks
 * routing rather than just this screen. See `config/optionalNative.ts`.
 */
const ImagePicker = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-image-picker') as typeof ImagePickerModule,
  'expo-image-picker',
  'Uploading payment proof needs a full build of the app.'
);

function waitMessage(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) return 'Please wait a moment and try again.';
  if (seconds < 60) return `Please wait about ${Math.ceil(seconds)} seconds and try again.`;
  return `Please wait about ${Math.ceil(seconds / 60)} minutes and try again.`;
}

/**
 * Group buy detail.
 *
 * There is no "am I already a member" endpoint on this backend — `join`,
 * `exit` and `detail` are the only three calls, and `detail` does not carry
 * per-user membership. So this screen cannot reliably show "Joined" for a
 * membership that happened in an earlier session; it tracks join/exit only
 * for what happens THIS session, and otherwise lets the backend's own 400
 * ("already a member" / "not a member") be the source of truth, surfaced as
 * the error message rather than guessed at client-side.
 */
export default function CampaignScreen() {
  const { campaignId } = useLocalSearchParams<{ campaignId: string }>();
  const toast = useToast();
  const { campaign, isLoading, error, refresh } = useCampaignDetail(campaignId);
  const { join, isPending: isJoining, error: joinError } = useJoinCampaign(campaignId);
  const { exit, isPending: isExiting, error: exitError } = useExitCampaign(campaignId);
  const { upload, isPending: isUploading, error: uploadError } = useUploadPaymentProof(campaignId);

  const [joinedThisSession, setJoinedThisSession] = useState(false);
  const [proofSubmitted, setProofSubmitted] = useState(false);

  if (isLoading) {
    return (
      <Screen>
        <View className="p-base">
          <Skeleton height={200} radius={16} />
        </View>
      </Screen>
    );
  }

  if (error || !campaign) {
    return (
      <Screen>
        <ErrorState title="Could not load this group buy" onRetry={refresh} />
      </Screen>
    );
  }

  const startDate = campaign.duration?.startDate ? new Date(campaign.duration.startDate) : undefined;
  const endDate = campaign.duration?.endDate ? new Date(campaign.duration.endDate) : undefined;
  const daysLeft = endDate ? Math.ceil((endDate.getTime() - Date.now()) / 86_400_000) : undefined;

  const activeError = joinError ?? exitError;

  const handleJoin = async () => {
    try {
      await join();
      setJoinedThisSession(true);
    } catch {
      // surfaced via joinError below
    }
  };

  const handleExit = () => {
    Alert.alert('Leave this group buy?', 'You can rejoin later if spots remain.', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Leave',
        style: 'destructive',
        onPress: async () => {
          try {
            await exit();
            setJoinedThisSession(false);
            toast.show('You have left this group buy.');
          } catch {
            // surfaced via exitError below
          }
        },
      },
    ]);
  };

  const handleUploadProof = async () => {
    if (!ImagePicker) return;

    const permission = await ImagePicker.requestMediaLibraryPermissionsAsync();
    if (!permission.granted) return;

    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ['images'],
      quality: 0.8,
    });
    if (result.canceled || !result.assets[0]) return;

    try {
      await upload(result.assets[0].uri);
      setProofSubmitted(true);
    } catch {
      // surfaced via uploadError below
    }
  };

  return (
    <Screen>
      <ScreenHeader title="Group buy" backTo="/projects" />

      <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 48 }}>
        <Card>
          <View className="flex-row items-center justify-between">
            <Text variant="title3" className="flex-1 pr-base">
              {campaign.basics?.name ?? 'Group buy'}
            </Text>
            {campaign.status ? <Badge label={campaign.status} tone="accent" /> : null}
          </View>

          {campaign.basics?.description ? (
            <Text variant="body" tone="secondary" className="mt-sm">
              {campaign.basics.description}
            </Text>
          ) : null}

          <View className="mt-base flex-row flex-wrap">
            <StatTile label="Members" value={String(campaign.memberCount ?? 0)} />
            <StatTile label="Paid" value={String(campaign.paidMemberCount ?? 0)} />
            {daysLeft !== undefined ? (
              <StatTile label="Days left" value={daysLeft > 0 ? String(daysLeft) : 'Ended'} />
            ) : null}
          </View>

          {startDate && endDate ? (
            <Text variant="footnote" tone="secondary" className="mt-base">
              {startDate.toLocaleDateString('en-IN', { dateStyle: 'medium' })} –{' '}
              {endDate.toLocaleDateString('en-IN', { dateStyle: 'medium' })}
            </Text>
          ) : null}
        </Card>

        <Card className="mt-base">
          <Text variant="bodyEmphasis">Joining this group</Text>
          <Text variant="footnote" tone="secondary" className="mt-xs mb-base">
            Join and exit requests are limited to 10 per 15 minutes.
          </Text>

          {activeError instanceof ApiError ? (
            <Text variant="footnote" tone="danger" className="mb-base">
              {activeError.kind === 'rateLimited'
                ? waitMessage(activeError.retryAfterSeconds)
                : activeError.message}
            </Text>
          ) : null}

          <View className="flex-row">
            <Button
              label="Join"
              className="mr-sm flex-1"
              loading={isJoining}
              disabled={joinedThisSession}
              onPress={() => void handleJoin()}
            />
            <Button
              label="Leave"
              variant="secondary"
              className="flex-1"
              loading={isExiting}
              onPress={handleExit}
            />
          </View>
        </Card>

        <Card className="mt-base">
          <Text variant="bodyEmphasis">Payment proof</Text>
          <Text variant="footnote" tone="secondary" className="mt-xs mb-base">
            Already joined? Upload a screenshot of your token payment.
          </Text>

          {uploadError instanceof ApiError ? (
            <Text variant="footnote" tone="danger" className="mb-base">
              {uploadError.message}
            </Text>
          ) : null}
          {proofSubmitted ? (
            <Badge label="Submitted" tone="success" className="mb-base" />
          ) : null}

          <Button
            label="Upload payment proof"
            variant="secondary"
            loading={isUploading}
            onPress={() => void handleUploadProof()}
          />
        </Card>
      </ScrollView>
    </Screen>
  );
}

function StatTile({ label, value }: { label: string; value: string }) {
  return (
    <View className="mr-lg">
      <Text variant="title3">{value}</Text>
      <Text variant="caption" tone="muted">
        {label}
      </Text>
    </View>
  );
}
