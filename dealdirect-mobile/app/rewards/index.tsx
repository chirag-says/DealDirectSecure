import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { Share, View } from 'react-native';

import { useAuth, SignInPrompt } from '@/auth';
import { copyToClipboard, selection } from '@/native';
import { useReferral, useRewardsPolicy, useTransactions, useWallet } from '@/features/rewards';
import type { NextTierProgress, RewardTier, RewardTransaction } from '@/types/backend/rewards';
import { screenPadding, scrollBottomPadding, spacing, touchTarget, useTheme } from '@/theme';
import {
  Badge,
  Button,
  Card,
  PressableScale,
  ProgressBar,
  Refreshable,
  Screen,
  ScreenHeader,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * Rewards: balance, tier, referrals and activity.
 *
 * REDEMPTION IS DELIBERATELY ABSENT. The in-house store/redeem endpoints are
 * deleted backend-side, and the website's only redemption path is the Hubble
 * SDK iframe, which has no native equivalent. Mobile redemption is its own
 * workstream with its own approval (HANDOFF §9.1 D3) because real money moves
 * through it. Until then this screen sends the user to the website rather
 * than pretending a redemption path exists here.
 */
export default function RewardsScreen() {
  const { status } = useAuth();
  const theme = useTheme();

  const wallet = useWallet();
  const transactions = useTransactions();
  const referral = useReferral();

  if (status !== 'authenticated') {
    return (
      <Screen>
        <SignInPrompt
          icon="gift-outline"
          title="Your rewards"
          description="Earn points for enquiring, listing a property and referring friends."
        />
      </Screen>
    );
  }

  // `wallet.isLoading` is the FIRST load, not a refresh. Including it made the
  // pull-to-refresh spinner appear on cold open, over a screen that was already
  // showing its own skeletons.
  const isRefreshing = transactions.isRefreshing;

  return (
    <Screen>
      <ScreenHeader title="Rewards" backTo="/(tabs)/profile" />

      <Refreshable
        contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
        refreshing={isRefreshing}
        onRefresh={() => {
          wallet.refresh();
          transactions.refresh();
        }}
      >
        <Card padded={false} className="items-center px-base py-lg">
          <Text variant="footnote" tone="secondary">
            Your balance
          </Text>
          {/*
            A FAILED FETCH MUST NOT RENDER AS A BALANCE OF ZERO.

            `balance` defaults to 0 when the wallet is null, and the null case
            includes every error, so a dropped request told a user with points
            that they had none — in the largest type on the screen, about their
            money. An em dash and a retry say the true thing: we do not know.
          */}
          {wallet.isLoading ? (
            <Skeleton width={120} height={36} className="mt-sm" />
          ) : wallet.error ? (
            <Text variant="display" className="mt-xs">
              —
            </Text>
          ) : (
            <Text variant="display" className="mt-xs">
              {wallet.balance.toLocaleString('en-IN')}
            </Text>
          )}
          <Text variant="caption" tone="muted">
            points
          </Text>

          {/*
            Milestone points (Phase 3) sit outside the balance by construction:
            the backend routes them into `lockedPoints`, never into
            `availablePoints`. Shown only when there are any, and said plainly,
            so nobody reads the balance and the tier as disagreeing.
          */}
          {!wallet.isLoading && !wallet.error && wallet.lockedPoints > 0 ? (
            <View className="mt-md items-center px-md">
              <View className="flex-row items-center">
                <Ionicons name="lock-closed-outline" size={14} color={theme.colors.textMuted} />
                <Text variant="footnote" tone="secondary" className="ml-xs">
                  {wallet.lockedPoints.toLocaleString('en-IN')} locked
                </Text>
              </View>
              <Text variant="caption" tone="muted" className="mt-xs text-center">
                Locked milestone points count toward your tier and unlock only at a verified
                close.
              </Text>
            </View>
          ) : null}

          {wallet.error && !wallet.isLoading ? (
            <View className="mt-sm items-center">
              <Text variant="footnote" tone="danger">
                We could not load your balance.
              </Text>
              <PressableScale
                accessibilityRole="button"
                accessibilityLabel="Retry loading your balance"
                onPress={wallet.refresh}
                className="mt-xs"
              >
                <Text variant="footnote" tone="accent">
                  Try again
                </Text>
              </PressableScale>
            </View>
          ) : null}

          {wallet.tier ? (
            <View className="mt-base items-center">
              <Badge label={TIER_LABEL[wallet.tier]} tone={TIER_TONE[wallet.tier]} />
              {wallet.tierMultiplier > 1 ? (
                <Text variant="caption" tone="muted" className="mt-xs">
                  Earning {wallet.tierMultiplier}× points
                </Text>
              ) : null}
            </View>
          ) : null}
        </Card>

        {wallet.nextTierProgress ? (
          <TierProgressCard progress={wallet.nextTierProgress} />
        ) : null}

        <ReferralCard
          code={referral.referralCode}
          link={referral.referralLink}
          totalReferred={referral.totalReferred}
          signups={referral.signups}
          firstActions={referral.firstActions}
          dealClosures={referral.dealClosures}
        />

        <RedeemCard />

        <HowRewardsWork />

        <TransactionsSection
          transactions={transactions.transactions}
          isLoading={transactions.isLoading}
          error={transactions.error}
          onRetry={transactions.refresh}
          total={transactions.totalTransactions}
        />
      </Refreshable>
    </Screen>
  );
}

const TIER_LABEL: Record<RewardTier, string> = {
  bronze: 'Bronze',
  silver: 'Silver',
  gold: 'Gold',
  diamond: 'Diamond',
};

/** The design system has no metallics; these map tier rank onto its tones. */
const TIER_TONE: Record<RewardTier, 'neutral' | 'accent' | 'warning' | 'success'> = {
  bronze: 'neutral',
  silver: 'accent',
  gold: 'warning',
  diamond: 'success',
};

function TierProgressCard({ progress }: { progress: NextTierProgress }) {
  // At diamond there is no next tier, so a progress bar would be meaningless.
  if (!progress.nextTier) {
    return (
      <Card className="mt-base">
        <Text variant="bodyEmphasis">Top tier reached</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          You are earning at the highest rate available.
        </Text>
      </Card>
    );
  }

  return (
    <Card className="mt-base">
      <View className="flex-row items-center justify-between">
        <Text variant="bodyEmphasis">Next: {TIER_LABEL[progress.nextTier]}</Text>
        <Text variant="footnote" tone="secondary">
          {progress.progress}%
        </Text>
      </View>

      <View className="mt-sm">
        <ProgressBar
          value={progress.progress / 100}
          label={`${progress.progress}% toward ${TIER_LABEL[progress.nextTier]}`}
        />
      </View>

      {progress.pointsNeeded > 0 ? (
        <Text variant="footnote" tone="secondary" className="mt-sm">
          {progress.pointsNeeded.toLocaleString('en-IN')} more lifetime points to go.
        </Text>
      ) : null}
    </Card>
  );
}

/**
 * Redemption lives on the website. Stating that plainly, with a way to get
 * there, is better than a store section that silently renders nothing —
 * which is what shipped before, once the backend routes were removed.
 */
function RedeemCard() {
  const router = useRouter();

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis">Redeem your points</Text>
      <Text variant="footnote" tone="secondary" className="mb-base mt-xs">
        Spend your points on gift cards and vouchers, without leaving the app.
      </Text>
      <Button label="Browse rewards" onPress={() => router.push('/rewards/redeem')} />
    </Card>
  );
}

/**
 * The numbers behind the programme, from `GET /rewards/policy`.
 *
 * Numbers only, no promises: each line states what the server is configured
 * to award and when, and nothing here says "earn up to" or "guaranteed". The
 * milestone list renders only when the server has milestones switched on;
 * the close payout and the hold are always present because a verified close
 * is the one reward this programme has always paid.
 *
 * The section is an explainer, so a failed fetch gets one retry line rather
 * than an error state of its own on a screen that already has the balance to
 * worry about.
 */
function HowRewardsWork() {
  const { policy, isLoading, error, refresh } = useRewardsPolicy();

  if (isLoading) {
    return <Skeleton height={140} radius={16} className="mt-base" />;
  }

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis">How rewards work</Text>

      {error || !policy ? (
        <View className="mt-xs">
          <Text variant="footnote" tone="secondary">
            We could not load the details.
          </Text>
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Retry loading how rewards work"
            onPress={refresh}
            className="mt-xs"
          >
            <Text variant="footnote" tone="accent">
              Try again
            </Text>
          </PressableScale>
        </View>
      ) : (
        <View className="mt-sm" style={{ gap: spacing.sm }}>
          {policy.milestones.map((milestone) => (
            <PolicyLine
              key={milestone.key}
              icon="flag-outline"
              text={`${milestone.points.toLocaleString('en-IN')} locked points ${milestone.when}`}
            />
          ))}

          <PolicyLine
            icon="ribbon-outline"
            text={
              policy.close.fixedPoints > 0
                ? `A verified close pays ${policy.close.fixedPoints.toLocaleString('en-IN')} points plus a reward draw.`
                : 'A verified close pays a reward draw.'
            }
          />

          <PolicyLine
            icon="time-outline"
            text={
              policy.close.holdDaysFlagged > policy.close.holdDays
                ? `Close rewards unlock after ${policy.close.holdDays} days, or ${policy.close.holdDaysFlagged} days when a deal needs an extra check.`
                : `Close rewards unlock after ${policy.close.holdDays} days.`
            }
          />

          {policy.pointValueRupees > 0 ? (
            <PolicyLine
              icon="cash-outline"
              text={`1 point is worth ₹${policy.pointValueRupees.toLocaleString('en-IN')} at redemption.`}
            />
          ) : null}
        </View>
      )}
    </Card>
  );
}

function PolicyLine({
  icon,
  text,
}: {
  icon: React.ComponentProps<typeof Ionicons>['name'];
  text: string;
}) {
  const theme = useTheme();
  return (
    <View className="flex-row items-start">
      <Ionicons
        name={icon}
        size={16}
        color={theme.colors.textMuted}
        style={{ marginTop: 2 }}
      />
      <Text variant="footnote" tone="secondary" className="ml-sm flex-1">
        {text}
      </Text>
    </View>
  );
}

function ReferralCard({
  code,
  link,
  totalReferred,
  signups,
  firstActions,
  dealClosures,
}: {
  code: string | null;
  link: string | null;
  totalReferred: number;
  signups: number;
  firstActions: number;
  dealClosures: number;
}) {
  const theme = useTheme();
  const toast = useToast();

  /**
   * Tap the code to COPY it; the button below still shares.
   *
   * Tapping a code to copy it is the universal pattern, and it is what a user
   * reaching for their referral code to paste into a chat they are already
   * writing actually wants. Sharing is the separate, deliberate button.
   */
  const handleCopy = async () => {
    if (!code) return;
    const copied = await copyToClipboard(code);
    if (copied) {
      selection();
      toast.show('Referral code copied.', 'success');
    }
  };

  const handleShare = () => {
    if (!link && !code) return;
    void Share.share({
      message: link
        ? `Join DealDirect and skip the brokerage. Use my code ${code ?? ''}: ${link}`
        : `Join DealDirect and skip the brokerage. Use my referral code: ${code}`,
    });
  };

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis">Invite friends</Text>
      <Text variant="footnote" tone="secondary" className="mt-xs mb-base">
        {totalReferred > 0
          ? `${totalReferred} friend${totalReferred === 1 ? '' : 's'} joined so far.`
          : 'Earn points when someone signs up with your code.'}
      </Text>

      {/*
        THE PILL IS THE CONTROL NOW, OR IT CARRIES NO ICON.

        It used to be a plain `View` with a share glyph in the corner: the most
        button-shaped thing in the card, and the only thing in it that did
        nothing when pressed. The real share was the button underneath. An
        appearance that contradicts its behaviour is the failure this whole
        pass keeps finding, so the pill became the control it already looked
        like — same target, same glyph, and now it shares.
      */}
      {code ? (
        <PressableScale
          accessibilityRole="button"
          accessibilityLabel={`Copy your referral code ${code}`}
          onPress={() => void handleCopy()}
          activeScale={0.98}
          style={{ marginBottom: spacing.base }}
        >
          <View
            className="flex-row items-center justify-between rounded-lg bg-surface-muted px-base"
            style={{ minHeight: touchTarget.min }}
          >
            <Text variant="bodyEmphasis" className="tracking-wide">
              {code}
            </Text>
            <Ionicons name="copy-outline" size={18} color={theme.colors.textMuted} />
          </View>
        </PressableScale>
      ) : null}

      {totalReferred > 0 ? (
        <View className="mb-base flex-row">
          <ReferralStat label="Signed up" value={signups} />
          <ReferralStat label="Active" value={firstActions} />
          <ReferralStat label="Closed a deal" value={dealClosures} />
        </View>
      ) : null}

      <Button label="Share invite" variant="secondary" onPress={handleShare} disabled={!code} />
    </Card>
  );
}

function ReferralStat({ label, value }: { label: string; value: number }) {
  return (
    <View className="flex-1">
      <Text variant="title3">{value}</Text>
      <Text variant="caption" tone="muted">
        {label}
      </Text>
    </View>
  );
}

function TransactionsSection({
  transactions,
  isLoading,
  error,
  onRetry,
  total,
}: {
  transactions: RewardTransaction[];
  isLoading: boolean;
  error: unknown;
  onRetry: () => void;
  total: number;
}) {
  // One page of 50 is fetched. Saying so beats silently truncating.
  const hasMore = total > transactions.length;

  return (
    <View className="mt-lg">
      <Text variant="title3" className="mb-base">
        Activity
      </Text>
      {isLoading ? (
        <Skeleton height={56} radius={12} />
      ) : error ? (
        /* "No activity yet" is a statement about the user's history. It must
           not be produced by our own failed request. */
        <View>
          <Text variant="callout" tone="danger">
            We could not load your activity.
          </Text>
          <PressableScale
            accessibilityRole="button"
            accessibilityLabel="Retry loading your activity"
            onPress={onRetry}
            className="mt-xs"
          >
            <Text variant="footnote" tone="accent">
              Try again
            </Text>
          </PressableScale>
        </View>
      ) : transactions.length === 0 ? (
        <Text variant="callout" tone="secondary">
          No activity yet.
        </Text>
      ) : (
        <>
          {transactions.map((tx, index) => (
            <TransactionRow key={tx._id ?? index} tx={tx} />
          ))}
          {hasMore ? (
            <Text variant="footnote" tone="muted" className="mt-sm">
              Showing your {transactions.length} most recent of {total}.
            </Text>
          ) : null}
        </>
      )}
    </View>
  );
}

function TransactionRow({ tx }: { tx: RewardTransaction }) {
  const points = typeof tx.points === 'number' ? tx.points : 0;
  const positive = points >= 0;

  return (
    <View className="mb-sm flex-row items-center justify-between border-b border-border pb-sm">
      <View className="flex-1 pr-base">
        <Text variant="body">{tx.description ?? tx.type ?? 'Transaction'}</Text>
        {tx.createdAt ? (
          <Text variant="caption" tone="muted">
            {new Date(tx.createdAt).toLocaleDateString('en-IN', { dateStyle: 'medium' })}
          </Text>
        ) : null}
      </View>
      <Text variant="bodyEmphasis" tone={positive ? 'success' : 'danger'}>
        {positive ? '+' : ''}
        {points}
      </Text>
    </View>
  );
}
