import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { RefreshControl, ScrollView, View, type LayoutChangeEvent } from 'react-native';

import { track } from '@/analytics';
import { ApiError } from '@/api';
import { RequireAuth, useAuth } from '@/auth';
import {
  AgreementCard,
  BuyerContextCard,
  CloseCard,
  CounterpartCard,
  DealMessages,
  DealProgress,
  VisitCard,
  VisitSheet,
  isVisitOpen,
  stageLabel,
  useAttestClose,
  useDeal,
  useProposeVisit,
  useUpdateVisit,
  useVisitFeedback,
  visitUpdateErrorCopy,
} from '@/features/deals';
import { SocketProvider } from '@/socket';
import { radius, screenPadding, scrollBottomPadding, spacing, useTheme } from '@/theme';
import type { DealDetail, Visit, VisitAction, VisitFeedback } from '@/types/backend/deal';
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Image,
  KeyboardAvoider,
  PriceLabel,
  Screen,
  ScreenHeader,
  SectionLabel,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/**
 * The deal page: one lead, both sides, everything that has happened on it.
 *
 * ---------------------------------------------------------------------------
 * ONE SCREEN, IN THE ORDER THINGS HAPPEN
 *
 *   the listing         what this is about (tap: the public detail)
 *   progress            where it stands, five rows
 *   the other party     who, verified or not, phone once revealed
 *   visits              the open one with its controls; earlier ones under it
 *   messages            the thread, on this page, not a separate screen
 *   agreement           only when the server has the feature on
 *   close               verification, attestation, claim, review
 *   about this buyer    owner only: four totals and the owner's own notes
 *
 * ---------------------------------------------------------------------------
 * THE SOCKET LIVES EXACTLY WHILE THIS PAGE IS OPEN
 *
 * D2 (HANDOFF §9.1) unmounted `SocketProvider` from the root. It is mounted
 * HERE, around the message wall and only when the deal has a conversation,
 * so the connection exists while a thread is on screen and not otherwise.
 * `SocketProvider` disconnects in its effect cleanup for exactly this use.
 *
 * ---------------------------------------------------------------------------
 * A DEEP LINK LANDS, IT DOES NOT ACT
 *
 * `/deal/:leadId` is where every deal, visit and message push resolves. The
 * page renders the state; nothing here opens a sheet, confirms a visit or
 * starts a claim because of the way it was reached. A lapsed session goes
 * through `RequireAuth` with a `deal` intent, which brings the user back to
 * this page and nothing more.
 */
export default function DealRoute() {
  const { leadId } = useLocalSearchParams<{ leadId: string }>();

  return (
    <RequireAuth
      title="Deal"
      promptTitle="Sign in to see this deal"
      promptDescription="Deals are private to the buyer and the owner. Sign in and we will bring you straight back here."
      icon="briefcase-outline"
      backTo="/(tabs)/activity"
      intent={leadId ? { kind: 'deal', leadId } : undefined}
    >
      <DealScreen />
    </RequireAuth>
  );
}

function DealScreen() {
  const { leadId } = useLocalSearchParams<{ leadId: string }>();
  const { user } = useAuth();
  const { deal, isLoading, isRefreshing, error, isNotAParty, isMissing, refresh } =
    useDeal(leadId);

  // Once per mount, once the stage is known. A refetch does not re-fire.
  const tracked = useRef(false);
  useEffect(() => {
    if (!deal || tracked.current) return;
    tracked.current = true;
    track('deal_open', { leadId: deal.id, stage: deal.stage });
  }, [deal]);

  if (isLoading || (!deal && !error)) {
    return (
      <Screen>
        <ScreenHeader title="Deal" backTo="/(tabs)/activity" />
        <DealSkeleton />
      </Screen>
    );
  }

  if (!deal) {
    return (
      <Screen>
        <ScreenHeader title="Deal" backTo="/(tabs)/activity" />
        {isNotAParty ? (
          <ErrorState
            title="Not your deal"
            description="This deal belongs to another account. If you have more than one, sign in with the one that made the enquiry."
          />
        ) : isMissing ? (
          <ErrorState
            title="We could not find this deal"
            description="It may have been removed, or the link is out of date."
          />
        ) : (
          <ErrorState
            title="Could not load this deal"
            description={error instanceof ApiError ? error.message : undefined}
            requestId={error instanceof ApiError ? error.requestId : undefined}
            onRetry={refresh}
          />
        )}
      </Screen>
    );
  }

  return (
    <DealBody deal={deal} userId={user?._id ?? ''} isRefreshing={isRefreshing} refresh={refresh} />
  );
}

function DealBody({
  deal,
  userId,
  isRefreshing,
  refresh,
}: {
  deal: DealDetail;
  userId: string;
  isRefreshing: boolean;
  refresh: () => void;
}) {
  const router = useRouter();
  const theme = useTheme();
  const toast = useToast();

  const propose = useProposeVisit(deal.id);
  const update = useUpdateVisit(deal.id);
  const feedback = useVisitFeedback(deal.id);
  const attest = useAttestClose(deal.id);

  const counterpartName =
    deal.counterpart?.name ?? (deal.role === 'buyer' ? 'the owner' : 'the buyer');

  // --- Visits ---------------------------------------------------------------

  const visits = useMemo(
    () =>
      [...deal.visits].sort((a, b) => {
        // The open visit first, then newest first.
        const openA = isVisitOpen(a) ? 0 : 1;
        const openB = isVisitOpen(b) ? 0 : 1;
        if (openA !== openB) return openA - openB;
        return new Date(b.scheduledAt).getTime() - new Date(a.scheduledAt).getTime();
      }),
    [deal.visits]
  );
  const hasOpenVisit = visits.some(isVisitOpen);
  const closed = deal.stage === 'closed';

  const [sheet, setSheet] = useState<{ open: boolean; replacing: Visit | null }>({
    open: false,
    replacing: null,
  });

  const failWith = useCallback(
    (caught: unknown, fallback: string) => {
      toast.show(
        caught instanceof ApiError
          ? visitUpdateErrorCopy(caught.code, caught.message || fallback)
          : fallback,
        'danger'
      );
    },
    [toast]
  );

  const handleAction = useCallback(
    async (visit: Visit, action: VisitAction) => {
      try {
        const response = await update.update({ visitId: visit.id, action });
        if (action === 'confirm') {
          track('visit_confirmed', { leadId: deal.id });
          toast.show('Visit confirmed.', 'success');
        } else if (action === 'done') {
          // The buyer's `visit_done` fires with their feedback instead, so
          // each party records the visit once.
          if (deal.role === 'owner') track('visit_done', { leadId: deal.id });
          toast.show(
            response.milestone
              ? `Visit recorded. ${response.milestone.pointsAwarded} milestone points added.`
              : 'Visit recorded.',
            'success'
          );
        } else if (action === 'cancel') {
          toast.show('Visit cancelled.');
        } else {
          toast.show('Recorded as not happened.');
        }
      } catch (caught) {
        failWith(caught, 'Could not update the visit.');
      }
    },
    [update, deal.id, deal.role, toast, failWith]
  );

  const handleFeedback = useCallback(
    async (visit: Visit, value: VisitFeedback) => {
      try {
        await feedback.give({ visitId: visit.id, feedback: value });
        track('visit_done', { leadId: deal.id, feedback: value });
        toast.show('Thanks. The owner can see your answer.', 'success');
      } catch (caught) {
        failWith(caught, 'Could not record your feedback.');
      }
    },
    [feedback, deal.id, toast, failWith]
  );

  /**
   * Plan or re-plan. "Propose another time" is a cancel of the current
   * proposal followed by a new proposal; the sheet only knows it is
   * replacing, and this is where the two requests are sequenced. If the
   * cancel fails the sheet shows why and nothing is proposed.
   */
  const handlePropose = useCallback(
    async (scheduledAt: string, note?: string) => {
      if (sheet.replacing) {
        await update.update({ visitId: sheet.replacing.id, action: 'cancel' });
      }
      await propose.propose({ scheduledAt, note });
      track('visit_proposed', { leadId: deal.id });
      toast.show(`Proposed. Waiting for ${counterpartName} to confirm.`, 'success');
    },
    [sheet.replacing, update, propose, deal.id, toast, counterpartName]
  );

  // --- Keyboard: bring the composer above it ---------------------------------

  const scrollRef = useRef<ScrollView>(null);
  const messagesLayout = useRef<{ y: number; height: number } | null>(null);
  const wantsComposerVisible = useRef(false);

  const revealComposer = useCallback((viewportHeight: number) => {
    const layout = messagesLayout.current;
    if (!layout || !wantsComposerVisible.current) return;
    wantsComposerVisible.current = false;
    const bottom = layout.y + layout.height + spacing.base;
    scrollRef.current?.scrollTo({ y: Math.max(0, bottom - viewportHeight), animated: true });
  }, []);

  const onComposerFocus = useCallback(() => {
    wantsComposerVisible.current = true;
  }, []);

  // The KeyboardAvoidingView shrinks the scroll view when the keyboard shows,
  // which fires this with the new, smaller height: the moment to scroll.
  const onScrollLayout = useCallback(
    (event: LayoutChangeEvent) => revealComposer(event.nativeEvent.layout.height),
    [revealComposer]
  );

  // --- Render -----------------------------------------------------------------

  const property = deal.property;
  const place = [property?.locality, property?.city].filter(Boolean).join(', ');

  const messages = (
    <DealMessages
      leadId={deal.id}
      conversation={deal.conversation}
      chatEnabled={deal.chatEnabled}
      counterpartName={counterpartName}
      onComposerFocus={onComposerFocus}
    />
  );

  return (
    <Screen>
      <ScreenHeader
        title={property?.title ?? 'Deal'}
        subtitle={`${deal.role === 'buyer' ? 'Buying' : 'Selling'} · ${stageLabel(deal.stage)}`}
        backTo="/(tabs)/activity"
      />

      <KeyboardAvoider>
        <ScrollView
          ref={scrollRef}
          onLayout={onScrollLayout}
          keyboardShouldPersistTaps="handled"
          contentContainerStyle={{ padding: screenPadding, paddingBottom: scrollBottomPadding }}
          refreshControl={
            <RefreshControl
              refreshing={isRefreshing}
              onRefresh={refresh}
              tintColor={theme.colors.textMuted}
              colors={[theme.colors.accent]}
              progressBackgroundColor={theme.colors.surface}
            />
          }
        >
          {/* The listing. */}
          <Card
            padded={false}
            className="flex-row items-center overflow-hidden"
            onPress={property ? () => router.push(`/property/${property.id}`) : undefined}
            accessibilityLabel={property ? `Open listing ${property.title}` : undefined}
          >
            <View
              style={{
                width: 84,
                height: 84,
                backgroundColor: theme.colors.surfaceMuted,
              }}
            >
              {property?.image ? (
                <Image uri={property.image} size="thumb" style={{ width: 84, height: 84 }} />
              ) : (
                <View className="flex-1 items-center justify-center">
                  <Ionicons name="home-outline" size={24} color={theme.colors.textMuted} />
                </View>
              )}
            </View>
            <View className="flex-1 px-base py-md">
              {property ? (
                <>
                  <Text variant="bodyEmphasis" numberOfLines={2}>
                    {property.title}
                  </Text>
                  <View className="mt-xs flex-row items-center">
                    {property.price ? (
                      <PriceLabel price={property.price} variant="subhead" numberOfLines={1} />
                    ) : null}
                    {place ? (
                      <Text
                        variant="caption"
                        tone="muted"
                        numberOfLines={1}
                        className={property.price ? 'ml-sm flex-1' : 'flex-1'}
                      >
                        {place}
                      </Text>
                    ) : null}
                  </View>
                </>
              ) : (
                <Text variant="body" tone="muted">
                  Listing no longer available
                </Text>
              )}
            </View>
            {property ? (
              <Ionicons
                name="chevron-forward"
                size={18}
                color={theme.colors.textMuted}
                style={{ marginRight: spacing.md }}
              />
            ) : null}
          </Card>

          <View className="mt-xl">
            <SectionLabel>Progress</SectionLabel>
            <Card>
              <DealProgress progress={deal.progress} />
            </Card>
          </View>

          <View className="mt-xl">
            <SectionLabel>{deal.role === 'buyer' ? 'Owner' : 'Buyer'}</SectionLabel>
            <CounterpartCard
              counterpart={deal.counterpart}
              role={deal.role}
              contactRevealed={deal.contactRevealed}
            />
          </View>

          <View className="mt-xl">
            <View className="flex-row items-center justify-between">
              <SectionLabel>Visits</SectionLabel>
              {hasOpenVisit ? <Badge label="1 open" tone="accent" className="mb-sm" /> : null}
            </View>

            {visits.length === 0 ? (
              <Card>
                <Text variant="footnote" tone="secondary">
                  {closed
                    ? 'No visits were recorded on this deal.'
                    : 'Nothing planned yet. Propose a time and the other side confirms it.'}
                </Text>
                {!closed ? (
                  <View className="mt-base">
                    <Button
                      label="Plan a visit"
                      size="sm"
                      onPress={() => setSheet({ open: true, replacing: null })}
                      leading={
                        <Ionicons name="calendar-outline" size={15} color={theme.colors.textOnAccent} />
                      }
                    />
                  </View>
                ) : null}
              </Card>
            ) : (
              <View style={{ gap: spacing.md }}>
                {visits.map((visit) => (
                  <VisitCard
                    key={visit.id}
                    visit={visit}
                    role={deal.role}
                    userId={userId}
                    counterpartName={counterpartName}
                    pending={update.pending}
                    feedbackPending={feedback.pending?.visitId === visit.id}
                    onAction={(v, action) => void handleAction(v, action)}
                    onProposeAnother={(v) => setSheet({ open: true, replacing: v })}
                    onFeedback={(v, value) => void handleFeedback(v, value)}
                  />
                ))}
                {!hasOpenVisit && !closed ? (
                  <Button
                    label="Plan another visit"
                    variant="secondary"
                    size="sm"
                    onPress={() => setSheet({ open: true, replacing: null })}
                  />
                ) : null}
              </View>
            )}
          </View>

          <View
            className="mt-xl"
            onLayout={(event) => {
              messagesLayout.current = {
                y: event.nativeEvent.layout.y,
                height: event.nativeEvent.layout.height,
              };
            }}
          >
            {deal.conversation && deal.chatEnabled ? (
              <SocketProvider>{messages}</SocketProvider>
            ) : (
              messages
            )}
          </View>

          {deal.agreementsEnabled ? (
            <View className="mt-xl">
              <AgreementCard deal={deal} />
            </View>
          ) : null}

          {deal.verification ? (
            <View className="mt-xl">
              <SectionLabel>Close</SectionLabel>
              <CloseCard
                verification={deal.verification}
                counterpartName={counterpartName}
                pending={attest.pending}
                onAttest={attest.attest}
              />
            </View>
          ) : null}

          {deal.role === 'owner' && deal.buyerContext ? (
            <View className="mt-xl">
              <BuyerContextCard context={deal.buyerContext} notes={deal.notes} />
            </View>
          ) : deal.role === 'owner' && deal.notes?.trim() ? (
            <View className="mt-xl">
              <Card>
                <Text variant="footnote" tone="secondary">
                  Your notes
                </Text>
                <Text variant="body" className="mt-xs">
                  {deal.notes.trim()}
                </Text>
              </Card>
            </View>
          ) : null}
        </ScrollView>
      </KeyboardAvoider>

      <VisitSheet
        visible={sheet.open}
        replacing={!!sheet.replacing}
        onClose={() => setSheet({ open: false, replacing: null })}
        onSubmit={handlePropose}
        isPending={propose.isPending || (!!sheet.replacing && update.isPending)}
      />
    </Screen>
  );
}

/** Mirrors the loaded composition so nothing jumps when the data lands. */
function DealSkeleton() {
  return (
    <View style={{ padding: screenPadding }}>
      <Skeleton height={84} radius={radius.lg} />
      <Skeleton width="30%" height={13} className="mt-xl" />
      <Skeleton height={220} radius={radius.lg} className="mt-sm" />
      <Skeleton width="24%" height={13} className="mt-xl" />
      <Skeleton height={88} radius={radius.lg} className="mt-sm" />
      <Skeleton width="20%" height={13} className="mt-xl" />
      <Skeleton height={120} radius={radius.lg} className="mt-sm" />
    </View>
  );
}
