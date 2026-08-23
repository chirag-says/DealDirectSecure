import Ionicons from '@expo/vector-icons/Ionicons';
import { useLocalSearchParams, useRouter } from 'expo-router';
import { useCallback, useState } from 'react';
import { Linking, ScrollView, View, type LayoutChangeEvent } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { ApiError } from '@/api';
import { setPendingIntent, useAuth } from '@/auth';
import {
  useCampaignsForUnitType,
  useCreateBooking,
  useProjectDetail,
  useUnitTypeDetail,
} from '@/features/projects';
import { screenPadding, spacing, useTheme } from '@/theme';
import type { GroupBuyCampaign, UnitType } from '@/types/backend/project';
import {
  Badge,
  Button,
  Card,
  ErrorState,
  Image,
  Input,
  KeyboardAvoider,
  PriceLabel,
  Screen,
  ScreenHeader,
  Sheet,
  Skeleton,
  Text,
  useToast,
} from '@/ui';

/** What the buyer is being asked for. Drives the copy, not just the payload. */
type Intent = 'booking' | 'enquiry';

export default function UnitTypeScreen() {
  const router = useRouter();
  const theme = useTheme();
  const { unitTypeId, resume } = useLocalSearchParams<{ unitTypeId: string; resume?: string }>();
  const { unitType, isLoading, error, refresh } = useUnitTypeDetail(unitTypeId);
  const { campaigns } = useCampaignsForUnitType(unitTypeId);
  const { status } = useAuth();
  const insets = useSafeAreaInsets();
  /**
   * `resume` carries which CTA a guest pressed before signing in, so the sheet
   * they asked for opens on arrival. Validated against the two real values
   * rather than cast: a deep link must not be able to raise a payment sheet on
   * its own say-so.
   */
  const [intent, setIntent] = useState<Intent | null>(
    resume === 'booking' || resume === 'enquiry' ? resume : null
  );

  const projectId =
    typeof unitType?.project === 'object' ? unitType.project?._id : unitType?.project;

  /**
   * The project is fetched for ONE field: `financials.bookingAmount`, the
   * legacy fallback in the server's token resolution. Without it this screen
   * cannot tell "no token configured anywhere" from "configured at project
   * level", and would hide a booking button that would have worked.
   *
   * Nearly free in practice — arriving here means the project detail is already
   * in cache, and it is held for 30 minutes.
   */
  const { project } = useProjectDetail(projectId ?? '');

  /**
   * Measured, not assumed. The scroll view used a hardcoded `paddingBottom:
   * 100` to clear the action bar, which is wrong on the first device with a
   * different bottom inset and wrong again when the label wraps at a large
   * text size. Same approach `property/[id]` takes with `DetailActions`.
   */
  const [actionBarHeight, setActionBarHeight] = useState(96);
  const onActionBarLayout = useCallback(
    (event: LayoutChangeEvent) => setActionBarHeight(event.nativeEvent.layout.height),
    []
  );

  const isAuthenticated = status === 'authenticated';

  // `POST /bookings` is authMiddleware-gated, so a guest who filled this form
  // in would only discover that at submit — and a 401 there reads as a dead
  // session rather than "please sign in". Gate before the form opens, which
  // is what the website does too.
  const openSheet = (next: Intent) => {
    if (!isAuthenticated) {
      // Which of the two CTAs was pressed is recorded, not just the unit: the
      // book and enquire paths differ in what they ask for and what they cost,
      // so returning a signed-in user to the wrong sheet would be worse than
      // returning them to neither. See `auth/pendingIntent.ts`.
      setPendingIntent({ kind: 'unit', unitTypeId, intent: next });
      router.push('/(auth)/login');
      return;
    }
    setIntent(next);
  };

  if (isLoading) {
    return (
      <Screen>
        <View className="p-base">
          <Skeleton height={200} radius={16} className="mb-base" />
          <Skeleton height={120} radius={12} />
        </View>
      </Screen>
    );
  }

  if (error || !unitType) {
    return (
      <Screen>
        <ErrorState title="Could not load this unit type" onRetry={refresh} />
      </Screen>
    );
  }

  const price = unitType.pricing?.effectivePrice ?? unitType.pricing?.basePrice;
  // `twoDUrl` / `threeDUrl`, not `twoDFloorPlan` — see the note on the type.
  // This read has been `undefined` since the screen shipped.
  const floorPlan = unitType.floorPlans?.twoDUrl ?? unitType.floorPlans?.threeDUrl;
  const videoUrl = unitType.floorPlans?.videoUrl;

  /**
   * Availability, read from the field that exists. `inventory.available` was
   * read here for months and is not on the model — see the note on the type.
   *
   * The server's gate is `availableUnits >= 1`, and it runs BEFORE the enquiry
   * exemption, so an unset or exhausted count refuses a question as firmly as a
   * payment. The two causes get different copy because they mean different
   * things to a buyer: one is "come back later", the other is "we have not
   * published this yet".
   */
  const available = unitType.inventory?.availableUnits;
  const hasUnits = typeof available === 'number' && available >= 1;
  const soldOut = typeof available === 'number' && available <= 0;

  /**
   * The token, resolved exactly as the server resolves it. This figure is for
   * DISPLAY and for deciding which buttons to show; the amount actually owed is
   * always the one the create response returns.
   */
  const bookingAmount =
    unitType.paymentTerms?.bookingAmount ?? project?.financials?.bookingAmount ?? 0;
  const canBook = bookingAmount > 0;

  return (
    <Screen>
      {/*
        Back to the PROJECT, not the projects list. This screen is only ever
        reached from a project's unit-type rows, so `/projects` skipped a level
        and dropped the user two screens back from where they were. Falls back
        to the list only when the unit type carries no project reference.
      */}
      <ScreenHeader
        title={unitType.config?.name ?? 'Unit type'}
        backTo={projectId ? `/projects/${projectId}` : '/projects'}
      />

      <ScrollView
        contentContainerStyle={{
          padding: screenPadding,
          paddingBottom: actionBarHeight + spacing.xl,
        }}
      >
        {floorPlan ? (
          <Image uri={floorPlan} size="full" style={{ width: '100%', height: 220, borderRadius: 12 }} />
        ) : null}

        <Card className="mt-base">
          {price ? <PriceLabel price={price} variant="title1" /> : null}
          <View className="mt-sm flex-row flex-wrap">
            {unitType.config?.bedrooms ? (
              <SpecChip label={`${unitType.config.bedrooms} Bed`} />
            ) : null}
            {unitType.config?.bathrooms ? (
              <SpecChip label={`${unitType.config.bathrooms} Bath`} />
            ) : null}
            {hasUnits ? <SpecChip label={`${available} available`} /> : null}
          </View>
        </Card>

        {unitType.highlights && unitType.highlights.length > 0 ? (
          <Card className="mt-base">
            <Text variant="bodyEmphasis" className="mb-sm">
              Highlights
            </Text>
            {unitType.highlights.map((h) => (
              <View key={h} className="mb-xs flex-row items-start">
                <Ionicons name="checkmark-circle" size={16} color={theme.colors.success} />
                <Text variant="body" className="ml-sm flex-1">
                  {h}
                </Text>
              </View>
            ))}
          </Card>
        ) : null}

        <AreaCard unitType={unitType} />
        <PriceBreakdown unitType={unitType} />
        <CostSheet unitType={unitType} />
        <SpecsCard specs={unitType.specifications} />
        <InventoryCard inventory={unitType.inventory} />
        <InteriorPhotos photos={unitType.photos} />

        {videoUrl ? (
          /*
            Linked, never embedded. The field is free-text and admins paste
            YouTube links, Drive links and raw MP4s into it interchangeably —
            a player that assumes any one of those is broken for the other two,
            and the website made the same call for the same reason.
          */
          <Card
            className="mt-base flex-row items-center justify-between"
            onPress={() => void Linking.openURL(videoUrl)}
          >
            <View className="flex-1 pr-base">
              <Text variant="bodyEmphasis">Video tour</Text>
              <Text variant="footnote" tone="secondary" className="mt-xs">
                Opens outside the app
              </Text>
            </View>
            <Ionicons name="play-circle" size={28} color={theme.colors.accent} />
          </Card>
        ) : null}

        {/* Group buy is held product-wide — `useCampaignsForUnitType` returns
            nothing while the flag is off, so this section stays dark with it.
            See config/features.ts. */}
        {campaigns.length > 0 ? (
          <View className="mt-base">
            <Text variant="title3" className="mb-sm">
              Group buy
            </Text>
            {campaigns.map((campaign) => (
              <CampaignRow
                key={campaign._id}
                campaign={campaign}
                onPress={() => router.push(`/projects/campaign/${campaign._id}`)}
              />
            ))}
          </View>
        ) : null}
      </ScrollView>

      {/*
        The action bar. `insets.bottom` was missing entirely, so on any device
        with a home indicator the button sat underneath it.
      */}
      <View
        onLayout={onActionBarLayout}
        className="border-t border-border bg-surface"
        style={{
          paddingHorizontal: screenPadding,
          paddingTop: spacing.md,
          paddingBottom: insets.bottom + spacing.md,
        }}
      >
        {/* A disabled control needs to say why. A greyed button with no caption
            is the most common way an interface makes a user feel stupid - see
            `DetailActions`, which states its own refusal. */}
        {!hasUnits ? (
          <Text variant="caption" tone="muted" className="mb-sm">
            {soldOut
              ? 'Every unit of this type is taken. Other unit types in this project may still be available.'
              : 'Availability for this unit type has not been published yet. Please check back, or contact us.'}
          </Text>
        ) : !canBook ? (
          /*
            The honest version of a missing booking amount.

            Three of the eight real unit types have none, and a booking against
            them is refused server-side with BOOKING_NOT_CONFIGURED. Showing a
            "Book" button that cannot succeed teaches the user the app is
            broken; the enquiry below is a real path to the same outcome.
          */
          <Text variant="caption" tone="muted" className="mb-sm">
            Token booking is not set up for this unit yet. Send an enquiry and our team will
            call you with the payment details.
          </Text>
        ) : null}

        {canBook ? (
          <Button
            label={isAuthenticated ? 'Book this unit' : 'Sign in to book'}
            disabled={!hasUnits}
            fullWidth
            onPress={() => openSheet('booking')}
          />
        ) : null}

        <Button
          label={canBook ? 'Enquire — no payment needed' : 'Enquire about this unit'}
          variant={canBook ? 'secondary' : 'primary'}
          disabled={!hasUnits}
          fullWidth
          className={canBook ? 'mt-sm' : undefined}
          onPress={() => openSheet('enquiry')}
        />
      </View>

      {projectId ? (
        <BookingSheet
          intent={intent}
          onClose={() => setIntent(null)}
          projectId={projectId}
          unitTypeId={unitType._id}
          bookingAmount={bookingAmount}
        />
      ) : null}
    </Screen>
  );
}

function SpecChip({ label }: { label: string }) {
  return <Badge label={label} className="mb-xs mr-sm" />;
}

/** ₹ with Indian digit grouping. */
function rupees(value: number): string {
  return `₹${Math.round(value).toLocaleString('en-IN')}`;
}

/** One label/value line. The unit page is mostly these. */
function Row({
  label,
  value,
  emphasis = false,
  tone,
}: {
  label: string;
  value: string;
  emphasis?: boolean;
  tone?: 'secondary' | 'success';
}) {
  return (
    <View className="flex-row items-baseline justify-between py-xs">
      <Text variant={emphasis ? 'bodyEmphasis' : 'body'} tone={tone === 'success' ? 'primary' : 'secondary'} className="flex-1 pr-base">
        {label}
      </Text>
      <Text variant={emphasis ? 'bodyEmphasis' : 'body'} tone={tone === 'success' ? 'success' : 'primary'}>
        {value}
      </Text>
    </View>
  );
}

function AreaCard({ unitType }: { unitType: UnitType }) {
  const area = unitType.area;
  if (!area) return null;

  const rows: [string, string][] = [];
  if (area.carpetSqft) rows.push(['Carpet area', `${area.carpetSqft} sq.ft`]);
  if (area.builtUpSqft) rows.push(['Built-up area', `${area.builtUpSqft} sq.ft`]);
  if (area.superBuiltUpSqft) rows.push(['Super built-up', `${area.superBuiltUpSqft} sq.ft`]);
  if (area.plotAreaSqft) rows.push(['Plot area', `${area.plotAreaSqft} sq.ft`]);

  const dims = area.plotDimensions;
  if (dims?.length && dims?.width) rows.push(['Plot dimensions', `${dims.length} × ${dims.width} ft`]);
  if (unitType.pricing?.pricePerSqft) {
    rows.push(['Rate', `${rupees(unitType.pricing.pricePerSqft)} / sq.ft`]);
  }
  if (unitType.furnishing) rows.push(['Furnishing', unitType.furnishing]);
  if (unitType.facing?.length) rows.push(['Facing', unitType.facing.join(', ')]);

  const parking = unitType.parking;
  const parkingParts = [
    parking?.covered ? `${parking.covered} covered` : null,
    parking?.open ? `${parking.open} open` : null,
    parking?.ev ? `${parking.ev} EV` : null,
  ].filter(Boolean);
  if (parkingParts.length) rows.push(['Parking', parkingParts.join(' · ')]);

  if (rows.length === 0) return null;

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis" className="mb-sm">
        Area and configuration
      </Text>
      {rows.map(([label, value]) => (
        <Row key={label} label={label} value={value} />
      ))}
    </Card>
  );
}

/**
 * What makes up the list price.
 *
 * `effectivePrice` is base + these charges + view premium, computed in a
 * pre-save hook on the server. Showing the parts matters because the headline
 * figure is otherwise unexplained — a buyer comparing two projects needs to
 * know whether parking and clubhouse are inside the number or waiting after it.
 */
function PriceBreakdown({ unitType }: { unitType: UnitType }) {
  const pricing = unitType.pricing;
  const charges = pricing?.additionalCharges;
  const base = pricing?.basePrice ?? 0;

  const candidates: [string, number][] = [
    ['PLC', charges?.plc ?? 0],
    ['Parking', charges?.parking ?? 0],
    ['Clubhouse', charges?.clubhouse ?? 0],
    ['Legal', charges?.legal ?? 0],
    ['Maintenance', charges?.maintenance ?? 0],
    ['View premium', pricing?.viewPremium ?? 0],
  ];
  const lines = candidates.filter(([, value]) => value > 0);

  if (!base || lines.length === 0) return null;

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis" className="mb-sm">
        Price breakdown
      </Text>
      <Row label="Base price" value={rupees(base)} />
      {lines.map(([label, value]) => (
        <Row key={label} label={label} value={rupees(value)} />
      ))}
      {pricing?.effectivePrice ? (
        <View className="mt-xs border-t border-border pt-sm">
          <Row label="List price" value={rupees(pricing.effectivePrice)} emphasis />
        </View>
      ) : null}
    </Card>
  );
}

/**
 * The all-inclusive figure.
 *
 * GST, stamp duty and registration are deliberately kept OUT of
 * `effectivePrice` server-side — they are government charges, not list price,
 * and folding them in would misstate the comparison against every other
 * listing. So they are added here instead, and only here, with the percentages
 * shown so the arithmetic is checkable.
 *
 * Hidden entirely when none of the three is configured: a "total" identical to
 * the price above it teaches the buyer nothing and implies there is nothing
 * more to pay, which is a promise this data cannot make.
 */
function CostSheet({ unitType }: { unitType: UnitType }) {
  const terms = unitType.paymentTerms;
  const base = unitType.pricing?.effectivePrice ?? unitType.pricing?.basePrice ?? 0;

  const gst = terms?.gstPercentage ? Math.round((base * terms.gstPercentage) / 100) : 0;
  const stamp = terms?.stampDutyPercentage
    ? Math.round((base * terms.stampDutyPercentage) / 100)
    : 0;
  const registration = terms?.registrationCharges ?? 0;

  if (!base || (gst === 0 && stamp === 0 && registration === 0)) return null;

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis" className="mb-sm">
        All-inclusive cost
      </Text>
      <Row label="List price" value={rupees(base)} />
      {gst > 0 ? <Row label={`GST (${terms?.gstPercentage}%)`} value={rupees(gst)} /> : null}
      {stamp > 0 ? (
        <Row label={`Stamp duty (${terms?.stampDutyPercentage}%)`} value={rupees(stamp)} />
      ) : null}
      {registration > 0 ? <Row label="Registration" value={rupees(registration)} /> : null}
      <View className="mt-xs border-t border-border pt-sm">
        <Row label="Total" value={rupees(base + gst + stamp + registration)} emphasis />
      </View>
      <Text variant="caption" tone="muted" className="mt-sm">
        Indicative. Government charges vary by state and are confirmed at registration.
      </Text>
    </Card>
  );
}

function SpecsCard({ specs }: { specs: UnitType['specifications'] }) {
  if (!specs) return null;

  const rows: [string, string][] = [];
  const add = (label: string, value: unknown) => {
    if (typeof value === 'string' && value.trim()) rows.push([label, value.trim()]);
  };

  add('Structure', specs.structure);
  add('Living / dining floor', specs.flooring?.livingDining);
  add('Bedroom floor', specs.flooring?.bedrooms);
  add('Kitchen floor', specs.flooring?.kitchen);
  add('Bathroom floor', specs.flooring?.bathroom);
  add('Balcony floor', specs.flooring?.balcony);
  add('Kitchen countertop', specs.kitchen?.countertop);
  add('Sink', specs.kitchen?.sink);
  add('Sanitaryware', specs.bathroom?.sanitaryBrand);
  add('Bath fittings', specs.bathroom?.fittingsBrand);
  add('Dado height', specs.bathroom?.dadoHeight);
  add('Main door', specs.doors?.mainDoor);
  add('Internal doors', specs.doors?.internalDoors);
  add('Windows', specs.windows?.type);
  add('Wiring', specs.electrical?.wiringType);
  add('Switches', specs.electrical?.switchBrand);

  // Booleans read as absent when false, which is correct: "no modular kitchen"
  // is not a specification anyone advertises, and rendering it as a row would
  // turn an unfilled field into a stated negative.
  const flags = [
    specs.kitchen?.isModular ? 'Modular kitchen' : null,
    specs.kitchen?.chimney ? 'Chimney' : null,
    specs.windows?.mosquitoMesh ? 'Mosquito mesh' : null,
    specs.electrical?.acPointsPerRoom
      ? `${specs.electrical.acPointsPerRoom} AC point${specs.electrical.acPointsPerRoom === 1 ? '' : 's'} per room`
      : null,
  ].filter(Boolean) as string[];

  if (rows.length === 0 && flags.length === 0) return null;

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis" className="mb-sm">
        Specifications
      </Text>
      {rows.map(([label, value]) => (
        <Row key={label} label={label} value={value} />
      ))}
      {flags.length > 0 ? (
        <View className="mt-sm flex-row flex-wrap">
          {flags.map((flag) => (
            <SpecChip key={flag} label={flag} />
          ))}
        </View>
      ) : null}
    </Card>
  );
}

function InventoryCard({ inventory }: { inventory: UnitType['inventory'] }) {
  if (!inventory) return null;

  const { availableUnits, bookedUnits, totalUnits, towerAllocation } = inventory;
  if (availableUnits == null && totalUnits == null) return null;

  return (
    <Card className="mt-base">
      <Text variant="bodyEmphasis" className="mb-sm">
        Availability
      </Text>
      {availableUnits != null ? (
        <Row label="Available" value={`${availableUnits} units`} tone="success" />
      ) : null}
      {bookedUnits != null && bookedUnits > 0 ? (
        <Row label="Booked" value={`${bookedUnits} units`} />
      ) : null}
      {totalUnits != null ? <Row label="Total" value={`${totalUnits} units`} /> : null}

      {Array.isArray(towerAllocation) && towerAllocation.length > 0 ? (
        <View className="mt-sm border-t border-border pt-sm">
          <Text variant="footnote" tone="secondary" className="mb-xs">
            By tower
          </Text>
          {towerAllocation.map((entry, index) => {
            const tower = entry as { tower?: string; units?: number };
            if (!tower?.tower) return null;
            return (
              <Row
                key={`${tower.tower}-${index}`}
                label={tower.tower}
                value={`${tower.units ?? 0} units`}
              />
            );
          })}
        </View>
      ) : null}
    </Card>
  );
}

/** Interior photos, grouped by the room they belong to. */
function InteriorPhotos({ photos }: { photos: UnitType['photos'] }) {
  if (!photos || photos.length === 0) return null;

  const grouped = new Map<string, { url: string; caption?: string }[]>();
  for (const photo of photos) {
    if (!photo?.url) continue;
    const room = photo.room?.trim() || 'Other';
    const bucket = grouped.get(room) ?? [];
    bucket.push({ url: photo.url, caption: photo.caption });
    grouped.set(room, bucket);
  }
  if (grouped.size === 0) return null;

  return (
    <View className="mt-base">
      <Text variant="title3" className="mb-sm">
        Interiors
      </Text>
      {[...grouped.entries()].map(([room, items]) => (
        <View key={room} className="mb-base">
          <Text variant="footnote" tone="secondary" className="mb-xs">
            {room}
          </Text>
          <ScrollView horizontal showsHorizontalScrollIndicator={false}>
            {items.map((item, index) => (
              <Image
                key={`${item.url}-${index}`}
                uri={item.url}
                size="medium"
                style={{ width: 220, height: 150, borderRadius: 12, marginRight: spacing.sm }}
              />
            ))}
          </ScrollView>
        </View>
      ))}
    </View>
  );
}

function CampaignRow({ campaign, onPress }: { campaign: GroupBuyCampaign; onPress: () => void }) {
  const theme = useTheme();

  // `Card`'s own `onPress` rather than a wrapping `Pressable`: the bare
  // Pressable this used had no `style` callback, so the row gave no feedback
  // on touch at all. Card springs.
  return (
    <Card onPress={onPress} className="mb-base flex-row items-center justify-between">
      <View className="flex-1 pr-base">
        <Text variant="bodyEmphasis">{campaign.basics?.name ?? 'Group buy'}</Text>
        <Text variant="footnote" tone="secondary" className="mt-xs">
          {campaign.memberCount ?? 0} joined
          {campaign.status ? ` · ${campaign.status}` : ''}
        </Text>
      </View>
      <Ionicons name="chevron-forward" size={20} color={theme.colors.textMuted} />
    </Card>
  );
}

/**
 * One sheet, two asks.
 *
 * A booking and an enquiry post the same body to the same route and differ by a
 * single field, so they are one form. What changes is what the buyer is being
 * told: a booking quotes money and leads to a payment screen, an enquiry
 * promises a callback and leads nowhere. Duplicating the form to say that would
 * mean two places to fix the next time the field list moves.
 */
function BookingSheet({
  intent,
  onClose,
  projectId,
  unitTypeId,
  bookingAmount,
}: {
  intent: Intent | null;
  onClose: () => void;
  projectId: string;
  unitTypeId: string;
  bookingAmount: number;
}) {
  const router = useRouter();
  const toast = useToast();
  const { user } = useAuth();
  const { createBooking, isPending, error, reset } = useCreateBooking();

  const [clientName, setClientName] = useState(user?.name ?? '');
  const [clientPhone, setClientPhone] = useState(user?.phone ?? '');
  const [clientEmail, setClientEmail] = useState(user?.email ?? '');
  const [notes, setNotes] = useState('');

  const isEnquiry = intent === 'enquiry';

  const close = () => {
    reset();
    onClose();
  };

  const handleSubmit = async () => {
    try {
      const response = await createBooking({
        projectId,
        unitTypeId,
        clientName: clientName.trim(),
        clientPhone: clientPhone.trim(),
        clientEmail: clientEmail.trim() || undefined,
        notes: notes.trim() || undefined,
        ...(isEnquiry ? { intent: 'enquiry' as const } : {}),
      });

      close();

      if (isEnquiry) {
        // Nothing is owed, so there is nowhere to send them. The server's own
        // sentence is the right one — it is the promise being made.
        toast.show(response.message || 'Thanks — our team will call you shortly.');
        return;
      }

      router.push(`/projects/booking/${response.data.bookingId}`);
    } catch {
      // surfaced via `error` below
    }
  };

  /**
   * Every refusal this route makes is one the buyer can do something about, so
   * each gets its own sentence and, where there is one, its own way out. The
   * generic message would be true and useless: "please check the details" for a
   * unit that is simply sold out.
   */
  const refusal = (() => {
    if (!(error instanceof ApiError)) return null;

    switch (error.code) {
      case 'DUPLICATE_ENQUIRY':
        return {
          message:
            'You already have an open request for this unit. Cancel it from My bookings if you want to start again.',
          actionLabel: 'View my bookings',
          onAction: () => {
            close();
            router.push('/projects/bookings');
          },
        };
      case 'NO_INVENTORY':
        return {
          message:
            'The last unit of this type went while this was open. Nothing was submitted.',
        };
      case 'BOOKING_NOT_CONFIGURED':
        return {
          message:
            'Token booking is not set up for this unit yet. Send an enquiry instead and our team will call you.',
        };
      default:
        return { message: error.message };
    }
  })();

  return (
    <Sheet
      visible={intent !== null}
      onClose={close}
      title={isEnquiry ? 'Enquire about this unit' : 'Book this unit'}
      heightRatio={0.75}
    >
      <KeyboardAvoider>
        <ScrollView contentContainerStyle={{ padding: 24 }} keyboardShouldPersistTaps="handled">
          <Text variant="footnote" tone="secondary" className="mb-base">
            {isEnquiry
              ? 'No payment needed. Our team will call you back about this unit — availability, pricing and next steps.'
              : bookingAmount > 0
                ? `This reserves the unit with a token payment of ₹${bookingAmount.toLocaleString('en-IN')}, which you submit on the next screen.`
                : 'This reserves the unit with a token payment, submitted after the builder confirms your request.'}
          </Text>

          <Input label="Full name" value={clientName} onChangeText={setClientName} />
          <Input
            label="Phone"
            value={clientPhone}
            onChangeText={setClientPhone}
            keyboardType="phone-pad"
            containerClassName="mt-base"
          />
          <Input
            label="Email (optional)"
            value={clientEmail}
            onChangeText={setClientEmail}
            keyboardType="email-address"
            autoCapitalize="none"
            containerClassName="mt-base"
          />
          <Input
            label={isEnquiry ? 'What would you like to know? (optional)' : 'Notes (optional)'}
            value={notes}
            onChangeText={setNotes}
            multiline
            containerClassName="mt-base"
          />

          {refusal ? (
            <View className="mt-base">
              <Text variant="footnote" tone="danger">
                {refusal.message}
              </Text>
              {refusal.actionLabel ? (
                <Button
                  label={refusal.actionLabel}
                  variant="secondary"
                  className="mt-sm"
                  onPress={refusal.onAction}
                />
              ) : null}
            </View>
          ) : null}

          <Button
            label={isEnquiry ? 'Send enquiry' : 'Confirm booking'}
            className="mt-lg"
            loading={isPending}
            disabled={!clientName.trim() || !clientPhone.trim()}
            onPress={() => void handleSubmit()}
          />
        </ScrollView>
      </KeyboardAvoider>
    </Sheet>
  );
}
