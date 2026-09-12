import Ionicons from '@expo/vector-icons/Ionicons';
import { useEffect, useMemo, useState } from 'react';
import { Image as RNImage, Pressable, ScrollView, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { spacing, useTheme, type Theme } from '@/theme';
import {
  Button,
  Card,
  Chip,
  DateField,
  Input,
  KeyboardAvoider,
  Select,
  Sheet,
  Skeleton,
  Text,
  formatPrice,
  useToast,
} from '@/ui';
import { captureListingImage, canCapture, canPickImages, pickListingImages } from '../imagePicker';
import {
  BHK_OPTIONS,
  COMMERCIAL_CONFIGS,
  COMMERCIAL_SUBTYPES,
  CONSTRUCTION_STATUS_OPTIONS,
  FACING_OPTIONS,
  FURNISHING_OPTIONS,
  PROPERTY_AGE_OPTIONS,
  TENANT_OPTIONS,
  amenitiesFor,
  photoCategoriesForType,
} from '../catalog';
import { PriceGuidanceLine } from '@/features/locality';
import { LocationPicker } from './LocationPicker';
import { useListingTaxonomy } from '../taxonomy';
import {
  photoCategoryLabel,
  type CategorizedPhoto,
  type ListingFormValues,
} from '../types';

const MAX_PHOTOS = 15;

/** Server limits (`validators/index.js`): title 5–200, description ≤ 5000. */
const TITLE_MIN = 5;
const TITLE_MAX = 200;
const DESCRIPTION_MAX = 5000;

/**
 * Which area figures make sense for a property type.
 *
 * Every listing used to be asked for all five: a flat for its plot area, a
 * plot for its carpet area. An owner facing a question that cannot apply to
 * their property either guesses or loses confidence in the form, and both
 * pollute the corpus. Land types get the plot figure only; houses on their
 * own land get plot plus the built figures; everything else gets the built
 * figures. Total area stays for commercial, where it is the figure quoted.
 */
function areaFieldsFor(categoryName: string, propertyTypeName: string) {
  const type = propertyTypeName.toLowerCase();
  const land = /plot|land/.test(type);
  const onOwnLand = /villa|independent|farm|row house|bungalow/.test(type);
  return {
    plot: land || onOwnLand,
    carpet: !land,
    builtUp: !land,
    superBuiltUp: !land && categoryName === 'Residential',
    total: !land && categoryName !== 'Residential',
  };
}

/** Digits only; a price typed with commas or a stray space still parses. */
function digits(value: string): string {
  return value.replace(/[^\d]/g, '');
}

/** The ₹/sqft the listing will carry, derived exactly as `formData.ts` does. */
function ratePerSqft(values: ListingFormValues): number | undefined {
  const price = Number(values.price);
  const area = [values.superBuiltUpSqft, values.builtUpSqft, values.totalSqft]
    .map((v) => Number(v))
    .find((v) => Number.isFinite(v) && v > 0);
  if (!Number.isFinite(price) || price <= 0 || !area) return undefined;
  return Math.round(price / area);
}

/**
 * Why the current step cannot be left yet, in the owner's words, or null.
 *
 * This replaced a bare `disabled` on Next. A button that will not press and
 * does not say why is the single most common reason a form is abandoned: the
 * owner has no way to know whether it is a missing field, a bug, or their
 * network. The reason is shown after the first attempt, and the field it
 * names is outlined, so the fix is one glance away.
 */
function stepBlocker(step: number, values: ListingFormValues): string | null {
  switch (step) {
    case 0:
      if (!values.categoryName.trim()) return 'Choose a category to continue.';
      if (!values.propertyTypeName.trim()) return 'Choose a property type to continue.';
      return null;
    case 1:
      if (values.title.trim().length < TITLE_MIN)
        return `Give the listing a title of at least ${TITLE_MIN} characters.`;
      return null;
    case 2:
      if (!values.locality.trim() && !values.city.trim())
        return 'Enter the locality and city, or use your location to fill them in.';
      if (!values.locality.trim()) return 'Enter the locality or area.';
      if (!values.city.trim()) return 'Enter the city.';
      return null;
    case 3:
      if (!values.price.trim())
        return values.listingType === 'Rent' ? 'Enter the monthly rent.' : 'Enter the price.';
      return null;
    default:
      return null;
  }
}

export interface ListingFormProps {
  values: ListingFormValues;
  onChange: (values: ListingFormValues) => void;
  /** Existing (already-uploaded) photos, tagged with their room. */
  existingPhotos: CategorizedPhoto[];
  onChangeExistingPhotos: (photos: CategorizedPhoto[]) => void;
  newPhotos: CategorizedPhoto[];
  onChangeNewPhotos: (photos: CategorizedPhoto[]) => void;
  onSubmit: () => void;
  submitLabel: string;
  isSubmitting: boolean;
  submitError?: string;
  /**
   * Every step is already complete, so every step is reachable from the
   * progress bar at once. The edit screen sets this: an owner changing one
   * price should not have to walk six steps to reach it.
   */
  allStepsReached?: boolean;
}

const STEP_TITLES = ['Category', 'Basics', 'Location', 'Price & area', 'Details', 'Photos', 'Review'];

/**
 * The shared multi-step body for both add and edit. What differs between the
 * two screens is entirely in how `values` is seeded and what `onSubmit` does —
 * this component only edits the in-memory form and never calls the network
 * itself.
 */
export function ListingForm({
  values,
  onChange,
  existingPhotos,
  onChangeExistingPhotos,
  newPhotos,
  onChangeNewPhotos,
  onSubmit,
  submitLabel,
  isSubmitting,
  submitError,
  allStepsReached = false,
}: ListingFormProps) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const [step, setStep] = useState(0);
  // The furthest step reached, so the progress bar can jump back to any
  // step already visited, and only those: forward jumps would skip the
  // checks that make the review step trustworthy.
  const [reached, setReached] = useState(allStepsReached ? STEP_TITLES.length - 1 : 0);
  // Set by a Next press that could not proceed. Errors are shown from then
  // on for that step, and cleared when the step changes.
  const [attempted, setAttempted] = useState(false);
  // Latitude and longitude are set by the map; typing them is for the rare
  // owner who has the numbers from elsewhere. Folded away by default.
  const [showCoordinates, setShowCoordinates] = useState(false);
  // uri of the tile whose category sheet is open, and which list it came
  // from — a photo's identity (existing vs new) determines which setter the
  // sheet writes back through.
  const [categorizing, setCategorizing] = useState<{ uri: string; list: 'existing' | 'new' } | null>(
    null
  );

  const set = <K extends keyof ListingFormValues>(key: K, value: ListingFormValues[K]) =>
    onChange({ ...values, [key]: value });

  /** Several fields in one write — see the note on `ResidentialDetails`. */
  const patch = (next: Partial<ListingFormValues>) => onChange({ ...values, ...next });

  /*
    The vocabulary comes from the server. See `taxonomy.ts` for why a constant
    here was failing half of all submissions at the final step.
  */
  const taxonomy = useListingTaxonomy();
  const toast = useToast();

  const activeCategory = useMemo(
    () => taxonomy.categories.find((c) => c.name === values.categoryName) ?? null,
    [taxonomy.categories, values.categoryName]
  );

  const propertyTypeOptions = useMemo(
    () => (activeCategory?.types ?? []).map((t) => ({ label: t, value: t })),
    [activeCategory]
  );

  /*
    Keep the selected type valid for the selected category, but ONLY once the
    real vocabulary is in hand.

    The old version cleared the field against a hardcoded list, which is what
    wiped an existing listing's property type the instant its owner opened Edit
    — `Villa`, `Independent House` and `Shop / Retail` are all real stored
    values that the list did not contain. Waiting for the fetch means a stored
    value is judged against the server's answer or not at all.
  */
  useEffect(() => {
    if (taxonomy.isLoading || taxonomy.categories.length === 0) return;
    if (!values.propertyTypeName) return;
    if (activeCategory?.types.includes(values.propertyTypeName)) return;

    /*
      Before clearing, see whether the type is simply filed under a different
      category than the form currently shows — which is the normal case when
      editing a listing whose category the form defaulted. Moving the category
      to match preserves the owner's data; clearing it destroys it.
    */
    const owner = taxonomy.categories.find((c) => c.types.includes(values.propertyTypeName));
    if (owner) {
      if (owner.name !== values.categoryName) set('categoryName', owner.name);
      return;
    }

    set('propertyTypeName', '');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.categoryName, values.propertyTypeName, taxonomy.isLoading, taxonomy.categories, activeCategory]);

  const totalPhotos = existingPhotos.length + newPhotos.length;
  const canAddMorePhotos = totalPhotos < MAX_PHOTOS;
  /*
    Per property TYPE, not merely per category. A Studio has no Building
    Exterior and a Warehouse has no Bedroom; asking for both was how mobile's
    single pair of lists behaved. `photoCategoriesForType` falls back the way
    the website does for a type it has no set for, which matters more here
    because the type list is fetched and can contain a name this table has not
    seen. Returns `{key,label,max,tip}`; the tiles below want `{label,value}`.
  */
  const photoCategories = photoCategoriesForType(values.categoryName, values.propertyTypeName);
  const categoryOptions = photoCategories.map((c) => ({ label: c.label, value: c.key }));

  // Both halves of step 0, because the server rejects a type that does not
  // sit under the category submitted alongside it.
  const blocker = useMemo(() => stepBlocker(step, values), [step, values]);
  const showErrors = attempted && blocker !== null;

  const goTo = (next: number) => {
    setStep(next);
    setReached((r) => Math.max(r, next));
    setAttempted(false);
  };

  const next = () => {
    if (blocker) {
      setAttempted(true);
      return;
    }
    goTo(step + 1);
  };

  const areaFields = areaFieldsFor(values.categoryName, values.propertyTypeName);
  const rate = ratePerSqft(values);
  const priceWords = values.price ? formatPrice(values.price) : '';

  const handlePickPhotos = async () => {
    const { uris, deniedPermission } = await pickListingImages({
      remainingSlots: MAX_PHOTOS - totalPhotos,
    });
    // Refusing permission and picking nothing are different events and were
    // both silent, so a denied prompt looked exactly like a broken button.
    if (deniedPermission) {
      toast.show('Photo access is off. Turn it on in Settings to add photos.', 'neutral');
      return;
    }
    if (uris.length === 0) return;
    onChangeNewPhotos([...newPhotos, ...uris.map((uri) => ({ uri, category: 'other' }))]);
  };

  /**
   * Shoot a photo now.
   *
   * The phone is a camera; an owner standing in the room should be able to
   * photograph it without leaving the app for the gallery and back. One shot
   * per tap, appended like a picked one.
   */
  const handleCapturePhoto = async () => {
    const { uri, deniedPermission } = await captureListingImage();
    if (deniedPermission) {
      toast.show('Camera access is off. Turn it on in Settings to take photos.', 'neutral');
      return;
    }
    if (!uri) return;
    onChangeNewPhotos([...newPhotos, { uri, category: 'other' }]);
  };

  const applyCategory = (category: string) => {
    if (!categorizing) return;
    if (categorizing.list === 'existing') {
      onChangeExistingPhotos(
        existingPhotos.map((p) => (p.uri === categorizing.uri ? { ...p, category } : p))
      );
    } else {
      onChangeNewPhotos(newPhotos.map((p) => (p.uri === categorizing.uri ? { ...p, category } : p)));
    }
    setCategorizing(null);
  };

  return (
    <View className="flex-1">
      <View className="flex-row items-center justify-between px-lg pb-sm">
        <Text variant="footnote" tone="secondary">
          Step {step + 1} of {STEP_TITLES.length} · {STEP_TITLES[step]}
        </Text>
      </View>
      {/* Each visited segment is a target: an owner who spots a mistake on
          the review step can go straight to it rather than pressing Back
          six times. Unvisited segments are inert. */}
      <View className="mb-base flex-row px-lg">
        {STEP_TITLES.map((title, index) => {
          const visited = index <= reached;
          return (
            <Pressable
              key={title}
              accessibilityRole="button"
              accessibilityLabel={`Step ${index + 1}, ${title}`}
              accessibilityState={{ selected: index === step, disabled: !visited }}
              disabled={!visited || index === step}
              onPress={() => goTo(index)}
              hitSlop={8}
              className="mr-xs flex-1 py-xs"
            >
              <View
                className={`h-1 rounded-full ${index <= step ? 'bg-accent' : visited ? 'bg-border' : 'bg-surface-muted'}`}
              />
            </Pressable>
          );
        })}
      </View>

      <KeyboardAvoider className="flex-1">
        <ScrollView contentContainerStyle={{ padding: 16, paddingBottom: 32 }} keyboardShouldPersistTaps="handled">
          {step === 0 && (
            <Card>
              <Text variant="bodyEmphasis" className="mb-base">
                What are you listing?
              </Text>

              {/*
                The vocabulary is the server's, with a canonical mirror behind
                it for the window in which production has the taxonomy code but
                not the seeded data. Either way the owner always has options —
                blocking here would turn a wizard that failed at the last step
                into one that could not be started. See `taxonomy.ts`.
              */}
              {taxonomy.isLoading ? (
                <View className="mb-base gap-sm">
                  <Skeleton height={36} />
                  <Skeleton height={48} />
                </View>
              ) : (
                <>
                  <View className="mb-base flex-row flex-wrap">
                    {taxonomy.categories.map((c) => (
                      <Chip
                        key={c.id}
                        label={c.name}
                        selected={values.categoryName === c.name}
                        onPress={() => set('categoryName', c.name)}
                        className="mb-sm mr-sm"
                      />
                    ))}
                  </View>

                  <Select
                    label="Property type"
                    placeholder="Choose a type"
                    value={values.propertyTypeName || undefined}
                    options={propertyTypeOptions}
                    onChange={(v) => set('propertyTypeName', v)}
                  />

                  {/* How finished the space is handed over — the first thing a
                      commercial tenant asks, and mobile could not state it. */}
                  {values.categoryName === 'Commercial' ? (
                    <View className="mt-base">
                      <Text variant="footnote" tone="secondary" className="mb-xs">
                        Sub-type
                      </Text>
                      <View className="flex-row flex-wrap">
                        {COMMERCIAL_SUBTYPES.map((sub) => (
                          <Chip
                            key={sub}
                            label={sub}
                            selected={values.commercialSubType === sub}
                            onPress={() =>
                              // Tapping the selected chip clears it: the field
                              // is optional and there is no other way back to
                              // "not stated" once a chip has been pressed.
                              set('commercialSubType', values.commercialSubType === sub ? '' : sub)
                            }
                            className="mb-sm mr-sm"
                          />
                        ))}
                      </View>
                    </View>
                  ) : null}
                </>
              )}

              <Text variant="bodyEmphasis" className="mb-base mt-lg">
                For sale or rent?
              </Text>
              <View className="flex-row">
                {(['Sale', 'Rent'] as const).map((t) => (
                  <Chip
                    key={t}
                    label={t}
                    selected={values.listingType === t}
                    onPress={() => set('listingType', t)}
                    className="mr-sm"
                  />
                ))}
              </View>
            </Card>
          )}

          {step === 1 && (
            <Card>
              <StepIntro
                title="Describe it"
                hint="A specific title and an honest description get more enquiries than a long one."
              />
              <Input
                label="Title"
                placeholder="e.g. 3 BHK Apartment in Whitefield"
                value={values.title}
                onChangeText={(v) => set('title', v)}
                maxLength={TITLE_MAX}
                error={showErrors && step === 1 ? blocker ?? undefined : undefined}
                hint={
                  values.title.trim().length < TITLE_MIN
                    ? `At least ${TITLE_MIN} characters. Say what and where.`
                    : `${values.title.length}/${TITLE_MAX}`
                }
              />
              <Input
                label="Description"
                placeholder="Condition, what is nearby, what makes it worth a visit…"
                value={values.description}
                onChangeText={(v) => set('description', v)}
                multiline
                numberOfLines={5}
                maxLength={DESCRIPTION_MAX}
                hint={
                  values.description.length > 0
                    ? `${values.description.length.toLocaleString('en-IN')}/${DESCRIPTION_MAX.toLocaleString('en-IN')}`
                    : 'Optional, but a listing with none is easy to scroll past.'
                }
                containerClassName="mt-base"
              />
            </Card>
          )}

          {step === 2 && (
            <Card>
              <StepIntro
                title="Where is it?"
                hint="Use your location or drop the pin, and the address fills itself in. Then correct anything the map got wrong."
              />

              {/*
                The map FIRST, then the fields it fills. It used to sit under
                seven text inputs, so an owner typed the whole address by hand
                and only then met the control that would have typed it for
                them. A listing created on mobile carried NO coordinate before
                the picker existed, which is why so much of the corpus cannot
                be mapped or distance-sorted. See `LocationPicker`.
              */}
              <View>
                <LocationPicker
                  latitude={values.latitude}
                  longitude={values.longitude}
                  onChange={(next) =>
                    onChange({ ...values, latitude: next.latitude, longitude: next.longitude })
                  }
                  onResolvePlace={(place) =>
                    /*
                      Fills only what is still EMPTY. The owner may have typed a
                      locality the geocoder words differently, and overwriting
                      what they wrote with the OS's phrasing is the kind of
                      helpful that loses data.
                    */
                    onChange({
                      ...values,
                      city: values.city || place.city,
                      locality: values.locality || place.locality,
                      addressLine: values.addressLine || place.addressLine,
                      state: values.state || place.state,
                      pincode: values.pincode || place.pincode,
                      landmark: values.landmark || place.landmark,
                    })
                  }
                  addressQuery={[values.addressLine, values.locality, values.city]
                    .filter(Boolean)
                    .join(', ')}
                />
              </View>

              <Input
                label="Locality / area"
                placeholder="e.g. Whitefield"
                value={values.locality}
                onChangeText={(v) => set('locality', v)}
                error={showErrors && !values.locality.trim() ? 'Required' : undefined}
                containerClassName="mt-lg"
              />
              <Input
                label="City"
                placeholder="e.g. Bangalore"
                value={values.city}
                onChangeText={(v) => set('city', v)}
                error={showErrors && !values.city.trim() ? 'Required' : undefined}
                containerClassName="mt-base"
              />
              <Input
                label="Address line (optional)"
                placeholder="Building, street"
                value={values.addressLine}
                onChangeText={(v) => set('addressLine', v)}
                containerClassName="mt-base"
              />
              <View className="mt-base flex-row">
                <Input
                  label="State"
                  value={values.state}
                  onChangeText={(v) => set('state', v)}
                  containerClassName="mr-base flex-1"
                />
                <Input
                  label="Pincode"
                  value={values.pincode}
                  onChangeText={(v) => set('pincode', digits(v).slice(0, 6))}
                  keyboardType="number-pad"
                  maxLength={6}
                  containerClassName="w-[38%]"
                />
              </View>
              <Input
                label="Landmark (optional)"
                placeholder="e.g. Opposite Phoenix Mall"
                value={values.landmark}
                onChangeText={(v) => set('landmark', v)}
                containerClassName="mt-base"
              />

              <Input
                label="Nearby (optional)"
                placeholder="Metro, School, Hospital"
                hint="Separate with commas."
                value={values.nearby.join(', ')}
                onChangeText={(v) =>
                  set(
                    'nearby',
                    v
                      .split(',')
                      .map((item) => item.trim())
                      .filter(Boolean)
                  )
                }
                containerClassName="mt-base"
              />

              {/* The raw numbers, folded away. The map writes them; an owner
                  who wants to type them can, but nobody has to look at six
                  decimal places to list a flat. */}
              <Pressable
                accessibilityRole="button"
                accessibilityState={{ expanded: showCoordinates }}
                onPress={() => setShowCoordinates((v) => !v)}
                className="mt-lg flex-row items-center py-xs"
              >
                <Ionicons
                  name={showCoordinates ? 'chevron-down' : 'chevron-forward'}
                  size={16}
                  color={theme.colors.textMuted}
                />
                <Text variant="footnote" tone="secondary" className="ml-xs">
                  {values.latitude && values.longitude
                    ? `Pinned at ${Number(values.latitude).toFixed(4)}, ${Number(values.longitude).toFixed(4)}`
                    : 'Enter coordinates manually'}
                </Text>
              </Pressable>
              {showCoordinates ? (
                <View className="flex-row">
                  <Input
                    label="Latitude"
                    placeholder="19.076000"
                    value={values.latitude}
                    onChangeText={(v) => set('latitude', v)}
                    keyboardType="numbers-and-punctuation"
                    containerClassName="mr-base mt-sm flex-1"
                  />
                  <Input
                    label="Longitude"
                    placeholder="72.877700"
                    value={values.longitude}
                    onChangeText={(v) => set('longitude', v)}
                    keyboardType="numbers-and-punctuation"
                    containerClassName="mt-sm flex-1"
                  />
                </View>
              ) : null}
            </Card>
          )}

          {step === 3 && (
            <Card>
              <StepIntro
                title={values.listingType === 'Rent' ? 'Rent and size' : 'Price and size'}
                hint="Figures are shown in words as you type, so a missing zero is caught here and not by a buyer."
              />
              <Input
                label={values.listingType === 'Rent' ? 'Monthly rent (₹)' : 'Price (₹)'}
                placeholder={values.listingType === 'Rent' ? '25000' : '7500000'}
                value={values.price}
                onChangeText={(v) => set('price', digits(v))}
                keyboardType="number-pad"
                error={showErrors && !values.price.trim() ? blocker ?? undefined : undefined}
                /*
                  The number in words. ₹7500000 and ₹75000000 are one keystroke
                  apart and look alike in a field; "₹75 Lakh" and "₹7.5 Crore"
                  do not. The rate line appears once an area is entered, since
                  ₹/sqft is what a buyer compares on and it is derived from
                  these two fields anyway (see `formData.ts`).
                */
                hint={
                  priceWords
                    ? `${priceWords}${values.listingType === 'Rent' ? ' per month' : ''}${
                        rate ? ` · about ₹${rate.toLocaleString('en-IN')} per sq.ft` : ''
                      }`
                    : undefined
                }
              />

              {/*
                WHAT THE NEIGHBOURS ASK (Phase 1/4, F19)

                One muted line, under the field, and that is the whole feature.
                It does not prefill, does not suggest, does not warn that the
                price entered is high or low, and does not block anything. An
                owner asking above the local median usually has a reason, and a
                form that argues with them is a form they abandon.

                It renders nothing at all when the locality is below the sample
                floor, which is most localities today. See
                `features/locality/components/PriceGuidanceLine.tsx`.
              */}
              <PriceGuidanceLine
                city={values.city}
                locality={values.locality}
                listingType={values.listingType === 'Rent' ? 'rent' : 'sale'}
                bhk={values.bhk || values.bhkType}
              />
              <Pressable
                accessibilityRole="button"
                onPress={() => set('negotiable', !values.negotiable)}
                className="mt-base flex-row items-center justify-between py-sm"
              >
                <Text variant="body">Price negotiable</Text>
                <Ionicons
                  name={values.negotiable ? 'checkbox' : 'square-outline'}
                  size={22}
                  color={values.negotiable ? theme.colors.accent : theme.colors.textMuted}
                />
              </Pressable>

              {/*
                The rent and sale paths ask for genuinely different money, so
                they are separate fields rather than one relabelled one. A sale
                has a booking amount and may attract GST; a rental has a deposit
                and a maintenance figure that is usually quoted as included.
              */}
              {values.listingType === 'Rent' ? (
                <>
                  <Input
                    label="Security deposit (₹)"
                    value={values.deposit}
                    onChangeText={(v) => set('deposit', v)}
                    keyboardType="number-pad"
                    containerClassName="mt-base"
                  />
                  <Pressable
                    accessibilityRole="button"
                    accessibilityState={{ checked: values.maintenanceIncluded }}
                    onPress={() =>
                      // Clearing the amount when it becomes included: leaving a
                      // figure behind would submit a maintenance charge the
                      // owner has just said is part of the rent.
                      patch({
                        maintenanceIncluded: !values.maintenanceIncluded,
                        maintenance: !values.maintenanceIncluded ? '' : values.maintenance,
                      })
                    }
                    className="mt-base flex-row items-center justify-between py-sm"
                  >
                    <Text variant="body">Maintenance included in rent</Text>
                    <Ionicons
                      name={values.maintenanceIncluded ? 'checkbox' : 'square-outline'}
                      size={22}
                      color={
                        values.maintenanceIncluded ? theme.colors.accent : theme.colors.textMuted
                      }
                    />
                  </Pressable>
                </>
              ) : (
                <>
                  <Input
                    label="Booking amount (₹)"
                    value={values.bookingAmount}
                    onChangeText={(v) => set('bookingAmount', v)}
                    keyboardType="number-pad"
                    containerClassName="mt-base"
                  />
                  <Pressable
                    accessibilityRole="button"
                    accessibilityState={{ checked: values.gstApplicable }}
                    onPress={() => set('gstApplicable', !values.gstApplicable)}
                    className="mt-base flex-row items-center justify-between py-sm"
                  >
                    <Text variant="body">GST applicable</Text>
                    <Ionicons
                      name={values.gstApplicable ? 'checkbox' : 'square-outline'}
                      size={22}
                      color={values.gstApplicable ? theme.colors.accent : theme.colors.textMuted}
                    />
                  </Pressable>
                </>
              )}

              {values.listingType === 'Rent' && values.maintenanceIncluded ? null : (
                <Input
                  label="Maintenance per month (₹, optional)"
                  value={values.maintenance}
                  onChangeText={(v) => set('maintenance', digits(v))}
                  keyboardType="number-pad"
                  hint={values.maintenance ? formatPrice(values.maintenance) : undefined}
                  containerClassName="mt-base"
                />
              )}

              <Text variant="subhead" tone="secondary" className="mb-sm mt-lg">
                Area, in sq.ft
              </Text>
              {/* Only the figures that apply to this type; see `areaFieldsFor`.
                  Two per row, so the pair a buyer compares sits side by side. */}
              <View className="flex-row flex-wrap justify-between">
                {areaFields.carpet ? (
                  <Input
                    label="Carpet"
                    value={values.carpetSqft}
                    onChangeText={(v) => set('carpetSqft', digits(v))}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                ) : null}
                {areaFields.builtUp ? (
                  <Input
                    label="Built-up"
                    value={values.builtUpSqft}
                    onChangeText={(v) => set('builtUpSqft', digits(v))}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                ) : null}
                {areaFields.superBuiltUp ? (
                  <Input
                    label="Super built-up"
                    value={values.superBuiltUpSqft}
                    onChangeText={(v) => set('superBuiltUpSqft', digits(v))}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                ) : null}
                {areaFields.total ? (
                  <Input
                    label="Total"
                    value={values.totalSqft}
                    onChangeText={(v) => set('totalSqft', digits(v))}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                ) : null}
                {areaFields.plot ? (
                  <Input
                    label="Plot"
                    value={values.plotSqft}
                    onChangeText={(v) => set('plotSqft', digits(v))}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                ) : null}
              </View>

              {/* No ₹/sqft field: it is derived from price and area in
                  `formData.ts`, the way the website derives it. */}

              {/* Native date picker; degrades to typed entry where the module
                  is absent. Availability is in the FUTURE, so the picker opens
                  at today and allows dates ahead — the mirror of the birth-date
                  field, which only allows the past. */}
              <DateField
                label="Available from (optional)"
                value={values.availableFrom}
                onChange={(v) => set('availableFrom', v)}
                placeholder="Available now"
                minimumDate={new Date()}
                maximumDate={new Date(new Date().getFullYear() + 3, 11, 31)}
                containerClassName="mt-lg"
              />
            </Card>
          )}

          {step === 4 && (
            <>
              <Card>
                <StepIntro
                  title="The details"
                  hint="Everything here is optional. Each answer is one question a buyer will not have to message you about."
                />
                {values.categoryName === 'Residential' ? (
                  <ResidentialDetails values={values} set={set} patch={patch} theme={theme} />
                ) : (
                  <CommercialDetails values={values} set={set} />
                )}

                <View className="mt-lg flex-row flex-wrap">
                  <Input
                    label="Covered parking"
                    value={values.parkingCovered}
                    onChangeText={(v) => set('parkingCovered', v)}
                    keyboardType="number-pad"
                    containerClassName="mr-base mb-base w-[47%]"
                  />
                  <Input
                    label="Open parking"
                    value={values.parkingOpen}
                    onChangeText={(v) => set('parkingOpen', v)}
                    keyboardType="number-pad"
                    containerClassName="mb-base w-[47%]"
                  />
                </View>
                <Input label="RERA ID (optional)" value={values.reraId} onChangeText={(v) => set('reraId', v)} />

                {/*
                  Only the true state is sent (see `formData.ts`): an unticked
                  chip means "not stated", not "does not have one". Asserting
                  the negative on every listing would be a claim the owner
                  never made.
                */}
                <Text variant="subhead" tone="secondary" className="mb-sm mt-lg">
                  Compliance documents available
                </Text>
                <View className="flex-row flex-wrap">
                  {(
                    [
                      ['occupancyCertificate', 'Occupancy certificate'],
                      ['tradeLicense', 'Trade licence'],
                      ['fireNoc', 'Fire NOC'],
                    ] as const
                  ).map(([key, label]) => (
                    <Chip
                      key={key}
                      label={label}
                      selected={values[key]}
                      onPress={() => set(key, !values[key])}
                      className="mb-sm mr-sm"
                    />
                  ))}
                </View>
              </Card>

              <Card className="mt-base">
                <Text variant="bodyEmphasis" className="mb-base">
                  Amenities
                </Text>
                <View className="flex-row flex-wrap">
                  {amenitiesFor(values.categoryName).map((amenity) => (
                    <Chip
                      key={amenity}
                      label={amenity}
                      selected={values.amenities.includes(amenity)}
                      onPress={() =>
                        set(
                          'amenities',
                          values.amenities.includes(amenity)
                            ? values.amenities.filter((a) => a !== amenity)
                            : [...values.amenities, amenity]
                        )
                      }
                      className="mb-sm mr-sm"
                    />
                  ))}
                </View>
              </Card>
            </>
          )}

          {step === 5 && (
            <Card>
              <StepIntro
                title={`Photos · ${totalPhotos} of ${MAX_PHOTOS}`}
                hint="Daylight, landscape, the room from its doorway. Tap a photo's label to say which room it is."
              />
              <View className="flex-row flex-wrap">
                {existingPhotos.map((photo) => (
                  <PhotoTile
                    key={photo.uri}
                    uri={photo.uri}
                    categoryLabel={photoCategoryLabel(values.categoryName, photo.category)}
                    onRemove={() =>
                      onChangeExistingPhotos(existingPhotos.filter((p) => p.uri !== photo.uri))
                    }
                    onPressCategory={() => setCategorizing({ uri: photo.uri, list: 'existing' })}
                  />
                ))}
                {newPhotos.map((photo) => (
                  <PhotoTile
                    key={photo.uri}
                    uri={photo.uri}
                    categoryLabel={photoCategoryLabel(values.categoryName, photo.category)}
                    onRemove={() => onChangeNewPhotos(newPhotos.filter((p) => p.uri !== photo.uri))}
                    onPressCategory={() => setCategorizing({ uri: photo.uri, list: 'new' })}
                  />
                ))}
                {canAddMorePhotos ? (
                  <>
                    {canCapture ? (
                      <Pressable
                        accessibilityRole="button"
                        accessibilityLabel="Take a photo"
                        onPress={() => void handleCapturePhoto()}
                        className="mb-base mr-base h-24 w-24 items-center justify-center rounded-lg border border-dashed border-border"
                      >
                        <Ionicons name="camera-outline" size={26} color={theme.colors.textMuted} />
                        <Text variant="caption" tone="muted" className="mt-xs">
                          Camera
                        </Text>
                      </Pressable>
                    ) : null}
                    {/* Gated like the camera tile above it. `pickListingImages`
                        THROWS when the native module is absent, so an ungated
                        tile was a dead button plus an unhandled rejection
                        wherever the module is missing. `canPickImages` existed
                        for exactly this and was never used. */}
                    {canPickImages ? (
                      <Pressable
                        accessibilityRole="button"
                        accessibilityLabel="Add photos from gallery"
                        onPress={() => void handlePickPhotos()}
                        className="mb-base mr-base h-24 w-24 items-center justify-center rounded-lg border border-dashed border-border"
                      >
                        <Ionicons name="images-outline" size={26} color={theme.colors.textMuted} />
                        <Text variant="caption" tone="muted" className="mt-xs">
                          Gallery
                        </Text>
                      </Pressable>
                    ) : null}
                  </>
                ) : null}
              </View>
              {totalPhotos === 0 ? (
                <Text variant="footnote" tone="secondary">
                  Listings with photos get far more interest. Add at least a few.
                </Text>
              ) : null}
            </Card>
          )}

          <Sheet
            visible={categorizing !== null}
            onClose={() => setCategorizing(null)}
            title="What room is this?"
            heightRatio={0.5}
          >
            <View className="flex-row flex-wrap gap-sm">
              {categoryOptions.map((option) => (
                <Chip key={option.value} label={option.label} onPress={() => applyCategory(option.value)} />
              ))}
            </View>
          </Sheet>

          {step === 6 && (
            <Card>
              <StepIntro
                title="Check it over"
                hint="Tap any line to change it. You can edit the listing after it is live, too."
              />
              {/* Every row is a way back to its step. Without that, a mistake
                  spotted here cost six Back presses and the owner's patience. */}
              <ReviewRow
                label="Type"
                value={[values.categoryName, values.propertyTypeName].filter(Boolean).join(' · ')}
                onEdit={() => goTo(0)}
              />
              <ReviewRow
                label="Listing"
                value={values.listingType === 'Rent' ? 'For rent' : 'For sale'}
                onEdit={() => goTo(0)}
              />
              <ReviewRow label="Title" value={values.title} onEdit={() => goTo(1)} />
              <ReviewRow
                label="Location"
                value={[values.locality, values.city].filter(Boolean).join(', ')}
                onEdit={() => goTo(2)}
              />
              <ReviewRow
                label={values.listingType === 'Rent' ? 'Rent' : 'Price'}
                value={
                  values.price
                    ? `${formatPrice(values.price)}${values.listingType === 'Rent' ? ' per month' : ''}${
                        values.negotiable ? ' · negotiable' : ''
                      }`
                    : ''
                }
                onEdit={() => goTo(3)}
              />
              <ReviewRow
                label="Area"
                value={[
                  values.carpetSqft && `${values.carpetSqft} carpet`,
                  values.builtUpSqft && `${values.builtUpSqft} built-up`,
                  values.superBuiltUpSqft && `${values.superBuiltUpSqft} super built-up`,
                  values.totalSqft && `${values.totalSqft} total`,
                  values.plotSqft && `${values.plotSqft} plot`,
                ]
                  .filter(Boolean)
                  .join(', ')}
                onEdit={() => goTo(3)}
              />
              {values.categoryName === 'Residential' ? (
                <ReviewRow
                  label="Home"
                  value={[values.bhkType, values.furnishing, values.propertyAge && `${values.propertyAge} old`]
                    .filter(Boolean)
                    .join(' · ')}
                  onEdit={() => goTo(4)}
                />
              ) : null}
              <ReviewRow
                label="Photos"
                value={totalPhotos > 0 ? `${totalPhotos} added` : ''}
                onEdit={() => goTo(5)}
              />

              {totalPhotos === 0 ? (
                <Text variant="footnote" tone="danger" className="mt-sm">
                  No photos yet. Listings without one get a fraction of the enquiries.
                </Text>
              ) : null}

              {submitError ? (
                <Text variant="footnote" tone="danger" className="mt-base">
                  {submitError}
                </Text>
              ) : null}

              <Button
                label={submitLabel}
                className="mt-lg"
                loading={isSubmitting}
                onPress={onSubmit}
              />
            </Card>
          )}
        </ScrollView>
      </KeyboardAvoider>

      {/*
        The footer pays the bottom inset itself. Both listing screens mount
        this with `edges={['top']}`, and the app draws edge-to-edge on
        Android, so on a phone with three-button navigation the system bar
        sat over Back and Next (reported 2026-09-06). Gesture navigation and
        iOS report a smaller inset, and the padding never drops below the
        footer's own step.
      */}
      <View
        className="border-t border-border px-lg pt-md"
        style={{ paddingBottom: Math.max(insets.bottom, spacing.md) }}
      >
        {/* The reason Next did not proceed, in the footer where the press
            happened. Nothing is shown until the owner has tried once. */}
        {showErrors ? (
          <Text variant="footnote" tone="danger" className="mb-sm">
            {blocker}
          </Text>
        ) : null}
        <View className="flex-row">
          {step > 0 ? (
            <Button
              label="Back"
              variant="secondary"
              className="mr-base flex-1"
              onPress={() => goTo(step - 1)}
            />
          ) : null}
          {step < STEP_TITLES.length - 1 ? (
            <Button label="Next" className="flex-1" onPress={next} />
          ) : null}
        </View>
      </View>
    </View>
  );
}

function ResidentialDetails({
  values,
  set,
  patch,
  theme,
}: {
  values: ListingFormValues;
  set: <K extends keyof ListingFormValues>(key: K, value: ListingFormValues[K]) => void;
  /**
   * Several fields at once.
   *
   * `set` rebuilds from the `values` it closed over, so two calls in a row both
   * start from the same snapshot and the second silently discards the first.
   * Anything writing more than one field has to go through here.
   */
  patch: (next: Partial<ListingFormValues>) => void;
  theme: Theme;
}) {
  /*
    The website's seven options, not five.

    Mobile offered 1-5+ BHK only, so a studio or a 1 RK — two of the commonest
    rental configurations in an Indian city — could not be described at all.
    The value IS the label here: it is submitted verbatim as `features.bhk`,
    which is what the search parser reads back.
  */
  const bhkOptions = BHK_OPTIONS.map((v) => ({ label: v, value: v }));
  // From the catalog: the local copy read "Semi-furnished" where the website
  // and the corpus both say "Semi-Furnished", so the two clients disagreed on
  // the value stored for the same choice.
  const furnishingOptions = FURNISHING_OPTIONS.map((v) => ({
    label: v,
    value: v,
  }));

  return (
    <>
      <Select
        label="BHK"
        placeholder="Choose"
        value={values.bhkType || undefined}
        options={bhkOptions}
        onChange={(v) => {
          /*
            Picking a BHK also fills the bedroom count, exactly as the website
            does: "3 BHK" means three bedrooms, and asking again on the next
            step is asking the same question twice. "Studio" has no bedroom
            count, and "1 RK" is one room, which the split below yields as "1".
          */
          const bedrooms = v === 'Studio' ? '0' : v.split(' ')[0];
          patch({ bhkType: v, bhk: v, bedrooms });
        }}
      />
      <View className="mt-base flex-row flex-wrap">
        <Input
          label="Bedrooms"
          value={values.bedrooms}
          onChangeText={(v) => set('bedrooms', v)}
          keyboardType="number-pad"
          containerClassName="mr-base mb-base w-[30%]"
        />
        <Input
          label="Bathrooms"
          value={values.bathrooms}
          onChangeText={(v) => set('bathrooms', v)}
          keyboardType="number-pad"
          containerClassName="mr-base mb-base w-[30%]"
        />
        <Input
          label="Balconies"
          value={values.balconies}
          onChangeText={(v) => set('balconies', v)}
          keyboardType="number-pad"
          containerClassName="mb-base w-[30%]"
        />
      </View>

      <Select
        label="Property age"
        placeholder="Choose"
        value={values.propertyAge || undefined}
        options={PROPERTY_AGE_OPTIONS.map((v) => ({ label: v, value: v }))}
        onChange={(v) => set('propertyAge', v)}
      />

      {/*
        Rent only, and the two questions every Indian rental listing is asked
        before a viewing is agreed. Mobile collected neither, so an owner could
        not state them and a tenant had to message to find out.
      */}
      {values.listingType === 'Rent' ? (
        <View className="mt-base">
          <Select
            label="Preferred tenants"
            placeholder="Choose"
            value={values.allowedFor || undefined}
            options={TENANT_OPTIONS.map((v) => ({ label: v, value: v }))}
            onChange={(v) => set('allowedFor', v)}
          />
          <View className="mt-base">
            <Select
              label="Pet friendly"
              placeholder="Choose"
              value={values.petFriendly || undefined}
              options={[
                { label: 'No', value: 'No' },
                { label: 'Yes', value: 'Yes' },
              ]}
              onChange={(v) => set('petFriendly', v)}
            />
          </View>
        </View>
      ) : null}

      <Select
        label="Furnishing"
        placeholder="Choose"
        value={values.furnishing || undefined}
        options={furnishingOptions}
        onChange={(v) => set('furnishing', v)}
      />

      <Input
        label="Total floors in the building"
        value={values.totalFloors}
        onChangeText={(v) => set('totalFloors', v)}
        keyboardType="number-pad"
        containerClassName="mt-base"
      />

      {/*
        Chips from the catalog, not free text. Both of these were typed
        fields, so the corpus holds "east", "East facing", "E" and "Est" for
        one fact, and the search screen's construction-status filter, which
        keyword-matches the stored string, missed anything not spelled its
        way. The option lists already existed in `catalog.ts`; the form was
        the one place not using them. Tapping the chosen chip clears it,
        since both fields are optional and there is no other way back to
        "not stated".
      */}
      <Text variant="footnote" tone="secondary" className="mb-xs mt-base">
        Facing
      </Text>
      {values.facing && !(FACING_OPTIONS as readonly string[]).includes(values.facing) ? (
        <Text variant="caption" tone="muted" className="mb-xs">
          Currently “{values.facing}”. Pick a direction to replace it.
        </Text>
      ) : null}
      <View className="flex-row flex-wrap">
        {FACING_OPTIONS.map((option) => (
          <Chip
            key={option}
            label={option}
            selected={values.facing === option}
            onPress={() => set('facing', values.facing === option ? '' : option)}
            className="mb-sm mr-sm"
          />
        ))}
      </View>

      {values.listingType === 'Sale' ? (
        <>
          <Text variant="footnote" tone="secondary" className="mb-xs mt-sm">
            Construction status
          </Text>
          {values.constructionStatus &&
          !(CONSTRUCTION_STATUS_OPTIONS as readonly string[]).includes(values.constructionStatus) ? (
            <Text variant="caption" tone="muted" className="mb-xs">
              Currently “{values.constructionStatus}”. Pick one to replace it.
            </Text>
          ) : null}
          <View className="flex-row flex-wrap">
            {CONSTRUCTION_STATUS_OPTIONS.map((option) => (
              <Chip
                key={option}
                label={option}
                selected={values.constructionStatus === option}
                onPress={() =>
                  set('constructionStatus', values.constructionStatus === option ? '' : option)
                }
                className="mb-sm mr-sm"
              />
            ))}
          </View>
        </>
      ) : null}

      <View className="mt-base flex-row flex-wrap">
        {(
          [
            ['servantRoom', 'Servant room'],
            ['poojaRoom', 'Pooja room'],
            ['studyRoom', 'Study room'],
            ['storeRoom', 'Store room'],
          ] as const
        ).map(([key, label]) => (
          <Chip
            key={key}
            label={label}
            selected={values[key]}
            onPress={() => set(key, !values[key])}
            className="mb-sm mr-sm"
          />
        ))}
      </View>
    </>
  );
}

function CommercialDetails({
  values,
  set,
}: {
  values: ListingFormValues;
  set: <K extends keyof ListingFormValues>(key: K, value: ListingFormValues[K]) => void;
}) {
  /*
    The configuration that belongs to THIS property type.

    Two fixed fields — meeting rooms and pantry — stood here for every
    commercial listing, so a warehouse was asked about its pantry and never
    about its loading docks. `COMMERCIAL_CONFIGS` is the website's per-type
    table; a type with no entry (which the fetched taxonomy can produce) simply
    renders the shared fields and nothing else, rather than an empty card.
  */
  const config = COMMERCIAL_CONFIGS[values.propertyTypeName];

  const setConfig = (key: string, value: string) =>
    set('commercialConfig', { ...values.commercialConfig, [key]: value });

  return (
    <View>
      <View className="flex-row flex-wrap">
        <Input
          label="Washrooms"
          value={values.washrooms}
          onChangeText={(v) => set('washrooms', v)}
          keyboardType="number-pad"
          containerClassName="mr-base mb-base w-[30%]"
        />
        <Input
          label="Floor height (ft)"
          value={values.floorHeight}
          onChangeText={(v) => set('floorHeight', v)}
          keyboardType="number-pad"
          containerClassName="mr-base mb-base w-[30%]"
        />
        <Input
          label="Power load (kW)"
          value={values.powerLoad}
          onChangeText={(v) => set('powerLoad', v)}
          keyboardType="number-pad"
          containerClassName="mb-base w-[30%]"
        />
      </View>

      {config ? (
        <>
          <Text variant="bodyEmphasis" className="mb-base mt-sm">
            {config.label}
          </Text>
          <View className="flex-row flex-wrap">
            {config.fields.map((field) => (
              <Input
                key={field.key}
                label={field.label}
                value={values.commercialConfig[field.key] ?? ''}
                onChangeText={(v) => setConfig(field.key, v)}
                keyboardType="number-pad"
                containerClassName="mr-base mb-base w-[45%]"
              />
            ))}
          </View>
        </>
      ) : null}
    </View>
  );
}

/** A step's heading and the one line that says what good looks like. */
function StepIntro({ title, hint }: { title: string; hint: string }) {
  return (
    <View className="mb-base">
      <Text variant="bodyEmphasis">{title}</Text>
      <Text variant="footnote" tone="secondary" className="mt-xs">
        {hint}
      </Text>
    </View>
  );
}

function ReviewRow({ label, value, onEdit }: { label: string; value: string; onEdit: () => void }) {
  const theme = useTheme();
  return (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${label}: ${value || 'not set'}. Edit`}
      onPress={onEdit}
      className="flex-row items-center justify-between border-b border-border py-sm"
    >
      <Text variant="footnote" tone="secondary" className="w-[26%]">
        {label}
      </Text>
      <Text
        variant="body"
        tone={value ? 'primary' : 'muted'}
        numberOfLines={2}
        className="flex-1 text-right"
      >
        {value || 'Not set'}
      </Text>
      <Ionicons
        name="chevron-forward"
        size={16}
        color={theme.colors.textMuted}
        style={{ marginLeft: 6 }}
      />
    </Pressable>
  );
}

function PhotoTile({
  uri,
  categoryLabel,
  onRemove,
  onPressCategory,
}: {
  uri: string;
  categoryLabel: string;
  onRemove: () => void;
  onPressCategory: () => void;
}) {
  return (
    <View className="mb-base mr-base w-24">
      <View className="h-24 w-24">
        <RNImage source={{ uri }} className="h-24 w-24 rounded-lg" resizeMode="cover" />
        <Pressable
          accessibilityRole="button"
          accessibilityLabel="Remove photo"
          onPress={onRemove}
          className="absolute -right-2 -top-2 h-6 w-6 items-center justify-center rounded-full bg-black/70"
        >
          <Ionicons name="close" size={14} color="#fff" />
        </Pressable>
      </View>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`Room: ${categoryLabel}. Tap to change.`}
        onPress={onPressCategory}
        className="mt-xs rounded-full bg-surface-muted px-xs py-xs"
      >
        <Text variant="caption" tone="secondary" numberOfLines={1} className="text-center">
          {categoryLabel}
        </Text>
      </Pressable>
    </View>
  );
}
