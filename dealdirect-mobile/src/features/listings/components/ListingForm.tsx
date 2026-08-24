import Ionicons from '@expo/vector-icons/Ionicons';
import { useEffect, useMemo, useState } from 'react';
import { Image as RNImage, Pressable, ScrollView, View } from 'react-native';

import { useTheme, type Theme } from '@/theme';
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
  useToast,
} from '@/ui';
import { captureListingImage, canCapture, canPickImages, pickListingImages } from '../imagePicker';
import {
  BHK_OPTIONS,
  COMMERCIAL_CONFIGS,
  COMMERCIAL_SUBTYPES,
  FURNISHING_OPTIONS,
  PROPERTY_AGE_OPTIONS,
  TENANT_OPTIONS,
  amenitiesFor,
  photoCategoriesForType,
} from '../catalog';
import { LocationPicker } from './LocationPicker';
import { useListingTaxonomy } from '../taxonomy';
import {
  photoCategoryLabel,
  type CategorizedPhoto,
  type ListingFormValues,
} from '../types';

const MAX_PHOTOS = 15;

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
}: ListingFormProps) {
  const theme = useTheme();
  const [step, setStep] = useState(0);
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

  const stepValid = useMemo(() => {
    switch (step) {
      case 0:
        // Both halves, because the server rejects a type that does not sit
        // under the category submitted alongside it.
        return (
          values.categoryName.trim().length > 0 && values.propertyTypeName.trim().length > 0
        );
      case 1:
        return values.title.trim().length >= 5;
      case 2:
        return values.city.trim().length > 0 && values.locality.trim().length > 0;
      case 3:
        return values.price.trim().length > 0;
      default:
        return true;
    }
  }, [step, values]);

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
      <View className="mb-base h-1 flex-row px-lg">
        {STEP_TITLES.map((title, index) => (
          <View
            key={title}
            className={`mr-xs h-1 flex-1 rounded-full ${index <= step ? 'bg-accent' : 'bg-surface-muted'}`}
          />
        ))}
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
              <Input
                label="Title"
                placeholder="e.g. 3 BHK Apartment in Whitefield"
                value={values.title}
                onChangeText={(v) => set('title', v)}
              />
              <Input
                label="Description"
                placeholder="Describe the property, nearby landmarks, condition…"
                value={values.description}
                onChangeText={(v) => set('description', v)}
                multiline
                numberOfLines={5}
                containerClassName="mt-base"
              />
            </Card>
          )}

          {step === 2 && (
            <Card>
              <Input
                label="Address line"
                value={values.addressLine}
                onChangeText={(v) => set('addressLine', v)}
              />
              <Input
                label="Locality / area"
                value={values.locality}
                onChangeText={(v) => set('locality', v)}
                containerClassName="mt-base"
              />
              <Input label="City" value={values.city} onChangeText={(v) => set('city', v)} containerClassName="mt-base" />
              <Input label="State" value={values.state} onChangeText={(v) => set('state', v)} containerClassName="mt-base" />
              <Input
                label="Pincode"
                value={values.pincode}
                onChangeText={(v) => set('pincode', v)}
                keyboardType="number-pad"
                containerClassName="mt-base"
              />
              <Input
                label="Landmark (optional)"
                value={values.landmark}
                onChangeText={(v) => set('landmark', v)}
                containerClassName="mt-base"
              />

              <Input
                label="Nearby (comma separated)"
                placeholder="Metro, School, Hospital"
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

              {/*
                The map. A listing created on mobile carried NO coordinate
                before this, which is why so much of the corpus cannot be
                mapped or distance-sorted. See `LocationPicker`.
              */}
              <View className="mt-lg">
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
                label="Latitude"
                placeholder="e.g. 19.076000"
                value={values.latitude}
                onChangeText={(v) => set('latitude', v)}
                keyboardType="numbers-and-punctuation"
                containerClassName="mt-lg"
              />
              <Input
                label="Longitude"
                placeholder="e.g. 72.877700"
                value={values.longitude}
                onChangeText={(v) => set('longitude', v)}
                keyboardType="numbers-and-punctuation"
                containerClassName="mt-base"
              />
            </Card>
          )}

          {step === 3 && (
            <Card>
              <Input
                label={values.listingType === 'Rent' ? 'Monthly rent (₹)' : 'Price (₹)'}
                value={values.price}
                onChangeText={(v) => set('price', v)}
                keyboardType="number-pad"
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

              <Input
                label="Maintenance (per month)"
                value={values.maintenance}
                onChangeText={(v) => set('maintenance', v)}
                keyboardType="number-pad"
                editable={!(values.listingType === 'Rent' && values.maintenanceIncluded)}
                containerClassName="mt-base"
              />

              <View className="mt-lg flex-row flex-wrap">
                <Input
                  label="Carpet area (sqft)"
                  value={values.carpetSqft}
                  onChangeText={(v) => set('carpetSqft', v)}
                  keyboardType="number-pad"
                  containerClassName="mr-base mb-base w-[47%]"
                />
                <Input
                  label="Built-up area (sqft)"
                  value={values.builtUpSqft}
                  onChangeText={(v) => set('builtUpSqft', v)}
                  keyboardType="number-pad"
                  containerClassName="mb-base w-[47%]"
                />
                <Input
                  label="Total area (sqft)"
                  value={values.totalSqft}
                  onChangeText={(v) => set('totalSqft', v)}
                  keyboardType="number-pad"
                  containerClassName="mr-base mb-base w-[47%]"
                />
                <Input
                  label="Super built-up (sqft)"
                  value={values.superBuiltUpSqft}
                  onChangeText={(v) => set('superBuiltUpSqft', v)}
                  keyboardType="number-pad"
                  containerClassName="mb-base w-[47%]"
                />
                <Input
                  label="Plot area (sqft)"
                  value={values.plotSqft}
                  onChangeText={(v) => set('plotSqft', v)}
                  keyboardType="number-pad"
                  containerClassName="w-[47%]"
                />
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
              <Text variant="bodyEmphasis" className="mb-base">
                Photos ({totalPhotos}/{MAX_PHOTOS})
              </Text>
              <Text variant="footnote" tone="secondary" className="mb-base">
                Tap a photo&apos;s label to say which room it&apos;s from.
              </Text>
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
              <Text variant="bodyEmphasis" className="mb-base">
                Review
              </Text>
              <ReviewRow label="Title" value={values.title} />
              <ReviewRow label="Type" value={`${values.categoryName} · ${values.propertyTypeName}`} />
              <ReviewRow label="Listing" value={values.listingType === 'Rent' ? 'For rent' : 'For sale'} />
              <ReviewRow label="Location" value={`${values.locality}, ${values.city}`} />
              <ReviewRow label="Price" value={values.price ? `₹${values.price}` : '—'} />
              <ReviewRow label="Photos" value={String(totalPhotos)} />

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

      <View className="flex-row border-t border-border px-lg py-md">
        {step > 0 ? (
          <Button
            label="Back"
            variant="secondary"
            className="mr-base flex-1"
            onPress={() => setStep((s) => s - 1)}
          />
        ) : null}
        {step < STEP_TITLES.length - 1 ? (
          <Button
            label="Next"
            className="flex-1"
            disabled={!stepValid}
            onPress={() => setStep((s) => s + 1)}
          />
        ) : null}
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

      <View className="mt-base flex-row flex-wrap">
        <Input
          label="Total floors"
          value={values.totalFloors}
          onChangeText={(v) => set('totalFloors', v)}
          containerClassName="mr-base mb-base w-[47%]"
        />
        <Input
          label="Facing"
          value={values.facing}
          onChangeText={(v) => set('facing', v)}
          containerClassName="mb-base w-[47%]"
        />
      </View>
      <Input
        label="Construction status"
        placeholder="Ready to move / Under construction"
        value={values.constructionStatus}
        onChangeText={(v) => set('constructionStatus', v)}
      />

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

function ReviewRow({ label, value }: { label: string; value: string }) {
  return (
    <View className="mb-sm flex-row justify-between">
      <Text variant="footnote" tone="secondary">
        {label}
      </Text>
      <Text variant="body" className="max-w-[70%] text-right">
        {value || '—'}
      </Text>
    </View>
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
