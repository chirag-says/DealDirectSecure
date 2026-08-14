import Ionicons from '@expo/vector-icons/Ionicons';
import { useEffect, useMemo, useState } from 'react';
import { Image as RNImage, Pressable, ScrollView, View } from 'react-native';

import { useTheme, type Theme } from '@/theme';
import { Button, Card, Chip, Input, KeyboardAvoider, Select, Sheet, Text } from '@/ui';
import { pickListingImages } from '../imagePicker';
import {
  AMENITIES,
  COMMERCIAL_TYPES,
  RESIDENTIAL_TYPES,
  photoCategoriesFor,
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

  const propertyTypeOptions = useMemo(
    () =>
      (values.categoryName === 'Residential' ? RESIDENTIAL_TYPES : COMMERCIAL_TYPES).map((t) => ({
        label: t,
        value: t,
      })),
    [values.categoryName]
  );

  // A property type picked under one category is meaningless under the other.
  useEffect(() => {
    const valid = (values.categoryName === 'Residential' ? RESIDENTIAL_TYPES : COMMERCIAL_TYPES) as readonly string[];
    if (values.propertyTypeName && !valid.includes(values.propertyTypeName)) {
      set('propertyTypeName', '');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values.categoryName]);

  const totalPhotos = existingPhotos.length + newPhotos.length;
  const canAddMorePhotos = totalPhotos < MAX_PHOTOS;
  const categoryOptions = photoCategoriesFor(values.categoryName);

  const stepValid = useMemo(() => {
    switch (step) {
      case 0:
        return values.propertyTypeName.trim().length > 0;
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
    if (deniedPermission || uris.length === 0) return;
    onChangeNewPhotos([...newPhotos, ...uris.map((uri) => ({ uri, category: 'other' }))]);
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
              <View className="mb-base flex-row">
                {(['Residential', 'Commercial'] as const).map((c) => (
                  <Chip
                    key={c}
                    label={c}
                    selected={values.categoryName === c}
                    onPress={() => set('categoryName', c)}
                    className="mr-sm"
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

              <Input
                label={values.listingType === 'Rent' ? 'Security deposit' : 'Booking amount'}
                value={values.deposit}
                onChangeText={(v) => set('deposit', v)}
                containerClassName="mt-base"
              />
              <Input
                label="Maintenance (per month)"
                value={values.maintenance}
                onChangeText={(v) => set('maintenance', v)}
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

              <Input
                label="Available from (optional)"
                placeholder="YYYY-MM-DD"
                value={values.availableFrom}
                onChangeText={(v) => set('availableFrom', v)}
                hint="Leave blank if the property is available now"
                containerClassName="mt-lg"
              />
            </Card>
          )}

          {step === 4 && (
            <>
              <Card>
                {values.categoryName === 'Residential' ? (
                  <ResidentialDetails values={values} set={set} theme={theme} />
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
                  {AMENITIES.map((amenity) => (
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
                  <Pressable
                    accessibilityRole="button"
                    accessibilityLabel="Add photos"
                    onPress={() => void handlePickPhotos()}
                    className="mb-base mr-base h-24 w-24 items-center justify-center rounded-lg border border-dashed border-border"
                  >
                    <Ionicons name="add" size={28} color={theme.colors.textMuted} />
                  </Pressable>
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
  theme,
}: {
  values: ListingFormValues;
  set: <K extends keyof ListingFormValues>(key: K, value: ListingFormValues[K]) => void;
  theme: Theme;
}) {
  const bhkOptions = ['1', '2', '3', '4', '5+'].map((v) => ({ label: `${v} BHK`, value: v }));
  const furnishingOptions = ['Unfurnished', 'Semi-furnished', 'Fully furnished'].map((v) => ({
    label: v,
    value: v,
  }));

  return (
    <>
      <Select
        label="BHK"
        placeholder="Choose"
        value={values.bhk || undefined}
        options={bhkOptions}
        onChange={(v) => set('bhk', v)}
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
  return (
    <View className="flex-row flex-wrap">
      <Input
        label="Washrooms"
        value={values.washrooms}
        onChangeText={(v) => set('washrooms', v)}
        keyboardType="number-pad"
        containerClassName="mr-base mb-base w-[30%]"
      />
      <Input
        label="Meeting rooms"
        value={values.meetingRooms}
        onChangeText={(v) => set('meetingRooms', v)}
        keyboardType="number-pad"
        containerClassName="mr-base mb-base w-[30%]"
      />
      <Input
        label="Pantry"
        placeholder="Yes / No"
        value={values.pantry}
        onChangeText={(v) => set('pantry', v)}
        containerClassName="mb-base w-[30%]"
      />
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
