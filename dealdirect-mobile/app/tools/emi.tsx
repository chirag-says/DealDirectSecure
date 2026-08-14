import { useMemo, useState } from 'react';
import { ScrollView, View } from 'react-native';
import Animated, { FadeIn, FadeInDown, useReducedMotion } from 'react-native-reanimated';

import { RupeeField, DEFAULT_INTEREST_RATE, DEFAULT_TENURE_YEARS, emiForLoan } from '@/features/tools';
import {
  radius,
  reducedMotion,
  screenPadding,
  scrollBottomPadding,
  spacing,
  timing,
  useTheme,
} from '@/theme';
import { Input, KeyboardAvoider, Screen, ScreenHeader, Text, formatPrice } from '@/ui';

/**
 * EMI calculator, standalone.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS IS NOT `properties/EmiCalculator` WITH A HEADER AROUND IT
 *
 * That component takes a `priceRupees` and seeds its loan field at 80% of it,
 * which is exactly right on a detail page: the price is a fact of the listing
 * and the only thing the user is deciding is the terms. Here there is no
 * listing. The amount IS the question, so it starts empty and there is nothing
 * to derive it from.
 *
 * The two share the formula rather than the component — `emiForLoan` in
 * `features/tools/affordability.ts` — which is the part that must never
 * disagree between them. Wrapping the detail-page component and passing it a
 * fake price would have made this screen's loan field secretly a property price
 * multiplied by 0.8, which is the kind of thing that produces a bug report
 * nobody can reproduce.
 *
 * ---------------------------------------------------------------------------
 * THE BREAKDOWN IS THE POINT
 *
 * A monthly figure alone makes a 30-year loan look cheaper than a 15-year one.
 * Total interest is what shows the trade, and on a typical Indian home loan it
 * is a number most people have never seen — frequently larger than the amount
 * borrowed. It is shown at the same weight as the total, not tucked under it.
 */
export default function EmiScreen() {
  const theme = useTheme();
  const reduceMotion = useReducedMotion();

  const [amount, setAmount] = useState('');
  const [rate, setRate] = useState(String(DEFAULT_INTEREST_RATE));
  const [tenure, setTenure] = useState(String(DEFAULT_TENURE_YEARS));

  const { emi, totalPayment, totalInterest } = useMemo(() => {
    const principal = Number(amount) || 0;
    const monthly = emiForLoan(principal, Number(rate) || 0, Number(tenure) || 0);
    const months = (Number(tenure) || 0) * 12;
    const total = monthly * months;

    return {
      emi: monthly,
      totalPayment: total,
      totalInterest: total > 0 ? total - principal : 0,
    };
  }, [amount, rate, tenure]);

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="EMI calculator" backTo="/(tabs)" />

      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <View style={{ gap: spacing.lg }}>
            <RupeeField label="Loan amount" value={amount} onChangeText={setAmount} />

            <View className="flex-row" style={{ gap: spacing.md }}>
              <View className="flex-1">
                <Input
                  label="Interest rate (%)"
                  value={rate}
                  onChangeText={setRate}
                  keyboardType="decimal-pad"
                />
              </View>
              <View className="flex-1">
                <Input
                  label="Tenure (years)"
                  value={tenure}
                  onChangeText={setTenure}
                  keyboardType="number-pad"
                />
              </View>
            </View>
          </View>

          {emi > 0 ? (
            <Animated.View
              // Same entrance as the affordability result, and for the same
              // reason — see the long note at that call site. Once, on mount;
              // the figures inside update without the card re-entering.
              entering={
                reduceMotion
                  ? FadeIn.duration(reducedMotion.crossfade)
                  : FadeInDown.duration(timing.base).springify().damping(20)
              }
              className="mt-2xl"
              style={{
                padding: spacing.lg,
                borderRadius: radius.xl,
                backgroundColor: theme.colors.surface,
              }}
            >
              <Text variant="footnote" tone="secondary">
                Monthly payment
              </Text>
              <Text variant="display" tone="accent" className="mt-xs">
                {formatPrice(Math.round(emi))}
              </Text>

              <View
                style={{
                  height: 1,
                  backgroundColor: theme.colors.border,
                  marginVertical: spacing.lg,
                }}
              />

              <View className="flex-row justify-between">
                <View>
                  <Text variant="caption" tone="muted">
                    Interest paid
                  </Text>
                  <Text variant="bodyEmphasis" className="mt-xs">
                    {formatPrice(Math.round(totalInterest))}
                  </Text>
                </View>
                <View>
                  <Text variant="caption" tone="muted">
                    Total repaid
                  </Text>
                  <Text variant="bodyEmphasis" className="mt-xs">
                    {formatPrice(Math.round(totalPayment))}
                  </Text>
                </View>
              </View>
            </Animated.View>
          ) : null}

          <Text variant="caption" tone="muted" className="mt-xl">
            An estimate. Processing fees, insurance and any rate change over the
            term are not included.
          </Text>
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
