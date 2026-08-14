import Ionicons from '@expo/vector-icons/Ionicons';
import { useRouter } from 'expo-router';
import { useMemo, useState } from 'react';
import { ScrollView, View } from 'react-native';
import Animated, { FadeIn, FadeInDown, useReducedMotion } from 'react-native-reanimated';

import { bandForPrice } from '@/features/search';
import {
  DEFAULT_FOIR,
  DEFAULT_INTEREST_RATE,
  DEFAULT_LTV,
  DEFAULT_TENURE_YEARS,
  RupeeField,
  calculateAffordability,
} from '@/features/tools';
import {
  radius,
  reducedMotion,
  screenPadding,
  scrollBottomPadding,
  spacing,
  timing,
  useTheme,
} from '@/theme';
import { Button, Input, KeyboardAvoider, Screen, ScreenHeader, Text, formatPrice } from '@/ui';

/**
 * "What can I afford?"
 *
 * The whole point of this screen is the button at the bottom. A buyer who does
 * not know where to start gets a number AND a search that number applies to,
 * in one step. See `features/tools/affordability.ts` for the model and for why
 * a calculator that stops at a figure is not worth building.
 *
 * ---------------------------------------------------------------------------
 * IT COMPUTES AS YOU TYPE, WITH NO CALCULATE BUTTON
 *
 * The arithmetic is instant and local — no request, no rate limit, nothing to
 * batch. A Calculate button in front of a pure function exists only to make the
 * form look like a form, and it costs the user the thing that makes a
 * calculator worth using, which is watching the answer move as they change an
 * assumption. Every field here is one someone will want to try three values of.
 *
 * ---------------------------------------------------------------------------
 * THE DEFAULTS ARE FILLED IN, THE INCOME IS NOT
 *
 * Rate and tenure arrive at the values the website's own EMI calculator ships
 * with, because a first-time buyer does not know what to put there and a blank
 * field asking for an interest rate is where people leave. Income and savings
 * are blank, because guessing those for someone would produce an authoritative
 * budget built on numbers they never gave.
 */
export default function AffordabilityScreen() {
  const router = useRouter();
  const theme = useTheme();
  const reduceMotion = useReducedMotion();

  const [income, setIncome] = useState('');
  const [obligations, setObligations] = useState('');
  const [downPayment, setDownPayment] = useState('');
  const [rate, setRate] = useState(String(DEFAULT_INTEREST_RATE));
  const [tenure, setTenure] = useState(String(DEFAULT_TENURE_YEARS));

  const result = useMemo(
    () =>
      calculateAffordability({
        monthlyIncome: Number(income) || 0,
        monthlyObligations: Number(obligations) || 0,
        downPayment: Number(downPayment) || 0,
        interestRate: Number(rate) || 0,
        tenureYears: Number(tenure) || 0,
      }),
    [income, obligations, downPayment, rate, tenure]
  );

  const band = bandForPrice(result.affordablePrice);

  return (
    <Screen edges={['top']}>
      <ScreenHeader title="What can I afford?" backTo="/(tabs)" />

      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingBottom: scrollBottomPadding,
          }}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <Text variant="callout" tone="secondary">
            Two things decide what you can buy: what your income will support in
            monthly repayments, and how much you have saved for the deposit. This
            works out both and takes the lower one.
          </Text>

          <View className="mt-xl" style={{ gap: spacing.lg }}>
            <RupeeField
              label="Your monthly income"
              value={income}
              onChangeText={setIncome}
              hint="Take-home pay, after tax"
            />

            <RupeeField
              label="Existing monthly EMIs"
              value={obligations}
              onChangeText={setObligations}
              hint="Car loans, personal loans, other repayments. Leave empty if none."
            />

            <RupeeField
              label="Money saved for the deposit"
              value={downPayment}
              onChangeText={setDownPayment}
              hint={`Lenders fund up to ${Math.round(DEFAULT_LTV * 100)}% of the price, so the rest comes from here`}
            />

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

          {/*
            The answer, as one large number and the two figures that produced
            it. Held back until there is genuinely something to show: a result
            card reading "₹0" under a blank form is a screen telling the user
            they can afford nothing before they have said a word.
          */}
          {result.affordablePrice > 0 ? (
            <Animated.View
              /*
                An entrance, and one of very few places in this app that gets
                one.

                The rule the rest of the app follows is that anything seen tens
                of times a day should not animate — a filter pill, a list row, a
                tab. This is the opposite case. Someone reaches this card once,
                after typing their salary into a phone, and it is the answer to
                the question they opened the screen with. Appearing out of
                nothing is the jarring change; a short rise into place says
                where it came from.

                It fires ONCE, on mount, not on every keystroke. The card is
                mounted the moment the inputs first produce a number and stays
                mounted while they are edited, so the figures inside it update
                without the container re-entering — which would make the answer
                flicker as the user refines the inputs.

                Under reduced motion it is a plain fade: the appearance still
                needs announcing, the 12pt rise does not.
              */
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
                You could look at homes up to
              </Text>
              <Text variant="display" tone="accent" className="mt-xs">
                {formatPrice(result.affordablePrice)}
              </Text>

              <View className="mt-lg flex-row justify-between">
                <View>
                  <Text variant="caption" tone="muted">
                    Loan
                  </Text>
                  <Text variant="callout" className="mt-xs">
                    {formatPrice(result.loanAmount)}
                  </Text>
                </View>
                <View>
                  <Text variant="caption" tone="muted">
                    Monthly repayment
                  </Text>
                  <Text variant="callout" className="mt-xs">
                    {formatPrice(result.monthlyEmi)}
                  </Text>
                </View>
              </View>

              {/*
                What to change to move the number. This is the part a
                calculator usually leaves out and it is the part that is
                actionable — the model knows which of the two ceilings bound
                the answer and the user cannot see it.
              */}
              {result.limitedBy !== 'none' ? (
                <View className="mt-lg flex-row items-start">
                  <Ionicons
                    name="information-circle-outline"
                    size={15}
                    color={theme.colors.textMuted}
                    style={{ marginTop: 2 }}
                  />
                  <Text variant="caption" tone="muted" className="ml-xs flex-1">
                    {result.limitedBy === 'downPayment'
                      ? `Your deposit is what is holding this back — lenders fund at most ${Math.round(DEFAULT_LTV * 100)}% of the price, so every extra rupee saved raises this by five.`
                      : `Your income is what is holding this back — lenders allow around ${Math.round(DEFAULT_FOIR * 100)}% of it toward repayments. Clearing an existing EMI or a longer tenure both raise this.`}
                  </Text>
                </View>
              ) : null}
            </Animated.View>
          ) : null}

          {/*
            THE HANDOFF, and the reason this screen exists.

            The band is the closest thing the results screen can filter by, and
            the label says which band rather than implying the search is capped
            at the exact figure above. Overstating what the button does here
            would be the one lie on a screen otherwise built to be trusted with
            someone's salary.
          */}
          {band ? (
            <Button
              label={`Browse homes in ${band.label}`}
              className="mt-xl"
              align="center"
              onPress={() =>
                router.push({
                  pathname: '/properties',
                  params: { priceBand: band.id, listingType: 'sale' },
                })
              }
            />
          ) : null}

          <Text variant="caption" tone="muted" className="mt-xl">
            An estimate, not an offer. Lenders assess credit history, employment
            and the property itself, and the rate you are quoted may differ from
            the one above.
          </Text>
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
