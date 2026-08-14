import { useMemo, useState } from 'react';
import { View } from 'react-native';

import { formatPrice, Input, Text } from '@/ui';

/**
 * EMI calculator, ported from `PropertyDetailsContent.jsx` (~L567–753).
 *
 * Same defaults, same formula, same standard amortising-loan EMI equation —
 * this is arithmetic, not backend data, so there is nothing to verify against
 * production beyond matching the website's numbers on the same inputs.
 */
export interface EmiCalculatorProps {
  priceRupees: number;
}

const DEFAULT_INTEREST_RATE = 8.5;
const DEFAULT_TENURE_YEARS = 20;
/** 80% loan-to-value, same as the website's default. */
const DEFAULT_LTV = 0.8;

export function EmiCalculator({ priceRupees }: EmiCalculatorProps) {
  const [loanAmountText, setLoanAmountText] = useState(
    String(Math.round(priceRupees * DEFAULT_LTV))
  );
  const [interestRateText, setInterestRateText] = useState(String(DEFAULT_INTEREST_RATE));
  const [tenureYearsText, setTenureYearsText] = useState(String(DEFAULT_TENURE_YEARS));

  const { emi, totalPayment, totalInterest } = useMemo(() => {
    const principal = Number(loanAmountText) || 0;
    const rate = Number(interestRateText) || 0;
    const tenureYears = Number(tenureYearsText) || 0;

    if (principal <= 0 || rate <= 0 || tenureYears <= 0) {
      return { emi: 0, totalPayment: 0, totalInterest: 0 };
    }

    const r = rate / 100 / 12;
    const n = tenureYears * 12;
    const monthlyEmi = (principal * r * Math.pow(1 + r, n)) / (Math.pow(1 + r, n) - 1);
    const totalPay = monthlyEmi * n;

    return { emi: monthlyEmi, totalPayment: totalPay, totalInterest: totalPay - principal };
  }, [loanAmountText, interestRateText, tenureYearsText]);

  return (
    <View className="rounded-xl border border-border p-md">
      <Input
        label="Loan amount"
        value={loanAmountText}
        onChangeText={setLoanAmountText}
        keyboardType="numeric"
      />
      <View className="mt-base flex-row gap-sm">
        <View className="flex-1">
          <Input
            label="Interest rate (%)"
            value={interestRateText}
            onChangeText={setInterestRateText}
            keyboardType="decimal-pad"
          />
        </View>
        <View className="flex-1">
          <Input
            label="Tenure (years)"
            value={tenureYearsText}
            onChangeText={setTenureYearsText}
            keyboardType="number-pad"
          />
        </View>
      </View>

      <View className="mt-lg rounded-lg bg-surface-muted p-md">
        <Text variant="footnote" tone="secondary">
          Monthly EMI
        </Text>
        <Text variant="title2" tone="accent">
          {emi > 0 ? formatPrice(Math.round(emi)) : '—'}
        </Text>

        <View className="mt-md flex-row justify-between">
          <View>
            <Text variant="caption" tone="muted">
              Total interest
            </Text>
            <Text variant="callout">
              {totalInterest > 0 ? formatPrice(Math.round(totalInterest)) : '—'}
            </Text>
          </View>
          <View>
            <Text variant="caption" tone="muted">
              Total payment
            </Text>
            <Text variant="callout">
              {totalPayment > 0 ? formatPrice(Math.round(totalPayment)) : '—'}
            </Text>
          </View>
        </View>
      </View>
    </View>
  );
}
