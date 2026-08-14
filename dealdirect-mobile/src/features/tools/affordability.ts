/**
 * What a buyer can afford, and the loan arithmetic behind it.
 *
 * ---------------------------------------------------------------------------
 * WHY THE APP HAS THIS AT ALL
 *
 * Housing.com's mobile home carries a whole section of them — "Use property
 * research tools: EMI, Eligibility, Affordability, Area, Valuation, Rent
 * Value" — and of the six, affordability is the only one that changes what the
 * user does next. The other five answer a question about a number they already
 * have. This one answers "where do I even start", which is the question a
 * first-time buyer actually opens the app with, and its answer is a price
 * range they can then search.
 *
 * That is the reason it exists here and the reason the screen ends in a search
 * rather than in a figure. A calculator that produces a number and stops is a
 * toy; one that hands its result to the results screen is part of the product.
 *
 * ---------------------------------------------------------------------------
 * THE MODEL, AND WHY IT IS THE ONE INDIAN LENDERS USE
 *
 * Two independent ceilings, and the affordable price is the LOWER of them.
 * Getting only one right is the usual mistake and it overstates the answer by
 * a wide margin in both directions.
 *
 *  1. **Repayment capacity (FOIR).** Lenders cap total monthly obligations at a
 *     fixed share of net income — the fixed-obligation-to-income ratio, around
 *     50% at most Indian banks for a salaried applicant. Whatever is left after
 *     existing EMIs is what a new one can be. Inverting the standard amortising
 *     EMI formula turns that monthly figure into a principal.
 *
 *  2. **Loan-to-value.** No lender funds the whole purchase. At the usual 80%
 *     ceiling the down payment has to cover the remaining 20%, so a buyer with
 *     ₹10 lakh saved cannot buy above ₹50 lakh however large their income —
 *     which is exactly the case a calculator that only models income gets
 *     badly wrong, and the case most first-time buyers are actually in.
 *
 * Every rate here is a DEFAULT the user can change, not a claim about their
 * bank. The numbers are the ones the website's own EMI calculator ships with,
 * so the two clients agree.
 */

/** Share of net monthly income a lender will let all EMIs consume. */
export const DEFAULT_FOIR = 0.5;
/** Share of the property price a lender will fund. */
export const DEFAULT_LTV = 0.8;
export const DEFAULT_INTEREST_RATE = 8.5;
export const DEFAULT_TENURE_YEARS = 20;

export interface AffordabilityInput {
  /** Net monthly income, in rupees, after tax. */
  monthlyIncome: number;
  /** Existing monthly EMIs and other fixed obligations, in rupees. */
  monthlyObligations: number;
  /** Cash available for the down payment, in rupees. */
  downPayment: number;
  /** Annual interest rate, as a percentage. */
  interestRate: number;
  tenureYears: number;
}

export interface AffordabilityResult {
  /** The lower of the two ceilings — what the buyer can actually pay. */
  affordablePrice: number;
  /** The loan that price implies. */
  loanAmount: number;
  /** The monthly repayment on that loan. */
  monthlyEmi: number;
  /**
   * Which ceiling bound the answer, so the screen can say what to change.
   *
   * This is the single most useful output and the reason the result is a shape
   * rather than a number: "increase your down payment" and "reduce your
   * existing EMIs" are completely different advice, and which one applies is
   * something the calculation knows and the user cannot see.
   */
  limitedBy: 'income' | 'downPayment' | 'none';
}

/**
 * The principal a given monthly payment can service.
 *
 * The standard amortising formula solved for P:
 *
 *   EMI = P·r·(1+r)^n / ((1+r)^n − 1)
 *   P   = EMI·((1+r)^n − 1) / (r·(1+r)^n)
 *
 * where r is the monthly rate and n the number of months.
 */
export function loanForEmi(emi: number, annualRate: number, tenureYears: number): number {
  if (emi <= 0 || annualRate <= 0 || tenureYears <= 0) return 0;

  const r = annualRate / 100 / 12;
  const n = tenureYears * 12;
  const growth = Math.pow(1 + r, n);

  return (emi * (growth - 1)) / (r * growth);
}

/** The monthly payment a given principal requires. The formula above, forward. */
export function emiForLoan(principal: number, annualRate: number, tenureYears: number): number {
  if (principal <= 0 || annualRate <= 0 || tenureYears <= 0) return 0;

  const r = annualRate / 100 / 12;
  const n = tenureYears * 12;
  const growth = Math.pow(1 + r, n);

  return (principal * r * growth) / (growth - 1);
}

export function calculateAffordability(input: AffordabilityInput): AffordabilityResult {
  const { monthlyIncome, monthlyObligations, downPayment, interestRate, tenureYears } = input;

  const empty: AffordabilityResult = {
    affordablePrice: 0,
    loanAmount: 0,
    monthlyEmi: 0,
    limitedBy: 'none',
  };

  if (monthlyIncome <= 0) return empty;

  // Ceiling 1: what income supports. Clamped at zero — obligations exceeding
  // the FOIR allowance is a real situation and it means no new loan, not a
  // negative one.
  const availableEmi = Math.max(0, monthlyIncome * DEFAULT_FOIR - Math.max(0, monthlyObligations));
  const maxLoan = loanForEmi(availableEmi, interestRate, tenureYears);
  const priceFromIncome = maxLoan + Math.max(0, downPayment);

  // Ceiling 2: what the down payment supports at the LTV cap. With no down
  // payment at all there is no purchase, whatever the income.
  const priceFromDownPayment =
    downPayment > 0 ? downPayment / (1 - DEFAULT_LTV) : 0;

  const affordablePrice = Math.min(priceFromIncome, priceFromDownPayment);
  if (affordablePrice <= 0) return empty;

  const loanAmount = Math.max(0, affordablePrice - downPayment);

  return {
    affordablePrice: Math.round(affordablePrice),
    loanAmount: Math.round(loanAmount),
    monthlyEmi: Math.round(emiForLoan(loanAmount, interestRate, tenureYears)),
    // A near-tie is reported as neither: telling someone to raise a down
    // payment that is already within a percent of binding is advice that will
    // not move the answer.
    limitedBy:
      Math.abs(priceFromIncome - priceFromDownPayment) / affordablePrice < 0.01
        ? 'none'
        : priceFromIncome < priceFromDownPayment
          ? 'income'
          : 'downPayment',
  };
}
