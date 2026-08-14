/**
 * Property research tools. Cross-feature imports come through this file only.
 */

export {
  DEFAULT_FOIR,
  DEFAULT_INTEREST_RATE,
  DEFAULT_LTV,
  DEFAULT_TENURE_YEARS,
  calculateAffordability,
  emiForLoan,
  loanForEmi,
  type AffordabilityInput,
  type AffordabilityResult,
} from './affordability';

export { ToolsRow, type ToolsRowProps, type ToolRoute } from './components/ToolsRow';
export { RupeeField, type RupeeFieldProps } from './components/RupeeField';
