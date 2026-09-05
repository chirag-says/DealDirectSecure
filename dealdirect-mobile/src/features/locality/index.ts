/**
 * Locality price data (Phase 4, F18).
 *
 * Asking prices from DealDirect listings, aggregated per quarter and published
 * only above a sample floor. Not sale prices and not a valuation — every
 * surface that renders this says so, and `format.ts` is written so those
 * strings survive being read next to the disclosure.
 */

export {
  useLocalities,
  useLocality,
  usePriceGuidance,
  type LocalityDetailQuery,
  type LocalityListQuery,
  type PriceGuidanceQuery,
} from './hooks';

export {
  QOQ_DEAD_BAND_PCT,
  configurationHeading,
  formatMedian,
  formatQoq,
  formatQuarter,
  formatRange,
  formatSampleLine,
  trendBars,
  type QoqDirection,
  type QoqLine,
  type TrendBar,
} from './format';

export { TrendBars, type TrendBarsProps } from './components/TrendBars';
export { PriceGuidanceLine, type PriceGuidanceLineProps } from './components/PriceGuidanceLine';
