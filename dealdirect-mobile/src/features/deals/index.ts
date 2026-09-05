/**
 * Deals: the lead seen from either side. Cross-feature imports come through
 * this file only.
 */

export {
  useMyDeals,
  useDeal,
  useProposeVisit,
  useUpdateVisit,
  useVisitFeedback,
  useOpenConversation,
  useAttestClose,
  type DealListState,
  type DealState,
} from './hooks';
export {
  DEAL_STAGES,
  isDealStage,
  stageLabel,
  stageProgressLabel,
  stageTone,
  stageIcon,
  stageIndex,
  isStageAtLeast,
  type StageIcon,
} from './stage';
export {
  visitState,
  visitActions,
  visitWaitingCopy,
  visitUpdateErrorCopy,
  isVisitOpen,
  type VisitControl,
  type VisitState,
  type VisitWaiting,
} from './visitState';
export {
  validateVisitTime,
  composeVisitDate,
  visitTimeErrorCopy,
  MAX_DAYS_AHEAD,
  type VisitTimeError,
} from './visitTime';

export { DealProgress, type DealProgressProps } from './components/DealProgress';
export { VisitCard, type VisitCardProps } from './components/VisitCard';
export { VisitSheet, type VisitSheetProps } from './components/VisitSheet';
export { DealRow, type DealRowProps } from './components/DealRow';
export { CounterpartCard, type CounterpartCardProps } from './components/CounterpartCard';
export { DealMessages, type DealMessagesProps } from './components/DealMessages';
export { AgreementCard, type AgreementCardProps } from './components/AgreementCard';
export { CloseCard, type CloseCardProps } from './components/CloseCard';
export { BuyerContextCard, type BuyerContextCardProps } from './components/BuyerContextCard';
