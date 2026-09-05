/**
 * The five stages of a deal, in one place.
 *
 * `stage` is derived server-side (`backend/utils/dealStage.js`) and arrives
 * on every deal read and every deal write. This file only turns it into words,
 * a tone and an icon; it never decides what stage a deal is in.
 *
 * Pure TypeScript with no React Native import, so `stage.test.ts` runs under
 * `node --test`. The icon type is a type-only import and is erased.
 */

import type Ionicons from '@expo/vector-icons/Ionicons';

import type { DealStage } from '@/types/backend/deal';
import type { BadgeTone } from '@/ui';

export type StageIcon = keyof typeof Ionicons.glyphMap;

/** Stage order. The index is the progress position. */
export const DEAL_STAGES: readonly DealStage[] = [
  'contacted',
  'visit_scheduled',
  'visited',
  'agreement',
  'closed',
];

interface StageVocabulary {
  label: string;
  /** For the progress tracker row: what happened, as a short past-tense line. */
  progressLabel: string;
  tone: BadgeTone;
  icon: StageIcon;
}

const VOCABULARY: Record<DealStage, StageVocabulary> = {
  contacted: {
    label: 'Contacted',
    progressLabel: 'Enquiry sent',
    tone: 'neutral',
    icon: 'chatbubble-ellipses-outline',
  },
  visit_scheduled: {
    label: 'Visit planned',
    progressLabel: 'Visit planned',
    tone: 'accent',
    icon: 'calendar-outline',
  },
  visited: {
    label: 'Visited',
    progressLabel: 'Visit done',
    tone: 'accent',
    icon: 'walk-outline',
  },
  agreement: {
    label: 'Agreement',
    progressLabel: 'Agreement drafted',
    tone: 'warning',
    icon: 'document-text-outline',
  },
  closed: {
    label: 'Closed',
    progressLabel: 'Deal closed',
    tone: 'success',
    icon: 'checkmark-circle-outline',
  },
};

/**
 * The fallback for a stage this build does not know. The server may grow a
 * stage before the app does, and an unknown value must still render a row
 * rather than crash a screen about someone's home purchase.
 */
const UNKNOWN: StageVocabulary = {
  label: 'In progress',
  progressLabel: 'In progress',
  tone: 'neutral',
  icon: 'ellipse-outline',
};

export function isDealStage(value: unknown): value is DealStage {
  return typeof value === 'string' && (DEAL_STAGES as readonly string[]).includes(value);
}

function vocabulary(stage: string): StageVocabulary {
  return isDealStage(stage) ? VOCABULARY[stage] : UNKNOWN;
}

export function stageLabel(stage: string): string {
  return vocabulary(stage).label;
}

export function stageProgressLabel(stage: string): string {
  return vocabulary(stage).progressLabel;
}

export function stageTone(stage: string): BadgeTone {
  return vocabulary(stage).tone;
}

export function stageIcon(stage: string): StageIcon {
  return vocabulary(stage).icon;
}

/** Position in `DEAL_STAGES`, or -1 for an unknown stage. */
export function stageIndex(stage: string): number {
  return isDealStage(stage) ? DEAL_STAGES.indexOf(stage) : -1;
}

/** True when `stage` is `at` or later. An unknown stage is never "at least". */
export function isStageAtLeast(stage: string, at: DealStage): boolean {
  const index = stageIndex(stage);
  return index >= 0 && index >= DEAL_STAGES.indexOf(at);
}
