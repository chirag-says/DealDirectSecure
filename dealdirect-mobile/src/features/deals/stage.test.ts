import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  DEAL_STAGES,
  isDealStage,
  isStageAtLeast,
  stageIcon,
  stageIndex,
  stageLabel,
  stageProgressLabel,
  stageTone,
} from './stage.ts';

describe('stage vocabulary', () => {
  it('lists the five stages in order', () => {
    assert.deepEqual(DEAL_STAGES, ['contacted', 'visit_scheduled', 'visited', 'agreement', 'closed']);
  });

  it('has a label, a progress label, a tone and an icon for every stage', () => {
    for (const stage of DEAL_STAGES) {
      assert.ok(stageLabel(stage).length > 0, `${stage} label`);
      assert.ok(stageProgressLabel(stage).length > 0, `${stage} progress label`);
      assert.ok(stageIcon(stage).length > 0, `${stage} icon`);
      assert.ok(
        ['neutral', 'accent', 'success', 'warning', 'danger'].includes(stageTone(stage)),
        `${stage} tone`
      );
    }
  });

  it('pins the tones that carry meaning', () => {
    assert.equal(stageTone('contacted'), 'neutral');
    assert.equal(stageTone('closed'), 'success');
    assert.equal(stageTone('agreement'), 'warning');
  });

  it('falls back for an unknown stage instead of throwing', () => {
    assert.equal(stageLabel('escrow'), 'In progress');
    assert.equal(stageTone('escrow'), 'neutral');
    assert.equal(stageIcon('escrow'), 'ellipse-outline');
    assert.equal(stageProgressLabel(''), 'In progress');
  });

  it('recognises stages', () => {
    assert.equal(isDealStage('visited'), true);
    assert.equal(isDealStage('Visited'), false);
    assert.equal(isDealStage(undefined), false);
    assert.equal(isDealStage(3), false);
  });

  it('orders stages', () => {
    assert.equal(stageIndex('contacted'), 0);
    assert.equal(stageIndex('closed'), 4);
    assert.equal(stageIndex('nope'), -1);
    assert.equal(isStageAtLeast('visited', 'visit_scheduled'), true);
    assert.equal(isStageAtLeast('visited', 'visited'), true);
    assert.equal(isStageAtLeast('visit_scheduled', 'visited'), false);
    assert.equal(isStageAtLeast('nope', 'contacted'), false);
  });
});
