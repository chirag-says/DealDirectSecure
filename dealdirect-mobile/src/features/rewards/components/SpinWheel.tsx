import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Modal, Pressable, StyleSheet, View, useWindowDimensions } from 'react-native';
import Animated, {
  Easing,
  FadeInUp,
  ZoomIn,
  runOnJS,
  useAnimatedStyle,
  useReducedMotion,
  useSharedValue,
  withTiming,
  type SharedValue,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { selection as hapticTick, success as hapticSuccess } from '@/native/haptics';
import { radius, spacing } from '@/theme';
import type { ActionReward } from '@/types/backend/property';
import { Button, Text } from '@/ui';

/**
 * The spin wheel reveal, ported from the website's `SpinWheelOverlay`.
 *
 * ---------------------------------------------------------------------------
 * THE WHEEL DOES NOT DECIDE ANYTHING
 *
 * The points were drawn and credited by the server before this opens
 * (`awardPoints`, weighted random by category), and the response carries the
 * amount and its rarity. The wheel is a reveal of that answer: it always
 * lands on the segment holding the awarded amount, and if the amount is not
 * on the wheel it lands on the nearest one, exactly as the website does.
 * Nothing here can change what was credited, and dismissing it changes
 * nothing either; the "Claim" button is a close button with a better name.
 *
 * ---------------------------------------------------------------------------
 * DRAWN WITH VIEWS, NOT SVG
 *
 * The website draws the wheel in SVG. This app does not carry react-native-svg
 * and a reveal is not worth a native dependency, so each segment is a border
 * triangle with its apex at the hub, rotated into place and clipped by the
 * wheel's circle. A sector of radius R and half-angle θ is exactly covered by
 * a triangle of height R and half-width R·tan θ, so there are no gaps; the
 * corners that stick out past R are what the circle mask trims.
 *
 * The spin is one timed rotation on the UI thread with the website's easing,
 * so it starts fast and settles slowly over the last turn. With the OS
 * "reduce motion" on, the wheel does not spin: the result is shown at once.
 */

interface Segment {
  points: number;
  label: string;
  color: string;
}

/** The website's wheels, one per random-reward category. */
const POSTING_WHEEL: readonly Segment[] = [
  { points: 40, label: '40', color: '#2563EB' },
  { points: 100, label: '100', color: '#7C3AED' },
  { points: 200, label: '200', color: '#0891B2' },
  { points: 1000, label: '1K', color: '#7C3AED' },
  { points: 5000, label: '5K', color: '#2563EB' },
  { points: 10000, label: '10K', color: '#7C3AED' },
  { points: 40000, label: '40K', color: '#0891B2' },
  { points: 100000, label: '100K', color: '#7C3AED' },
];
const ENQUIRY_WHEEL: readonly Segment[] = [
  { points: 20, label: '20', color: '#2563EB' },
  { points: 40, label: '40', color: '#7C3AED' },
  { points: 100, label: '100', color: '#0891B2' },
  { points: 400, label: '400', color: '#7C3AED' },
  { points: 1000, label: '1K', color: '#2563EB' },
  { points: 1600, label: '1.6K', color: '#7C3AED' },
  { points: 2000, label: '2K', color: '#0891B2' },
];
const WHEEL_SEGMENTS: Record<string, readonly Segment[]> = {
  property_posting: POSTING_WHEEL,
  property_enquiry: ENQUIRY_WHEEL,
};

interface Tier {
  label: string;
  color: string;
  explosive: boolean;
}
const COMMON_TIER: Tier = { label: 'Common', color: '#94A3B8', explosive: false };
const TIERS: Record<string, Tier> = {
  common: COMMON_TIER,
  uncommon: { label: 'Uncommon', color: '#34D399', explosive: false },
  rare: { label: 'Rare', color: '#A78BFA', explosive: true },
  epic: { label: 'Epic', color: '#FB923C', explosive: true },
  legendary: { label: 'Legendary', color: '#FBBF24', explosive: true },
};

/** The segment holding the amount, or the nearest one. Same as the website. */
function findTarget(segments: readonly Segment[], points: number): number {
  const exact = segments.findIndex((s) => s.points === points);
  if (exact !== -1) return exact;
  let best = 0;
  let distance = Number.POSITIVE_INFINITY;
  segments.forEach((s, i) => {
    const d = Math.abs(s.points - points);
    if (d < distance) {
      distance = d;
      best = i;
    }
  });
  return best;
}

const CONFETTI_COLOURS = ['#D4AF37', '#FBBF24', '#F59E0B', '#FDE68A'] as const;
const SPIN_MS = 4800;
const COUNTDOWN_STEP_MS = 600;
const RING = 16;
const HUB = 40;
const SHEET = '#111111';

type Phase = 'idle' | 'countdown' | 'spinning' | 'done';

export interface SpinWheelProps {
  /** Null or zero points renders nothing, so this can stay mounted. */
  reward: ActionReward | null;
  onDismiss: () => void;
}

export function SpinWheel({ reward, onDismiss }: SpinWheelProps) {
  if (!reward || reward.pointsAwarded <= 0) return null;
  return <SpinWheelOverlay reward={reward} onDismiss={onDismiss} />;
}

function SpinWheelOverlay({ reward, onDismiss }: { reward: ActionReward; onDismiss: () => void }) {
  const { width, height } = useWindowDimensions();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();

  const segments = WHEEL_SEGMENTS[reward.rewardCategory ?? ''] ?? ENQUIRY_WHEEL;
  const span = 360 / segments.length;
  const target = useMemo(
    () => findTarget(segments, reward.pointsAwarded),
    [segments, reward.pointsAwarded]
  );
  const tier = TIERS[reward.rewardTier ?? ''] ?? COMMON_TIER;

  // Geometry, from the width the card actually has.
  const size = Math.min(width - spacing['2xl'] * 2 - spacing.lg * 2, 320);
  const radiusPx = size / 2 - RING;
  const halfWidth = radiusPx * Math.tan(Math.PI / segments.length);

  const [phase, setPhase] = useState<Phase>(reduceMotion ? 'done' : 'idle');
  const [count, setCount] = useState<number | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);
  const later = (fn: () => void, ms: number) => {
    timers.current.push(setTimeout(fn, ms));
  };

  const rotation = useSharedValue(0);
  const flash = useSharedValue(0);

  const wheelStyle = useAnimatedStyle(() => ({
    transform: [{ rotate: `${rotation.value}deg` }],
  }));
  const flashStyle = useAnimatedStyle(() => ({ opacity: flash.value }));

  const landed = useCallback(() => {
    hapticSuccess();
    if (tier.explosive) {
      flash.value = 1;
      flash.value = withTiming(0, { duration: 500 });
    }
    later(() => setPhase('done'), tier.explosive ? 400 : 150);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tier.explosive]);

  const spin = () => {
    if (phase !== 'idle') return;
    setPhase('countdown');
    setCount(3);
    hapticTick();
    later(() => {
      setCount(2);
      hapticTick();
    }, COUNTDOWN_STEP_MS);
    later(() => {
      setCount(1);
      hapticTick();
    }, COUNTDOWN_STEP_MS * 2);
    later(() => {
      setCount(null);
      setPhase('spinning');
      // Six or seven full turns, then the target segment's centre under the
      // pointer at twelve o'clock. Segment i spans [i·span, (i+1)·span]
      // clockwise from the top, so rotating by 360 minus its centre brings
      // it there.
      const turns = 6 + Math.floor(Math.random() * 2);
      const final = turns * 360 + (360 - (target * span + span / 2));
      rotation.value = withTiming(
        final,
        { duration: SPIN_MS, easing: Easing.bezier(0.08, 0.6, 0.08, 1) },
        (finished) => {
          if (finished) runOnJS(landed)();
        }
      );
    }, COUNTDOWN_STEP_MS * 3);
  };

  const done = phase === 'done';
  const spinning = phase === 'spinning';

  return (
    <Modal
      visible
      transparent
      animationType="fade"
      onRequestClose={done ? onDismiss : () => undefined}
      statusBarTranslucent
      navigationBarTranslucent
    >
      <View
        style={[
          styles.backdrop,
          {
            paddingTop: insets.top + spacing.lg,
            paddingBottom: insets.bottom + spacing.lg,
            paddingHorizontal: spacing['2xl'],
          },
        ]}
      >
        <Animated.View pointerEvents="none" style={[styles.flash, flashStyle]} />

        {done && tier.explosive ? <Confetti height={height} width={width} /> : null}

        <View style={styles.card}>
          <Text variant="overline" style={styles.eyebrow}>
            {done ? 'RESULT' : 'REWARD'}
          </Text>
          <Text variant="title2" style={styles.heading}>
            {done ? 'You won' : 'Spin the wheel'}
          </Text>

          {!done ? (
            <View style={{ alignItems: 'center', marginTop: spacing.lg }}>
              <View style={{ width: size, height: size }}>
                {/* The pointer, fixed at twelve o'clock above the wheel. */}
                <View
                  style={[
                    styles.pointer,
                    {
                      left: size / 2 - 16,
                      borderLeftWidth: 16,
                      borderRightWidth: 16,
                      borderTopWidth: 30,
                    },
                  ]}
                />

                <Pressable
                  accessibilityRole="button"
                  accessibilityLabel={phase === 'idle' ? 'Spin the wheel' : 'Spinning'}
                  accessibilityState={{ disabled: phase !== 'idle' }}
                  onPress={spin}
                  style={{ width: size, height: size }}
                >
                  <Animated.View
                    style={[
                      styles.ring,
                      { width: size, height: size, borderRadius: size / 2 },
                      wheelStyle,
                    ]}
                  >
                    <View
                      style={{
                        position: 'absolute',
                        left: RING - 6,
                        top: RING - 6,
                        width: radiusPx * 2,
                        height: radiusPx * 2,
                        borderRadius: radiusPx,
                        overflow: 'hidden',
                        backgroundColor: SHEET,
                      }}
                    >
                      {segments.map((segment, i) => {
                        const mid = i * span + span / 2;
                        return (
                          <View
                            key={segment.points}
                            style={{
                              position: 'absolute',
                              left: radiusPx - halfWidth,
                              top: 0,
                              width: 0,
                              height: 0,
                              borderLeftWidth: halfWidth,
                              borderRightWidth: halfWidth,
                              borderTopWidth: radiusPx,
                              borderLeftColor: 'transparent',
                              borderRightColor: 'transparent',
                              borderTopColor: segment.color,
                              transformOrigin: '50% 100%',
                              transform: [{ rotate: `${mid}deg` }],
                            }}
                          />
                        );
                      })}

                      {/* Hairlines between segments, so adjacent colours read
                          as separate prizes. */}
                      {segments.map((segment, i) => (
                        <View
                          key={`line-${segment.points}`}
                          style={{
                            position: 'absolute',
                            left: radiusPx - 0.75,
                            top: 0,
                            width: 1.5,
                            height: radiusPx,
                            backgroundColor: SHEET,
                            transformOrigin: '50% 100%',
                            transform: [{ rotate: `${i * span}deg` }],
                          }}
                        />
                      ))}

                      {segments.map((segment, i) => {
                        const mid = i * span + span / 2;
                        return (
                          <View
                            key={`label-${segment.points}`}
                            style={{
                              position: 'absolute',
                              left: radiusPx - 40,
                              top: radiusPx - 12,
                              width: 80,
                              height: 24,
                              alignItems: 'center',
                              justifyContent: 'center',
                              transform: [
                                { rotate: `${mid}deg` },
                                { translateY: -radiusPx * 0.63 },
                              ],
                            }}
                          >
                            <Text
                              style={{
                                color: '#FFFFFF',
                                fontWeight: '700',
                                fontSize: segment.label.length > 3 ? 12 : 15,
                                opacity: 0.92,
                              }}
                            >
                              {segment.label}
                            </Text>
                          </View>
                        );
                      })}

                      {/* The hub. Counter-rotated so its word stays upright
                          while the wheel turns. */}
                      <Animated.View
                        style={[
                          styles.hub,
                          {
                            left: radiusPx - HUB - 4,
                            top: radiusPx - HUB - 4,
                            width: (HUB + 4) * 2,
                            height: (HUB + 4) * 2,
                            borderRadius: HUB + 4,
                          },
                        ]}
                      >
                        <View
                          style={[
                            styles.hubInner,
                            { width: HUB * 2, height: HUB * 2, borderRadius: HUB },
                          ]}
                        >
                          <Text
                            style={{
                              color: '#FFFFFF',
                              fontWeight: '800',
                              fontSize: count !== null ? 22 : 13,
                              letterSpacing: 0.5,
                            }}
                          >
                            {count !== null ? String(count) : spinning ? '•••' : 'SPIN'}
                          </Text>
                        </View>
                      </Animated.View>
                    </View>
                  </Animated.View>
                </Pressable>
              </View>

              <Text
                variant="footnote"
                style={[styles.prompt, { opacity: phase === 'idle' ? 0.4 : 0.6 }]}
              >
                {count !== null ? 'Get ready' : spinning ? 'Spinning' : 'Tap the wheel to spin'}
              </Text>
            </View>
          ) : (
            <View
              style={{ alignItems: 'center', paddingVertical: spacing.lg }}
              accessibilityLiveRegion="polite"
            >
              <Animated.View
                entering={reduceMotion ? undefined : ZoomIn.springify().damping(14)}
                style={[
                  styles.tierChip,
                  { borderColor: `${tier.color}55`, backgroundColor: `${tier.color}14` },
                ]}
              >
                <Text variant="overline" style={{ color: tier.color, letterSpacing: 2 }}>
                  {tier.label.toUpperCase()}
                </Text>
              </Animated.View>

              <Animated.View
                entering={reduceMotion ? undefined : ZoomIn.delay(100).springify().damping(14)}
                style={{ alignItems: 'center', marginTop: spacing.xl }}
              >
                <Text style={styles.points}>{reward.pointsAwarded.toLocaleString('en-IN')}</Text>
                <Text variant="overline" style={styles.pointsCaption}>
                  POINTS
                </Text>
              </Animated.View>

              <Animated.View
                entering={reduceMotion ? undefined : FadeInUp.delay(300)}
                style={{ alignItems: 'center', marginTop: spacing.lg }}
              >
                {reward.cashValue ? (
                  <Text variant="callout" style={styles.muted}>
                    Worth ₹{reward.cashValue.toLocaleString('en-IN')} in the rewards store
                  </Text>
                ) : null}
                {typeof reward.newBalance === 'number' ? (
                  <Text variant="footnote" style={[styles.muted, { marginTop: spacing.xs }]}>
                    Balance: {reward.newBalance.toLocaleString('en-IN')} points
                  </Text>
                ) : null}
              </Animated.View>

              <Animated.View
                entering={reduceMotion ? undefined : FadeInUp.delay(400)}
                style={{ alignSelf: 'stretch', marginTop: spacing['2xl'] }}
              >
                <Button label="Claim reward" fullWidth onPress={onDismiss} />
              </Animated.View>
            </View>
          )}
        </View>
      </View>
    </Modal>
  );
}

/**
 * Gold confetti for the rare tiers. One shared clock drives every particle,
 * each with its own drift, size and speed chosen once, so forty views cost
 * one animation.
 */
function Confetti({ width, height }: { width: number; height: number }) {
  const clock = useSharedValue(0);
  useEffect(() => {
    clock.value = withTiming(1, { duration: 3200, easing: Easing.out(Easing.quad) });
  }, [clock]);

  const particles = useMemo(
    () =>
      Array.from({ length: 36 }, (_, i) => ({
        x: Math.random() * width,
        size: 4 + Math.random() * 5,
        drift: (Math.random() - 0.5) * 180,
        speed: 0.6 + Math.random() * 0.4,
        color: CONFETTI_COLOURS[i % CONFETTI_COLOURS.length] ?? '#FBBF24',
      })),
    [width]
  );

  return (
    <View pointerEvents="none" style={StyleSheet.absoluteFill}>
      {particles.map((p, i) => (
        <Particle key={i} clock={clock} height={height} {...p} />
      ))}
    </View>
  );
}

function Particle({
  clock,
  height,
  x,
  size,
  drift,
  speed,
  color,
}: {
  clock: SharedValue<number>;
  height: number;
  x: number;
  size: number;
  drift: number;
  speed: number;
  color: string;
}) {
  const style = useAnimatedStyle(() => {
    const t = Math.min(clock.value / speed, 1);
    return {
      opacity: 1 - t,
      transform: [
        { translateY: -10 + t * (height + 20) },
        { translateX: t * drift },
        { rotate: `${t * 540}deg` },
      ],
    };
  });
  return (
    <Animated.View
      style={[
        {
          position: 'absolute',
          top: 0,
          left: x,
          width: size,
          height: size,
          borderRadius: size / 2,
          backgroundColor: color,
        },
        style,
      ]}
    />
  );
}

const styles = StyleSheet.create({
  backdrop: {
    flex: 1,
    justifyContent: 'center',
    backgroundColor: 'rgba(0, 0, 0, 0.85)',
  },
  flash: {
    ...StyleSheet.absoluteFillObject,
    backgroundColor: 'rgba(251, 191, 36, 0.18)',
  },
  card: {
    backgroundColor: SHEET,
    borderRadius: 24,
    paddingHorizontal: spacing.lg,
    paddingTop: spacing['2xl'],
    paddingBottom: spacing['2xl'],
    shadowColor: '#000',
    shadowOpacity: 0.6,
    shadowRadius: 40,
    shadowOffset: { width: 0, height: 24 },
    elevation: 12,
  },
  eyebrow: {
    color: 'rgba(255,255,255,0.3)',
    textAlign: 'center',
    letterSpacing: 3,
  },
  heading: {
    color: '#FFFFFF',
    textAlign: 'center',
    marginTop: spacing.xs,
  },
  pointer: {
    position: 'absolute',
    top: -6,
    zIndex: 20,
    width: 0,
    height: 0,
    borderLeftColor: 'transparent',
    borderRightColor: 'transparent',
    borderTopColor: '#FFFFFF',
  },
  ring: {
    borderWidth: 6,
    borderColor: '#333333',
    backgroundColor: '#222222',
  },
  hub: {
    position: 'absolute',
    backgroundColor: '#333333',
    alignItems: 'center',
    justifyContent: 'center',
  },
  hubInner: {
    backgroundColor: SHEET,
    alignItems: 'center',
    justifyContent: 'center',
  },
  prompt: {
    color: '#FFFFFF',
    marginTop: spacing.lg,
    letterSpacing: 0.5,
  },
  tierChip: {
    paddingHorizontal: spacing.base,
    paddingVertical: spacing.xs + 2,
    borderRadius: radius.full,
    borderWidth: 1,
  },
  points: {
    color: '#FFFFFF',
    fontSize: 64,
    lineHeight: 70,
    fontWeight: '900',
    letterSpacing: -1,
  },
  pointsCaption: {
    color: 'rgba(255,255,255,0.3)',
    letterSpacing: 4,
    marginTop: spacing.sm,
  },
  muted: {
    color: 'rgba(255,255,255,0.45)',
    textAlign: 'center',
  },
});
