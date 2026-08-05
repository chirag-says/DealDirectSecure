/**
 * Motion tokens.
 *
 * Motion here is described as BEHAVIOUR, not as a fixed-duration animation. A
 * scripted timing curve cannot respond to new input mid-flight; a spring can,
 * because new input only changes the target while the motion stays continuous.
 * Anything the user can touch gets a spring.
 *
 * Springs are parameterised the way a designer reasons about them rather than
 * as mass/stiffness/damping:
 *
 *   dampingRatio — controls overshoot. 1.0 settles with no bounce. Below 1.0
 *                  overshoots; lower is bouncier.
 *   duration     — how quickly the value reaches its target, in ms. This is NOT
 *                  a fixed runtime; a spring's settle time emerges from the
 *                  parameters. Reanimated calls this `duration` on a spring
 *                  config, which maps onto the "response" parameter.
 *
 * Default to `standard` (critically damped, no overshoot). Reach for `momentum`
 * ONLY when the gesture itself carried momentum, such as a flick or a drag
 * release. Overshoot on a menu that merely faded in reads as wrong; overshoot
 * on a card the user threw reads as right.
 */

export interface SpringToken {
  dampingRatio: number;
  duration: number;
}

export const spring = {
  /** Default for repositioning and state changes. No overshoot. */
  standard: { dampingRatio: 1.0, duration: 400 },
  /** Snappier variant for small elements and inline affordances. */
  quick: { dampingRatio: 1.0, duration: 280 },
  /** Follows a flick or drag release. Slight overshoot, earned by the gesture. */
  momentum: { dampingRatio: 0.8, duration: 400 },
  /** Bottom sheets and drawers. */
  sheet: { dampingRatio: 0.8, duration: 300 },
} as const satisfies Record<string, SpringToken>;

export type SpringName = keyof typeof spring;

/**
 * Timing values, reserved for non-interactive changes only: opacity fades,
 * color transitions, skeleton shimmer. Never use these for anything the user
 * can grab, because a timing curve cannot be interrupted cleanly.
 */
export const timing = {
  instant: 100,
  fast: 160,
  base: 220,
  slow: 320,
} as const;

/**
 * Deceleration rate for projecting where a flick is heading, used to pick the
 * snap target BEFORE animating to it. Snapping to the nearest point from the
 * release position ignores the throw; projecting forward is what makes a flick
 * feel like it carries.
 *
 * Projection uses exponential decay, matching platform scroll deceleration:
 *
 *   projected = current + (velocity / 1000) * rate / (1 - rate)
 *
 * The physics-textbook v^2/(2a) form is not what the platform ships and reads
 * noticeably differently.
 */
export const deceleration = {
  /** Normal scroll feel. */
  normal: 0.998,
  /** Snappier, for short-throw surfaces such as sheets. */
  fast: 0.99,
} as const;

/**
 * Gesture thresholds.
 *
 * `hysteresis` is the movement required before a drag commits to a direction,
 * which prevents a tap with a shaky finger from registering as a swipe.
 * `hitSlop` widens the touch target beyond the painted bounds.
 */
export const gesture = {
  hysteresis: 10,
  hitSlop: 10,
} as const;

/**
 * Reduced-motion substitution.
 *
 * Reduced motion means a gentler, non-vestibular equivalent, not the absence of
 * feedback. Slides, springs and parallax become short opacity cross-fades;
 * overshoot is dropped. Opacity and color changes that carry meaning stay.
 * Components read the OS setting and swap to this token rather than each site
 * inventing its own fallback.
 */
export const reducedMotion = {
  crossfade: timing.base,
} as const;
