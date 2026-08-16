import Ionicons from '@expo/vector-icons/Ionicons';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import { Pressable } from 'react-native';
import Animated, {
  FadeIn,
  FadeInDown,
  FadeOut,
  FadeOutDown,
  useReducedMotion,
} from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { gesture, radius, reducedMotion, spacing, timing, touchTarget, useTheme } from '@/theme';
import { Text } from './Text';

/**
 * Transient confirmation.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * The app had no non-blocking notification surface at all, so every "saved",
 * "copied", "removed" and "sent" was an `Alert.alert` — a modal, with a button,
 * that stops the world to tell you the thing you just asked for happened.
 * Eleven screens did this.
 *
 * A modal is the right shape for a question ("delete this listing?") and the
 * wrong shape for an answer ("deleted"). Confirmations that require dismissal
 * train users to tap OK without reading, which is precisely how a genuine
 * warning gets dismissed unread later.
 *
 * `Alert.alert` stays for destructive confirmations and for errors that must
 * be acknowledged. This is for everything else.
 *
 * ---------------------------------------------------------------------------
 * IT SITS ABOVE THE TAB BAR, NOT AT THE BOTTOM OF THE SCREEN
 *
 * Anchored to `insets.bottom` plus the tab bar's height, so it never covers the
 * navigation the user might want next. Bottom rather than top because the
 * thumb is there and because the top edge belongs to the nav bar.
 */

export type ToastTone = 'neutral' | 'success' | 'danger';

export interface ToastAction {
  /** One word if possible. "Undo" is the case this was built for. */
  label: string;
  onPress: () => void;
}

export interface ToastOptions {
  tone?: ToastTone;
  /**
   * Turns the toast into the reversal path for the action that raised it.
   *
   * This is the half of "do, don't ask" that most implementations skip. A
   * confirmation dialog is an admission that an action cannot be taken back;
   * the fix is to make it reversible, not to word the dialog better. Removing
   * a saved listing and marking interest are both routed through here rather
   * than through `Alert.alert`, so the common case costs one tap and the
   * mis-tap costs two.
   *
   * The toast stops being `pointerEvents="none"` when an action is present,
   * and only then — a toast with nothing to press must never eat a tap meant
   * for the screen behind it.
   */
  action?: ToastAction;
}

interface ToastState {
  id: number;
  message: string;
  tone: ToastTone;
  action?: ToastAction;
}

interface ToastApi {
  /** The second argument takes a bare tone for the common case, or options. */
  show: (message: string, options?: ToastTone | ToastOptions) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

/**
 * Never throws when unmounted.
 *
 * A missing provider should not crash a screen over a confirmation message —
 * the worst honest outcome is that the toast does not appear. This is
 * deliberately unlike `useChat`, where a missing provider means the feature
 * genuinely cannot work.
 */
export function useToast(): ToastApi {
  return useContext(ToastContext) ?? NOOP_TOAST;
}

const NOOP_TOAST: ToastApi = { show: () => {} };

/** Long enough to read a short sentence, short enough not to linger. */
const VISIBLE_MS = 2600;

/** An undo the user has to notice, read, and reach for needs longer than one
 *  they only have to read. */
const VISIBLE_WITH_ACTION_MS = 5000;

/** Roughly the tab bar's painted height, so a toast clears it. */
const TAB_BAR_ALLOWANCE = 64;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const reduceMotion = useReducedMotion();
  const [toast, setToast] = useState<ToastState | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const nextId = useRef(0);

  const show = useCallback((message: string, options?: ToastTone | ToastOptions) => {
    const resolved: ToastOptions = typeof options === 'string' ? { tone: options } : (options ?? {});

    // A second toast replaces the first rather than queueing. A queue means the
    // user reads a stale confirmation for an action two steps ago.
    if (timer.current) clearTimeout(timer.current);
    nextId.current += 1;
    setToast({
      id: nextId.current,
      message,
      tone: resolved.tone ?? 'neutral',
      action: resolved.action,
    });
    timer.current = setTimeout(
      () => setToast(null),
      resolved.action ? VISIBLE_WITH_ACTION_MS : VISIBLE_MS
    );
  }, []);

  const dismiss = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    setToast(null);
  }, []);

  const api = useMemo(() => ({ show }), [show]);

  const icon: Record<ToastTone, keyof typeof Ionicons.glyphMap> = {
    neutral: 'information-circle',
    success: 'checkmark-circle',
    danger: 'alert-circle',
  };

  const iconColor: Record<ToastTone, string> = {
    neutral: theme.colors.textOnAccent,
    success: theme.colors.success,
    danger: theme.colors.danger,
  };

  return (
    <ToastContext.Provider value={api}>
      {children}

      {toast ? (
        <Animated.View
          // Keyed on id so a replacement toast re-runs the entrance rather than
          // silently swapping its text, which reads as the message changing
          // under you.
          key={toast.id}
          /*
            The slide is dropped under reduced motion; the fade is not.

            This is the clearest case in the app for that setting. A toast is
            AUTONOMOUS motion — it arrives because the app decided to show it,
            not because the user moved anything — and it enters from off-screen
            near the bottom edge, which is the largest unrequested travel any
            element here makes. The fade alone still announces it, and
            `accessibilityLiveRegion` announces it to a screen reader either way.

            Everything else animated in this app already honours the rule stated
            in `theme/motion.ts`; this component was the exception.
          */
          entering={
            reduceMotion
              ? FadeIn.duration(reducedMotion.crossfade)
              : FadeInDown.springify().damping(18)
          }
          exiting={
            reduceMotion ? FadeOut.duration(timing.fast) : FadeOutDown.duration(timing.fast)
          }
          // Only interactive when there is something to press. A toast that
          // swallows taps for its own benefit is worse than no toast.
          pointerEvents={toast.action ? 'box-none' : 'none'}
          accessibilityLiveRegion="polite"
          style={{
            position: 'absolute',
            left: spacing.base,
            right: spacing.base,
            bottom: insets.bottom + TAB_BAR_ALLOWANCE,
            flexDirection: 'row',
            alignItems: 'center',
            paddingVertical: spacing.md,
            paddingHorizontal: spacing.base,
            borderRadius: radius.lg,
            // Inverted against the page, so it reads as a layer above the app
            // rather than as another card in it.
            backgroundColor: theme.colors.textPrimary,
            shadowColor: '#000',
            shadowOpacity: 0.18,
            shadowRadius: 16,
            shadowOffset: { width: 0, height: 6 },
            elevation: 8,
          }}
        >
          <Ionicons name={icon[toast.tone]} size={19} color={iconColor[toast.tone]} />
          <Text
            variant="callout"
            numberOfLines={2}
            style={{ marginLeft: spacing.md, flex: 1, color: theme.colors.surface }}
          >
            {toast.message}
          </Text>

          {toast.action ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={toast.action.label}
              // The visible label is a word; the target is a thumb.
              hitSlop={gesture.hitSlop}
              onPress={() => {
                const run = toast.action?.onPress;
                dismiss();
                run?.();
              }}
              className="active:opacity-60"
              style={{
                marginLeft: spacing.md,
                justifyContent: 'center',
                minHeight: touchTarget.min,
                paddingHorizontal: spacing.xs,
              }}
            >
              <Text
                variant="bodyEmphasis"
                style={{ color: theme.colors.accent }}
              >
                {toast.action.label}
              </Text>
            </Pressable>
          ) : null}
        </Animated.View>
      ) : null}
    </ToastContext.Provider>
  );
}
