import Ionicons from '@expo/vector-icons/Ionicons';
import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react';
import Animated, { FadeInDown, FadeOutDown } from 'react-native-reanimated';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { radius, spacing, useTheme } from '@/theme';
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

interface ToastState {
  id: number;
  message: string;
  tone: ToastTone;
}

interface ToastApi {
  show: (message: string, tone?: ToastTone) => void;
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

/** Roughly the tab bar's painted height, so a toast clears it. */
const TAB_BAR_ALLOWANCE = 64;

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const theme = useTheme();
  const insets = useSafeAreaInsets();
  const [toast, setToast] = useState<ToastState | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const nextId = useRef(0);

  const show = useCallback((message: string, tone: ToastTone = 'neutral') => {
    // A second toast replaces the first rather than queueing. A queue means the
    // user reads a stale confirmation for an action two steps ago.
    if (timer.current) clearTimeout(timer.current);
    nextId.current += 1;
    setToast({ id: nextId.current, message, tone });
    timer.current = setTimeout(() => setToast(null), VISIBLE_MS);
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
          entering={FadeInDown.springify().damping(18)}
          exiting={FadeOutDown.duration(160)}
          pointerEvents="none"
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
        </Animated.View>
      ) : null}
    </ToastContext.Provider>
  );
}
