import Ionicons from '@expo/vector-icons/Ionicons';

import { useTheme } from '@/theme';
import { EmptyState, Screen, ScreenHeader } from '@/ui';

/**
 * A terminal state in the auth flow: "code sent", "password updated",
 * "session expired", "missing details".
 *
 * Four screens hand-built this exact block — a centred `View`, a `title2`, a
 * `callout` beneath it, a `Button` — which is `EmptyState`'s layout, written
 * out four times with three different spacings between them.
 *
 * The icon is the fastest signal of which KIND of ending this is, and these
 * screens had none: "Password updated" and "Session expired" rendered
 * identically apart from their words.
 */

export type AuthResultTone = 'success' | 'info' | 'warning';

const ICON: Record<AuthResultTone, keyof typeof Ionicons.glyphMap> = {
  success: 'checkmark-circle',
  info: 'mail-unread-outline',
  warning: 'alert-circle-outline',
};

export interface AuthResultProps {
  tone?: AuthResultTone;
  title: string;
  description?: string;
  actionLabel: string;
  onAction: () => void;
  /** Shows a back affordance. Off by default: these are usually one-way. */
  showBack?: boolean;
  backTo?: string;
}

export function AuthResult({
  tone = 'success',
  title,
  description,
  actionLabel,
  onAction,
  showBack = false,
  backTo = '/(auth)/login',
}: AuthResultProps) {
  const theme = useTheme();

  const color =
    tone === 'success'
      ? theme.colors.success
      : tone === 'warning'
        ? theme.colors.warning
        : theme.colors.accent;

  return (
    <Screen>
      {showBack ? <ScreenHeader backTo={backTo} tight /> : null}
      <EmptyState
        icon={<Ionicons name={ICON[tone]} size={44} color={color} />}
        title={title}
        description={description}
        actionLabel={actionLabel}
        onAction={onAction}
        actionVariant="primary"
      />
    </Screen>
  );
}
