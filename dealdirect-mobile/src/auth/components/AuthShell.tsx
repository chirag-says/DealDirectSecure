import React from 'react';
import { ScrollView, View } from 'react-native';

import { screenPadding, spacing } from '@/theme';
import { KeyboardAvoider, Screen, ScreenHeader, Text } from '@/ui';

/**
 * The frame every auth screen sits in.
 *
 * ---------------------------------------------------------------------------
 * WHY THIS EXISTS
 *
 * Five screens, five layouts. Four centred their content
 * (`justifyContent: 'center'`) and one — register, the longest form — did not,
 * so moving between them shifted the title vertically for no reason a user
 * could explain. All five padded at 24 while the rest of the app used 16, and
 * each carried its own way back: a ghost Button on one, a bare Pressable on
 * another, nothing on a third.
 *
 * ---------------------------------------------------------------------------
 * CENTRING IS CONDITIONAL, AND THAT IS THE POINT
 *
 * A short form (three fields) centred in the viewport looks composed. A long
 * one (register, seven fields plus a role picker) centred does not fit, and
 * `justifyContent: 'center'` on a scroll view whose content exceeds the
 * viewport clips the TOP — the title scrolls off above the first field and
 * cannot be reached. So `center` is opt-out, and register opts out.
 *
 * ---------------------------------------------------------------------------
 * THE TITLE IS IN THE BODY, NOT THE HEADER
 *
 * `ScreenHeader` here carries only the back affordance. Auth screens open with
 * a large `display` greeting that is part of the page rather than a nav bar
 * label — putting "Welcome back" in a 22pt header bar would make the sign-in
 * screen look like a settings sub-page.
 */

export interface AuthShellProps {
  title: string;
  subtitle?: string;
  /** Back affordance. Off for the two entry points (login, register). */
  showBack?: boolean;
  /** Where back goes with no history — a deep link into a reset flow. */
  backTo?: string;
  /**
   * Vertically centre the form. Defaults on; turn OFF for a form tall enough
   * to scroll, or its title becomes unreachable above the fold.
   */
  center?: boolean;
  /** Sits below the form: sign-up prompts, "forgot password", legal notes. */
  footer?: React.ReactNode;
  children: React.ReactNode;
}

export function AuthShell({
  title,
  subtitle,
  showBack = false,
  backTo = '/(auth)/login',
  center = true,
  footer,
  children,
}: AuthShellProps) {
  return (
    <Screen>
      {showBack ? <ScreenHeader backTo={backTo} tight /> : null}

      <KeyboardAvoider>
        <ScrollView
          contentContainerStyle={{
            paddingHorizontal: screenPadding,
            paddingTop: showBack ? spacing.lg : spacing['4xl'],
            paddingBottom: spacing['4xl'],
            flexGrow: 1,
            justifyContent: center ? 'center' : 'flex-start',
          }}
          keyboardShouldPersistTaps="handled"
        >
          <Text variant="display">{title}</Text>
          {subtitle ? (
            <Text variant="callout" tone="secondary" className="mb-xl mt-sm">
              {subtitle}
            </Text>
          ) : (
            <View style={{ height: spacing.xl }} />
          )}

          {children}

          {footer ? <View className="mt-xl">{footer}</View> : null}
        </ScrollView>
      </KeyboardAvoider>
    </Screen>
  );
}
