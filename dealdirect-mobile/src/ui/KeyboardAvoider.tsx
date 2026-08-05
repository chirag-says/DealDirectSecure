import React from 'react';
import { KeyboardAvoidingView, Platform, type KeyboardAvoidingViewProps } from 'react-native';

/**
 * Keyboard avoidance.
 *
 * The two platforms need different behaviours: iOS moves the whole view with
 * `padding`, Android resizes via `height` because its window already adjusts.
 * Getting this wrong hides the submit button behind the keyboard, which is the
 * most common reason a mobile form feels broken.
 */

export interface KeyboardAvoiderProps extends KeyboardAvoidingViewProps {
  className?: string;
}

export function KeyboardAvoider({
  children,
  className = '',
  ...rest
}: KeyboardAvoiderProps) {
  return (
    <KeyboardAvoidingView
      behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
      className={`flex-1 ${className}`}
      {...rest}
    >
      {children}
    </KeyboardAvoidingView>
  );
}
