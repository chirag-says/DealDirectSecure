import Ionicons from '@expo/vector-icons/Ionicons';
import { useCallback, useState } from 'react';
import { Pressable, TextInput, View } from 'react-native';

import { useTheme } from '@/theme';
import { useTextInputStyle } from '@/ui';

/**
 * The message input and send button.
 *
 * Owns its own text state rather than being controlled from the thread
 * screen: every keystroke re-rendering the whole message list (which the
 * thread screen also owns) would make a long conversation feel sluggish while
 * typing. Only `onSend` and `onChangeText` (for the typing-indicator emit)
 * cross the boundary.
 */

export interface ChatComposerProps {
  onSend: (text: string) => void;
  onChangeText?: (text: string) => void;
  onStopTyping?: () => void;
  disabled?: boolean;
}

export function ChatComposer({ onSend, onChangeText, onStopTyping, disabled }: ChatComposerProps) {
  const theme = useTheme();
  const inputStyle = useTextInputStyle({ variant: 'callout' });
  const [text, setText] = useState('');

  const handleChange = useCallback(
    (next: string) => {
      setText(next);
      onChangeText?.(next);
    },
    [onChangeText]
  );

  const handleSend = useCallback(() => {
    const trimmed = text.trim();
    if (!trimmed) return;

    onSend(trimmed);
    setText('');
    onStopTyping?.();
  }, [text, onSend, onStopTyping]);

  const canSend = text.trim().length > 0 && !disabled;

  return (
    <View className="flex-row items-end border-t border-border bg-surface px-md py-sm">
      <TextInput
        value={text}
        onChangeText={handleChange}
        placeholder="Message"
        placeholderTextColor={theme.colors.textMuted}
        multiline
        maxLength={5000}
        className="mr-sm max-h-32 flex-1 rounded-2xl border border-border bg-background px-md py-sm"
        // `callout` (15pt) — the size this already used, now taken from the
        // scale and carrying the app's typeface. Multiline, so it is the one
        // field where a line height would be legitimate; it still does not get
        // one, because the platform's own metrics are what clear a descender
        // and `ui/textInputStyle.ts` explains why a declared box does not.
        style={inputStyle}
        onBlur={onStopTyping}
      />

      <Pressable
        accessibilityRole="button"
        accessibilityLabel="Send message"
        onPress={handleSend}
        disabled={!canSend}
        className="h-11 w-11 items-center justify-center rounded-full"
        style={{ backgroundColor: canSend ? theme.colors.accent : theme.colors.borderStrong }}
      >
        <Ionicons name="send" size={18} color="#ffffff" />
      </Pressable>
    </View>
  );
}
