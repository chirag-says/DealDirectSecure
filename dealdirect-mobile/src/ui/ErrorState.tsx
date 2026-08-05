import { View } from 'react-native';

import { Button } from './Button';
import { Text } from './Text';

/**
 * Error state.
 *
 * Shows a plain message and a way forward. It never renders a raw backend
 * string: the backend does sanitise its messages, but a client that depends on
 * that is one deploy away from leaking a stack trace into the UI.
 *
 * `requestId` is the `X-Request-ID` the backend sets on every response. Showing
 * it turns "the app broke" into a support ticket that can be traced to a single
 * server log line, which is worth the small amount of visual noise.
 */

export interface ErrorStateProps {
  title?: string;
  description?: string;
  requestId?: string;
  onRetry?: () => void;
  retryLabel?: string;
}

export function ErrorState({
  title = 'Something went wrong',
  description = 'Please check your connection and try again.',
  requestId,
  onRetry,
  retryLabel = 'Try again',
}: ErrorStateProps) {
  return (
    <View className="flex-1 items-center justify-center px-xl py-2xl">
      <Text variant="title3" className="text-center">
        {title}
      </Text>

      <Text variant="callout" tone="secondary" className="mt-sm text-center">
        {description}
      </Text>

      {onRetry ? <Button label={retryLabel} onPress={onRetry} className="mt-lg" /> : null}

      {requestId ? (
        <Text variant="caption" tone="muted" selectable className="mt-lg">
          Reference: {requestId}
        </Text>
      ) : null}
    </View>
  );
}
