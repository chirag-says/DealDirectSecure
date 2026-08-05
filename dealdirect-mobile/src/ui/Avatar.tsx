import { View } from 'react-native';

import { Image } from './Image';
import { Text } from './Text';

/**
 * Avatar with an initials fallback.
 *
 * Profile images are optional on the User model, so the fallback is the common
 * case rather than an edge case and gets the same care as the image path.
 */

export type AvatarSize = 'sm' | 'md' | 'lg';

const dimension: Record<AvatarSize, number> = { sm: 32, md: 44, lg: 64 };

const initialsOf = (name?: string): string => {
  if (!name) return '?';
  const parts = name.trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  const first = parts[0]?.[0] ?? '';
  const last = parts.length > 1 ? (parts[parts.length - 1]?.[0] ?? '') : '';
  return (first + last).toUpperCase() || '?';
};

export interface AvatarProps {
  uri?: string;
  name?: string;
  size?: AvatarSize;
  className?: string;
}

export function Avatar({ uri, name, size = 'md', className = '' }: AvatarProps) {
  const px = dimension[size];

  if (uri) {
    return (
      <Image
        uri={uri}
        size="thumb"
        style={{ width: px, height: px, borderRadius: px / 2 }}
        accessibilityLabel={name ? `${name} profile photo` : 'Profile photo'}
      />
    );
  }

  return (
    <View
      className={`items-center justify-center bg-accent-muted ${className}`}
      style={{ width: px, height: px, borderRadius: px / 2 }}
      accessible
      accessibilityLabel={name ?? 'Profile'}
    >
      <Text variant={size === 'sm' ? 'caption' : 'subhead'} tone="accent">
        {initialsOf(name)}
      </Text>
    </View>
  );
}
