/**
 * Design-system primitives.
 *
 * A screen is composition. If a styling decision in a screen would be needed by
 * another screen, it belongs here instead.
 *
 * Domain components (PropertyCard, MessageBubble, LeadRow and so on) do NOT
 * live here; they belong to their feature module.
 */

export { Screen, type ScreenProps } from './Screen';
export { ScreenHeader, HeaderAction, type ScreenHeaderProps } from './ScreenHeader';
export {
  ListGroup,
  ListRow,
  SectionLabel,
  type ListGroupProps,
  type ListRowProps,
} from './ListGroup';
export {
  Stat,
  StatRow,
  ProgressBar,
  Segmented,
  type StatProps,
  type ProgressBarProps,
  type SegmentedProps,
  type SegmentedOption,
} from './Metrics';
export { ToastProvider, useToast, type ToastTone } from './Toast';
export {
  Text,
  FontOverrideProvider,
  useFontFamily,
  type TextProps,
  type TextVariant,
  type TextTone,
  type FontOverride,
} from './Text';
export { useTextInputStyle, type TextInputStyleOptions } from './textInputStyle';
export { Button, type ButtonProps, type ButtonVariant, type ButtonSize } from './Button';
export { Input, type InputProps } from './Input';
export { Select, type SelectProps, type SelectOption } from './Select';
export { Sheet, type SheetProps } from './Sheet';
export { Card, type CardProps, type CardRadius } from './Card';
export { Tag, type TagProps } from './Tag';
export { Badge, type BadgeProps, type BadgeTone } from './Badge';
export { Avatar, type AvatarProps, type AvatarSize } from './Avatar';
export { Image, buildImageUrl, type ImageProps, type ImageSize } from './Image';
export { Skeleton, SkeletonList, type SkeletonProps } from './Skeleton';
export { EmptyState, type EmptyStateProps } from './EmptyState';
export { ErrorState, type ErrorStateProps } from './ErrorState';
export { Refreshable, type RefreshableProps } from './Refreshable';
export { KeyboardAvoider, type KeyboardAvoiderProps } from './KeyboardAvoider';
export { Chip, type ChipProps } from './Chip';
export {
  PriceLabel,
  formatPrice,
  formatPriceParts,
  formatRatePerSqft,
  type PriceLabelProps,
} from './PriceLabel';
export { RangeSlider, type RangeSliderProps } from './RangeSlider';

// Discovery surfaces. Added with the Home redesign: photography-led layouts
// need a scrim to put text on an image, a press that reads as a press rather
// than as a disable, and one horizontal scroller instead of nine.
export { Gradient, linearGradient, type GradientProps } from './Gradient';
export { Scrim, type ScrimProps } from './Scrim';
export { PressableScale, type PressableScaleProps } from './PressableScale';
export { Rail, useRailItemWidth, type RailProps, type RailSize } from './Rail';
export { TabBar, type TabBarProps } from './TabBar';
export { OfflineBanner } from './OfflineBanner';
