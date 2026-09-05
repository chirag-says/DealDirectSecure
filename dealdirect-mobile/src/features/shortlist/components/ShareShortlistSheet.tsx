import Ionicons from '@expo/vector-icons/Ionicons';
import { useState } from 'react';
import { Share, View } from 'react-native';

import { track } from '@/analytics';
import { WEB_URL } from '@/config/env';
import { spacing, useTheme } from '@/theme';
import { Button, Sheet, Text, useToast } from '@/ui';
import { useShortlistShare } from '../hooks';

/**
 * Share the shortlist as a link.
 *
 * ---------------------------------------------------------------------------
 * THE LINK ROTATES, AND THE SHEET SAYS SO BEFORE IT HAPPENS
 *
 * `POST /shortlist/share` issues a new token and kills the previous one. That
 * is the right server behaviour — one live link is one thing to revoke — but
 * it is invisible from here, and a user who has already sent the old link to
 * their partner will not connect "I pressed share again" with "the link my
 * partner had stopped working". So the second and subsequent presses are
 * labelled as replacing, not as sharing.
 *
 * ---------------------------------------------------------------------------
 * REVOKE IS OFFERED AS PLAINLY AS SHARE
 *
 * A shared list is a list of the places somebody is thinking about living.
 * Taking it back has to be as easy as putting it out, and it has to be
 * reachable from the same sheet rather than buried in settings.
 *
 * ---------------------------------------------------------------------------
 * WHAT THE LINK POINTS AT
 *
 * The website, not a `dealdirect://` scheme URL. A share is read by somebody
 * who does not have the app — that is the entire point of sending it — and the
 * same reasoning already governs the referral link and the listing share.
 */

export interface ShareShortlistSheetProps {
  visible: boolean;
  onClose: () => void;
  /** How many listings are on the list right now, for the empty-state copy. */
  count: number;
}

export function sharedShortlistUrl(token: string): string {
  return `${WEB_URL}/shortlist/shared/${token}`;
}

export function ShareShortlistSheet({ visible, onClose, count }: ShareShortlistSheetProps) {
  const theme = useTheme();
  const toast = useToast();
  const { create, revoke, isCreating, isRevoking, isEmpty, error } = useShortlistShare();

  const [link, setLink] = useState<string | null>(null);
  const [shared, setShared] = useState(0);

  const close = () => {
    setLink(null);
    onClose();
  };

  const makeLink = async () => {
    try {
      const result = await create();
      setLink(sharedShortlistUrl(result.token));
      setShared(result.count);
      track('shortlist_share', { count: result.count });
    } catch {
      // `error` and `isEmpty` below carry it; nothing to do here.
    }
  };

  const sendLink = async (url: string) => {
    await Share.share({
      message: `My DealDirect shortlist — ${shared} ${shared === 1 ? 'listing' : 'listings'}: ${url}`,
      url,
    });
  };

  const revokeLink = async () => {
    try {
      await revoke();
      setLink(null);
      toast.show('Link revoked. Anyone holding it now sees nothing.', 'success');
    } catch {
      toast.show('Could not revoke that link. Please try again.', 'danger');
    }
  };

  return (
    <Sheet visible={visible} onClose={close} title="Share your shortlist" heightRatio={0.55}>
      {isEmpty || count === 0 ? (
        <Text variant="body" tone="secondary">
          There is nothing on your shortlist to share yet. Save a few listings first.
        </Text>
      ) : link ? (
        <>
          <View
            className="flex-row items-center rounded-xl border border-border bg-surface-muted"
            style={{ padding: spacing.base, gap: spacing.sm }}
          >
            <Ionicons name="link-outline" size={18} color={theme.colors.textMuted} />
            <Text variant="footnote" numberOfLines={2} className="flex-1">
              {link}
            </Text>
          </View>

          <Text variant="caption" tone="muted" className="mt-md">
            Anyone with this link can see the {shared} {shared === 1 ? 'listing' : 'listings'} on
            your shortlist. Your notes are not included, and they cannot change anything.
          </Text>

          <Button
            label="Send link"
            onPress={() => void sendLink(link)}
            fullWidth
            className="mt-lg"
          />
          <Button
            label="Replace this link"
            variant="secondary"
            onPress={() => void makeLink()}
            loading={isCreating}
            fullWidth
            className="mt-md"
          />
          <Button
            label="Revoke"
            variant="secondary"
            onPress={() => void revokeLink()}
            loading={isRevoking}
            fullWidth
            className="mt-md"
          />
        </>
      ) : (
        <>
          <Text variant="body" tone="secondary">
            A link anyone can open to see the listings you have saved. Your notes stay private, and
            you can revoke it whenever you like.
          </Text>
          <Text variant="caption" tone="muted" className="mt-sm">
            Making a link replaces any link you shared before.
          </Text>

          <Button
            label="Create link"
            onPress={() => void makeLink()}
            loading={isCreating}
            fullWidth
            className="mt-lg"
          />
          <Button
            label="Revoke the previous link"
            variant="secondary"
            onPress={() => void revokeLink()}
            loading={isRevoking}
            fullWidth
            className="mt-md"
          />
        </>
      )}

      {error ? (
        <Text variant="footnote" tone="danger" className="mt-md">
          Could not create a link. Please check your connection and try again.
        </Text>
      ) : null}
    </Sheet>
  );
}
