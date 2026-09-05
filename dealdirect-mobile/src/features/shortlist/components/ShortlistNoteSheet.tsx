import { useEffect, useState } from 'react';

import { ApiError } from '@/api';
import { Button, Input, Sheet, Text } from '@/ui';
import { useShortlistNote } from '../hooks';
import type { ShortlistItem } from '../types';

/**
 * The private note on a shortlisted listing.
 *
 * ---------------------------------------------------------------------------
 * WHY A NOTE IS WORTH A SHEET
 *
 * A shortlist of twelve flats becomes indistinguishable from itself within a
 * week: the reason a listing is on it lives entirely in the user's head, and
 * that is where it stops being useful. One line — "north facing, landlord
 * wants 11 months" — is the difference between a list you can act on and a
 * list you have to re-research.
 *
 * ---------------------------------------------------------------------------
 * IT IS PRIVATE, AND THE SHEET SAYS SO
 *
 * The owner never sees it, and it is stripped from the shared link by the
 * server. Both facts are stated rather than assumed, because a user who is not
 * sure will write nothing.
 *
 * Saving is awaited rather than optimistic: there is a button to keep
 * spinning, and a note that appeared and then vanished reads as lost work.
 * Clearing the field and saving removes the note — no separate delete control
 * for something that is one line of text.
 */

export interface ShortlistNoteSheetProps {
  entry: ShortlistItem | null;
  onClose: () => void;
}

const MAX_NOTE = 280;

export function ShortlistNoteSheet({ entry, onClose }: ShortlistNoteSheetProps) {
  const { setNote, isPending, error } = useShortlistNote();
  const [text, setText] = useState('');

  // Reseeded per listing rather than per open: the sheet is one component
  // reused for every row, so without this the note from the last row typed
  // into would appear under the next one.
  useEffect(() => {
    setText(entry?.note ?? '');
  }, [entry?.property.id, entry?.note]);

  const save = async () => {
    if (!entry) return;
    try {
      await setNote(entry.property.id, text.trim());
      onClose();
    } catch {
      // Surfaced below.
    }
  };

  const gone = error instanceof ApiError && error.code === 'NOT_SHORTLISTED';

  return (
    <Sheet
      visible={!!entry}
      onClose={onClose}
      title={entry?.note ? 'Edit your note' : 'Add a note'}
      heightRatio={0.5}
    >
      <Text variant="footnote" tone="muted">
        Only you can see this. It is not shown to the owner and it is not included in a shared
        link.
      </Text>

      <Input
        value={text}
        onChangeText={setText}
        placeholder="e.g. North facing, owner wants an 11-month lease"
        multiline
        maxLength={MAX_NOTE}
        containerClassName="mt-lg"
      />

      {gone ? (
        <Text variant="footnote" tone="danger" className="mt-md">
          This listing is no longer on your shortlist, so there is nowhere to keep the note.
        </Text>
      ) : error ? (
        <Text variant="footnote" tone="danger" className="mt-md">
          Could not save that note. Please try again.
        </Text>
      ) : null}

      <Button
        label={text.trim() ? 'Save note' : 'Remove note'}
        onPress={() => void save()}
        loading={isPending}
        fullWidth
        className="mt-lg"
      />
    </Sheet>
  );
}
