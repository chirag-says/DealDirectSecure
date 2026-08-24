import type * as ClipboardModule from 'expo-clipboard';

import { optionalNativeModule } from '@/config/optionalNative';

/**
 * Copy to the system clipboard.
 *
 * One function, because the app has one use for it: the referral code, which
 * was share-only. A user who wants to paste their code into a WhatsApp message
 * they are already writing should not have to route through the share sheet.
 *
 * Returns whether the copy happened, so the caller can withhold its "copied"
 * toast in the host where the module is absent rather than claiming success it
 * cannot deliver.
 */

const Clipboard = optionalNativeModule(
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  () => require('expo-clipboard') as typeof ClipboardModule,
  'expo-clipboard',
  'Copying to the clipboard is unavailable in this host.'
);

export const clipboardAvailable = Clipboard !== null;

export async function copyToClipboard(text: string): Promise<boolean> {
  if (!Clipboard) return false;
  try {
    await Clipboard.setStringAsync(text);
    return true;
  } catch {
    return false;
  }
}
