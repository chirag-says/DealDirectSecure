import type Ionicons from '@expo/vector-icons/Ionicons';
import type { Href } from 'expo-router';

/**
 * The shape of a static content page: privacy policy, terms, FAQ, about.
 *
 * One model, one renderer (`components/ContentPageView.tsx`), seven pages of
 * data. The website renders each of these as bespoke JSX; here the same copy
 * is DATA, so a change to how a heading or a bullet looks is made once and
 * every page follows, and a page is added by writing a file of text rather
 * than a screen.
 *
 * The block vocabulary is exactly what the website's seven pages needed and
 * nothing more. Add a block type when a page needs one, not before.
 */

export type IconName = keyof typeof Ionicons.glyphMap;

/**
 * Plain text with `**bold**` runs.
 *
 * Legal copy leans on bold for defined terms ("**Buyer**", "**as is**") and
 * for the one line a reader must not skim past. A string with two-character
 * markers keeps the content files readable as prose, which matters when the
 * text is compared line by line against the website. `parseRichText` splits
 * it; nothing else may interpret the markers.
 */
export type RichText = string;

export interface TextRun {
  text: string;
  bold: boolean;
}

/**
 * Splits `**bold**` markup into runs. An unbalanced marker is kept as
 * literal text rather than silently bolding the rest of the paragraph.
 */
export function parseRichText(text: RichText): TextRun[] {
  const parts = text.split('**');
  if (parts.length % 2 === 0) {
    const tail = parts.pop() ?? '';
    parts[parts.length - 1] = `${parts[parts.length - 1]}**${tail}`;
  }
  const runs: TextRun[] = [];
  parts.forEach((part, index) => {
    if (part.length > 0) runs.push({ text: part, bold: index % 2 === 1 });
  });
  return runs;
}

export type CalloutTone = 'info' | 'success' | 'warning' | 'danger' | 'neutral';

export interface CardItem {
  icon?: IconName;
  title: string;
  /** Blank lines (`\n\n`) split it into paragraphs. */
  text: RichText;
  /** A short line under the title: who a plan is for, a policy's tag. */
  meta?: string;
  /** A short line after the text: a price band, a date. */
  footnote?: string;
}

export interface FaqItem {
  id: string;
  question: string;
  answer: RichText;
}

export interface ActionItem {
  label: string;
  href: Href;
  variant?: 'primary' | 'secondary';
}

export type Block =
  | { type: 'paragraph'; text: RichText }
  /** A run-in heading inside a section, below the section title. */
  | { type: 'heading'; text: string }
  | { type: 'bullets'; items: RichText[] }
  | { type: 'callout'; tone: CalloutTone; title?: string; text?: RichText; items?: RichText[] }
  | { type: 'cards'; items: CardItem[] }
  | { type: 'stats'; items: { value: string; label: string }[] }
  | { type: 'quote'; text: string }
  | { type: 'tags'; items: string[] }
  | { type: 'faq'; items: FaqItem[] }
  | {
      type: 'contact';
      name?: string;
      role?: string;
      org?: string;
      address?: string;
      email?: string;
      phone?: string;
      hours?: string;
    }
  | { type: 'actions'; items: ActionItem[] };

export interface Section {
  id: string;
  title?: string;
  /** One line under the title. The FAQ uses it to say what a topic covers. */
  blurb?: string;
  icon?: IconName;
  blocks: Block[];
  /** Renders as an accordion. The terms run to forty clauses; open, they are a wall. */
  collapsible?: boolean;
  defaultOpen?: boolean;
}

/** A tab within a page. The terms have three: general, buyer, seller. */
export interface ContentPart {
  id: string;
  label: string;
  /** Sits above the sections: the note saying which users a part applies to. */
  blocks?: Block[];
  sections: Section[];
}

interface ContentPageBase {
  id: string;
  /** Small label above the title: "Legal", "About". */
  eyebrow: string;
  title: string;
  intro?: RichText;
  /** "Last updated" or "Effective date". Shown as given, never computed. */
  meta?: string;
  /** The website route carrying the same text. See the module doc in `../index.ts`. */
  webPath: `/${string}`;
}

export type ContentPage = ContentPageBase &
  ({ sections: Section[]; parts?: undefined } | { parts: ContentPart[]; sections?: undefined });
