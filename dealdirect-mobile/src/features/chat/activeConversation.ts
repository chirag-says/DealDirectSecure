/**
 * Which conversation, if any, is currently on screen.
 *
 * A plain module-level ref rather than context or a store: the only consumer
 * is the M13 push bridge deciding whether to suppress a local notification
 * for a message the user is already looking at, and that check happens
 * outside React's render cycle (inside a socket event callback), so a ref
 * that any module can read synchronously is the right shape — a subscription
 * would be paid for by every message just to answer one boolean.
 */

let activeConversationId: string | null = null;

export function setActiveConversationId(id: string | null): void {
  activeConversationId = id;
}

export function getActiveConversationId(): string | null {
  return activeConversationId;
}
