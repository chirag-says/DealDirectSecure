/**
 * Socket.IO event contract. Source: the `io.on("connection", ...)` block in
 * backend/server.js — there is no separate socket route file, so this was
 * read straight out of the handler bodies, not out of a schema.
 *
 * ---------------------------------------------------------------------------
 * TWO THINGS THE SERVER DOES NOT DO, WORTH KNOWING BEFORE WRITING A CLIENT
 *
 * `join_conversation` gives no success acknowledgement. The server either
 * silently `socket.join()`s or emits `error`. There is no `joined` event, so
 * this client treats "no error within a short window" as success rather than
 * waiting for a positive signal that does not exist.
 *
 * `error` carries no correlation id — `{ code, message }` only, nothing that
 * says which emitted action it responds to. Two actions in flight at once
 * cannot be told apart from the error alone. Every consumer here treats `error`
 * as informational rather than routes it back to a specific call.
 *
 * Also worth naming rather than working around: `send_message` and
 * `typing`/`stop_typing` never check that `data.userId` or a message's
 * `sender` actually matches the authenticated socket. `join_conversation` DOES
 * verify room membership against the database, so the blast radius of a
 * forged payload is limited to conversations the sender is already a genuine
 * participant in — but within that room, this client cannot rely on the
 * SERVER to guarantee a relayed message's claimed sender is honest. This app
 * only ever emits its own already-REST-validated data, which is the correct
 * client-side behaviour; the gap itself is a backend hardening item, not
 * something fixable from here.
 */

export interface AuthenticatePayload {
  token: string;
}

export interface AuthenticatedPayload {
  userId: string;
}

export interface SocketErrorPayload {
  code: string;
  message: string;
}

export interface TypingPayload {
  conversationId: string;
  userId: string;
  userName?: string;
}

export interface StopTypingPayload {
  conversationId: string;
  userId: string;
}

export interface UserTypingEvent {
  userId: string;
  userName?: string;
}

export interface UserStopTypingEvent {
  userId: string;
}

/**
 * `send_message`'s `message` payload is passed through verbatim to
 * `receive_message` by the server (`socket.to(id).emit("receive_message",
 * data.message)`), so it is typed as `unknown` here and left to the caller —
 * in practice always the `Message` object `POST /chat/message/send` already
 * returned, decoded the same way REST history is.
 */
export interface SendMessagePayload {
  conversationId: string;
  message: unknown;
}

export interface ServerToClientEvents {
  authenticated: (payload: AuthenticatedPayload) => void;
  auth_error: (payload: SocketErrorPayload) => void;
  error: (payload: SocketErrorPayload) => void;
  /**
   * The FULL set of online user ids, broadcast to every connected socket on
   * every authenticate and disconnect — not scoped to a conversation or a
   * contact list. Treat it as a global presence set, not a private signal.
   */
  users_online: (userIds: string[]) => void;
  receive_message: (message: unknown) => void;
  user_typing: (payload: UserTypingEvent) => void;
  user_stop_typing: (payload: UserStopTypingEvent) => void;
}

export interface ClientToServerEvents {
  authenticate: (payload: AuthenticatePayload) => void;
  /** A bare conversation id string, not an object. */
  join_conversation: (conversationId: string) => void;
  /** A bare conversation id string, not an object. */
  leave_conversation: (conversationId: string) => void;
  send_message: (payload: SendMessagePayload) => void;
  typing: (payload: TypingPayload) => void;
  stop_typing: (payload: StopTypingPayload) => void;
}
