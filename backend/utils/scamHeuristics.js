/**
 * Payment-lure detection for chat (Phase 2, F13).
 *
 * The failure mode this guards against is documented on every classifieds
 * platform that mounted chat without it: a "token amount" or "advance" asked
 * for before a visit, a UPI id or QR pushed into the thread, a request to
 * move to another app to pay. None of these is proof of fraud; all of them
 * are the shape of it. The response is a warning message in the thread, not a
 * block, because the honest owner asking for a token after a visit exists too.
 *
 * Pure function over the text. No network, no state, so it is trivially
 * unit-tested and cannot slow a send.
 */

const RULES = [
  {
    flag: "token_advance",
    // "token", "advance", "booking amount" near "pay", "transfer", "send"
    // or a rupee figure, in either order; catches Hinglish spellings of the
    // common asks.
    re: /\b(token|advance|booking\s*(amount|money)|security\s*deposit)\b[^.\n]{0,60}\b(pay|paid|transfer|send|bhej|de\s*do|google\s*pay|gpay|phonepe|paytm|upi|rs\.?|₹|\d{3,})|\b(pay|transfer|send|bhej)\b[^.\n]{0,40}\b(token|advance|booking\s*(amount|money))\b/i,
  },
  {
    flag: "upi_request",
    // A UPI VPA: something@bank, or the words asking for one.
    re: /\b[a-z0-9._-]{2,}@(?:okaxis|okhdfcbank|oksbi|okicici|ybl|ibl|axl|paytm|upi|apl|fam|jupiteraxis|kotak|sbi|hdfc|icici|axis|ptyes|ptsbi|pthdfc|ptaxis|waicici|wahdfcbank|waaxis|wasbi)\b|\b(upi\s*id|vpa)\b[^.\n]{0,30}\b(send|share|pay|transfer)/i,
  },
  {
    flag: "qr_code",
    re: /\bqr\s*code\b[^.\n]{0,40}\b(scan|pay|send|transfer)|\b(scan)\b[^.\n]{0,20}\bqr\b/i,
  },
  {
    flag: "off_platform_payment",
    re: /\b(pay|transfer|send)\b[^.\n]{0,40}\b(before|prior\s*to)\b[^.\n]{0,20}\b(visit|seeing|viewing|meeting)/i,
  },
];

export const LURE_WARNING =
  "DealDirect never asks for a token, advance or deposit before you have visited the property and met the owner. " +
  "Do not pay anyone to \"hold\" a home. If you are asked to, report this conversation.";

/**
 * @param {string} text
 * @returns {{ flag: string, matched: string } | null}
 */
export function detectLure(text) {
  if (typeof text !== "string" || text.length === 0) return null;
  const sample = text.slice(0, 2000);
  for (const rule of RULES) {
    const m = rule.re.exec(sample);
    if (m) return { flag: rule.flag, matched: m[0].slice(0, 80) };
  }
  return null;
}
