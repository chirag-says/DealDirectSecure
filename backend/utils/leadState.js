/**
 * Lead status transitions.
 *
 * Both write paths validated enum membership and nothing else. `updateLeadStatus`
 * (owner) called `sanitizeLeadStatus`, which checks the value is one of the six;
 * `updateAdminLeadStatus` had no whitelist at all and assigned `lead.status`
 * directly. Neither ever read the CURRENT status, so every state was reachable
 * from every other state: `converted → new` erased the record of a closed deal,
 * and `lost → converted` turned a dead enquiry into a conversion statistic.
 *
 * The table below is deliberately permissive among the working states. Sales
 * pipelines move backwards for real reasons — someone marked interested who
 * goes quiet returns to contacted — and forbidding that would generate support
 * tickets without protecting anything.
 *
 * It is strict about the two ends:
 *
 *   converted is TERMINAL. A closed deal does not reopen, and the deal flow
 *   writes this status itself (see SYSTEM_TRANSITION below). Allowing anything
 *   out of it means the one status that corresponds to money changing hands can
 *   be erased by a dropdown.
 *
 *   lost reopens only to contacted. Reopening an enquiry is legitimate;
 *   promoting a dead one straight to converted is how a conversion rate stops
 *   meaning anything.
 */

export const LEAD_STATUSES = ["new", "contacted", "interested", "negotiating", "converted", "lost"];

const WORKING = ["new", "contacted", "interested", "negotiating"];

export const LEAD_TRANSITIONS = Object.freeze({
  new: [...WORKING, "converted", "lost"],
  contacted: [...WORKING, "converted", "lost"],
  interested: [...WORKING, "converted", "lost"],
  negotiating: [...WORKING, "converted", "lost"],
  // Reopen only. A lost lead that revives is a fresh conversation, not a sale.
  lost: ["contacted"],
  // Terminal.
  converted: [],
});

export class LeadTransitionError extends Error {
  constructor(from, to) {
    const allowed = LEAD_TRANSITIONS[from] || [];
    super(
      allowed.length
        ? `A lead in "${from}" can only move to: ${allowed.join(", ")}.`
        : `A lead in "${from}" is final and its status cannot change.`
    );
    this.name = "LeadTransitionError";
    this.code = "ILLEGAL_LEAD_TRANSITION";
    this.status = 409;
    this.from = from;
    this.to = to;
  }
}

/**
 * Validate a human-initiated status change.
 *
 * `to === from` is allowed and is a no-op: both endpoints accept a whole payload
 * and resubmitting the current status is not an attempt to transition.
 */
export function assertLeadTransition(from, to) {
  if (!LEAD_STATUSES.includes(to)) {
    const err = new LeadTransitionError(from, to);
    err.message = `"${to}" is not a lead status.`;
    err.code = "INVALID_LEAD_STATUS";
    err.status = 400;
    throw err;
  }
  if (from === to) return;
  if (!(LEAD_TRANSITIONS[from] || []).includes(to)) throw new LeadTransitionError(from, to);
}

/**
 * The deal flow writes `converted` itself, from whatever state the lead is in.
 *
 * This bypasses the table on purpose. An approved TransactionVerification is
 * the authoritative record that the property changed hands, so a lead sitting
 * in `lost` when the deal completes is stale data, not a veto. Before this,
 * nothing wrote `Lead.status = "converted"` at all, which is why
 * `conversionRate` measured a field owners set by hand.
 */
export const SYSTEM_TRANSITION = Object.freeze({ reason: "deal_verification_approved" });
