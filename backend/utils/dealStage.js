/**
 * The deal stage, derived from facts on the Lead (Phase 2, engine E3).
 *
 * A stage is never set by a client. Every transition has exactly one cause
 * that is already recorded on the lead: a visit document, an agreement
 * reference, a converted status. `deriveStage` reads those and nothing else,
 * so the tracker on the deal page can only ever show what actually happened.
 *
 * The order is the buyer's journey; the tracker renders it top to bottom.
 */

export const STAGES = Object.freeze(["contacted", "visit_scheduled", "visited", "agreement", "closed"]);

export const VISIT_OPEN = Object.freeze(["proposed", "confirmed"]);

export const stageIndex = (stage) => Math.max(0, STAGES.indexOf(stage));

export function deriveStage(lead, now = new Date()) {
  if (!lead) return "contacted";
  if (lead.status === "converted") return "closed";
  if (lead.agreement) return "agreement";

  const visits = Array.isArray(lead.visits) ? lead.visits : [];
  if (visits.some((v) => v.status === "done")) return "visited";
  if (visits.some((v) => VISIT_OPEN.includes(v.status) && new Date(v.scheduledAt) >= now)) {
    return "visit_scheduled";
  }
  return "contacted";
}

/**
 * The tracker rows. The first row is pre-stamped with the enquiry itself and
 * says why ("endowed progress": the person did do something, and the tracker
 * says so rather than opening at zero).
 */
export function progressFor(lead, now = new Date()) {
  const stage = deriveStage(lead, now);
  const reached = stageIndex(stage);
  const visits = Array.isArray(lead.visits) ? lead.visits : [];

  const doneVisit = visits.find((v) => v.status === "done");
  const openVisit = visits.find((v) => VISIT_OPEN.includes(v.status) && new Date(v.scheduledAt) >= now);

  return [
    {
      key: "contacted",
      done: true,
      at: lead.createdAt || null,
      reason: "Enquiry sent to the owner",
    },
    {
      key: "visit_scheduled",
      done: reached >= 1,
      at: openVisit?.scheduledAt || doneVisit?.scheduledAt || null,
      reason: openVisit
        ? openVisit.status === "confirmed"
          ? "Visit confirmed"
          : "Visit proposed, awaiting confirmation"
        : null,
    },
    {
      key: "visited",
      done: reached >= 2,
      at: doneVisit?.updatedAt || null,
      reason: doneVisit?.feedback ? `Feedback: ${doneVisit.feedback.replace("_", " ")}` : null,
    },
    {
      key: "agreement",
      done: reached >= 3,
      at: lead.agreementAt || null,
      reason: lead.agreement ? "Agreement generated" : null,
    },
    {
      key: "closed",
      done: reached >= 4,
      at: lead.closedAt || null,
      reason: lead.status === "converted" ? "Deal verified by DealDirect" : null,
    },
  ];
}
