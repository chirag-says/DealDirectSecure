/**
 * Status → tone mapping.
 *
 * Lives apart from `Badge.jsx` so that file only exports components, which is
 * what React Fast Refresh needs in order to hot-swap a component without
 * remounting the tree.
 *
 * Maps the status strings the API actually returns onto the five tones, so a
 * status looks the same on every screen without each screen re-deciding.
 */

/** Unknown values fall back to neutral rather than throwing — a status added
 *  on the backend should render as uncoloured text, not crash the table. */
export function toneForStatus(status) {
  switch (String(status ?? "").toLowerCase()) {
    case "approved":
    case "verified":
    case "converted":
    case "completed":
    case "active":
    case "resolved":
    case "signed":
    case "paid":
      return "ok";

    case "pending":
    case "awaiting":
    case "in_review":
    case "under_review":
    case "submitted":
    case "unpaid":
      return "warn";

    case "rejected":
    case "disapproved":
    case "failed":
    case "cancelled":
    case "canceled":
    case "expired":
    case "blocked":
    case "reported":
      return "danger";

    case "new":
    case "contacted":
    case "negotiating":
    case "scheduled":
    case "draft":
      return "info";

    default:
      return "neutral";
  }
}

export default toneForStatus;
