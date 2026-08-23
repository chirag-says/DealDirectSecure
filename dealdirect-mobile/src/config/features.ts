/**
 * Product flags.
 *
 * Not experiment toggles and not env-driven: these are decisions about what the
 * product currently promises, kept in code so the reasoning travels with the
 * switch.
 */

/**
 * Group buy — OFF.
 *
 * The mechanic is incomplete on the server, and has been since it was built.
 * `discountPerBuyer` is a flat rupee figure stored on the campaign, but nothing
 * anywhere applies it: no endpoint computes an unlocked state, no booking
 * carries a discounted price, and `paidMemberCount >= minBuyers` is a
 * comparison no code performs. A campaign that "succeeds" produces no different
 * outcome from one that does not.
 *
 * The website reached this conclusion first and deleted its entire group-buy
 * render in commit 79461c3 — the banner, the member progress bar and the
 * discounted price all came out, on the grounds that advertising a discount no
 * code will honour is the defect. That left this app as the only client still
 * offering membership, and the only one taking payment proof for it.
 *
 * Joining is worse than displaying. A member who pays a token against an
 * unfinished mechanic cannot be made whole by a client-side change: exit is
 * refused once `tokenStatus` is `paid` (409
 * `CAMPAIGN_MEMBER_PAYMENT_PROTECTED`), by design, because the payment is
 * evidence. So the actions come off first.
 *
 * This is the D4 hold made real rather than assumed. The wiring underneath is
 * correct and stays on disk: when the completion engine ships, this flag is the
 * whole of the change on this side.
 */
export const GROUP_BUY_ENABLED = false;
