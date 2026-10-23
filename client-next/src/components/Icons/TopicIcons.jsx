/**
 * Help-centre topic icons, in the same duotone language as the rewards set
 * (components/Rewards/RewardIcons.jsx): 24px grid, soft tint of the current
 * colour, 1.75px outline. Decorative (aria-hidden).
 */

export { ListingIcon, GiftIcon, FairPlayIcon as ShieldIcon } from "../Rewards/RewardIcons";

const base = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.75,
  strokeLinecap: "round",
  strokeLinejoin: "round",
  "aria-hidden": true,
};
const TINT = { fill: "currentColor", fillOpacity: 0.12 };

/** About DealDirect: a speech-free "i" in a rounded square. */
export function AboutIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="3.5" y="3.5" width="17" height="17" rx="4" {...TINT} />
      <path d="M12 11v5.5M12 7.8v.1" />
    </svg>
  );
}

/** Buying and renting: a key. */
export function KeyIcon(props) {
  return (
    <svg {...base} {...props}>
      <circle cx="8" cy="15.5" r="4.5" {...TINT} />
      <circle cx="8" cy="15.5" r="1.4" />
      <path d="m11.2 12.3 8.3-8.3M16.5 7l2.5 2.5M14.5 9l1.8 1.8" />
    </svg>
  );
}

/** Builder projects: a tower with a crane arm. */
export function ProjectIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M6 21V9.5a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1V21" {...TINT} />
      <path d="M3.5 21h17M9 12h2M9 15h2M9 18h2M17 21V4.5M12.5 4.5h8M17 4.5l-3 3" />
    </svg>
  );
}
