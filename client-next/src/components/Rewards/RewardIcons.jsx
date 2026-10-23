/**
 * Custom duotone icons for DealDirect Rewards.
 *
 * One drawing language for the whole set: a 24px grid, a soft tint of the
 * current colour as fill, a 1.75px outline, and a solid circular badge for
 * the detail that names the action (a check for a verified deal, a plus for a
 * first listing). Colour comes from `currentColor`, so a parent's text colour
 * themes the icon. Decorative by default (aria-hidden).
 */

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

/** Solid badge in the lower right, with a white glyph drawn by `children`. */
function Badge({ children }) {
  return (
    <g>
      <circle cx="18" cy="18" r="5" fill="currentColor" stroke="white" strokeWidth="1.5" />
      <g stroke="white" strokeWidth="1.6">{children}</g>
    </g>
  );
}

const House = () => (
  <>
    <path d="M3.5 10.2 11 4.4a1.6 1.6 0 0 1 2 0l7.5 5.8" />
    <path d="M5.5 9v10a1.5 1.5 0 0 0 1.5 1.5h5.5" {...TINT} />
    <path d="M9.5 20.5v-5a1 1 0 0 1 1-1h2" />
    {/* Right wall, stopping above the badge. */}
    <path d="M18.5 9v3.2" />
  </>
);

export function DealIcon(props) {
  return (
    <svg {...base} {...props}>
      <House />
      <Badge>
        <path d="m15.8 18 1.5 1.5 2.9-3" />
      </Badge>
    </svg>
  );
}

export function ListingIcon(props) {
  return (
    <svg {...base} {...props}>
      <House />
      <Badge>
        <path d="M18 15.6v4.8M15.6 18h4.8" />
      </Badge>
    </svg>
  );
}

export function EnquiryIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M4 6.5A2.5 2.5 0 0 1 6.5 4h11A2.5 2.5 0 0 1 20 6.5v7a2.5 2.5 0 0 1-2.5 2.5H11l-4.2 3.3a.5.5 0 0 1-.8-.4V16h0A2.5 2.5 0 0 1 4 13.5z" {...TINT} />
      <path d="m8.5 10.6 3.5-2.8 3.5 2.8M9.6 9.9v3.1h4.8V9.9" />
    </svg>
  );
}

export function PhotosIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="6.5" y="3.5" width="14" height="12" rx="2" />
      <rect x="3.5" y="7.5" width="14" height="12" rx="2" {...TINT} />
      <circle cx="8" cy="11.5" r="1.3" />
      <path d="m3.8 18 4.4-3.8 2.8 2.4 2.5-2 3.6 3" />
    </svg>
  );
}

const Person = () => (
  <>
    <circle cx="9" cy="8" r="3.5" {...TINT} />
    <path d="M3 19.5a6 6 0 0 1 10.8-3.6" />
  </>
);

export function ReferralIcon(props) {
  return (
    <svg {...base} {...props}>
      <Person />
      <Badge>
        <path d="M18 15.6v4.8M15.6 18h4.8" />
      </Badge>
    </svg>
  );
}

export function FriendActiveIcon(props) {
  return (
    <svg {...base} {...props}>
      <Person />
      <Badge>
        <path d="m18.6 15.4-2 2.9h2.8l-2 2.9" />
      </Badge>
    </svg>
  );
}

export function FriendDealIcon(props) {
  return (
    <svg {...base} {...props}>
      <Person />
      <Badge>
        <path d="m15.8 18 1.5 1.5 2.9-3" />
      </Badge>
    </svg>
  );
}

export function ReportIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M5.5 21V4" />
      <path d="M5.5 4.5h11.2a.6.6 0 0 1 .5.9L15 9l2.2 3.6a.6.6 0 0 1-.5.9H5.5" {...TINT} />
    </svg>
  );
}

export function GiftIcon(props) {
  return (
    <svg {...base} {...props}>
      <rect x="3.5" y="8" width="17" height="4" rx="1" />
      <path d="M5 12v7.5A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5V12" {...TINT} />
      <path d="M12 8v13M12 8C10.5 4.5 7 4.5 7 6.3 7 7.6 9.4 8 12 8zm0 0c1.5-3.5 5-3.5 5-1.7C17 7.6 14.6 8 12 8z" />
    </svg>
  );
}

export function FairPlayIcon(props) {
  return (
    <svg {...base} {...props}>
      <path d="M12 3.5 5 6v5.6c0 4.3 3 7.6 7 8.9 4-1.3 7-4.6 7-8.9V6z" {...TINT} />
      <path d="m9 12 2.2 2.2 4-4.2" />
    </svg>
  );
}

const MEDAL_COLOURS = {
  bronze: { ring: "#b06a34", face: "#f1d2b6", ribbon: "#c98653" },
  silver: { ring: "#7c8a9c", face: "#e6ebf1", ribbon: "#9aa7b7" },
  gold: { ring: "#b8860b", face: "#fbe7a6", ribbon: "#d9a62a" },
};

/** Tier badge: ribboned medals for Bronze, Silver and Gold; a cut gem for Diamond. */
export function TierBadge({ tier, className = "h-10 w-10" }) {
  if (tier === "diamond") {
    return (
      <svg viewBox="0 0 40 40" className={className} aria-hidden="true">
        <path d="M11 9h18l6 8-15 16L5 17z" fill="#e0f2fe" stroke="#0284c7" strokeWidth="1.8" strokeLinejoin="round" />
        <path d="M5 17h30M15 9l-3 8 8 16 8-16-3-8M12 17l8-8 8 8" fill="none" stroke="#0284c7" strokeWidth="1.4" strokeLinejoin="round" />
      </svg>
    );
  }
  const c = MEDAL_COLOURS[tier] || MEDAL_COLOURS.bronze;
  return (
    <svg viewBox="0 0 40 40" className={className} aria-hidden="true">
      <path d="M13 3h6l3 10h-6zM27 3h-6l-3 10h6z" fill={c.ribbon} />
      <circle cx="20" cy="25" r="11" fill={c.face} stroke={c.ring} strokeWidth="2" />
      <circle cx="20" cy="25" r="7.5" fill="none" stroke={c.ring} strokeWidth="1.2" strokeDasharray="2 1.6" />
      <path d="m20 20.6 1.4 2.9 3.1.4-2.3 2.2.6 3.1-2.8-1.5-2.8 1.5.6-3.1-2.3-2.2 3.1-.4z" fill={c.ring} />
    </svg>
  );
}
