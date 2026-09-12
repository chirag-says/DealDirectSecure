import React from "react";
import { NavLink } from "react-router-dom";
import {
  Building2,
  CalendarCheck,
  DraftingCompass,
  FileCheck,
  Flag,
  Funnel,
  Gift,
  Handshake,
  KeyRound,
  LayoutDashboard,
  LogOut,
  Mail,
  MessageSquareWarning,
  Newspaper,
  SquarePlus,
  Tags,
  Users,
} from "lucide-react";
import { useAdmin } from "../context/AdminContext";

/**
 * All menu items are available to all authenticated admins.
 *
 * Not an oversight: the product has ONE admin role with full administrative
 * powers, so there is no tier to gate on. The permission layer that used to
 * sit behind these routes was retired in Phase 3F because every admin held
 * every permission, so it separated nothing while remaining able to 403 the
 * whole panel when a code could not resolve.
 *
 * The backend enforces ADMIN AUTHENTICATION on every one of these routes
 * (protectAdmin: session, fingerprint, MFA, active account), plus a role-level
 * check on the audit log. It does not enforce per-menu permissions, and this
 * comment used to claim it did.
 *
 * ── On the grouping and the icons ──────────────────────────────────────────
 *
 * Seventeen items in one undifferentiated list is a list nobody reads; they
 * are grouped by the job being done instead. Every item also carries its own
 * icon. Previously seven of them shared `BarChart3`, which meant the icon
 * column told you nothing and the collapsed rail was unusable — you had to
 * hover each identical bar chart to find "Categories".
 *
 * Each icon names the thing on the other side of the link, and no glyph means
 * two things anywhere in the panel. Where a role has a defining attribute the
 * icon is that attribute rather than a generic person: drawings for builders,
 * keys for owners. Clients have no such attribute, so they get the plain
 * group glyph.
 *
 * Corrections made in this pass, each because the icon was describing
 * something other than the page it opens:
 *
 *   All Owners        UserCheck → KeyRound
 *       The page is "Property Owner Panel". A ticked user reads as
 *       "verified account", which is a different screen entirely.
 *   Builders          HardHat → DraftingCompass
 *       A Builder here is a development firm with a logo, a RERA number
 *       and a portfolio of Projects — not somebody on a site. A hard hat
 *       drew the labour; the drawing board draws the developer. Building2
 *       would have been the other candidate, but All Properties already
 *       holds it and two building silhouettes in one rail is the problem
 *       this pass exists to remove.
 *   Lead Monitoring   Target → Funnel
 *       A lead pipeline is a funnel. A target is a goal or a quota.
 *   Group Buy         Megaphone → Handshake
 *       A megaphone is an announcement. Group buy is a collective deal.
 *   Reported Messages ShieldAlert → MessageSquareWarning
 *       These are reported chat messages. A shield is generic moderation,
 *       and it did not distinguish this from Property Reports.
 *   Add Category      FolderPlus → SquarePlus
 *       Categories are tags one row above, so a folder was a second
 *       metaphor for the same thing. A plain plus just means "add".
 *
 * Taxonomy management had no navigation path at all: /all-category and
 * /add-category were routed and guarded but reachable only by typing the URL.
 * That matters operationally, since /admin-add-property depends on these
 * taxonomies and the property filters are driven by them.
 *
 * /add-subcategory is gone: the subcategory level is retired (decision D9)
 * and its API is unmounted.
 */
const NAV_SECTIONS = [
  {
    items: [{ path: "/dashboard", name: "Dashboard", icon: LayoutDashboard }],
  },
  {
    label: "Inventory",
    items: [
      { path: "/all-properties", name: "All Properties", icon: Building2 },
      { path: "/all-category", name: "Categories", icon: Tags },
      { path: "/add-category", name: "Add Category", icon: SquarePlus },
    ],
  },
  {
    label: "People",
    items: [
      { path: "/all-clients", name: "All Clients", icon: Users },
      { path: "/all-owners", name: "All Owners", icon: KeyRound },
      { path: "/builder-management", name: "Builders", icon: DraftingCompass },
    ],
  },
  {
    label: "Pipeline",
    items: [
      { path: "/lead-monitoring", name: "Lead Monitoring", icon: Funnel },
      { path: "/bookings", name: "Bookings", icon: CalendarCheck },
      { path: "/deal-verifications", name: "Deal Verifications", icon: FileCheck },
      // Signpost only: this route renders a "Group Buy Has Moved" notice that
      // sends you to Builder Management, because campaigns now live at
      // Project → Unit Type. The nav entry is worth retiring, not re-drawing.
      { path: "/group-buy", name: "Group Buy", icon: Handshake },
    ],
  },
  {
    label: "Moderation",
    items: [
      { path: "/contact-inquiries", name: "Contact Inquiries", icon: Mail },
      {
        path: "/reported-messages",
        name: "Reported Messages",
        icon: MessageSquareWarning,
      },
      { path: "/property-reports", name: "Property Reports", icon: Flag },
    ],
  },
  {
    label: "Content",
    items: [
      { path: "/blog-management", name: "Blog Management", icon: Newspaper },
      { path: "/rewards-management", name: "Rewards", icon: Gift },
    ],
  },
];

const Sidebar = ({ isOpen, toggleSidebar }) => {
  const { logout } = useAdmin();

  /**
   * Logout handler - calls the context logout which:
   * 1. Calls /api/admin/logout to invalidate the session cookie
   * 2. Clears the admin state
   * 3. App will redirect to login automatically
   */
  const handleLogout = async () => {
    await logout();
    // Navigation is handled by AdminProtectedRoute based on auth state
    window.location.href = "/admin/login";
  };

  /**
   * The active row gets a 2px accent bar on its leading edge plus a tinted
   * background. The bar is what survives collapse: in the icon rail the tint
   * alone is too subtle to locate at a glance.
   */
  const linkClasses = ({ isActive }) =>
    [
      "group relative flex items-center rounded-control transition-colors duration-100",
      isOpen ? "gap-2.5 pl-3 pr-2 py-2" : "justify-center px-0 py-2",
      isActive
        ? "bg-accent-soft text-accent font-medium"
        : "text-ink-muted hover:bg-surface-hover hover:text-ink",
    ].join(" ");

  return (
    // The collapse control used to sit in a 48px row above this nav, which
    // spent a whole row of the panel on one icon. It lives in the header now,
    // with the other global chrome, and the navigation starts at the top.
    <div className="flex flex-col h-full">
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-3 px-2">
        {NAV_SECTIONS.map((section, sectionIdx) => (
          <div key={section.label ?? "root"} className={sectionIdx > 0 ? "mt-4" : ""}>
            {/* Collapsed, a text heading has nowhere to go, so the section
                reads as a rule between icon groups instead. */}
            {section.label &&
              (isOpen ? (
                <p className="px-3 pb-1.5 type-micro text-ink-faint">
                  {section.label}
                </p>
              ) : (
                <div className="mx-3 mb-2 border-t border-line" />
              ))}

            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.path}>
                  <NavLink
                    to={item.path}
                    // Closing on navigate is correct on mobile, where the
                    // sidebar is an overlay covering the page you just asked
                    // for. On desktop it is static, so leave it alone.
                    onClick={() => {
                      if (isOpen && window.innerWidth < 1024) toggleSidebar();
                    }}
                    className={linkClasses}
                    title={isOpen ? undefined : item.name}
                  >
                    {({ isActive }) => (
                      <>
                        {isActive && (
                          <span
                            className="absolute left-0 top-1 bottom-1 w-0.5 rounded-full bg-accent"
                            aria-hidden="true"
                          />
                        )}
                        <item.icon className="h-4.5 w-4.5 shrink-0" />
                        {isOpen && (
                          <span className="type-body truncate">{item.name}</span>
                        )}
                      </>
                    )}
                  </NavLink>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {/* Logout is a session action, not a destination. Keeping it pinned to
          the footer stops it sitting in the tab order among the nav links. */}
      <div className="shrink-0 border-t border-line p-2">
        <button
          type="button"
          onClick={handleLogout}
          title={isOpen ? undefined : "Log out"}
          className={`w-full flex items-center rounded-control py-2 text-ink-muted hover:bg-danger-soft hover:text-danger transition-colors ${isOpen ? "gap-2.5 px-3" : "justify-center"
            }`}
        >
          <LogOut className="h-4.5 w-4.5 shrink-0" />
          {isOpen && <span className="type-body">Log out</span>}
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
