# STYLING_GUIDE.md — Design System & Styling Conventions

Related: [COMPONENT_INDEX.md](COMPONENT_INDEX.md) · [DEPENDENCIES.md](DEPENDENCIES.md)

---

## 1. The Honest Summary

**The web apps have no design system.** They have Tailwind and a consistent-by-habit colour choice. There is no token file, no theme config, no shared component primitives, and no documented scale. Every value is a literal utility class typed at the call site.

**The mobile app has a real design system** — semantic tokens, a typography scale, motion constants, and 18 UI primitives, all in `dealdirect-mobile/src/theme/` and `src/ui/`. It is the only place in this repository where design decisions are written down.

If you are asked to "make the web match the design system", the mobile theme is the reference. Its `colors.ts` header says so explicitly: the palette was *sampled from the production website's dominant Tailwind usage so the two clients read as one product.*

---

## 2. Tailwind Configuration

| App | Tailwind | Config style | Config file |
|---|---|---|---|
| `client-next` | **4** | CSS-first | **none** — `@import "tailwindcss"` in `globals.css` |
| `Admin` | **4** | CSS-first | **none** — `@import "tailwindcss"` in `index.css` |
| `dealdirect-mobile` | **3** (NativeWind 4 requirement) | JS/TS config | `tailwind.config.ts`, projected from `src/theme/` |

Tailwind 4 removed `tailwind.config.js` in favour of CSS-native configuration. Neither web app declares custom theme values, so **only stock Tailwind utilities are available**. There is no `bg-brand`, no `text-primary`, no custom spacing step.

### `client-next/src/app/globals.css` (56 lines — the entire web styling layer)
```css
@import "tailwindcss";

:root {
  --background: #ffffff;
  --foreground: #171717;
}

@theme inline {
  --color-background: var(--background);
  --color-foreground: var(--foreground);
  --font-sans: var(--font-geist-sans);   /* ⚠️ never defined — see §7 */
  --font-mono: var(--font-geist-mono);   /* ⚠️ never defined */
}

body { background: var(--background); color: var(--foreground);
       font-family: Arial, Helvetica, sans-serif; }   /* ⚠️ overrides Inter */
```
Plus two utilities: `.custom-scrollbar` (6 px thumb) and a `slideInRight` keyframe used by `.mobile-nav-item`.

### `Admin/src/index.css` (15 lines)
`@import "tailwindcss"` plus one `fadeIn` keyframe → `.animate-fadeIn`.

---

## 3. Colour

### Web — by convention only
Extracted from actual usage across the codebase:

| Role | Classes in use | Notes |
|---|---|---|
| **Brand / primary action** | `bg-red-600`, `hover:bg-red-700`, `text-red-600`, `border-red-600` | Red is the DealDirect brand mark. Email templates use the gradient `#dc2626 → #b91c1c` |
| **Secondary action** | `bg-blue-600`, `text-blue-600` | Admin leans blue |
| **Success** | `green-600` / `green-100` | |
| **Warning** | `amber-500` / `yellow-*` | Inconsistent between the two |
| **Danger** | `red-*` | **Same family as brand** — a destructive button and a primary CTA can look alike |
| **Text** | `text-gray-900` / `700` / `600` / `500` | |
| **Surface** | `bg-white`, `bg-gray-50` | |
| **Border** | `border-gray-200` / `300` | |

Loading spinners are consistently `border-t-2 border-b-2 border-red-600` with `animate-spin`.

⚠️ **Danger and brand share the red family.** The mobile theme fixed this deliberately — its comment: *"`danger` is kept as a separate role from `brand` even though the two currently resolve to neighbouring reds, because they carry different meaning and will diverge if either is ever retuned."* The web has not adopted that separation.

### Mobile — semantic tokens (`src/theme/colors.ts`)
Raw palette (blue/red/green/amber + a 12-step neutral ramp) is **never consumed directly**. Components use semantic roles, and both schemes define the same role set so light/dark is one swap rather than a per-component branch:

```
background · surface · surface-muted · border · border-strong
text-primary · text-secondary · text-muted · text-on-accent
accent · accent-pressed · accent-muted
brand · success · success-muted · warning · warning-muted · danger · danger-muted
```

Bound as CSS variables and consumed via `rgb(var(--color-x) / <alpha-value>)` in `tailwind.config.ts`, so opacity modifiers (`bg-surface/50`) work.

`darkMode: 'class'` — chosen so the in-app override in `ThemeProvider` beats the OS setting.

---

## 4. Typography

### Web
- `client-next/src/app/layout.js` loads **Inter** via `next/font/google` with `display: swap`, exposed as `--font-inter`, applied as `className={inter.variable}` on `<body>`.
- ⚠️ `globals.css` then sets `body { font-family: Arial, Helvetica, sans-serif; }`, which **overrides Inter**. The variable is defined but the font is not applied unless a component explicitly uses `font-[family-name:var(--font-inter)]`. See §7.
- Sizes are stock Tailwind (`text-sm` … `text-4xl`), chosen per component.

### Mobile — a real scale (`src/theme/typography.ts`)
Named tokens carrying `fontSize`, `lineHeight`, `letterSpacing`, and `fontWeight` together (`title2`, `callout`, …), projected into `theme.fontSize` so a Tailwind class and a `StyleSheet` value cannot drift. The `<Text variant="title2">` primitive is the only way text is styled.

---

## 5. Layout & Responsive

### Breakpoints
Stock Tailwind: `sm` 640 · `md` 768 · `lg` 1024 · `xl` 1280 · `2xl` 1536.

**`lg` (1024 px) is the app's real desktop/mobile boundary**, not `md`:
- `ClientLayout`: `pt-16 lg:pt-20` — navbar height changes at `lg`
- `Navbar`: drawer below `lg`, full nav at and above
- `Admin/App.jsx`: sidebar off-canvas below `lg`, mini-rail (`lg:w-20`) above; `getInitialSidebarState()` and the resize listener both test `window.innerWidth >= 1024`

Mobile-first is followed consistently — base classes are the phone layout, `lg:` adds desktop.

### Container pattern
`max-w-7xl mx-auto px-4 sm:px-6 lg:px-8` is the dominant page wrapper. Cards: `rounded-lg`/`rounded-xl` + `shadow-sm`/`shadow-md` + `border border-gray-200`.

### Overflow discipline
`ClientLayout` sets `overflow-x-hidden` on the app wrapper; Admin's shell uses `overflow-hidden` with `overflow-y-auto` on `<main>` only. Both exist to stop wide tables and marquees from scrolling the page body.

---

## 6. Dark Mode

**Web: infrastructure present, implementation absent.**

`layout.js` runs a blocking pre-hydration script:
```js
(function(){
  var t = localStorage.getItem('dd-theme');
  if (t==='dark' || (t==='system'||!t) && matchMedia('(prefers-color-scheme: dark)').matches)
    document.documentElement.classList.add('dark');
})();
```
This is the correct anti-flash pattern. But:
- Nothing ever **writes** `dd-theme` — there is no theme toggle anywhere.
- Almost no component uses `dark:` variants.
- `globals.css` defines no dark values for `--background` / `--foreground`.

Net effect: a user whose OS is dark gets `.dark` on `<html>` and **no visual change**. Implementing dark mode means adding `dark:` variants across the app plus a toggle that writes `dd-theme`.

**Mobile: fully implemented.** `ThemeProvider` (116 L) toggles NativeWind's `colorScheme`, which flips the `.dark` class that `global.css` binds the semantic variables against.

---

## 7. Known Styling Issues

1. **Inter is loaded but not applied.** `globals.css` `body { font-family: Arial… }` overrides the `next/font` variable. *Fix:* `font-family: var(--font-inter), system-ui, sans-serif;`
2. **`--font-geist-sans` / `--font-geist-mono` are referenced in `@theme inline` but never defined** — leftovers from the `create-next-app` template. They resolve to nothing.
3. **Dark mode is half-wired** (§6).
4. **Danger and brand share red** (§3).
5. **Admin mixes antd and Tailwind.** Two design languages, two reset behaviours, competing specificity. Any new admin UI has to pick one per component, and the codebase is inconsistent about which.
6. **Three icon libraries per frontend** (lucide-react, react-icons, @heroicons/react). Visual weight and stroke width differ between sets, so icons sitting side by side don't always match.

---

## 8. Conventions to Follow

**Web**
1. Utility classes inline. No CSS modules, no styled-components, no `@apply`.
2. Stock Tailwind values only — there is no custom theme to extend.
3. Mobile-first; add `lg:` for desktop. Use `lg`, not `md`, for the primary breakpoint.
4. Brand actions `bg-red-600 hover:bg-red-700`; keep destructive actions visually distinct (an outline or a darker red) since the palette does not separate them.
5. Page wrapper `max-w-7xl mx-auto px-4 sm:px-6 lg:px-8`.
6. Loading state: `animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-red-600`.
7. Feedback via `react-toastify` — client bottom-right, admin top-right. Do not add a second toast system.
8. Animation via framer-motion (client) or a keyframe in the global stylesheet (admin). Keep new keyframes in `globals.css`/`index.css`, not inline.

**Mobile**
1. Never write a raw hex or a magic number. Import from `src/theme/`.
2. Never use a palette entry directly — use the semantic role.
3. Compose from `src/ui/` primitives; add a primitive rather than styling ad hoc.
4. Text always goes through `<Text variant="…">`.
5. Motion values come from `src/theme/motion.ts`.

**If you introduce a design token to the web**, put it in `globals.css` under `@theme inline` (Tailwind 4's mechanism) and mirror the mobile role names so the two clients converge rather than diverge further.
