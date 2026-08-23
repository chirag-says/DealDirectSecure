import { SearchScreen } from '@/features/search';

/**
 * Search — the property discovery workspace.
 *
 * ---------------------------------------------------------------------------
 * WHAT WAS HERE BEFORE, AND WHY IT IS NOT — 2026-08-24
 *
 * A Home screen: hero headline ("Buy, Rent & Sell Properties Directly from
 * Owners. No middleman. No commission fees."), a popular rail, a projects
 * rail, budget tools, three collection rails, a city grid, and a closing
 * banner reading "Ready to find your home?".
 *
 * All of it was addressed to a stranger. The person seeing it has already
 * found DealDirect, believed the pitch enough to install an app, and opened
 * it — the argument is over, and repeating it costs them the fold. Worse, the
 * screen could not answer a single question on its own: every affordance on it
 * pushed to `/(tabs)/properties`, which is where the search actually lived. Two
 * tabs, one job, and the one you landed on was the one that could not do it.
 *
 * So the search engine moved here. `features/search/SearchScreen` is that
 * screen, unchanged; this file is the route that mounts it.
 *
 * ---------------------------------------------------------------------------
 * IT IS THE SECOND TAB AGAIN, AND THAT IS NOT A REVERSAL — 2026-08-24
 *
 * For one iteration this WAS the first tab and carried a discovery block above
 * its results, on the reasoning that a search tool should show something
 * useful before it has been asked anything. Home came back as a distinct
 * surface, and that block belongs there: it was personal content (what you
 * were looking at, what you were searching for) sitting on a screen whose job
 * is inventory.
 *
 * So the division is now clean, and keeping it clean is the point:
 *
 *   Home    "what matters to me"      personal, short, adaptive
 *   Search  "what can I find"         the corpus, filters, sort, compare
 *
 * This screen opens straight on results — the whole corpus, paginated — which
 * is what it did before the discovery block existed and what the 2026-08-15
 * blank-screen fix put there. Nothing personal renders here. If a section ever
 * wants to, it belongs on Home.
 */
export default function SearchTab() {
  return <SearchScreen />;
}
