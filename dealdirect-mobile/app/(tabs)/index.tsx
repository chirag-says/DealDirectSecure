import { SearchScreen } from '@/features/search';

/**
 * Search — the first tab, and the first thing the app shows.
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
 * The discovery content is not simply deleted — the parts of it that help
 * someone who has not typed anything yet come back as the tab's IDLE state, in
 * the step after this one. The distinction that matters is that they will be
 * what the search tool shows before you ask it something, rather than a
 * separate page you have to leave to start searching.
 */
export default function SearchTab() {
  return <SearchScreen />;
}
