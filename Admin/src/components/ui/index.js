/**
 * The admin panel's UI vocabulary.
 *
 * Screens import from here rather than hand-rolling Tailwind strings. If a
 * screen needs something this folder does not have, add it here first — that
 * is the whole point, and it is why the panel used to have thirty different
 * card treatments.
 */

export { Button } from "./Button";
export { Card, CardHeader, CardBody } from "./Card";
export { Badge, StatusBadge } from "./Badge";
export { toneForStatus } from "./status";
export { Stat } from "./Stat";
export { Sparkline } from "./Sparkline";
export { seriesDelta, seriesValues } from "./series";
export {
  Table,
  TableWrap,
  THead,
  TBody,
  TH,
  TR,
  TD,
} from "./Table";
export { PageHeader, EmptyState, Loading, Skeleton } from "./Feedback";
export { CHART, statusChartColor } from "./chart";
export { default as cn } from "./cn";
