import type { QueryLogQuery } from "./types";

export const DEFAULT_QUERY_LOG_QUERY: QueryLogQuery = {
  filter: "all",
  search: "",
  hours: null,
  source: "all",
  queryType: "all",
  sort: "newest",
};

export function parseQueryLogHours(value: string): number | null {
  if (value === "configured") {
    return null;
  }
  const hours = Number(value);
  return Number.isFinite(hours) && hours > 0 ? hours : null;
}

export function activeAdvancedQueryFilterCount(query: QueryLogQuery): number {
  return [
    query.hours !== null,
    query.source !== "all",
    query.queryType !== "all",
    query.sort !== "newest",
  ].filter(Boolean).length;
}
