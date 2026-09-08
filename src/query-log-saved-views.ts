import type { QueryLogQuery } from "./types";
import { t } from "./i18n";

const STORAGE_KEY = "dnsblackhole.query-log.saved-views.v1";
const MAX_SAVED_VIEWS = 12;

export type SavedQueryLogView = {
  id: string;
  name: string;
  query: QueryLogQuery;
};

export function loadSavedQueryLogViews(storage: Storage = window.localStorage): SavedQueryLogView[] {
  try {
    const raw = storage.getItem(STORAGE_KEY);
    if (!raw) {
      return [];
    }
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.flatMap(parseSavedView).slice(0, MAX_SAVED_VIEWS);
  } catch {
    return [];
  }
}

export function persistSavedQueryLogViews(
  views: SavedQueryLogView[],
  storage: Storage = window.localStorage,
): void {
  storage.setItem(STORAGE_KEY, JSON.stringify(views.slice(0, MAX_SAVED_VIEWS)));
}

export function upsertSavedQueryLogView(
  views: SavedQueryLogView[],
  name: string,
  query: QueryLogQuery,
): SavedQueryLogView[] {
  const normalizedName = name.replace(/\s+/g, " ").trim();
  if (!normalizedName || normalizedName.length > 40) {
    throw new Error(t("视图名称需要 1-40 个字符"));
  }
  const existing = views.find(
    (view) => view.name.localeCompare(normalizedName, undefined, { sensitivity: "accent" }) === 0,
  );
  if (!existing && views.length >= MAX_SAVED_VIEWS) {
    throw new Error(t("最多保存 {p0} 个查询视图", { p0: MAX_SAVED_VIEWS }));
  }
  const saved: SavedQueryLogView = {
    id: existing?.id ?? `view-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    name: normalizedName,
    query: { ...query },
  };
  return existing
    ? views.map((view) => (view.id === existing.id ? saved : view))
    : [...views, saved];
}

export function removeSavedQueryLogView(
  views: SavedQueryLogView[],
  id: string,
): SavedQueryLogView[] {
  return views.filter((view) => view.id !== id);
}

function parseSavedView(value: unknown): SavedQueryLogView[] {
  if (!isRecord(value) || typeof value.id !== "string" || typeof value.name !== "string") {
    return [];
  }
  const query = parseQuery(value.query);
  const name = value.name.replace(/\s+/g, " ").trim();
  if (!query || !name || name.length > 40 || !value.id || value.id.length > 80) {
    return [];
  }
  return [{ id: value.id, name, query }];
}

function parseQuery(value: unknown): QueryLogQuery | null {
  if (!isRecord(value)) {
    return null;
  }
  const filters = ["all", "processed", "blocked", "failed"] as const;
  const sources = [
    "all",
    "upstream",
    "cache",
    "rewrite",
    "blocked",
    "refused",
    "local_reverse",
  ] as const;
  const queryTypes = ["all", "a", "aaaa", "https", "other"] as const;
  const sorts = ["newest", "oldest", "slowest"] as const;
  const hours = value.hours;
  const domain = value.domain;
  if (
    !filters.includes(value.filter as (typeof filters)[number]) ||
    typeof value.search !== "string" ||
    value.search.length > 512 ||
    !(
      domain === undefined ||
      domain === null ||
      (typeof domain === "string" && domain.trim().length > 0 && domain.length <= 253)
    ) ||
    !(hours === null || (typeof hours === "number" && Number.isFinite(hours) && hours > 0)) ||
    !sources.includes(value.source as (typeof sources)[number]) ||
    !queryTypes.includes(value.queryType as (typeof queryTypes)[number]) ||
    !sorts.includes(value.sort as (typeof sorts)[number])
  ) {
    return null;
  }
  return {
    filter: value.filter as QueryLogQuery["filter"],
    search: value.search,
    domain: typeof domain === "string" ? domain.trim() : null,
    hours,
    source: value.source as QueryLogQuery["source"],
    queryType: value.queryType as QueryLogQuery["queryType"],
    sort: value.sort as QueryLogQuery["sort"],
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}
