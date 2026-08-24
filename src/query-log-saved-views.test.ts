import { describe, expect, it } from "vitest";

import { upsertSavedQueryLogView } from "./query-log-saved-views";
import { DEFAULT_QUERY_LOG_QUERY } from "./query-log-query";

describe("upsertSavedQueryLogView", () => {
  it("adds and updates a named query view", () => {
    const added = upsertSavedQueryLogView([], " 夜间排障 ", DEFAULT_QUERY_LOG_QUERY);
    expect(added).toHaveLength(1);
    expect(added[0].name).toBe("夜间排障");

    const updated = upsertSavedQueryLogView(added, "夜间排障", {
      ...DEFAULT_QUERY_LOG_QUERY,
      filter: "failed",
    });
    expect(updated).toHaveLength(1);
    expect(updated[0].id).toBe(added[0].id);
    expect(updated[0].query.filter).toBe("failed");
  });

  it("rejects empty names", () => {
    expect(() => upsertSavedQueryLogView([], "   ", DEFAULT_QUERY_LOG_QUERY)).toThrow();
  });
});
