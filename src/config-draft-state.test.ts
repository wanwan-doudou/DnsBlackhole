import { describe, expect, it } from "vitest";

import {
  configSaveCompletion,
  mergeQueryLogRuleIntoDraft,
  rebaseConfigFingerprint,
  shouldPreserveConfigDraft,
} from "./config-draft-state";

describe("config draft state", () => {
  it("keeps edits made while a slow save is pending until the next save", () => {
    const first = configSaveCompletion("config-a", "config-b");
    expect(first).toEqual({ savedFingerprint: "config-a", dirty: true });

    const second = configSaveCompletion("config-b", "config-b");
    expect(second).toEqual({ savedFingerprint: "config-b", dirty: false });
  });

  it("protects dirty and cross-view drafts from background reloads", () => {
    expect(shouldPreserveConfigDraft({
      loaded: true,
      force: false,
      dirty: true,
      savedAtStart: "saved",
      savedNow: "saved",
      draftAtStart: "dns-edit",
      draftNow: "security-edit",
    })).toBe(true);
  });

  it("allows discard reloads but still protects edits made while discard is loading", () => {
    expect(shouldPreserveConfigDraft({
      loaded: true,
      force: true,
      dirty: true,
      savedAtStart: "saved",
      savedNow: "saved",
      draftAtStart: "draft",
      draftNow: "draft",
    })).toBe(false);
    expect(shouldPreserveConfigDraft({
      loaded: true,
      force: true,
      dirty: true,
      savedAtStart: "saved",
      savedNow: "saved",
      draftAtStart: "draft",
      draftNow: "new-edit",
    })).toBe(true);
  });

  it("rebases authoritative fields without discarding unrelated saved state", () => {
    expect(rebaseConfigFingerprint(
      JSON.stringify({ enabled: true, blacklist: "old", nested: { value: 1 } }),
      { enabled: false, missing: "ignored" },
    )).toBe(JSON.stringify({ enabled: false, blacklist: "old", nested: { value: 1 } }));
  });

  it("merges a query-log rule into the current draft without losing unrelated edits", () => {
    expect(mergeQueryLogRuleIntoDraft(
      {
        blacklist: "# local draft\n||example.com^\n||draft.test^",
        dnsRewrites: "example.com 127.0.0.1\ndraft.test 127.0.0.2",
      },
      {
        blacklist: "||saved.test^\n@@||example.com^",
        dnsRewrites: "",
      },
      "allow",
    )).toEqual({
      blacklist: "# local draft\n||draft.test^\n@@||example.com^",
      dnsRewrites: "draft.test 127.0.0.2",
    });
  });
});
