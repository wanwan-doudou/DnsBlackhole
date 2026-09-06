import { configDefaults, defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // .claude/ 下可能存在历史工作副本（git worktree），跑它们会让本地结果和 CI 对不上
    exclude: [...configDefaults.exclude, "**/.claude/**"],
    setupFiles: ["./src/test-setup.ts"],
  },
});
