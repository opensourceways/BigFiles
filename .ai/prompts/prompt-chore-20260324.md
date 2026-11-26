# 提示词归档：AI 开发规范化基础设施提交

**日期**：2026-03-24
**类型**：chore
**任务**：将 AI 开发规范化初始化生成的全套基础设施文件纳入版本控制

## 包含内容

- `.ai/` 目录完整结构（architect、agents、skills、workflow、changelog、prompts）
- `CLAUDE.md` — AI Agent 行为宪法（6 条强制规则）
- `AGENTS.md` — 技能文档
- `.githooks/commit-msg`、`post-merge`、`pre-push` — Git Hooks
- `.github/workflows/workflow-validation.yml` — CI 工作流
- `.gitignore` — 新增 coverage.out
