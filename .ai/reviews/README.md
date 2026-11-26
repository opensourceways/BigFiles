# AI 审查报告

本目录保存每次任务的 Reviewer Agent 审查报告。

## 文件命名规则

`review-{type}-{YYYYMMDD}.md`

与 `.ai/prompts/` 目录的 prompt 文件一一对应：

| 需求输入 | 审查输出 |
|---|---|
| `prompts/prompt-development-20260323.md` | `reviews/review-development-20260323.md` |
| `prompts/prompt-fix-20260324.md` | `reviews/review-fix-20260324.md` |

## 可追溯链

```
.ai/prompts/prompt-{type}-YYYYMMDD.md   ← 需求输入（开发前归档）
.ai/reviews/review-{type}-YYYYMMDD.md   ← 审查输出（本目录）
.ai/changelog/ai-modifications.md        ← 变更记录（审查通过后更新）
```

## 结论说明

- **Pass**：所有维度通过或仅有 Warning，可以继续提交
- **Needs Revision**：存在 Fail 项，必须修复后重新走触发点 5（Refactor 阶段）

## 触发方式

审查报告由 `code-review-validation` 技能在提交前自动触发 Reviewer Agent（角色R）生成。Reviewer Agent 角色定义见 `.ai/agents/roles/code-reviewer.md`。
