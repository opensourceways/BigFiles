---
name: code-review-validation
version: 1.1.0
description: 触发独立 Reviewer Agent 对 coding agent 产出进行五维度对抗验证，检查语义对齐、测试真实性、边界覆盖、架构合规和反模式合规
categories:
  - governance
  - quality-assurance
modes:
  - orchestrator
  - code
priority: 8
---

# code-review-validation 技能

## 🎯 用途

在工具链验证通过（`[TEST_CMD]` + `[LINT_CMD]` + `[BUILD_CMD]` 均 ✅）之后，触发独立的 **Reviewer Agent（角色R）** 对 coding agent 的产出进行对抗性审查，防止以下问题进入代码库：

| 风险类型 | 典型表现 | 检测维度 |
|---------|---------|---------|
| 语义偏差 | 实现了需求中未提及的功能 | 维度 1：语义对齐 |
| 质量缺陷 | 空断言、直通测试、Mock 永远返回固定值 | 维度 2：测试真实性 |
| 边界遗漏 | 未处理 null / 负数 / 并发场景 | 维度 3：边界覆盖 |
| 架构违规 | 跨层调用、硬编码凭证、非标准响应结构 | 维度 4：架构合规 |
| 历史错误重现 | 触犯 `.ai/anti-patterns.md` 中已知反模式 | 维度 5：反模式合规 |

---

## 📋 触发流程

### 前置条件（必须全部满足才可触发）

```bash
# 1. 测试全部通过
[TEST_CMD]

# 2. 代码风格检查通过
[LINT_CMD]

# 3. 覆盖率满足要求（≥ 80%）
[TEST_COVERAGE_CMD]
```

### 执行步骤

```bash
# Step 1：定位今日 prompt 文件
TODAY=$(date +%Y%m%d)
PROMPT_FILE=$(ls .ai/prompts/prompt-*-${TODAY}.md 2>/dev/null | head -1)

# Step 2：获取 staged 变更
git diff --staged > /tmp/staged-diff.txt

# Step 3：找出测试文件变更
CHANGED_TESTS=$(git diff --staged --name-only | grep -E '(Test|Spec|_test|test_)' | head -20)

# Step 4：确保 reviews 目录存在
mkdir -p .ai/reviews

# Step 5：触发 Reviewer Agent
# 将以下内容提供给 Reviewer Agent（角色R）：
# - Prompt 文件：${PROMPT_FILE}
# - 代码变更：/tmp/staged-diff.txt
# - 变更测试：${CHANGED_TESTS}
# - 角色定义：.ai/agents/roles/code-reviewer.md
# - 反模式清单：.ai/anti-patterns.md（如存在，用于维度 5 检查）
```

### 报告输出

审查报告保存至：`.ai/reviews/review-{type}-${TODAY}.md`

---

## 🔍 五维度评估表

| 维度 | 失败条件 | 报告标记 |
|------|---------|---------|
| 语义对齐 | prompt 期望输出有未实现项；出现超出 prompt 的修改 | `[Fail]` / `[Warning]` |
| 测试真实性 | 空断言 / 直通测试 / 无意义 Mock | `[Fail]` |
| 边界覆盖 | 关键入参无空值保护；空 catch 块 | `[Warning]` / `[Fail]` |
| 架构合规 | 跨层调用 / 硬编码凭证 / 非标响应结构 | `[Fail]` |
| 反模式合规 | 触犯 `.ai/anti-patterns.md` 中任意 AP 记录 | `[Fail]`（anti-patterns.md 不存在则跳过）|

---

## 📊 结论处理

```
结论: Pass
  → coding agent 继续更新 .ai/changelog/ai-modifications.md
  → 执行 git add + git commit

结论: Needs Revision
  → 停止提交流程
  → coding agent 按报告中的 文件:行号 逐项修复
  → 修复完成后重新执行触发点 5（Refactor）+ 触发点 7（提交准备）
```

---

## 📁 可追溯链

```
.ai/prompts/prompt-{type}-{YYYYMMDD}.md   ← 需求输入
.ai/reviews/review-{type}-{YYYYMMDD}.md   ← 本技能输出的审查报告
.ai/changelog/ai-modifications.md          ← 审查通过后更新
```

---

## ⚙️ 依赖

- `workflow-enforcer`：确保工具链检查已完成
- `[CODE_STYLE_SKILL_NAME]`：提供架构合规判断标准
- `.ai/agents/roles/code-reviewer.md`：Reviewer Agent 角色定义文件
