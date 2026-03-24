# Agent 开发工作流程快速参考

## 📋 工作流程概览

```
需求提出 → 提示词生成 → 开发准备 → TDD开发 → 多智能体验证 → 提交前验证 → 代码审查 → Git提交 → CI/CD验证
```

> 每个阶段同时使用**项目技能**和 **Superpowers 增强技能**（如已集成），两者互补并列。

---

## 🔄 完整流程（11个阶段）

### 第1阶段：需求提出与分析
- **Superpowers 增强**：调用 `superpowers:brainstorming` 通过对话式问答探索需求意图和设计方案
- **项目技能**：调用 `task-prompt-generator` 生成标准化提示词
- **输出**：`.ai/prompts/prompt-{type}-{YYYYMMDD}.md`
- **检查点**：✅ 需求已充分探索，提示词已归档

### 第2阶段：开发准备
- **项目技能**：调用 `project-init` 自动读取架构文档和修改记录
- **Superpowers 增强**：调用 `superpowers:writing-plans` 生成结构化分步实现计划
- **读取文件**：
  - `.ai/architect/project-architecture-overview.md`
  - `.ai/changelog/ai-modifications.md`
- **输出**：项目上下文摘要 + 实现计划文档
- **检查点**：✅ 项目架构已理解，实现计划已生成

### 第3阶段：Red 阶段（编写测试）
- **Agent 标记**：`[Agent A - 测试编写]`
- **项目技能**：使用 `bigfiles-unit-test` 技能编写测试用例
- **Superpowers 增强**：使用 `superpowers:test-driven-development` 驱动红绿重构循环
- **输出**：`*_test.go` 文件
- **验证**：`go test ./...` → 所有测试失败
- **检查点**：✅ 测试编写完成，测试失败（预期）

### 第4阶段：Green 阶段（实现代码）
- **Agent 标记**：`[Agent B - 代码实现]`
- **操作**：按 writing-plans 生成的计划实现最小化代码
- **输出**：功能代码文件
- **验证**：`go test ./...` → 所有测试通过
- **检查点**：✅ 代码实现完成，测试通过

### 第5阶段：Refactor 阶段（优化代码）
- **Agent 标记**：`[Agent B - 代码实现]`
- **操作**：在测试保护下重构代码
- **Superpowers 增强**：调用 `superpowers:simplify` 技能审查代码质量和复用性
- **验证**：`go test ./...` → 所有测试仍然通过
- **检查点**：✅ 代码重构完成，simplify 审查通过

### 第6阶段：多智能体验证
- **Agent 标记**：`[Agent C - Debug验证]`
- **Superpowers 增强**：调用 `superpowers:dispatching-parallel-agents` 并行分发以下独立任务：
  - 并行任务1：运行所有测试 `go test ./...` + 覆盖率 `go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out`
  - 并行任务2：代码风格 `golangci-lint run` + 构建 `go build ./...`
  - 并行任务3：编写集成测试
- **若遇到 Bug**：调用 `superpowers:systematic-debugging` 系统化定位根因
- **输出**：验证报告
- **检查点**：✅ 所有验证通过

### 第7阶段：提交前验证 + Reviewer Agent 审查
- **Superpowers 增强**：调用 `superpowers:verification-before-completion`，强制实际运行验证命令并确认输出（不得仅凭记忆声明通过）
- **项目技能（核心）**：工具链通过后，使用 `code-review-validation` 触发独立 Reviewer Agent：
  - 传入今天的 prompt 文件 + `git diff --staged` + 变更测试文件 + `.ai/anti-patterns.md`（如存在）
  - Reviewer Agent 角色定义：`.ai/agents/roles/code-reviewer.md`
  - 审查报告保存：`.ai/reviews/review-{type}-{YYYYMMDD}.md`
  - 结论为 `Needs Revision` → 返回第5阶段修复；结论为 `Pass` → 继续
- **经验沉淀**（Pass 后，若本次含 Bug 修复）：
  - 在 `.ai/lessons-learned.md` 新增 LL 记录（症状→根因→正确做法）
  - 评估是否在 `.ai/anti-patterns.md` 新增 AP 记录
- **项目技能**：更新 `.ai/changelog/ai-modifications.md`
- **记录格式**：`[YYYY-MM-DD] [模式]：修改内容简述`
- **检查点**：✅ 验证命令已实际执行，Reviewer 审查通过，修改记录已更新

### 第8阶段：代码审查请求
- **项目技能**：使用 `workflow-enforcer` 执行工作流程检查
- **Superpowers 增强**：调用 `superpowers:requesting-code-review` 系统化整理审查要点
- **检查点**：✅ 审查要点已整理

### 第9阶段：Pre-commit Hook 检查
- **触发**：`git commit`
- **检查项**：
  - ✅ 代码风格检查
  - ✅ 提示词归档检查
  - ✅ 修改记录检查
  - ✅ 提交信息格式检查
- **检查点**：✅ Pre-commit Hook 检查通过

### 第10阶段：Pre-push Hook 检查
- **触发**：`git push`
- **检查项**：
  - ✅ 运行所有测试
  - ✅ 检查测试覆盖率
  - ✅ 构建验证
- **Superpowers 增强**：推送后调用 `superpowers:finishing-a-development-branch` 引导合并决策
- **检查点**：✅ Pre-push Hook 检查通过

### 第11阶段：GitHub Actions CI/CD 验证
- **触发**：创建 Pull Request
- **工作流**：`.github/workflows/workflow-validation.yml`
- **检查项**：测试、代码风格、构建（技术门禁，不含过程检查）
- **检查点**：✅ GitHub Actions 验证通过，PR 可以合并

---

## 🎯 关键规范

### 提示词规范
```markdown
# 任务提示词 - {任务类型}

**日期**: YYYY-MM-DD
**类型**: {development|testing|architecture|...}

## 需求描述
[清晰的需求描述]

## 项目上下文
[相关的项目背景信息]

## 期望输出
[期望的交付物列表]

## 质量要求
- 遵循 TDD 流程
- 测试覆盖率 ≥ 80%
- 符合项目代码规范

## 约束条件
[技术约束和限制]
```

### 修改记录规范
```markdown
### YYYY-MM-DD
- [💻 Code]：修改内容简述
    - 修改项1
    - 修改项2
```

### 提交信息规范
```
<type>(<scope>): <subject>
```
**类型**：feat|fix|refactor|test|docs|chore

---

## 📊 质量指标

| 指标 | 要求 | 检查方式 |
|------|------|---------|
| 测试覆盖率 | ≥ 80% | `go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out` |
| 核心业务覆盖率 | ≥ 90% | 代码审查 |
| 代码风格 | 符合规范 | `golangci-lint run` |
| 构建状态 | 成功 | `go build ./...` |
| 提交信息 | 符合规范 | Git Hook 检查 |
| 提示词归档 | 已归档 | Git Hook 检查 |
| 修改记录 | 已更新 | Git Hook 检查 |

---

## 🔍 检查清单

### 开发前检查
- [ ] 调用 `superpowers:brainstorming` 探索需求（或直接分析）
- [ ] 使用 `task-prompt-generator` 生成并归档提示词
- [ ] 调用 `project-init` 加载项目上下文
- [ ] 调用 `superpowers:writing-plans` 生成实现计划（或直接规划）
- [ ] 已读取 `.ai/architect/project-architecture-overview.md`
- [ ] 已读取 `.ai/changelog/ai-modifications.md`

### 开发中检查
- [ ] [Agent A] 使用 `bigfiles-unit-test` 编写测试
- [ ] 测试失败（Red 阶段，预期行为）
- [ ] [Agent B] 按实现计划编写最小化代码（Green 阶段）
- [ ] 所有测试通过
- [ ] [Agent B] 重构优化（Refactor 阶段）
- [ ] 测试仍然通过

### 提交前检查
- [ ] 调用 `superpowers:dispatching-parallel-agents` 并行验证（或逐一执行）
- [ ] 若有 Bug，调用 `superpowers:systematic-debugging`
- [ ] 调用 `superpowers:verification-before-completion` 强制验证（实际运行命令）：
  - [ ] `go test ./...` 通过
  - [ ] `go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out` ≥ 80%
  - [ ] `golangci-lint run` 通过
- [ ] 使用 `code-review-validation` 触发 Reviewer Agent 独立审查
- [ ] 审查报告结论为 Pass（或仅 Warning）
- [ ] **若本次含 Bug 修复**：`.ai/lessons-learned.md` 已新增 LL 记录
- [ ] 调用 `superpowers:requesting-code-review` 整理审查要点
- [ ] 修改记录已更新
- [ ] 提交信息格式正确

### 推送前检查
- [ ] 所有测试通过
- [ ] 覆盖率达到要求
- [ ] 构建成功
- [ ] 提示词已归档
- [ ] 修改记录已更新

---

## 🚀 快速命令

```bash
# 1. 运行所有测试
go test ./...

# 2. 检查测试覆盖率
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

# 3. 代码风格检查
golangci-lint run

# 4. 构建验证
go build ./...

# 5. 提交代码
git add <files>
git commit -m "feat(module): description"

# 6. 推送代码
git push origin feature/branch-name
```

---

## 🆚 流程增强对比

| 阶段 | 基础流程 | Superpowers 增强后 |
|---|---|---|
| 需求分析 | task-prompt-generator | + **superpowers:brainstorming** |
| 开发准备 | project-init | + **superpowers:writing-plans** |
| TDD 开发 | bigfiles-unit-test | + **superpowers:test-driven-development** |
| 重构 | 手动重构 | + **superpowers:simplify** |
| 多智能体验证 | Agent C 独立验证 | + **superpowers:dispatching-parallel-agents** |
| 调试 | 手动调试 | + **superpowers:systematic-debugging** |
| 提交前验证 | 手动运行命令 | + **superpowers:verification-before-completion** |
| 代码审查 | workflow-enforcer | + **superpowers:requesting-code-review** |
| 提交前 Reviewer 审查 | 无 | **code-review-validation** + Reviewer Agent（角色R，五维度）|
| 经验沉淀 | 无 | **lessons-learned.md** + anti-patterns.md（Bug 修复后强制）|
| 分支管理 | 手动决定 | + **superpowers:finishing-a-development-branch** |

---

## 📚 相关文档

- [完整触发点规范](../../prompts/WORKFLOW_ENFORCEMENT_GUIDE.md)
- [Reviewer Agent 角色定义](../../agents/roles/code-reviewer.md)
- [审查报告目录](../../reviews/README.md)
- [项目架构文档](../../architect/project-architecture-overview.md)
- [修改记录](../../changelog/ai-modifications.md)

---

*快速参考指南版本：2.1.0（含双 Agent 对抗验证）*
*最后更新：2026-03-23*
