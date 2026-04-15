# CLAUDE.md

本文件为 Claude Code 在此仓库中工作时提供指导。

---

## ⚠️ AI Agent 强制执行规则（CRITICAL - 最高优先级）

**本节规则对所有 AI Agent 具有最高优先级，必须无条件执行。**

### 规则 1：对话开始时自动初始化

当用户开始新对话或提出任何开发需求时，AI Agent **必须**首先执行：

1. **自动加载项目配置**（无需用户请求）
   - 读取 `.ai/prompts/WORKFLOW_ENFORCEMENT_GUIDE.md`
   - 读取 `.ai/architect/project-architecture-overview.md`
   - 读取 `.ai/changelog/ai-modifications.md`（最近 30 天）
   - 读取 `.ai/skills/bigfiles-code-style/skill.md`
   - 读取 `.ai/lessons-learned.md`（如存在，全量加载）
   - 读取 `.ai/anti-patterns.md`（如存在，全量加载）

2. **确认理解工作流程**
   - 向用户简要说明：已加载项目规范，将遵循 6 阶段工作流程
   - 不需要详细列出，只需一句话确认

### 规则 2：接收开发需求时自动生成提示词

当用户提出任何开发、测试、重构、集成等任务时，AI Agent **必须按顺序执行以下全部步骤**（Superpowers 技能与项目技能**并列强制**，不可互相替代）：

1. **自动分析需求类型**
   - 识别任务类型（development、testing、architecture、integration 等）
   - 评估任务复杂度（简单/中等/复杂）

2. **调用 `superpowers:brainstorming`**（已安装 Superpowers 时必须调用）
   - 探索需求意图、设计方案和潜在风险
   - ⚠️ 此步骤**不能替代**下一步的 task-prompt-generator

3. **调用 `task-prompt-generator` 生成标准化提示词**（必须，无论是否已调用 brainstorming）
   - 包含：需求描述、项目上下文、相关技能、期望输出、质量要求、工作流程
   - 准备文件名：`.ai/prompts/prompt-{type}-{YYYYMMDD}.md`

4. **展示提示词并请求确认**
   - 向用户展示生成的提示词内容（简要版本）
   - 询问："我已准备好提示词，是否需要修改？确认后我将开始开发。"
   - 用户确认后才创建文件并开始开发

> ⚠️ **禁止行为**：执行完 `superpowers:brainstorming` 后直接进入开发，跳过 `task-prompt-generator`。两个步骤必须都执行。（来源：LL-005）

### 规则 3：开发过程中主动检查工作流程

在开发过程中，AI Agent **必须**在以下节点自动执行检查：

1. **编写测试前**：确认已理解需求和架构；调用 `superpowers:test-driven-development` + `bigfiles-unit-test`
2. **实现代码前**：确认测试已编写且处于失败状态（Red 阶段）
3. **修复 Bug 后**：确认已按规则 6 更新 `.ai/lessons-learned.md`
4. **提交代码前**（以下步骤**全部必须执行**，缺一不可）：
   - 调用 `superpowers:verification-before-completion` 实际运行 `go test ./...`、`golangci-lint run`、`go build ./...` 并确认输出
   - 工具链全部通过后，**必须调用 `code-review-validation`** 触发 Reviewer Agent 独立审查
   - Reviewer Agent 审查结论为 **Pass** 后才允许继续提交；**Needs Revision** 时停止并返回步骤 1 修复
   - 确认修改记录已更新（`.ai/changelog/ai-modifications.md` 含今天日期）

> ⚠️ **禁止行为**：跳过 `code-review-validation` 直接提交代码，或仅凭记忆声称测试已通过而不实际运行命令。（来源：LL-005）

### 规则 4：提交前自动验证

在建议用户提交代码前，AI Agent **必须**：

1. **自动检查修改记录**
   - 验证 `.ai/changelog/ai-modifications.md` 是否包含今天的日期
   - 验证记录格式是否正确

2. **自动检查提示词归档**
   - 验证 `.ai/prompts/` 目录是否包含今天的提示词文件
   - 验证文件命名格式是否正确

3. **提醒用户运行本地检查**
   - 提醒运行 `go test ./...`
   - 提醒运行 `golangci-lint run`

4. **若当次包含 Bug 修复，验证经验沉淀**
   - 验证 `.ai/lessons-learned.md` 是否已新增对应的 LL 记录
   - 验证记录包含：症状、根因、正确做法三个必填字段

### 规则 5：第三方服务文档自动查询

当开发过程中遇到第三方服务问题时，AI Agent **必须**自动查询最新文档：

1. **自动识别第三方服务**（按项目实际情况填写）
   - 华为云 OBS（对象存储服务）
   - MySQL（关系型数据库）
   - Git LFS 协议（Large File Storage）

2. **查询触发条件**
   - 编写涉及第三方服务的代码前
   - 遇到第三方服务相关错误时
   - 需要了解最新 API 或最佳实践时

### 规则 5：违反规则的处理

如果 AI Agent 发现自己或用户跳过了任何强制步骤：

1. **立即停止当前操作**
2. **明确指出缺失的步骤**
3. **引导用户完成缺失步骤**
4. **不允许继续进行后续步骤**

### 规则 6：错误必须固化为约束（经验积累机制）

当发生以下**任意一种**情况时，AI Agent **必须**在当次会话结束前完成经验沉淀：

1. 修复了由"错误模式"导致的 bug
2. Reviewer Agent 标记了"Needs Revision"并指出具体问题
3. 用户对同一类问题进行了**第二次**提醒

**必须执行的步骤（缺一不可）：**

- [ ] 在 `.ai/lessons-learned.md` 新增 LL 记录
- [ ] 评估是否需要在 `.ai/anti-patterns.md` 新增 AP 记录（可机器检测的规则）
- [ ] 评估是否需要更新相关 `skill.md` 的 `## Known Issues & Lessons` 区块
- [ ] 若为用户重复提醒，在 CLAUDE.md 对应规则下新增具体限制说明

**LL 记录格式（`.ai/lessons-learned.md`）：**

```markdown
## LL-{序号} [{YYYY-MM-DD}] {问题简题}
- **症状**：（用户/CI/测试看到了什么现象）
- **根因**：（错误的根本原因，必须到代码/设计层面）
- **正确做法**：（应该怎么写/怎么做）
- **检测命令**（可选）：（grep/构建命令可自动检测此问题）
- **触发的规则更新**：（更新了哪些文件，如 anti-patterns.md、skill.md）
```

**AP 记录格式（`.ai/anti-patterns.md`）：**

```markdown
## AP-{序号} {禁止事项简题}
❌ 错误示例代码或做法
✅ 正确示例代码或做法
检测：`命令（可直接运行，应返回空）`
来源：LL-{序号}
```

---

## 项目概述

**BigFiles** 是一个基于 Go 1.24.0 + chi 路由框架 的 Git LFS (Large File Storage) 服务端实现，支持大文件通过华为云 OBS 对象存储进行上传、下载和管理，并集成用户认证功能。

**核心技术栈：**
- Go 1.24.0 + go-chi/chi v4 HTTP 路由框架
- GORM v1.31.1 + MySQL 数据持久化
- 华为云 OBS SDK (huaweicloud-sdk-go-obs v3.25.9) 对象存储

## 构建与开发命令

### 构建
```bash
# 清理构建（包含测试）
go build ./...

# 构建不运行测试（更快）
go build ./...

# 构建并进行代码质量检查
go vet ./... && go build ./...
```

### 运行
```bash
# 启动应用
go run main.go --config-file config.yml
```

### 测试
```bash
# 运行所有测试
go test ./...

# 运行特定测试
go test ./path/to/package -run TestFunctionName

# 运行测试并生成覆盖率报告
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

### 代码质量检查
```bash
# 运行代码风格检查
golangci-lint run

# 完整验证（风格 + 静态分析 + 测试）
go vet ./... && golangci-lint run && go test ./...
```

## 项目架构

### 目录结构
```
BigFiles/
├── auth/           # 认证模块（用户身份验证）
├── batch/          # 批处理模块（批量文件操作）
├── config/         # 配置模块（配置加载与解析）
├── db/             # 数据库模块（MySQL 数据访问）
├── docs/           # 文档目录
├── scripts/        # 脚本目录
├── server/         # HTTP 服务器模块（路由与处理器）
├── utils/          # 工具模块（辅助函数）
├── main.go         # 程序入口
├── go.mod          # Go 模块依赖
└── config.example.yml  # 配置示例
```

### 分层架构

1. **控制器层**：处理 HTTP 请求和参数验证，返回标准化响应，将业务逻辑委托给服务层
2. **服务层**：实现业务逻辑，协调控制器和 DAO 层
3. **数据访问层**：封装外部 API 调用，处理 HTTP 通信和响应解析

## 开发工作流程

本项目对 AI 辅助开发实施**强制性工作流程规范**：

### 第 1 阶段：需求规范化
- 使用 `task-prompt-generator` 技能
- 将提示词归档到 `.ai/prompts/`，命名格式：`prompt-{type}-{YYYYMMDD}.md`

### 第 2 阶段：开发准备
- 阅读 `.ai/architect/project-architecture-overview.md` 了解架构
- 阅读 `.ai/changelog/ai-modifications.md` 了解最近的修改

### 第 3 阶段：TDD 开发（红-绿-重构）
- **红**：先编写失败的测试
- **绿**：实现最小化代码使测试通过
- **重构**：在测试保护下改进代码质量

### 第 4 阶段：多智能体验证
- 测试编写、代码实现、Debug 验证分角色协作

### 第 5 阶段：提交前验证 + Reviewer Agent 审查
- **Superpowers 增强**：使用 `superpowers:verification-before-completion` 强制验证（实际运行命令）
- **双 Agent 对抗审查**：使用 `code-review-validation` 技能触发 Reviewer Agent（角色R）审查四维度
  - 审查报告保存：`.ai/reviews/review-{type}-{YYYYMMDD}.md`
  - 结论 `Needs Revision` → 返回第 3 阶段修复；`Pass` → 继续
- 在 `.ai/changelog/ai-modifications.md` 中记录所有 AI 生成的修改
- 格式：`[YYYY-MM-DD] [模式]：修改内容简述`（模式：feat、fix、refactor、test、docs）

### 第 6 阶段：代码审查
- **Superpowers 增强**：使用 `superpowers:requesting-code-review` 整理审查要点
- 代码风格验证（`golangci-lint run`）
- 测试覆盖率（整体 ≥80%，核心业务 ≥90%）

## 测试要求

- 使用 **Given-When-Then** 模式组织测试
- **行覆盖率**：≥80%；**分支覆盖率**：≥70%；**核心业务逻辑**：100% 覆盖
- 使用 Mock 隔离外部依赖

## 代码风格与规范

- 依赖注入：基于构造函数（必需依赖）
- 异常处理：统一异常处理，返回标准响应结构
- 日志记录：使用 logrus，关键操作记录审计日志

## Git 工作流程

### 分支命名
- 功能分支：`feature/description`
- Bug 修复：`fix/description`
- 发布分支：`release/version`

### 提交信息格式
```
<type>(<scope>): <subject>
```
类型：`feat`、`fix`、`refactor`、`test`、`docs`、`chore`

## 快速参考

| 任务 | 命令 |
|------|------|
| 构建 | `go build ./...` |
| 测试 | `go test ./...` |
| 代码质量 | `go vet ./... && golangci-lint run && go test ./...` |
| 代码风格 | `golangci-lint run` |
| 覆盖率报告 | `go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out` |

---

**最后更新**：2026-03-23
**维护团队**：项目开发组

---

## 项目技能（自动加载）

> 以下技能在每次会话启动时自动注入上下文，agent 无需主动读取即可执行。

@.ai/skills/task-prompt-generator/skill.md
@.ai/skills/code-review-validation/skill.md
@.ai/skills/workflow-enforcer/skill.md
