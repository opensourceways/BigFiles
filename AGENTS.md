# BigFiles AI Skills & Agents

本文档列出了 BigFiles 项目中所有可用的 AI 技能（Skills）和代理（Agents），用于指导 AI 工具（Claude Code、Cursor、GitHub Copilot 等）的工作流程和最佳实践。

## 与 CLAUDE.md 的关系

**CLAUDE.md** 定义了 AI Agent 必须遵循的强制执行规则和工作流程。本文档（AGENTS.md）提供了实现这些规则的技能工具。

### 规则与技能的对应关系

| CLAUDE.md 规则 | 对应技能 | 说明 |
|---|---|---|
| 规则 1：对话开始时自动初始化 | `project-init` | 自动加载项目配置（含 lessons-learned、anti-patterns） |
| 规则 2：接收需求时自动生成提示词 | `task-prompt-generator` | 生成标准化提示词 |
| 规则 3：开发过程中主动检查工作流程 | `workflow-enforcer` | 强制执行工作流程（含 Bug 修复后沉淀检查点） |
| 规则 4：提交前自动验证 | `workflow-enforcer` + `code-review-validation` | 验证修改记录、提示词、Reviewer 审查 |
| 规则 6：错误必须固化为约束 | `.ai/lessons-learned.md` + `.ai/anti-patterns.md` | Bug 修复/Reviewer 标记/用户重复提醒后，必须更新经验知识库 |
| 代码风格和安全约束 | `bigfiles-code-style` | 定义编码规范 |
| 单元测试生成 | `bigfiles-unit-test` | 遵循 TDD 原则 |
| 双 Agent 对抗验证 | `code-review-validation` | 防止语义偏差、测试造假、边界遗漏、已知反模式 |

### 工作流程与技能的对应关系

| 工作流程阶段 | 对应技能 | 说明 |
|---|---|---|
| 第 1 阶段：需求规范化 | `task-prompt-generator` | 生成标准化提示词 |
| 第 2 阶段：开发准备 | `project-init` | 加载项目配置（含经验知识库） |
| 第 3 阶段：TDD 开发 | `bigfiles-unit-test` | 编写单元测试 |
| 第 4 阶段：多智能体验证 | `agent-interaction-guide` | 指导 Agent 交互 |
| 第 5 阶段：提交前验证+审查 | `code-review-validation` + `workflow-enforcer` | Reviewer Agent 五维度审查 + 修改记录 |
| 第 5.5 阶段：经验沉淀（Bug 修复必须） | `.ai/lessons-learned.md` + `.ai/anti-patterns.md` | 将错误外化为约束，防止下次重蹈覆辙 |
| 第 6 阶段：代码审查 | `workflow-enforcer` | 执行工作流程检查 |

---

## 核心通用技能（来自 ai-standardization-kit）

#### 1. project-init
- **路径：** `.ai/skills/project-init/`
- **描述：** 项目初始化配置加载器，自动加载所有项目配置文件
- **文件：** `skill.md` · `package.json`

#### 2. task-prompt-generator
- **路径：** `.ai/skills/task-prompt-generator/`
- **描述：** 帮助用户生成标准化的任务提示词，定义任务工作流和步骤，确保提供给 Agent 的提示词一致且符合项目标准
- **文件：** `skill.md` · `package.json`

#### 3. workflow-enforcer
- **路径：** `.ai/skills/workflow-enforcer/`
- **描述：** 强制执行项目的开发工作流程规范，确保所有使用 Agent 进行开发的人员遵循标准化流程
- **文件：** `skill.md` · `package.json`

#### 4. code-review-validation
- **路径：** `.ai/skills/code-review-validation/`
- **描述：** 触发独立 Reviewer Agent（角色R）对 coding agent 产出进行五维度对抗验证（语义对齐、测试真实性、边界覆盖、架构合规、反模式合规）
- **文件：** `skill.md` · `package.json`
- **角色定义：** `.ai/agents/roles/code-reviewer.md`
- **输出：** `.ai/reviews/review-{type}-{YYYYMMDD}.md`

---

## 项目专属技能

<!-- 根据项目实际部署的技能在下方补充，格式参考上方核心技能 -->

#### 5. bigfiles-code-style
- **路径：** `.ai/skills/bigfiles-code-style/`
- **描述：** BigFiles 项目的代码风格和安全约束规范，定义编码标准、安全最佳实践和开发约束
- **文件：** `skill.md` · `package.json`

<!-- 如有更多项目专属技能，继续在此追加（序号顺延） -->

---

### 技能使用指南

#### 选择合适的技能
- 根据任务类型选择相应的技能
- 多个技能可以组合使用
- 优先使用特定领域的技能而不是通用技能

#### 技能执行流程
1. 识别任务需求
2. 选择匹配的技能
3. 按照技能指导执行
4. 验证执行结果
5. 更新相关文档

#### 技能最佳实践
- 始终遵循代码风格与安全约束
- 在开发前阅读相关技能文档
- 使用 `workflow-enforcer` 规范开发流程
- 为新功能编写单元测试
- 生成清晰的任务提示词

## 技能统计

- **总技能数**：5 个
- **核心通用技能**：4 个（project-init / task-prompt-generator / workflow-enforcer / code-review-validation）
- **项目专属技能**：1 个

---

## 🚀 Superpowers 外部技能集成

> 本节描述可选的 [obra/superpowers](https://github.com/obra/superpowers) 插件集成。安装后可解锁完整 11 阶段增强工作流。

### 安装方法（Claude Code v2.1.72+）

在 Claude Code 中执行：
```
/plugin marketplace add obra/superpowers-marketplace
/plugin install superpowers@superpowers-marketplace
```

安装后重启 Claude Code 即可生效。详情见 `ai-standardization-kit/SUPERPOWERS_SETUP.md`。

### 核心技能列表

| 技能 | 触发时机 |
|------|---------|
| `superpowers:brainstorming` | 阶段 1：探索需求意图和设计方案 |
| `superpowers:writing-plans` | 阶段 2：生成结构化分步实现计划 |
| `superpowers:test-driven-development` | 阶段 3：驱动 Red-Green-Refactor 循环 |
| `superpowers:simplify` | 阶段 5：重构时审查代码质量和复用性 |
| `superpowers:verification-before-completion` | 阶段 7：提交前强制实际运行命令 |
| `superpowers:requesting-code-review` | 阶段 8：系统化整理审查要点 |
| `superpowers:dispatching-parallel-agents` | 阶段 6：并行分发测试/构建/风格检查 |
| `superpowers:systematic-debugging` | 任何阶段：遇到 bug 时系统化定位 |
| `superpowers:finishing-a-development-branch` | 阶段 10：决策分支合并/PR 策略 |
| `superpowers:receiving-code-review` | 接受审查反馈时 |
| `superpowers:executing-plans` | 执行多步实现计划时 |
| `superpowers:using-git-worktrees` | 需要隔离工作区时 |

### 降级行为

所有 Superpowers 增强步骤均以"（如已集成 Superpowers）"标注。**未安装时工作流自动降级，核心 TDD 流程和双 Agent 验证机制不受影响。**

## 相关文档

- [CLAUDE.md](CLAUDE.md) - AI Agent 行为规范和强制执行规则（含规则 6：经验积累机制）
- [架构概览](./.ai/architect/project-architecture-overview.md)
- [修改记录](./.ai/changelog/ai-modifications.md)
- [踩雷知识库](./.ai/lessons-learned.md)（如已存在）
- [反模式清单](./.ai/anti-patterns.md)（如已存在）
- [技能索引](./.ai/skills/index.json)

---

**注意**：当 skills 发生变动时，请手动同步更新本文件的技能列表和统计数字。

**创建时间**：2026-03-23
**最后更新**：2026-03-23
**维护团队**：项目开发组
