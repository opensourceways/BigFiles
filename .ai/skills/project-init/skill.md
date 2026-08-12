---
id: project-init
name: 项目初始化配置加载器
description: 自动加载项目配置文件，包括工作流程规范、架构文档、技能索引、编码规范等，确保 AI Agent 了解项目规范
version: 1.0.0
license: MIT
author: AI Assistant
namespace: universal.initialization
keywords:
  - initialization
  - config
  - governance
  - onboarding
  - project-setup
categories:
  - initialization
  - governance
modes:
  - code
  - architect
  - ask
tags:
  - initialization
  - config
  - governance
  - onboarding
priority: 100
enabled: true
allowed-tools:
  - read
dependencies:
  skills: []
---

# 项目初始化配置加载器

## 📋 技能描述

**项目初始化配置加载器**是一个初始化类技能，用于自动加载项目的所有配置文件。这个技能确保 AI Agent 在开始任何开发任务前，都能够：

1. **加载工作流程规范** - 了解项目的开发流程和要求
2. **理解项目架构** - 掌握项目的整体结构和设计
3. **学习编码规范** - 遵循项目的代码风格和安全约束
4. **查看修改历史** - 了解项目的演进和已有的修改
5. **准备开发环境** - 为后续开发做好准备

## 🚀 使用方式

### 快速启动

在对话开始时，输入以下命令之一：

```
/init
```

或者：

```
使用 project-init skill
```

或者：

```
加载项目配置
```

### 详细模式

如果需要查看详细的加载过程，可以输入：

```
/init --verbose
```

## 📂 加载的配置文件

此 skill 会按顺序加载以下配置文件：

### 1. 工作流程规范（最高优先级）
**文件**：`.ai/prompts/WORKFLOW_ENFORCEMENT_GUIDE.md`

包含内容：
- 任务开始检查清单
- TDD 流程要求
- 修改记录规范
- 提交前检查清单

### 2. 项目架构文档
**文件**：`.ai/architect/project-architecture-overview.md`

包含内容：
- 项目整体架构
- 模块划分和职责
- 技术栈说明
- 分层架构规则

### 3. 技能索引
**文件**：`.ai/skills/index.json`

包含内容：
- 可用的 AI 技能列表
- 技能使用场景
- 技能依赖关系
- 技能优先级

### 4. 编码规范和安全约束
**文件**：`.ai/skills/[CODE_STYLE_SKILL_NAME]/skill.md`

包含内容：
- 代码风格规范
- 安全约束要求
- 常见违规示例
- 修复建议

### 5. 修改记录
**文件**：`.ai/changelog/ai-modifications.md`

包含内容：
- 历史修改记录（最近 30 天）
- 项目演进过程
- 已有的修改项

### 6. 踩雷知识库（如存在）
**文件**：`.ai/lessons-learned.md`

包含内容：
- 历史 Bug 的症状、根因和正确做法
- 每条 LL 记录对应一个真实错误场景
- 防止 Agent 重复犯同类错误

### 7. 反模式清单（如存在）
**文件**：`.ai/anti-patterns.md`

包含内容：
- 从 lessons-learned 提炼的可机器检测规则
- 每条 AP 记录含检测命令（应返回空 = 合规）
- 供 Reviewer Agent 维度 5 自动核对

### 6. 开发前检查清单
**文件**：`.ai/workflow/checklists/pre-development.md`

包含内容：
- 开发前必须完成的检查项
- 环境验证步骤

## ✅ 加载完成后的确认

当所有配置文件加载完成后，AI Agent 必须向用户报告：

```
✅ 项目配置加载完成

📋 当前项目：[PROJECT_NAME]
🔧 技术栈：[TECH_STACK]
📦 测试命令：[TEST_CMD]
🏗️ 构建命令：[BUILD_CMD]
🔍 代码检查：[LINT_CMD]

🧰 已加载技能（共 X 个）：
  - project-init（优先级：100）- 初始化
  - workflow-enforcer（优先级：10）- 流程管控
  - task-prompt-generator（优先级：5）- 提示词生成
  - [CODE_STYLE_SKILL_NAME]（优先级：15）- 代码规范
  - [TEST_SKILL_NAME]（优先级：40）- 测试生成

📝 最近修改（最近 3 条）：
  [来自 ai-modifications.md 的最后 3 条记录]

🚀 已准备就绪，请告诉我你的开发需求。
```

## 🎯 自动化初始化逻辑

执行本技能时，必须按顺序完成以下动作：

### Step A: 索引感知（Discovery）
- **动作**：扫描 `.ai/skills/index.json`
- **输出**：构建"当前可用技能地图"，识别哪些技能需要 `auto_load`

### Step B: 环境嗅探（Env Detection）
- **动作**：读取 `pom.xml`、`package.json`、`go.mod` 等构建文件
- **输出**：动态确定 `test`、`build`、`lint` 指令
- **失败处理**：如果识别失败，必须主动询问用户

### Step C: 规则同步（Policy Loading）
- **动作**：读取 `CLAUDE.md` 和 `AGENTS.md`
- **输出**：锁定本项目严禁执行的行为和推荐的架构模式

### Step D: 进度对齐（History Sync）
- **动作**：读取 `ai-modifications.md` 最后 3-5 条记录
- **输出**：告知用户当前项目进度

## 🔧 故障排除

### 问题 1：某个配置文件缺失
**解决方案**：
1. 检查是否已运行过初始化（`AUTO_SETUP_PROMPT`）
2. 手动创建缺失文件（参考 `ai-standardization-kit/ai-templates/`）

### 问题 2：配置文件内容过期
**解决方案**：
1. 更新相应的配置文件
2. 重新运行 `/init` 加载最新配置

## 📚 相关资源

- **工作流程规范**：`.ai/prompts/WORKFLOW_ENFORCEMENT_GUIDE.md`
- **项目架构**：`.ai/architect/project-architecture-overview.md`
- **技能索引**：`.ai/skills/index.json`
- **修改记录**：`.ai/changelog/ai-modifications.md`

## 💡 最佳实践

1. **每次新对话都运行 `/init`** - 确保加载最新的配置
2. **在开始开发前运行 `/init`** - 确保理解项目规范
3. **定期更新配置文件** - 当项目规范变更时，及时更新

---

**版本**：1.0.0
**状态**：生产就绪
