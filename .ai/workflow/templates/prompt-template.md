# 任务提示词模板

本模板用于生成标准化的任务提示词，确保 AI Agent 理解任务需求并按规范执行。

---

## 基础模板

```markdown
# 任务提示词：[任务标题]

## 任务信息
- **任务类型**：development / bugfix / refactoring / testing / architecture / integration
- **任务复杂度**：简单 / 中等 / 复杂
- **创建日期**：[YYYY-MM-DD]
- **文件路径**：`.ai/prompts/prompt-{type}-{YYYYMMDD}.md`

---

## [CONTEXT] 项目上下文

- **项目**：BigFiles
- **技术栈**：Go 1.24.0 + chi 路由框架
- **相关文件**：
  - `[相关源码文件路径]`
  - `[相关测试文件路径]`
  - `[相关配置文件路径]`
- **相关技能**：`bigfiles-unit-test`、`bigfiles-code-style`

---

## [STEPS] 任务描述与执行步骤

### 需求描述
[详细描述需要实现的功能或修复的问题]

### 执行计划
1. **P0 - 核心逻辑**
   - [ ] [核心步骤1]
   - [ ] [核心步骤2]
2. **P1 - 边界处理**
   - [ ] [边界步骤1]
3. **P2 - 文档更新**
   - [ ] 更新 `.ai/changelog/ai-modifications.md`

---

## [DEFINITION_OF_DONE] 完成标准

### 功能验收
- [ ] [验收条件1]
- [ ] [验收条件2]

### 质量门禁
- [ ] 所有测试通过：`go test ./...`
- [ ] 代码风格检查通过：`golangci-lint run`
- [ ] 核心业务覆盖率 ≥ 90%
- [ ] 修改记录已更新

---

## 约束条件

- 遵循分层架构规则（server → batch → auth/db → 外部服务）
- 使用构造函数注入依赖
- 错误统一使用 Go error 返回模式
- 不引入新的外部依赖（除非必要）
```

---

## 按任务类型的专用模板

### 开发新功能（development）

```markdown
# 任务提示词：新增 [功能名称] 功能

## [CONTEXT] 上下文
- 在 [模块名称] 模块中新增 [功能描述]
- 需修改文件：server / batch / auth / db（按需）
- 需新建测试：对应的 _test.go 文件

## [STEPS] 执行步骤
1. 编写 batch 层测试（Red）
2. 实现 batch 层逻辑（Green）
3. 编写 server 层测试（Red）
4. 实现 server 层路由处理（Green）
5. 重构优化（Refactor）
6. 更新修改记录

## [DEFINITION_OF_DONE] 完成标准
- 端点可以正确响应请求
- 单元测试覆盖正常/边界/异常场景
- 测试命令通过：`go test ./...`
- 代码风格检查通过：`golangci-lint run`
```

### 修复 Bug（bugfix）

```markdown
# 任务提示词：修复 [Bug描述]

## [CONTEXT] 上下文
- Bug 位置：[文件路径:行号]
- 复现步骤：[步骤描述]
- 预期行为：[描述]
- 实际行为：[描述]

## [STEPS] 执行步骤
1. 编写复现 Bug 的测试（Red）
2. 修复 Bug（Green）
3. 验证边界场景
4. 更新修改记录

## [DEFINITION_OF_DONE] 完成标准
- Bug 复现测试通过
- 已有测试未被破坏
- 测试命令通过：`go test ./...`
```

### 重构（refactoring）

```markdown
# 任务提示词：重构 [模块/功能名称]

## [CONTEXT] 上下文
- 重构目标：[描述当前问题和重构目标]
- 涉及文件：[文件列表]
- 重构原则：行为保持（不改变外部行为）

## [STEPS] 执行步骤
1. 确认已有测试覆盖现有行为
2. 执行重构
3. 验证所有测试仍然通过
4. 更新修改记录

## [DEFINITION_OF_DONE] 完成标准
- 所有已有测试通过：`go test ./...`
- 代码可读性/可维护性提升
- 无功能行为变化
```

---

## 验证清单

提示词创建后检查：
- [ ] 包含 `[CONTEXT]`、`[STEPS]`、`[DEFINITION_OF_DONE]` 三个核心块
- [ ] 包含明确的测试通过标准
- [ ] 包含代码风格检查步骤
- [ ] 文件已保存到 `.ai/prompts/` 目录

---

**最后更新**：2026-03-23
**状态**：生产就绪
