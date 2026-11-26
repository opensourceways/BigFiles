# Skill: Task Prompt Generator (Standardization Engine)

## 1. 核心职责
将模糊的用户意图转化为“零歧义”的 AI 任务包。

## 2. 深度处理流程
### 第一步：意图蒸馏 (Distillation)
- 识别用户请求中的隐含需求。
- **反幻觉检查**：如果用户要求的方案与项目既有模式（AGENTS.md 中定义）冲突，必须提出警告并提供替代方案。

### 第二步：任务分解 (Decomposition)
- 将大任务拆解为原子化的 Todo。
- **定义优先级**：
  - **P0**: 核心逻辑与测试。
  - **P1**: 边界处理与重构。
  - **P2**: 文档更新与清理。

### 第三步：上下文锚定 (Context Anchoring)
- 自动搜索并锁定完成任务必须修改的 `Src` 文件。
- 自动锁定相关的 `Test` 基类或工具类。

### 第四步：输出标准 Prompt
生成一个包含以下块的指令：
- **[CONTEXT]**: 本次任务关联的所有文件。
- **[STEPS]**: 详细的执行计划。
- **[DEFINITION_OF_DONE]**: 明确的验收标准（如：通过 TestA，LSP 0 错误）。

## 3. 交付物标准
- 必须包含一个 Markdown 格式的 Todo List。
- 必须包含明确的 `lsp_diagnostics` 检查步骤。
