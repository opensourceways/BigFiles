# 开发前准备检查清单

本清单用于确保开始开发前已做好充分准备。

---

## 文档阅读

- [ ] 已读取 `.ai/prompts/WORKFLOW_ENFORCEMENT_GUIDE.md`（工作流规范）
- [ ] 已读取 `.ai/architect/project-architecture-overview.md`（项目架构）
- [ ] 已读取 `.ai/changelog/ai-modifications.md`（最近 30 天的修改记录）
- [ ] 已读取 `.ai/skills/bigfiles-code-style/skill.md`（编码规范）

---

## 需求理解

- [ ] 已明确功能需求（输入、输出、约束）
- [ ] 已识别受影响的模块（server / batch / auth / db）
- [ ] 已确认与已有功能的关系（是新功能还是修改现有功能）
- [ ] 已生成并归档任务提示词（`.ai/prompts/prompt-{type}-{YYYYMMDD}.md`）

---

## 架构理解

- [ ] 了解本次任务涉及的层级（server / batch / auth / db）
- [ ] 确认遵循分层架构规则（server 不直接访问 db 或 OBS）
- [ ] 确认使用构造函数注入依赖
- [ ] 确认错误处理方式（使用标准 Go error 返回模式）

---

## 开发环境

- [ ] 项目可以正常编译：`go build ./...`
- [ ] 已有测试可以全部通过：`go test ./...`

---

## TDD 准备

- [ ] 已确定测试文件的位置（与源文件同目录，`_test.go` 后缀）
- [ ] 已确认可用的测试框架（testify/assert + monkey patching）
- [ ] 准备好遵循 Given-When-Then 测试模式

---

**最后更新**：2026-03-23
**状态**：生产就绪
