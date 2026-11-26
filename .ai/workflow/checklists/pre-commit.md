# 提交前检查清单

本清单用于确保代码提交前满足所有质量要求。

---

## 代码质量检查

### 编译验证
```bash
go build ./...
```
- [ ] 项目编译成功，无错误

### 测试验证
```bash
go test ./...
```
- [ ] 所有单元测试通过
- [ ] 无测试失败

### 覆盖率验证
```bash
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```
- [ ] 核心业务逻辑覆盖率 ≥ 90%
- [ ] 整体覆盖率 ≥ 80%

### 代码风格验证
```bash
golangci-lint run
```
- [ ] 无代码风格违规
- [ ] 无新增 Warning 或 Error

### 完整验证
```bash
go vet ./... && golangci-lint run && go test ./...
```
- [ ] 完整验证通过

---

## 文档与记录检查

### 修改记录
- [ ] `.ai/changelog/ai-modifications.md` 已更新
- [ ] 包含今天的日期
- [ ] 格式符合规范（`[YYYY-MM-DD] [模式]：描述`）
- [ ] 记录内容清晰说明了"为什么"而不仅仅是"做了什么"

### 提示词归档
- [ ] `.ai/prompts/` 目录包含今天的提示词文件
- [ ] 文件命名格式正确（`prompt-{type}-{YYYYMMDD}.md`）

### 经验沉淀（仅含 Bug 修复时检查）
- [ ] `.ai/lessons-learned.md` 已新增 LL 记录（症状、根因、正确做法）
- [ ] 已评估是否需要在 `.ai/anti-patterns.md` 新增 AP 记录

---

## Git 检查

### 代码状态
```bash
git status
git diff --staged
```
- [ ] 只暂存了预期的文件
- [ ] 没有意外的敏感文件（`config.yml`、密钥等）

### 提交信息格式
- [ ] 格式：`<type>(<scope>): <subject>`
- [ ] type 为：`feat`、`fix`、`refactor`、`test`、`docs`、`chore` 之一
- [ ] subject 简洁明确（不超过 72 字符）

---

## 最终确认

- [ ] 代码已经过自我审查
- [ ] 没有遗留的调试代码或临时注释
- [ ] 已准备好提交

---

**最后更新**：2026-03-23
**状态**：生产就绪
