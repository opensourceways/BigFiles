# AI 修改记录模板

本模板用于规范化记录 AI 辅助的代码修改历史。

---

## 基础格式

```markdown
## [YYYY-MM-DD] [模式]：任务简述

- **模式**：feat | fix | refactor | test | docs
- **修改意图**：[Why - 解释为什么要做这个修改，解决了什么问题]
- **归档提示词**：`.ai/prompts/prompt-[type]-[YYYYMMDD].md`
- **核心改动**：
  - `path/to/file.go`：[具体修改内容描述]
  - `path/to/file_test.go`：[测试修改描述]
- **自验证**：
  - 测试：`go test ./...` → ✅ X 个测试全部通过
  - 代码风格：`golangci-lint run` → ✅ 无违规
```

---

## 按模式的详细示例

### feat（新功能）

```markdown
## [YYYY-MM-DD] feat：新增文件锁定管理功能

- **模式**：feat
- **修改意图**：支持 Git LFS 文件锁定协议，防止多用户同时修改大文件；LFS 协议需求
- **归档提示词**：`.ai/prompts/prompt-development-[YYYYMMDD].md`
- **核心改动**：
  - `server/locks.go`：新增 `/locks` GET/POST/DELETE 端点
  - `batch/locks.go`：新增锁定业务逻辑
  - `db/locks.go`：新增锁定数据库操作
  - `server/locks_test.go`：新增锁定功能测试（5 个用例）
- **自验证**：
  - 测试：`go test ./...` → ✅ 全部通过
  - 代码风格：`golangci-lint run` → ✅ 无违规
```

### fix（Bug 修复）

```markdown
## [YYYY-MM-DD] fix：修复 OBS 预签名 URL 过期时间计算错误

- **模式**：fix
- **修改意图**：预签名 URL 过期时间以秒为单位但代码传入了毫秒，导致 URL 立即过期；Issue #42
- **归档提示词**：`.ai/prompts/prompt-bugfix-[YYYYMMDD].md`
- **核心改动**：
  - `batch/upload.go`：修复过期时间单位换算，第 89 行改为 `int64(3600)` 而非 `int64(3600000)`
  - `batch/upload_test.go`：新增过期时间验证测试
- **自验证**：
  - 测试：`go test ./...` → ✅ 全部通过（含新增 Bug 复现测试）
  - 代码风格：`golangci-lint run` → ✅ 无违规
```

### refactor（重构）

```markdown
## [YYYY-MM-DD] refactor：将 OBS 客户端初始化提取为独立函数

- **模式**：refactor
- **修改意图**：main.go 中 OBS 初始化逻辑冗长，违反单一职责原则，提取后便于测试
- **归档提示词**：`.ai/prompts/prompt-refactor-[YYYYMMDD].md`
- **核心改动**：
  - `config/obs.go`：新建，提取 OBS 客户端初始化逻辑
  - `main.go`：改为调用 config.NewOBSClient()
  - `config/obs_test.go`：新增独立测试
- **自验证**：
  - 测试：`go test ./...` → ✅ 所有已有测试通过，无行为变化
  - 代码风格：`golangci-lint run` → ✅ 无违规
```

---

## 常见错误示例（勿模仿）

```markdown
## ❌ 错误示例 1 - 记录内容过于模糊
## 2026-03-01 feat：修改了代码
- 改了一些文件
```

```markdown
## ❌ 错误示例 2 - 缺少"为什么"
## 2026-03-01 fix：修复问题
- **核心改动**：
  - `server.go`：修复了一个 bug
```

---

## 验证清单

修改记录创建后检查：
- [ ] 包含日期（`YYYY-MM-DD` 格式）
- [ ] 包含模式标签（feat / fix / refactor / test / docs）
- [ ] **修改意图**清楚说明"为什么"
- [ ] 关联了提示词文件路径
- [ ] 列出了具体修改的文件
- [ ] 包含自验证结果（测试通过 + 代码风格检查）

---

**最后更新**：2026-03-23
**状态**：生产就绪
