# 提示词归档：修复 Reviewer Agent 审查报告 F1~F7 + S1 的 8 项 Fail

**归档时间**：2026-03-24
**任务类型**：fix
**触发原因**：Reviewer Agent 第一轮审查（review-feat-20260324.md）返回 Needs Revision

---

## 需求描述

修复 `.ai/reviews/review-feat-20260324.md` 中标记的 8 项 Fail：

- **F1**：`dealWithAuthError` 和 `dealWithGithubAuthError` 中 `LFS-Authenticate` header 在 `WriteHeader` 之后设置，被静默忽略
- **F2**：`addGithubMetaData` 无返回值，导致 DB 错误后仍继续写入响应体（双重写入）
- **F3**：`addGithubMetaData` 直接调用 `db.InsertLFSObj`，违反分层架构（已知遗留问题，本次暂缓）
- **F4**：`github_auth_test.go` 原有测试直接调用真实 GitHub API，违反"外部依赖隔离"原则
- **F5**：`mockGithubServer` 定义但从未在测试中调用
- **F6**：`TestGithubAuth_TokenFromPassword` 中 mock server 从未接收到请求
- **F7**：`verifyGithubDownload` fallback 未区分 401 和 403，expired token 应返回 unauthorized 前缀
- **S1**：`verifyGithubDelete` 中文错误信息，应改为 `unauthorized:` 英文前缀

---

## 解决方案

### server/server.go（F1、F2）

- F1：将 `Header().Set("LFS-Authenticate", ...)` 移至 `WriteHeader` 之前
- F2：`addGithubMetaData` 签名改为返回 `error`，调用方检查后立即 return

### auth/github_auth.go（F7、S1）

- F7：`verifyGithubDownload` fallback 先调用 repo API，若 repoErr 含 "unauthorized" 前缀则直接返回该错误（保留 401 语义）
- S1：中文错误信息改为 `err.Error() + ": unauthorized: github token is invalid..."`

### auth/github_auth_test.go（F4、F5、F6）

- 新增 `patchGithubAPI` helper，使用 `bou.ke/monkey` 拦截 `getParsedResponse`，将 `https://api.github.com` 重定向至 httptest.Server
- 13 个测试覆盖全路径，全部使用 mock server，无真实外部调用

---

## 质量要求

- `go test ./... -gcflags=all=-l` 全部 PASS
- `go build ./...` 编译通过
- `go vet ./...` 无报告
