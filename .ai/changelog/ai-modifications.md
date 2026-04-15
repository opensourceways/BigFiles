# AI 修改历史记录

> 本文件记录所有 AI 辅助生成或修改的代码变更。每次 AI 开发任务完成后必须更新。

## 格式说明

每条记录包含以下字段：
- **模式**: feat | fix | refactor | test | docs
- **修改意图**: 说明为什么要做这个修改（Why）
- **归档提示词**: 对应的提示词文件路径
- **核心改动**: 具体修改了哪些文件（What）
- **自验证**: 测试通过情况和代码检查结果

## 记录模板

### [YYYY-MM-DD] [模式]：任务简述

- **模式**: feat | fix | refactor | test | docs
- **修改意图**: [Why - 解释这次修改的原因和目标]
- **归档提示词**: `.ai/prompts/prompt-[type]-[date].md`
- **核心改动**:
  - `path/to/file`: [具体修改内容]
- **自验证**: [测试通过情况 / 代码检查结果]

---

<!-- 以下为实际记录，按时间倒序排列 -->

### 2026-04-15 feat：allowedRepos 从配置文件读取

- **模式**: feat
- **修改意图**: allowedRepos 硬编码在代码中难以维护，通过配置文件管理更灵活
- **归档提示词**: `.ai/prompts/prompt-feat-20260415.md`
- **核心改动**:
  - `config/config.go`: 新增 `AllowedRepos []string` 字段（JSON key: `ALLOWED_REPOS`）
  - `auth/gitee.go`: 删除硬编码赋值，`Init()` 中从 `cfg.AllowedRepos` 读取，为空时保留默认值
  - `config.example.yml`: 新增 `ALLOWED_REPOS` 示例配置
- **自验证**: `go build ./...` ✅，`go test ./auth/... ./config/...` ✅

### 2026-03-24 fix：修复 Reviewer Agent 审查报告 F1~F7 + S1 的 8 项 Fail

- **模式**: fix
- **修改意图**: Reviewer Agent 第一轮审查（review-feat-20260324.md）返回 Needs Revision，修复 HTTP 响应头顺序 bug、双重写入 bug、测试真实外部 API 问题、mock 未使用问题、download 权限语义问题及中文错误信息问题
- **归档提示词**: `.ai/prompts/prompt-feat-20260323.md`
- **核心改动**:
  - `server/server.go`: F1 - `dealWithAuthError` 和 `dealWithGithubAuthError` 中将 `LFS-Authenticate` header Set 移至 `WriteHeader` 之前；F2 - `addGithubMetaData` 改为返回 `error`，调用方出错时提前 return
  - `auth/github_auth.go`: S1 - `verifyGithubDelete` 中文错误信息改为英文 `unauthorized:` 前缀；F7 - `verifyGithubDownload` 改为先调用 collaborator API 验证 username，fallback 时区分 401/403
  - `auth/github_auth_test.go`: F4/F5/F6 - 重写测试，新增 `patchGithubAPI` monkey patch 辅助函数，13 个测试覆盖 upload/download/delete 全路径；修复 `ForkAllowedParent` 测试实际走到 fork parent 分支
- **自验证**: `go test ./... -gcflags=all=-l` 全部通过；`go build ./...` 成功；`go vet ./...` 无报告

### 2026-03-24 chore：提交 AI 开发规范化基础设施文件

- **模式**: chore
- **修改意图**: 将 AI 开发规范化初始化时生成的 .ai/ 目录、CLAUDE.md、AGENTS.md、Git Hooks、GitHub Actions 等基础设施文件纳入版本控制
- **归档提示词**: `.ai/prompts/prompt-chore-20260324.md`
- **核心改动**:
  - `.ai/`: 新增完整 AI 目录结构（architect、agents、skills、workflow、prompts 等）
  - `CLAUDE.md`: AI Agent 行为宪法（6 条强制规则）
  - `AGENTS.md`: 技能文档
  - `.githooks/`: commit-msg、post-merge、pre-push hooks
  - `.github/workflows/workflow-validation.yml`: CI 工作流
  - `.gitignore`: 新增 coverage.out
- **自验证**: git status 确认文件完整

### 2026-03-23 feat：新增 GitHub LFS Batch 接口（server + main）

- **模式**: feat
- **修改意图**: 完成 GitHub LFS batch 接口的 server 层路由注册和 main.go 接入，实现完整的 GitHub 平台 LFS 支持
- **归档提示词**: `.ai/prompts/prompt-feat-20260323.md`
- **核心改动**:
  - `server/server.go`: 新增 handleGithubBatch、dealWithGithubAuthError、addGithubMetaData，注册 /github/{owner}/{repo}/objects/batch 路由
  - `server/server_test.go`: 新增 TestHandleGithubBatch 测试
  - `config/config.go`: 新增 DefaultGithubToken 字段
  - `main.go`: 传入 IsGithubAuthorized: auth.GithubAuth()
- **自验证**: go test ./... 全部 PASS，go vet ./... 无报错

### 2026-03-23 feat：新增 /github/{owner}/{repo}/objects/batch 路由及处理器

- **模式**: feat
- **修改意图**: 实现 Task 5 & Task 6（TDD），为 GitHub 平台添加独立的 LFS batch 接口，支持 isGithubAuthorized 认证、元数据写入及异步 OID 文件名检查
- **归档提示词**: 内联任务（Task 5 & Task 6）
- **核心改动**:
  - `server/server.go`: Options/server struct 追加 IsGithubAuthorized/isGithubAuthorized 字段；New() 注册 `/github/{owner}/{repo}/objects/batch` 路由；新增 dealWithGithubAuthError、handleGithubBatch、addGithubMetaData 三个方法
  - `server/server_test.go`: 追加 githubBatchUrlPath 常量及 TestHandleGithubBatch 测试（TDD 红→绿验证通过）
- **自验证**: `go build ./server/...` 编译通过；`go test ./server/... -v` 全部 PASS（含新增 TestHandleGithubBatch 2/2）

### 2026-03-23 docs：AI 开发规范化全量初始化配置

- **模式**: docs
- **修改意图**: 为 BigFiles 项目完成 AI 开发规范化初始化，部署 CLAUDE.md、AGENTS.md、.ai/ 目录结构、技能资产、Git Hooks 等，建立 AI 辅助开发的标准化工作流程
- **归档提示词**: `.ai/prompts/AI_AGENT_AUTOMATION_CHECKLIST.md`
- **核心改动**:
  - `CLAUDE.md`: 新建 AI Agent 行为宪法，包含 6 条强制规则
  - `AGENTS.md`: 新建技能文档，包含 5 个技能的规则-技能对应关系
  - `.ai/`: 新建完整 AI 目录结构（架构文档、工作流、技能、Agent 角色等）
  - `.gitignore`: 添加 config.yml 到忽略列表
- **自验证**: 目录结构验证通过，所有模板文件已正确替换占位符

### 2026-03-23 feat：新增 GitHub Auth 模块（org 白名单 + 权限校验）

- **模式**: feat
- **修改意图**: 实现 Git LFS 服务对 GitHub 平台的认证支持，与 Gitee/GitCode 模式一致，支持 org 白名单预校验和 upload/download/delete 权限分级验证
- **归档提示词**: `.ai/prompts/prompt-development-20260323.md`
- **核心改动**:
  - `auth/github_auth.go`: 新建 GitHub 认证模块，包含 GithubAuth、CheckGithubRepoOwner、VerifyGithubUser 及辅助函数
  - `auth/github_auth_test.go`: 新建测试套件，覆盖 org 白名单、forbidden org、token 解析、未知操作等场景
- **自验证**: `go test ./auth/... -v` 全部通过（TestGithubAuth 4/4，全 auth 套件 PASS）

### 2026-03-26 fix：修复 gosec 安全扫描问题并补充测试

- **模式**: fix + test
- **修改意图**: 修复 gosec 静态分析检测到的 G706（日志注入）和 G304（文件路径遍历）安全问题；修复 PowerShell CI 脚本中的参数解析 bug；补充 auth/gitee.go 和 server/server.go 的单元测试以提升覆盖率
- **归档提示词**: `.ai/prompts/prompt-fix-20260326.md`
- **核心改动**:
  - `server/server.go`: 将 log.Printf 中 `%s` 改为 `%q`，添加 `#nosec G706` 注释（4 处）
  - `utils/util.go`: 为 os.ReadFile 添加 `#nosec G304` 注释（CLI 可信参数）
  - `auth/gitee.go`: 为 os.ReadFile 添加 `#nosec G304` 注释（路径已做边界校验）
  - `.ai/skills/local-ci-go/scripts/run_tests.ps1`: 修复 5 处 PowerShell 参数解析 bug
  - `.ai/skills/local-ci-go/scripts/run_security.ps1`: 修复 ErrorActionPreference 问题
  - `.ai/skills/local-ci-go/scripts/run_gitleaks.ps1`: 修复 ErrorActionPreference 问题
  - `auth/gitee_test.go`: 新增 TestVerifyUserDelete/Upload/Download、TestResolveScriptPath、TestCreateTempOutputFile、TestParseOutputFile、TestGetAccountManageToken、TestGetOpenEulerUserInfo、TestGetLFSMapping 等测试
  - `server/server_test.go`: 新增 TestApplySearchFilter 测试
- **自验证**: `go test ./auth/... ./server/... -coverprofile=coverage.out` 全部通过；gosec 输出 Issues: 0, Nosec: 6
