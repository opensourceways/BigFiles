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

### 2026-08-10 fix：补 `.gitleaksignore` 忽略历史 commit 中的示例密钥（第一次修复的 follow-up）

- **模式**: fix
- **修改意图**: 上一 commit（`485d741`）仅替换了工作目录中的示例密钥占位符，但 gitleaks 扫描的是**整个 git 历史（166 commits）**——历史 commit `44db7ce` 中的 5 处原始字符串依然存在，PR #83 门禁再次 FAIL。补 `.gitleaksignore` 用 fingerprint 忽略这 5 处历史 finding。fingerprint 含 commit sha，只要历史不重写就稳定，是清理已入库泄露的**唯一**低风险方案（另一方案是 `git rebase` + force-push，风险高）
- **归档提示词**: 沿用 `.ai/prompts/prompt-fix-20260810.md`
- **核心改动**:
  - 新增 `.gitleaksignore`：5 条 fingerprint，全部指向 commit `44db7ce` 中的 `.ai/skills/local-ci-go/` 示例文档
  - 更新 `.ai/lessons-learned.md` LL-006：补充"gitleaks 扫描 full history"关键遗漏，修正"不要依赖 fingerprint"的片面结论
  - 更新 `.ai/anti-patterns.md` AP-004：追加"历史清理需 `.gitleaksignore`"的说明
- **自验证**: `.gitleaksignore` 格式与 gitleaks 官方文档一致；等 CI 验证
- **经验沉淀**: LL-006 已补充；未新增 AP（属于 LL-006 补充说明范畴）

### 2026-08-10 fix：升级 Go 至 1.26.5 修复 26 个 stdlib CVE

- **模式**: fix
- **修改意图**: PR #83 Trivy 扫描报告 Go stdlib 1.24.11 存在 26 个 CVE（含 crypto/tls 证书校验、net/url 内存耗尽、html/template XSS 等），其中仅 4 个能在 1.24 系列内修复，其余需升级到 1.25.x 或 1.26.x。选择升级至 1.26.5（当前 1.26 系列最新补丁版本）以一次性修复全部漏洞，避免后续被同类未修复漏洞反复阻塞。
- **归档提示词**: 无（CI 安全门禁修复）
- **核心改动**:
  - `go.mod`: `go 1.24.0` → `go 1.26.0`；`toolchain go1.24.11` → `toolchain go1.26.5`
  - `.github/workflows/workflow-validation.yml`: 3 处 `go-version: '1.24'` → `'1.26.5'`；顶部适配注释同步
  - `CLAUDE.md`、`.ai/architect/project-architecture-overview.md`、`.ai/skills/bigfiles-code-style/package.json`: 同步版本声明
- **自验证**: `go build ./...` ✅（toolchain 自动下载 1.26.5）；`go test ./...` 全部 pass（auth 14.9s / config 2.7s / server 9.6s / utils 1.6s）✅；`go vet ./...` ✅
- **经验沉淀**: 新增 [[LL-008]]

### 2026-08-10 fix：修复 Bandit SAST 在 lfsNameQuery.py 的 12 个告警（含 1 个 HIGH 命令注入）

- **模式**: fix
- **修改意图**: PR #83 Bandit 扫描 `scripts/lfsNameQuery.py` 报告 12 个安全问题，其中 B605 (HIGH) 存在真实命令注入风险：`force_remove` 兜底分支用 `os.system(f'rm -rf "{path}"')` 拼接 shell 命令，若 `path` 含引号可命令注入；其余 B404/B603/B607 为 subprocess 相关的低危提示（列表参数 + shell=False 已是安全用法，Bandit 静态无法识别）。
- **归档提示词**: 无（CI 安全门禁修复）
- **核心改动**:
  - `scripts/lfsNameQuery.py`:
    - 重写 `force_remove`：移除 `os.system` shell 拼接，改用 `shutil.rmtree(onerror=_handle_remove_readonly)` + `os.chmod(stat.S_IWRITE)` 处理 Windows 只读文件（消除 B605 HIGH）
    - 新增模块级 `GIT_BIN = shutil.which("git")`，subprocess 调用改用绝对路径（消除 5 处 B607）
    - 所有 `subprocess.run` 加 `# nosec B603` 注释（列表参数 + shell=False 是安全用法，属误报）
    - `import subprocess` 加 `# nosec B404`（导入模块本身不构成安全问题）
    - 顺手修复：`raise ... from e` 保留异常链；`main` 提取 `repo_dir` 变量避免 `locals()` 判断；`encoded_token` 提前初始化
- **自验证**: `python -c "import ast; ast.parse(...)"` 通过 ✅；本地无 Bandit，等 CI 验证
- **经验沉淀**: 新增 [[LL-007]] 与 [[AP-005]]

### 2026-08-10 fix：修复 gitleaks 门禁对文档示例密钥的误报

- **模式**: fix
- **修改意图**: PR #83 门禁阶段 gitleaks 在 `.ai/skills/local-ci-go/` 目录下的文档/脚本示例中检测到 5 个 `generic-api-key` 匹配（entropy=4.247），阻塞合入。这些字符串是教学示例（展示"错误做法"），非真实凭证。改用低熵占位符可从根源消除误报，避免维护 `.gitleaksignore` fingerprint 列表（fingerprint 含 commit hash，易随变更失效）。
- **归档提示词**: 无（CI 门禁误报修复，未走 task-prompt-generator）
- **核心改动**:
  - `.ai/skills/local-ci-go/references/security-best-practices.md`: 行 13、221 的 `sk-1234...cdef` → `sk-YOUR_API_KEY_HERE`
  - `.ai/skills/local-ci-go/scripts/run_gitleaks.ps1`: 行 133、140 同样替换
  - `.ai/skills/local-ci-go/scripts/run_gitleaks.sh`: 行 122、129 同样替换（共 6 处，含 gitleaks 未报出的 1 处，为一致性一并处理）
- **自验证**: `grep -r "sk-1234...cdef" .` 返回空 ✅；未涉及 Go 代码，无需 `go test` / `golangci-lint`
- **经验沉淀**: 新增 [[LL-006]] 与 [[AP-004]]

### 2026-06-03 feat：新增 GITHUB_MODEL 开关合并 GitHub LFS batch 路径

- **模式**: feat
- **修改意图**: 通过配置开关在同一个 `/objects/batch` 入口内切换 Gitee/GitCode 与 GitHub 的鉴权与元数据流程，同时保留 `/github/{owner}/{repo}/objects/batch` 路由用于按路径区分客户端
- **归档提示词**: `.ai/prompts/prompt-feat-20260603.md`
- **核心改动**:
  - `config/config.go`: 新增 `GithubModel bool` 字段（JSON key `GITHUB_MODEL`，默认 false）
  - `server/validate.go`: 新增包级变量 `githubModel`，在 `Init()` 中从配置读入
  - `server/server.go`: `handleBatch` 按 `githubModel` 分支调用 `dealWithGithubAuthError` + `addGithubMetaData` 或原有 Gitee 路径；保留 `/github/{owner}/{repo}/objects/batch` 路由
  - `config.example.yml`: 补充 `GIT_CODE_SWITCH` 与 `GITHUB_MODEL` 示例
- **自验证**: `go build ./...` ✅，`go vet ./...` ✅，`go test ./...` ✅

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
