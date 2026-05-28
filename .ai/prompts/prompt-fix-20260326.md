# Task Prompt: 修复 Gosec 安全问题并补充单元测试

**日期**: 2026-03-26 | **类型**: fix + test | **复杂度**: 中等

---

## Markdown Todo List

### P0 — 核心逻辑与测试

- [x] 修复 `server/server.go` 中 4 处 G706（日志注入）：`%s` → `%q` + `#nosec G706` 注释
- [x] 修复 `utils/util.go` 中 1 处 G304（文件路径遍历）：`os.ReadFile` + `#nosec G304` 注释
- [x] 修复 `auth/gitee.go` 中 1 处 G304（文件路径遍历）：`os.ReadFile` + `#nosec G304` 注释
- [x] 在 `auth/gitee_test.go` 补充 TestVerifyUserDelete / TestVerifyUserUpload / TestVerifyUserDownload
- [x] 在 `auth/gitee_test.go` 补充 TestResolveScriptPath / TestCreateTempOutputFile / TestParseOutputFile
- [x] 在 `auth/gitee_test.go` 补充 TestGetAccountManageToken / TestGetOpenEulerUserInfo / TestGetLFSMapping
- [x] 在 `server/server_test.go` 补充 TestApplySearchFilter

### P1 — 边界处理与重构

- [x] `run_tests.ps1`：修复 `./...` → `'./...'`（防止 shell 展开）
- [x] `run_tests.ps1`：修复 `-func=coverage.out` → `'-func=coverage.out'`（防止参数分割，3 处）
- [x] `run_tests.ps1`：修复 `$file:` → `${file}:`（变量展开）
- [x] `run_tests.ps1`：修复路径匹配 `^${file}:` → `/${file}:`（coverage.out 使用模块完整路径）
- [x] `run_tests.ps1`：在 `go test` 前添加 `$ErrorActionPreference = "Continue"`
- [x] `run_security.ps1`：在 `gosec` 前添加 `$ErrorActionPreference = "Continue"`
- [x] `run_gitleaks.ps1`：将 `$ErrorActionPreference = "Continue"` 移至 switch 块前

### P2 — 文档更新与清理

- [x] 更新 `.ai/changelog/ai-modifications.md`，补充 2026-03-26 条目
- [x] 归档本 prompt 至 `.ai/prompts/prompt-fix-20260326.md`

---

## [CONTEXT]

**Src 文件**（必须修改）：

| 文件 | 修改原因 |
|------|---------|
| `server/server.go` | 4 处 log.Printf 使用 `%s` 格式化用户可控值，触发 G706 |
| `utils/util.go` | `os.ReadFile(path)` path 来自 CLI 参数，触发 G304 |
| `auth/gitee.go` | `os.ReadFile(absPath)` 已做边界校验但未加 nosec，触发 G304 |
| `.ai/skills/local-ci-go/scripts/run_tests.ps1` | 5 处 PowerShell 参数解析缺陷 |
| `.ai/skills/local-ci-go/scripts/run_security.ps1` | NativeCommandError：gosec 写 stderr 时 Stop 模式报错 |
| `.ai/skills/local-ci-go/scripts/run_gitleaks.ps1` | NativeCommandError：gitleaks 写 stderr 时 Stop 模式报错 |

**Test 文件**（必须补充）：

| 文件 | 补充原因 |
|------|---------|
| `auth/gitee_test.go` | auth/gitee.go 覆盖率不足 80% |
| `server/server_test.go` | applySearchFilter 函数未覆盖 |

---

## [STEPS]

### Step 1：G706 日志注入修复（server/server.go）

对以下 4 处 log.Printf：
1. Cookie `yg` 值：`%s` → `%q`，追加 `// #nosec G706 -- value is quoted with %q, control chars escaped`
2. Cookie `ut` 值：同上
3. 对象获取错误（oid/repo/owner）：`%s` → `%q`，追加 `// #nosec G706 -- URL params quoted with %q`
4. 对象删除错误（oid/repo/owner）：同上

### Step 2：G304 文件路径修复

- `utils/util.go`：`os.ReadFile(path)` 后追加 `// #nosec G304 -- path is a trusted CLI --config-file argument`
- `auth/gitee.go`：`os.ReadFile(absPath)` 后追加 `// #nosec G304 -- absPath validated with directory boundary check above`

### Step 3：PowerShell CI 脚本修复（详见 P1 Todo）

关键原则：
- `go`/`gosec`/`gitleaks` 这类原生命令在写 stderr 时会触发 `Stop` 模式的 `NativeCommandError`，需在调用前切换为 `Continue`
- PowerShell 对 `./...` 和 `-param=value` 形式有特殊解析，需用单引号括起
- `$variable:` 中 `:` 会被当作驱动器说明符，需改为 `${variable}:`

### Step 4：补充 auth/gitee_test.go 测试

使用 `bou.ke/monkey` 对 `getParsedResponse` 函数打桩，避免真实网络调用。
对 `verifyUser*` 系列使用 table-driven 模式，覆盖 admin/developer/read/write 权限组合。

### Step 5：补充 server/server_test.go 测试

使用 `gorm.Open(nil, &gorm.Config{DryRun: true})` 创建无连接的 gorm DB 实例，
调用 `applySearchFilter(db, searchKey)` 验证返回值非 nil。

### Step 6：lsp_diagnostics 检查（必须执行）

```bash
# 静态分析（零错误）
go vet ./...

# 代码风格（零新警告）
golangci-lint run

# 安全扫描（Issues: 0）
gosec ./...
```

---

## [DEFINITION_OF_DONE]

| 验收标准 | 命令 | 期望结果 |
|---------|------|---------|
| 安全扫描通过 | `gosec ./...` | `Issues: 0, Nosec: 6` |
| 全量测试通过 | `go test ./...` | 所有包 PASS，无 FAIL |
| lsp_diagnostics 清零 | `go vet ./...` | 零输出 |
| 代码风格通过 | `golangci-lint run` | 零新警告 |
| auth 覆盖率 | `go test ./auth/... -cover` | statement coverage ≥ 60% |
| CI 脚本可执行 | 在 Windows PowerShell 运行 `run_tests.ps1` | 无 NativeCommandError |
