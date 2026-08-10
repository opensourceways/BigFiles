# 踩雷知识库（Lessons Learned）

> **用途**：记录项目开发中遇到的真实错误，防止同类问题重复发生。
> **维护规则**（CLAUDE.md 规则 6）：每次 Bug 修复后、Reviewer 标记 Needs Revision 后、用户第二次提醒同一问题后，必须新增记录。
> **加载时机**：每次对话初始化时自动加载（规则 1）。

---

## 记录格式

```markdown
## LL-{序号} [{YYYY-MM-DD}] {问题简题}
- **症状**：（用户/CI/测试看到了什么现象）
- **根因**：（错误的根本原因，必须到代码/设计层面）
- **正确做法**：（应该怎么写/怎么做）
- **检测命令**（可选）：（grep/go 命令可自动检测此问题；应返回空表示合规）
- **触发的规则更新**：（更新了哪些文件，如 anti-patterns.md、skill.md、CLAUDE.md）
```

---

## 使用说明

### 何时新增记录

根据 CLAUDE.md 规则 6，以下任意情况发生时，Agent **必须**在当次会话结束前新增 LL 记录：

1. 修复了一个由"错误模式"导致的 bug
2. Reviewer Agent 标记了 `Needs Revision` 并指出具体模式问题
3. 用户第二次提醒 Agent 同一类问题

### 与其他文件的关联

```
症状发现 → 记录到 lessons-learned.md（LL-XXX）
           ↓（若可机器检测）
           → 提炼到 anti-patterns.md（AP-XXX）
           ↓（供 Reviewer Agent 维度 5 自动核对）
           → 每次代码审查时自动检测
```

### 新增流程

1. 在本文件末尾新增 `## LL-{下一个序号}` 记录
2. 评估是否需要在 `.ai/anti-patterns.md` 新增对应 AP 记录
3. 评估是否需要更新相关 skill.md 的约束说明
4. 在 `.ai/changelog/ai-modifications.md` 记录此次经验沉淀

---

<!-- 实际 LL 记录从此处开始，按序号递增 -->

## LL-001 [2026-03-24] HTTP 响应头在 WriteHeader 后写入被静默忽略

- **症状**：Git LFS 客户端收到 401 响应但无 `LFS-Authenticate` 头，无法触发重新认证，导致客户端挂起或报错
- **根因**：Go 的 `http.ResponseWriter` 在 `WriteHeader(statusCode)` 调用后响应头即被冻结并发送，后续 `w.Header().Set(...)` 调用被静默丢弃。`server/server.go` 中 `dealWithAuthError` 和 `dealWithGithubAuthError` 均先调用 `w.WriteHeader(401)` 再调用 `w.Header().Set("LFS-Authenticate", ...)`，导致关键响应头永远不会被客户端收到
- **正确做法**：必须在调用 `w.WriteHeader(...)` 之前完成所有 `w.Header().Set(...)` 调用
- **检测命令**：`grep -n "WriteHeader" server/server.go | head -20`（人工检查每处 WriteHeader 前是否已设置所有需要的响应头）
- **触发的规则更新**：新增 AP-001

## LL-002 [2026-03-24] 无返回值函数内部写响应后调用方继续写入导致响应体损坏

- **症状**：`addGithubMetaData` 在 `db.InsertLFSObj` 失败时内部写入 500 错误体后 return，但调用方 `handleGithubBatch` 无感知，继续向已完成的 ResponseWriter 写入，客户端收到损坏的 JSON 响应
- **根因**：`addMetaData`/`addGithubMetaData` 设计为 `void` 函数（无返回值），在内部发生错误并写入响应后，调用方无法感知已写入，继续执行后续写操作
- **正确做法**：凡是在函数内部可能写入 HTTP 响应的辅助函数，必须返回 `error`，调用方在收到非 nil error 时立即 return
- **检测命令**：`grep -n "func add.*MetaData" server/server.go`（检查返回类型是否包含 error）
- **触发的规则更新**：新增 AP-002

## LL-003 [2026-03-24] Server 层直接调用 db 层违反分层约束

- **症状**：Reviewer Agent 维度 4 标记 Fail：`server/server.go` 中 `addGithubMetaData` 直接调用 `db.InsertLFSObj`
- **根因**：新增 GitHub batch 功能时，复制了原有 `addMetaData` 函数的结构，而原函数本身也存在跨层调用问题（server 层直接访问 db 层），导致该反模式通过复制粘贴传播到新代码
- **正确做法**：元数据写入逻辑必须封装在 `batch` 层，server 层只调用 batch 层的 service 函数，严禁 server 层直接 import 并调用 `db` 包
- **检测命令**：`grep -rn "db\." server/`（结果应为空，否则存在跨层调用）
- **触发的规则更新**：新增 AP-003

## LL-004 [2026-03-24] Mock Server 定义但从未使用导致核心路径零覆盖

- **症状**：`mockGithubServer` 函数完整定义在测试文件中但无任何调用点；upload/download/delete 三条核心权限验证路径均无测试覆盖；`TestCheckGithubRepoOwner_AllowedOrg` 直接调用真实 GitHub API，测试结果依赖网络
- **根因**：`getParsedResponse` 使用硬编码的完整 URL（`https://api.github.com/...`），无法通过参数注入替换为 mock server 地址。测试编写时未意识到需要修改被测函数以支持可测试性（如注入 base URL 或 http.Client）
- **正确做法**：需要 mock 外部 HTTP 调用时，被测函数应接受可配置的 base URL 参数或 HTTP client 接口，使测试能将请求重定向至 `httptest.Server`；或使用 monkey patching 替换 `getParsedResponse`（项目已使用 bou.ke/monkey）
- **触发的规则更新**：无新增 AP（此为设计问题，难以用命令检测）

## LL-005 [2026-03-24] Superpowers 技能链绕过项目强制工作流程

- **症状**：用户发现整个 GitHub LFS batch 功能开发过程中，`task-prompt-generator` 从未调用，无标准化提示词，`code-review-validation` 从未执行，无 Reviewer Agent 审查报告
- **根因**：Superpowers 技能链（brainstorming → writing-plans → subagent-driven-development）形成了完整的从需求到实现的闭环，Agent 在执行 Superpowers 流程时没有在关键节点插入项目自定义的强制检查点（触发点 2 的 task-prompt-generator、触发点 7 的 code-review-validation）
- **正确做法**：Superpowers 技能与项目工作流程必须并行执行，不能互相替代：brainstorming 后必须调用 task-prompt-generator；subagent-driven-development 完成后必须调用 code-review-validation；`WORKFLOW_ENFORCEMENT_GUIDE.md` 的触发点描述已更新为在各阶段明确注明"如已集成 Superpowers"的并行调用要求
- **触发的规则更新**：无新增 AP（流程遵从问题）；已在 `WORKFLOW_ENFORCEMENT_GUIDE.md` 中各触发点补充 Superpowers 并行调用说明

## LL-006 [2026-08-10] 文档/脚本中的示例密钥字符串被 gitleaks 判定为泄露

- **症状**：PR #83 CI 门禁阶段 gitleaks 扫描出 5 处 `generic-api-key` 匹配（entropy=4.247），全部位于 `.ai/skills/local-ci-go/` 目录下用于教学演示的文档与脚本（形如 `sk-1234...cdef`），阻塞合入
- **根因**：文档 / 演示脚本中直接书写符合 API key 形态的字符串（`sk-` 前缀 + 16 位 hex，熵值高），gitleaks 的 `generic-api-key` 规则依据前缀 + 熵判定，无法区分"真实密钥"与"教学示例"
- **正确做法**：文档、脚本、测试夹具中出现的示例凭证必须使用**低熵、明显是占位符**的字符串，如 `sk-YOUR_API_KEY_HERE`、`sk-EXAMPLE_PLACEHOLDER`、`<your-api-key>`。不要依赖 `.gitleaksignore` fingerprint（fingerprint 含 commit hash，一旦相关行变更或 rebase 即失效，需持续维护）
- **检测命令**：`grep -rnE 'sk-[0-9a-f]{16,}' --include='*.md' --include='*.sh' --include='*.ps1' --include='*.go' .`（应返回空）
- **触发的规则更新**：新增 [[AP-004]]

## LL-007 [2026-08-10] 用 os.system + f-string 拼接 shell 命令导致命令注入

- **症状**：PR #83 Bandit 对 `scripts/lfsNameQuery.py:154` 报告 B605 (HIGH)："Starting a process with a shell, possible injection detected"。代码为 `os.system(f'rm -rf "{path}"' if os.name != 'nt' else f'rd /s /q "{path}"')`
- **根因**：`os.system` 执行 shell 命令，f-string 将 `path` 直接拼接进命令字符串。当 `path` 含 `"` 时，可打破引号闭合并注入任意 shell 命令。属于典型的 CWE-78 (OS Command Injection)
- **正确做法**：**永远不要**用 `os.system` / `subprocess` 的 `shell=True` 搭配字符串拼接。跨平台强制删除应使用 `shutil.rmtree(path, onerror=callback)`，callback 内 `os.chmod(path, stat.S_IWRITE)` + 重试即可处理 Windows 只读文件场景，无需 shell。若必须调用外部命令，用列表参数 + `shell=False`（默认）
- **检测命令**：`grep -rnE '\bos\.system\(|shell\s*=\s*True' --include='*.py' --exclude-dir=venv --exclude-dir=.venv --exclude-dir=node_modules .`（结果应仅包含 nosec 注释行或空）
- **触发的规则更新**：新增 [[AP-005]]

## LL-008 [2026-08-10] Go 长期停留在旧 minor 版本导致 stdlib CVE 无补丁可用

- **症状**：PR #83 Trivy 扫描发现 Go 1.24.11 存在 26 个 stdlib CVE，其中 22 个在 1.24 系列内**无修复**（Go 上游仅对最新两个 minor 版本提供安全补丁：截至 2026-08，即 1.25.x 和 1.26.x）
- **根因**：`go.mod` 中的 `go` 指令和 `toolchain` 指令长期停留在 1.24 系列，未跟进上游 minor 版本更新。Go 上游的补丁策略是"仅维护最新两个 minor 版本"，一旦 1.26.x 发布，1.24.x 就进入 EOL，只有少量高危补丁反向移植
- **正确做法**：定期（建议每季度）跟进 Go minor 版本升级：
  1. 每次上游发布新 minor（如 1.26.0 → 1.27.0）后 2 个月内评估升级
  2. `go.mod` 的 `go` 指令与 `toolchain` 指令同步更新，CI workflow 的 `go-version` 也需同步（本项目在 `.github/workflows/workflow-validation.yml` 3 处）
  3. 依赖 Trivy / govulncheck 的定期扫描发现遗漏
- **检测命令**：`grep -E "^(go|toolchain) " go.mod`（人工比对是否与 https://go.dev/dl/ 最新两个 minor 匹配）；或 `govulncheck ./...`
- **触发的规则更新**：无新增 AP（此为运维治理问题，不适合静态规则）；已在 `CLAUDE.md`、`.ai/architect/project-architecture-overview.md` 同步版本声明
