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
