# Task Prompt: 修复 PR #83 门禁三个安全扫描失败（gitleaks / bandit / trivy）

**日期**: 2026-08-10 | **类型**: fix | **复杂度**: 中等（多工具链、含 Go 主版本升级）

---

## Markdown Todo List

### P0 — 核心逻辑与测试

- [x] gitleaks：定位 5 处 `generic-api-key` 误报，替换 `sk-1234567890abcdef` → `sk-YOUR_API_KEY_HERE`（低熵占位符）
- [x] bandit：修复 `scripts/lfsNameQuery.py:154` B605 命令注入（HIGH）：移除 `os.system` + f-string 拼接，改用 `shutil.rmtree(onerror=...)`
- [x] bandit：修复 B607 subprocess partial path：引入 `GIT_BIN = shutil.which("git")` 使用绝对路径
- [x] bandit：对列表参数 + shell=False 的 subprocess 调用添加 `# nosec B603`；对 `import subprocess` 添加 `# nosec B404`
- [x] trivy：升级 Go 1.24.11 → 1.26.5 修复 26 个 stdlib CVE（选 1.26.5 是当前 1.26 系列最新补丁版本，一次性覆盖）
- [x] 同步 `.github/workflows/workflow-validation.yml` 3 处 `go-version` 到 `1.26.5`
- [x] 同步 `CLAUDE.md`、`.ai/architect/project-architecture-overview.md`、`.ai/skills/bigfiles-code-style/package.json` 中的 Go 版本声明

### P1 — 边界处理与重构

- [x] `force_remove` 增加 `_handle_remove_readonly` 回调，处理 Windows 上 .git 只读文件删除场景
- [x] `clone_repo_skip_lfs`：`encoded_token` 提前初始化，避免 print/replace 分支未定义
- [x] `main`：显式初始化 `repo_dir = None`，替换 `locals()` 判断
- [x] `raise RuntimeError(...) from e` 保留异常链
- [x] AP-004 检测命令加 file-type/dir 过滤（`--include=*.md/*.sh/*.ps1/*.go/*.yml/*.yaml`）
- [x] AP-005 检测命令使用 `\bos\.system\(` 精确匹配 + `--exclude-dir=venv/.venv/node_modules`，避免命中 docstring 与虚拟环境

### P2 — 文档更新与清理

- [x] 更新 `.ai/changelog/ai-modifications.md`，追加 3 条 2026-08-10 fix 记录（gitleaks / bandit / trivy）
- [x] 新增 `.ai/lessons-learned.md` LL-006（gitleaks 高熵占位符）、LL-007（os.system 命令注入）、LL-008（Go 版本长期停滞导致 stdlib CVE 无补丁）
- [x] 新增 `.ai/anti-patterns.md` AP-004（示例密钥字符串）、AP-005（os.system + 字符串拼接）
- [x] 归档本 prompt 至 `.ai/prompts/prompt-fix-20260810.md`

---

## [CONTEXT]

**触发源**：PR https://github.com/opensourceways/BigFiles/pull/83 CI 门禁失败

**报告工具与失败摘要**：

| 工具 | 失败点 | 严重度 |
|------|--------|--------|
| gitleaks | 5 处 `generic-api-key` 匹配在示例文档 | 阻塞 |
| bandit | `scripts/lfsNameQuery.py` 12 issue（1 HIGH + 11 LOW） | 阻塞 |
| trivy | Go stdlib 1.24.11 存在 26 个 CVE | 阻塞 |

**Src 文件**（必须修改）：

| 文件 | 修改原因 |
|------|---------|
| `.ai/skills/local-ci-go/references/security-best-practices.md` | 教学文档中的示例 API key 触发 gitleaks 误报 |
| `.ai/skills/local-ci-go/scripts/run_gitleaks.ps1` | 演示脚本 echo 中的示例 API key 同上 |
| `.ai/skills/local-ci-go/scripts/run_gitleaks.sh` | 同上 |
| `scripts/lfsNameQuery.py` | B605 真实命令注入 + B607/B603/B404 需消除或抑制 |
| `go.mod` | Go 1.24 系列已无补丁可修复大多数 stdlib CVE |
| `.github/workflows/workflow-validation.yml` | CI 中 `go-version` 需同步升级 |
| `CLAUDE.md` / `.ai/architect/project-architecture-overview.md` / `.ai/skills/bigfiles-code-style/package.json` | 版本声明同步 |

**Test 文件**：本次纯配置/文档/脚本修复，无新增业务测试；沿用现有 `go test ./...` 覆盖回归

---

## [STEPS]

### Step 1：gitleaks 误报消除

对 6 处 `sk-1234567890abcdef` 统一替换为 `sk-YOUR_API_KEY_HERE`。字符串明显是占位符、含 `YOUR` / `HERE` 等英文单词，熵值远低于 gitleaks `generic-api-key` 阈值。避免使用 `.gitleaksignore` fingerprint 方案（含 commit hash 易失效）。

### Step 2：bandit 命令注入修复

- `force_remove` 完全移除 `os.system` 分支；改用 `shutil.rmtree(path, onerror=_handle_remove_readonly)`
- `_handle_remove_readonly(func, path, _exc_info)` 内 `os.chmod(path, stat.S_IWRITE)` 后重试 `func(path)`，处理 Windows `.git` 只读文件典型场景
- 单文件删除路径也加 `os.chmod(..., S_IWRITE)` 兜底

### Step 3：bandit subprocess 相关修复

- 模块顶部 `GIT_BIN = shutil.which("git")`；缺失则 `sys.exit(1)`
- 所有 `subprocess.run` 首参改为 `[GIT_BIN, ...]`；行尾加 `# nosec B603 - args are a fixed list, shell=False`
- `import subprocess` 加 `# nosec B404 - required for invoking git CLI`

### Step 4：Go 升级

- `go.mod`：`go 1.24.0` → `go 1.26.0`；`toolchain go1.24.11` → `toolchain go1.26.5`
- CI workflow 3 处 `go-version: '1.24'` → `'1.26.5'`
- 文档同步版本

### Step 5：工具链验证（必须执行）

```bash
go build ./...   # 期望 exit 0；toolchain 自动下载 1.26.5
go test ./...    # 全部包 PASS
go vet ./...     # 零输出
python -c "import ast; ast.parse(open('scripts/lfsNameQuery.py',encoding='utf-8').read())"  # 语法 OK
```

### Step 6：经验沉淀（CLAUDE.md 规则 6）

三个方向均属"错误模式"引发的门禁失败，必须新增 LL/AP 记录并链接到 changelog。

---

## [DEFINITION_OF_DONE]

| 验收标准 | 命令 | 期望结果 |
|---------|------|---------|
| 无高熵伪密钥 | `grep -rnE 'sk-[0-9a-f]{16,}' --include='*.md' --include='*.sh' --include='*.ps1' --include='*.go' .` | 空 |
| 无 shell 拼接 | `grep -rnE '\bos\.system\(\|shell\s*=\s*True' --include='*.py' --exclude-dir=venv .` | 空 |
| Go 版本升级 | `grep -E "^(go\|toolchain) " go.mod` | `go 1.26.0` / `toolchain go1.26.5` |
| 构建成功 | `go build ./...` | exit 0 |
| 全量测试通过 | `go test ./...` | 所有包 PASS |
| 静态分析清零 | `go vet ./...` | 零输出 |
| CI 门禁重跑 | GitHub Actions on PR #83 | gitleaks/bandit/trivy 全 PASS |
| 经验沉淀 | 新增 LL-006/007/008 与 AP-004/005 | 均已写入并交叉链接 |
