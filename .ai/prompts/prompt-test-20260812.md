# Task Prompt: 为 scripts/lfsNameQuery.py 补充 pytest 测试以生成 coverage.xml

**日期**: 2026-08-12 | **类型**: test | **复杂度**: 简单

---

## Markdown Todo List

### P0 — 核心逻辑与测试

- [x] `scripts/lfsNameQuery.py`：将 `sys.exit(1)`（GIT_BIN 缺失时）从模块顶层下沉到 `_require_git()`，在 `main()` 入口调用——允许 pytest 无 git 环境下 import 目标模块
- [x] 新建 `scripts/test_lfsNameQuery.py`：mock `subprocess.run` + `shutil.which`，覆盖 `force_remove` / `_handle_remove_readonly` / `branch_has_lfsconfig` / `clone_repo_skip_lfs` / `get_all_branches_lfs_mapping` / `main` 全部函数
- [x] 新建 `pytest.ini`：`testpaths=scripts`，`addopts` 含 `--cov=scripts --cov-report=xml:coverage.xml --cov-branch`
- [x] 新建 `requirements-dev.txt`：`pytest>=7.4,<9` + `pytest-cov>=4.1,<7`（**英文注释**避 Windows GBK 解码问题）
- [x] `.github/workflows/workflow-validation.yml`：新增 `python-test` job，跑 pytest 并 upload-artifact `coverage.xml`
- [x] `.gitignore`：新增 `coverage.xml` / `.coverage` / `.pytest_cache/` / `__pycache__/` / `*.pyc` / `venv/` / `.venv/`

### P1 — 边界处理与重构

- [x] test 文件顶部 `sys.path.insert(0, SCRIPT_DIR)`：pytest 从项目根启动时也能 `import lfsNameQuery`
- [x] `_ensure_git_bin` autouse fixture：CI runner 若无 git（罕见）自动 monkeypatch GIT_BIN 保证 import 不 crash
- [x] `force_remove` 边界：missing / file / dir / readonly / os.remove 抛异常 / `_handle_remove_readonly` chmod 抛异常
- [x] `clone_repo_skip_lfs` 分支：unsupported platform / 无凭证 URL / username+token / token-only（gitcode）/ CalledProcessError → RuntimeError

### P2 — 文档更新与清理

- [x] 更新 `.ai/changelog/ai-modifications.md`，追加 2026-08-12 test 记录
- [x] 归档本 prompt 至 `.ai/prompts/prompt-test-20260812.md`

---

## [CONTEXT]

**触发源**：PR #83 门禁中的 Python 增量覆盖率检查失败

**报错摘要**：
```
FileNotFoundError: [Errno 2] No such file or directory: 'coverage.xml'
Python(Inc) N/A ERROR
```

**根因**：diff-cover 期望消费 `coverage.xml` 计算增量覆盖率，但项目本无 pytest 基础设施（此前只有 Go 测试）。PR #83 修改了 `scripts/lfsNameQuery.py`（bandit 修复），触发 Python 语言检查，但 `coverage.xml` 无从生成

**Src 文件**（新增/修改）：

| 文件 | 状态 | 说明 |
|------|------|------|
| `scripts/lfsNameQuery.py` | 修改 | 允许无 git 环境 import（sys.exit 下沉） |
| `scripts/test_lfsNameQuery.py` | 新增 | 22 个用例，覆盖率 88% (branch) |
| `pytest.ini` | 新增 | pytest 配置 + 自动生成 coverage.xml |
| `requirements-dev.txt` | 新增 | 仅 pytest 与 pytest-cov |
| `.github/workflows/workflow-validation.yml` | 修改 | 新增 python-test job |
| `.gitignore` | 修改 | 排除 Python 产物 |

---

## [STEPS]

### Step 1：让 `lfsNameQuery.py` 可测试化

将 `GIT_BIN = shutil.which("git")` 后原本的 `if not GIT_BIN: sys.exit(1)` 逻辑提取为 `_require_git()`，仅在 `main()` 内调用。测试可通过 monkeypatch 强制设置 `GIT_BIN`。

### Step 2：pytest 测试

使用 `unittest.mock.patch("subprocess.run", ...)` 拦截所有 git 调用；`tmp_path` fixture 提供 `force_remove` 的目标；`capsys` 捕获 GitCode 提示输出。

### Step 3：pytest 配置

`pytest.ini` 通过 `addopts` 让 `pytest`（无参）等价于 `pytest --cov=scripts --cov-report=xml:coverage.xml --cov-branch`。外部 SAST CI 若跑 `pytest` 无需知道细节即可拿到 `coverage.xml`。

### Step 4：CI workflow

`python-test` job 使用 `actions/setup-python@v5` + `pip install -r requirements-dev.txt` + `pytest`，最后 upload-artifact `coverage.xml` 便于流水线其他步骤消费。

---

## [DEFINITION_OF_DONE]

| 验收标准 | 命令 | 期望结果 |
|---------|------|---------|
| pytest 通过 | `python -m pytest` | 22 passed |
| coverage.xml 生成 | `ls coverage.xml` | 文件存在 |
| Python 覆盖率 | pytest 输出 | scripts/lfsNameQuery.py ≥ 80% (branch) |
| Go 测试无回归 | `go test ./...` | 全部 PASS |
| CI 门禁 | GitHub Actions on PR #83 | Python(Inc) 从 ERROR 变 PASS |
