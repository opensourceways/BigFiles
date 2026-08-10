# 反模式清单（Anti-patterns）

> **用途**：从 lessons-learned.md 提炼出的**可机器检测**的禁止规则。
> **维护规则**（CLAUDE.md 规则 6）：当 lessons-learned 新增记录且该记录可被命令检测时，同步在此文件新增 AP 记录。
> **使用方**：Reviewer Agent（维度 5）在审查时逐条核对；pre-commit hook 可引用检测命令。

---

## 记录格式

```markdown
## AP-{序号} {禁止事项简题}

❌ 错误：
\`\`\`
// 错误示例代码
\`\`\`

✅ 正确：
\`\`\`
// 正确示例代码
\`\`\`

检测：\`命令（可直接运行，结果应为空 = 合规）\`

来源：LL-{序号}
```

---

## 使用说明

### 何时新增 AP 记录

当 `.ai/lessons-learned.md` 新增 LL 记录，且满足以下条件时，必须同步新增 AP 记录：

- 该错误模式**可以用命令自动检测**（grep、go vet、golangci-lint 规则等）
- 该错误模式**有明确的禁止写法**（非模糊的"应该更好"）
- 该错误**可能在未来代码中重复出现**

### 与 Reviewer Agent 的集成

Reviewer Agent（角色R）在进行代码审查时，**维度 5（反模式合规）**会：

1. 加载本文件中所有 AP 记录
2. 对本次变更文件逐条运行检测命令
3. 发现触犯 → 立即标记 `[Fail]`，引用 AP 编号和文件:行号

**检测命令格式要求**：
- 命令应能在项目根目录直接运行
- 合规时应返回**空输出**（exit code 0）
- 违规时应返回**具体匹配内容**（便于定位）

### 新增 AP 流程

1. 参考下方格式在本文件末尾新增 `## AP-{下一个序号}` 记录
2. 编写并验证检测命令（在项目根目录实际运行一次）
3. 在对应 LL 记录中记录"触发的规则更新：新增 AP-XXX"

---

<!-- 实际 AP 记录从此处开始，按序号递增 -->

## AP-001 WriteHeader 后设置响应头

❌ 错误：
```go
w.WriteHeader(http.StatusUnauthorized)
w.Header().Set("LFS-Authenticate", `Basic realm="Git LFS"`)  // 被静默忽略
```

✅ 正确：
```go
w.Header().Set("LFS-Authenticate", `Basic realm="Git LFS"`)  // 必须在 WriteHeader 之前
w.WriteHeader(http.StatusUnauthorized)
```

检测：`grep -n -A3 "WriteHeader" server/server.go | grep -B1 "Header().Set"`（结果应为空）

来源：LL-001

---

## AP-002 HTTP 响应辅助函数无返回值导致双重写入

❌ 错误：
```go
func addMetaData(req batch.Request, w http.ResponseWriter, ...) {  // 无返回值
    if err := db.InsertLFSObj(...); err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResp)
        return  // 调用方无感知，继续写入
    }
}
```

✅ 正确：
```go
func addMetaData(req batch.Request, w http.ResponseWriter, ...) error {  // 返回 error
    if err := db.InsertLFSObj(...); err != nil {
        w.WriteHeader(http.StatusInternalServerError)
        json.NewEncoder(w).Encode(errorResp)
        return err  // 调用方检查 error 后立即 return
    }
    return nil
}
```

检测：`grep -n "^func add.*MetaData" server/server.go`（检查返回类型是否含 error）

来源：LL-002

---

## AP-003 Server 层直接调用 db 层

❌ 错误：
```go
// server/server.go
import "github.com/metalogical/BigFiles/db"

func addGithubMetaData(...) {
    db.InsertLFSObj(lfsObj)  // server 层直接访问 db
}
```

✅ 正确：
```go
// server/server.go 调用 batch 层
batchService.InsertMetaData(userInRepo, req.Objects)

// batch/service.go 调用 db 层
func (s *Service) InsertMetaData(...) error {
    return db.InsertLFSObj(lfsObj)
}
```

检测：`grep -rn "db\." server/`（结果应为空）

来源：LL-003

## AP-004 文档 / 脚本示例中出现高熵伪密钥字符串

在文档、演示脚本、测试夹具中演示"如何存储 / 泄露 API key"时，禁止使用形如 `sk-` + hex 的高熵字符串——会被 gitleaks 的 `generic-api-key` 规则判定为真实密钥泄露，阻塞门禁。

❌ 错误：
```markdown
const apiKey = "sk-1234...cdef"
api_key: sk-1234...cdef
```

```bash
echo "   apiKey := \"sk-1234...cdef\""
```

✅ 正确：使用低熵、明显是占位符的字符串
```markdown
const apiKey = "sk-YOUR_API_KEY_HERE"
api_key: sk-YOUR_API_KEY_HERE
```

```bash
echo "   apiKey := \"sk-YOUR_API_KEY_HERE\""
```

检测：`grep -rnE 'sk-[0-9a-f]{16,}' --include='*.md' --include='*.sh' --include='*.ps1' --include='*.go' --include='*.yml' --include='*.yaml' .`（结果应为空）

来源：LL-006

## AP-005 用 os.system / shell=True 搭配字符串拼接执行命令

Python 中禁止用 `os.system(f'...{var}...')` 或 `subprocess.run(f'...{var}...', shell=True)` 拼接外部命令——`var` 若含 shell 元字符（`"`、`;`、`&`、反引号等）会导致命令注入 (CWE-78)，Bandit B605/B602 会拦截。

❌ 错误：
```python
os.system(f'rm -rf "{path}"')
subprocess.run(f'git clone {repo_url}', shell=True)
```

✅ 正确：使用列表参数 + shell=False（默认），或改用标准库跨平台 API
```python
import shutil, stat, os, subprocess

# 删除目录/文件：优先用标准库
shutil.rmtree(path, onerror=lambda f, p, _: (os.chmod(p, stat.S_IWRITE), f(p)))

# 必须调用外部命令：列表参数、绝对路径、shell=False
GIT_BIN = shutil.which("git")
subprocess.run([GIT_BIN, "clone", repo_url, target_dir], check=True)  # nosec B603
```

检测：`grep -rnE '\bos\.system\(|shell\s*=\s*True' --include='*.py' --exclude-dir=venv --exclude-dir=.venv --exclude-dir=node_modules .`（结果应仅命中已加 `# nosec` 的行或为空）

来源：LL-007
