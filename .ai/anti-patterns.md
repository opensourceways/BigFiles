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
