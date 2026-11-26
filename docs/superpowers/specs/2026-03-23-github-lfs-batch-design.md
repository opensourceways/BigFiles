# GitHub LFS Batch 接口设计文档

**日期**：2026-03-23
**分支**：feature/add-github-lfs
**状态**：已确认，待实现

---

## 需求概述

当前 BigFiles 服务支持 Gitee 和 GitCode 平台的 Git LFS 文件上传/下载。本次新增一个独立的 Batch 接口，支持 **GitHub 平台**用户使用 LFS 服务，包含 GitHub OIDC token 鉴权。

---

## 路由设计

```
POST /github/{owner}/{repo}/objects/batch
```

与现有 `POST /{owner}/{repo}/objects/batch` 完全独立，通过路由前缀 `/github` 区分平台。

---

## 整体架构与数据流

```
GitHub 客户端请求
    ↓
HTTP Router (server/) — 匹配 /github/{owner}/{repo}/objects/batch
    ↓
handleGithubBatch() — 解析请求体、校验 owner/repo 格式
    ↓
dealWithGithubAuthError() — 从 Basic Auth 提取 username/token
    ↓
auth.GithubAuth() (isGithubAuthorized)
    ├─ CheckGithubRepoOwner()  — GET /repos/{owner}/{repo}
    │   └─ 验证 org 白名单 + fork parent 检查
    └─ VerifyGithubUser()      — 按 operation 验证权限
        ├─ upload:   GET /repos/{owner}/{repo}/collaborators/{username}/permission → admin/write
        ├─ download: GET /repos/{owner}/{repo} → HTTP 200 即通过
        └─ delete:   GET /repos/{owner}/{repo}/collaborators/{username}/permission → admin only
    ↓
handleRequestObject() — 复用现有逻辑，生成 OBS 预签名 URL
    ↓
addMetaData() — 复用现有逻辑，platform 写入 "github"
    ↓
JSON 响应返回
```

---

## 涉及文件清单

| 文件 | 变动类型 | 说明 |
|------|---------|------|
| `auth/github_auth.go` | **新建** | GitHub 鉴权全部逻辑 |
| `auth/github_auth_test.go` | **新建** | 单元测试 |
| `auth/gitee.go` | **修改** | `Init()` 新增 `defaultGithubToken` 加载 |
| `server/server.go` | **修改** | 新增路由 + `handleGithubBatch()` + `Options/server` 字段 |
| `server/server_test.go` | **修改** | 新增 handler 测试 |
| `config/config.go` | **修改** | 新增 `DefaultGithubToken` 字段 |
| `main.go` | **修改** | `server.Options` 新增 `IsGithubAuthorized: auth.GithubAuth()` |

---

## 详细设计

### 1. `config/config.go`

```go
type Config struct {
    // 现有字段不变...
    DefaultGithubToken string `json:"DEFAULT_GITHUB_TOKEN"` // 新增
}
```

### 2. `auth/gitee.go` — `Init()` 新增

```go
var defaultGithubToken string // 包级变量，与 defaultToken/defaultGiteCodeToken 对齐

// Init() 中追加：
defaultGithubToken = cfg.DefaultGithubToken
if defaultGithubToken == "" {
    defaultGithubToken = os.Getenv("DEFAULT_GITHUB_TOKEN")
    if defaultGithubToken == "" {
        return errors.New("default github token required")
    }
}
```

### 3. `auth/github_auth.go` — 新建

#### 数据结构

```go
type githubRepo struct {
    FullName string       `json:"full_name"`
    Fork     bool         `json:"fork"`
    Parent   githubParent `json:"parent"`
}

type githubParent struct {
    FullName string `json:"full_name"`
}

type githubCollaboratorPermission struct {
    Permission string `json:"permission"` // admin, write, read, none
}
```

#### `GithubAuth()` — token 解析与 gitcode 完全一致

```go
func GithubAuth() func(UserInRepo) error {
    return func(userInRepo UserInRepo) error {
        // 与 gitcode 完全相同：直接用 password 字段作为 token
        userInRepo.Token = userInRepo.Password

        if _, err := CheckGithubRepoOwner(userInRepo); err != nil {
            return err
        }
        return VerifyGithubUser(userInRepo)
    }
}
```

#### `CheckGithubRepoOwner()` — org 白名单 + fork parent

```go
// 复用 auth 包内已有的 allowedRepos 变量
// API: GET https://api.github.com/repos/{owner}/{repo}
// Header: Authorization: Bearer {token}

func CheckGithubRepoOwner(userInRepo UserInRepo) (githubRepo, error) {
    token := userInRepo.Token
    if token == "" {
        token = defaultGithubToken
    }

    path := fmt.Sprintf("https://api.github.com/repos/%s/%s",
        userInRepo.Owner, userInRepo.Repo)
    headers := http.Header{
        "Authorization": []string{"Bearer " + token},
        "Accept":        []string{"application/vnd.github+json"},
        "X-GitHub-Api-Version": []string{"2022-11-28"},
    }

    repo := new(githubRepo)
    if err := getParsedResponse("GET", path, headers, nil, repo); err != nil {
        return *repo, errors.New(err.Error() + ": check github repo failed")
    }

    owner := strings.Split(repo.FullName, "/")[0]
    for _, allowed := range allowedRepos {
        if owner == allowed {
            return *repo, nil
        }
    }

    if repo.Fork && repo.Parent.FullName != "" {
        parentOwner := strings.Split(repo.Parent.FullName, "/")[0]
        for _, allowed := range allowedRepos {
            if parentOwner == allowed {
                return *repo, nil
            }
        }
    }

    msg := "forbidden: repo has no permission to use this lfs server"
    logrus.Error(fmt.Sprintf("CheckGithubRepoOwner | %s", msg))
    return *repo, errors.New(msg)
}
```

#### `VerifyGithubUser()` — upload / download / delete

```go
// upload/delete: GET https://api.github.com/repos/{owner}/{repo}/collaborators/{username}/permission
// download:      GET https://api.github.com/repos/{owner}/{repo} → 200 即通过

func VerifyGithubUser(userInRepo UserInRepo) error {
    token := userInRepo.Token
    if token == "" {
        token = defaultGithubToken
    }
    headers := http.Header{
        "Authorization":       []string{"Bearer " + token},
        "Accept":              []string{"application/vnd.github+json"},
        "X-GitHub-Api-Version": []string{"2022-11-28"},
    }

    switch userInRepo.Operation {
    case "upload":
        return verifyGithubUpload(userInRepo, headers)
    case "download":
        return verifyGithubDownload(userInRepo, headers)
    case "delete":
        return verifyGithubDelete(userInRepo, headers)
    default:
        return errors.New("system_error: unknown operation")
    }
}
```

权限判定：
- **upload**：`permission == "admin" || "write"` → 通过
- **download**：`GET /repos/{owner}/{repo}` HTTP 200 → 通过
- **delete**：`permission == "admin"` → 通过（与 gitee 一致）
- 错误消息风格与 gitee/gitcode 保持一致

### 4. `server/server.go` — 修改

```go
// Options 新增
IsGithubAuthorized func(auth.UserInRepo) error

// server struct 新增
isGithubAuthorized func(auth.UserInRepo) error

// New() 中
s.isGithubAuthorized = o.IsGithubAuthorized
r.Post("/github/{owner}/{repo}/objects/batch", s.handleGithubBatch)

// handleGithubBatch：结构与 handleBatch 完全相同
// 差异点：
//   1. 调用 s.dealWithGithubAuthError（内部调用 s.isGithubAuthorized）
//   2. addMetaData 中 platform 固定为 "github"（无需 gitCodeSwitch 判断）
```

### 5. `main.go` — 修改

```go
s, err := server.New(server.Options{
    // 现有字段不变...
    IsAuthorized:       auth.GiteeAuth(),
    IsGithubAuthorized: auth.GithubAuth(), // 新增
})
```

---

## GitHub API 说明

| 用途 | 接口 | 认证方式 |
|------|------|---------|
| 获取仓库信息（org/fork检查） | `GET https://api.github.com/repos/{owner}/{repo}` | `Authorization: Bearer {token}` |
| 查询协作者权限 | `GET https://api.github.com/repos/{owner}/{repo}/collaborators/{username}/permission` | `Authorization: Bearer {token}` |

**关键结论**：
- GitHub **不支持** Password Grant Flow（OAuth 2.1 已废弃），token 由用户通过 Basic Auth password 字段直接传入
- `permission` 响应字段值：`admin` / `write` / `read` / `none`
- 公开仓库无需 token 即可访问 `/repos/{owner}/{repo}`

---

## 测试要求

- `auth/github_auth_test.go`：使用 `httptest` mock GitHub API，覆盖以下场景：
  - `CheckGithubRepoOwner`：允许的 org、fork 仓库、被拒绝的 org
  - `VerifyGithubUser`：upload admin/write/read，download 200/404，delete admin/write
  - `GithubAuth`：token 从 password 字段正确设置
- `server/server_test.go`：`handleGithubBatch` handler 集成测试

---

## 参考

- [GitHub REST API — Collaborators](https://docs.github.com/en/rest/collaborators/collaborators)
- [GitHub REST API — Repositories](https://docs.github.com/en/rest/repos/repos)
- 现有实现参考：`auth/gitee.go`、`server/server.go:handleBatch`
