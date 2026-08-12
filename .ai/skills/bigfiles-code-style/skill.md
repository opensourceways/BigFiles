---
id: bigfiles-code-style
name: BigFiles 代码风格与安全约束
description: BigFiles 项目的代码风格和安全约束规范，基于 Go 语言特性定义编码标准、安全最佳实践和开发约束
version: 1.0.0
license: MIT
author: AI Assistant
namespace: bigfiles.governance
keywords:
  - code-style
  - security
  - constraints
  - governance
  - quality
  - golang
categories:
  - governance
  - quality-assurance
modes:
  - code
  - orchestrator
tags:
  - code-style
  - security
  - naming-convention
  - golang
priority: 15
enabled: true
allowed-tools:
  - read
  - write
  - edit
dependencies:
  skills:
    - workflow-enforcer
---

# BigFiles 代码风格与安全约束

## 📋 技能描述

本技能定义 BigFiles 项目的代码风格规范和安全约束，确保 AI Agent 生成的 Go 代码符合项目标准。

---

## 1. 命名约定（Go 规范）

### 包名（全小写，简短）
```go
✅ package server / package batch / package auth / package config
❌ package Server / package LFSBatch
```

### 函数名与类型名（驼峰式）
```go
// 导出（公开）：PascalCase
✅ type OBSClient struct{} / func NewOBSClient() / func HandleBatch()
❌ type obsClient struct{} / func newobsclient() / func handlebatch()

// 未导出（内部）：camelCase
✅ func parseConfig() / type batchRequest struct{}
❌ func ParseConfig() / type BatchRequest struct{} （仅内部使用时）
```

### 常量（驼峰式，非 ALL_CAPS）
```go
✅ const defaultTimeout = 30 * time.Second
✅ const maxRetryCount = 3
❌ const DEFAULT_TIMEOUT = 30 * time.Second（Go 不使用此风格）
```

### 错误变量（err 前缀，PascalCase）
```go
✅ var ErrInvalidCredentials = errors.New("invalid credentials")
✅ var ErrOBSUploadFailed = errors.New("OBS upload failed")
```

---

## 2. 代码格式要求

### 格式化工具
```bash
# 自动格式化（必须在提交前运行）
gofmt -w ./...

# 代码风格检查
golangci-lint run

# 完整验证
go vet ./... && golangci-lint run && go test ./...
```

### 函数复杂度
- 单个函数不超过 50 行（建议值）
- 函数圈复杂度不超过 10
- 嵌套层级不超过 4 层

### 错误处理（强制）
```go
// ✅ 正确：明确处理错误
result, err := obsClient.Upload(key, data)
if err != nil {
    return fmt.Errorf("upload to OBS failed for key %s: %w", key, err)
}

// ❌ 错误：忽略错误
result, _ := obsClient.Upload(key, data)
```

---

## 3. 安全约束

### 3.1 敏感信息处理

**禁止**在代码中硬编码以下信息：
- OBS AccessKey / SecretKey
- 数据库密码
- JWT 密钥

**正确做法**：通过 config.yml 配置文件注入
```go
// ✅ 正确
type Config struct {
    OBS struct {
        AccessKey string `yaml:"accessKey"`
        SecretKey string `yaml:"secretKey"`
    } `yaml:"obs"`
}

// ❌ 错误
const obsAccessKey = "AKIAIOSFODNN7EXAMPLE"
```

### 3.2 输入验证

所有外部输入必须在 server 层验证：
```go
// ✅ 验证 LFS 请求参数
if req.Operation != "upload" && req.Operation != "download" {
    http.Error(w, "invalid operation", http.StatusBadRequest)
    return
}

// ❌ 直接将请求参数传递给 OBS 或数据库
```

### 3.3 错误响应

使用标准 JSON 错误响应格式：
```go
// ✅ Git LFS 协议错误格式
type ErrorResponse struct {
    Message       string `json:"message"`
    Documentation string `json:"documentation_url,omitempty"`
}

// ❌ 直接暴露内部错误信息
http.Error(w, err.Error(), http.StatusInternalServerError)
```

### 3.4 日志记录

```go
// ✅ 使用 logrus，脱敏处理
logrus.WithFields(logrus.Fields{
    "user":      username,
    "operation": "upload",
    "oid":       oid,
}).Info("LFS batch operation")

// ❌ 记录敏感信息
logrus.Infof("User %s with password %s uploaded file", username, password)
```

---

## 4. 架构规则

### 4.1 分层架构（严格执行）

```
main.go → server/ → batch/ → auth/ + db/ → 华为云 OBS + MySQL
```

**约束**：
- `server/` 不可直接调用 `db/` 或 OBS SDK
- `batch/` 协调 `auth/`、`db/` 与 OBS 操作
- `config/` 只负责配置加载，不含业务逻辑
- 禁止循环依赖

### 4.2 依赖注入（构造函数模式）

```go
// ✅ 正确：通过构造函数传入依赖
type BatchHandler struct {
    obsClient *obs.ObsClient
    db        *gorm.DB
    auth      auth.Authenticator
}

func NewBatchHandler(obsClient *obs.ObsClient, db *gorm.DB, auth auth.Authenticator) *BatchHandler {
    return &BatchHandler{
        obsClient: obsClient,
        db:        db,
        auth:      auth,
    }
}

// ❌ 错误：全局变量注入
var globalOBSClient *obs.ObsClient
```

### 4.3 接口设计

对于 auth 等可替换模块，定义接口：
```go
// ✅ 定义接口，便于测试 Mock
type Authenticator interface {
    Authenticate(username, password string) (bool, error)
}
```

---

## 5. TDD 约束

- **禁止**：在没有对应测试的情况下提交业务逻辑代码
- **要求**：核心业务逻辑测试覆盖率 ≥ 90%
- **要求**：整体测试覆盖率 ≥ 80%
- **格式**：测试使用 Given-When-Then 模式
- **命名**：`Test{功能}_{条件}_{预期结果}` 格式

```go
// ✅ 测试命名示例
func TestHandleBatch_WhenValidUploadRequest_ShouldReturnPresignedURL(t *testing.T) {
    // Given
    ...
    // When
    ...
    // Then
    ...
}
```

---

## 6. Go 特有约束

### 6.1 Context 使用
```go
// ✅ 正确：传播 context
func (h *BatchHandler) Upload(ctx context.Context, req *BatchRequest) error {
    ...
}

// ❌ 错误：忽略 context
func (h *BatchHandler) Upload(req *BatchRequest) error {
    ...
}
```

### 6.2 defer 与资源释放
```go
// ✅ 正确：使用 defer 确保资源释放
resp, err := http.Get(url)
if err != nil {
    return err
}
defer resp.Body.Close()

// ❌ 错误：忘记关闭
resp, _ := http.Get(url)
// 无 defer resp.Body.Close()
```

### 6.3 goroutine 与并发
```go
// ✅ 使用 sync.WaitGroup 或 channel 管理 goroutine
var wg sync.WaitGroup
for _, item := range items {
    wg.Add(1)
    go func(i Item) {
        defer wg.Done()
        process(i)
    }(item)
}
wg.Wait()
```

---

## 7. 常见违规示例与修复

### 违规示例 1：忽略错误
```go
// ❌ 错误
db.Create(&user)  // 忽略错误

// ✅ 正确
if result := db.Create(&user); result.Error != nil {
    return fmt.Errorf("failed to create user: %w", result.Error)
}
```

### 违规示例 2：硬编码配置
```go
// ❌ 错误
obsEndpoint := "https://obs.cn-north-4.myhuaweicloud.com"

// ✅ 正确
obsEndpoint := cfg.OBS.Endpoint
```

---

**版本**：1.0.0
**状态**：生产就绪
**适用项目**：BigFiles (github.com/metalogical/BigFiles)
