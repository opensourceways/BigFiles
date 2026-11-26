# Task Prompt: 修复 Dockerfile 构建失败（Go 版本不匹配）

**日期**: 2026-11-26 | **类型**: fix | **复杂度**: 低

---

## 背景

容器部署时 Docker 构建报错：

```
go: go.mod requires go >= 1.26.0 (running go 1.24.13; GOTOOLCHAIN=local)
```

`go.mod` 声明 `go 1.26.0`，但 Dockerfile 使用 `golang:1.24` 镜像，Go 版本不满足要求。同时 Dockerfile 中的 `go get` 命令已废弃，且引用了未使用的依赖 `github.com/akrylysov/algnhsa`。

## 改动

- [x] `DockerFile`: `golang:1.24` → `golang:1.26`，满足 go.mod 的版本要求
- [x] `DockerFile`: 移除废弃的 `go get github.com/akrylysov/algnhsa`（代码中未使用）
- [x] `DockerFile`: 移除 `go get github.com/sirupsen/logrus`（已在 go.mod 中，go mod download 会处理）
- [x] `DockerFile`: `go build ./main.go` → `go mod download && go build -o main .`
