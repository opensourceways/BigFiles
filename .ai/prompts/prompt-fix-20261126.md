# Task Prompt: 修复 Dockerfile 构建失败 + Trivy CVE 门禁（Go 版本升级）

**日期**: 2026-11-26 | **类型**: fix | **复杂度**: 低

---

## 背景

### 问题 1：Docker 构建失败
容器部署时 Docker 构建报错：
```
go: go.mod requires go >= 1.26.0 (running go 1.24.13; GOTOOLCHAIN=local)
```

### 问题 2：Trivy CVE 门禁失败
PR 门禁 Trivy 扫描报告 23 个 stdlib CVE（当前版本 1.26.5），需升级到 1.26.11 覆盖所有修复版本。

## 改动

### Docker 构建修复
- [x] `DockerFile`: `golang:1.24` → `golang:1.26.11`，满足 go.mod 版本要求
- [x] `DockerFile`: 移除废弃的 `go get github.com/akrylysov/algnhsa`（代码中未使用）
- [x] `DockerFile`: 移除 `go get github.com/sirupsen/logrus`（已在 go.mod 中，go mod download 会处理）
- [x] `DockerFile`: `go build ./main.go` → `go mod download && go build -o main .`

### Trivy CVE 修复
- [x] `go.mod`: toolchain go1.26.5 → go1.26.11
- [x] `DockerFile`: golang:1.26 → golang:1.26.11
- [x] `.github/workflows/workflow-validation.yml`: 3 处 go-version 1.26.5 → 1.26.11 + 注释
- [x] `CLAUDE.md`: Go 1.26.0 → 1.26.11, toolchain 1.26.5 → 1.26.11
