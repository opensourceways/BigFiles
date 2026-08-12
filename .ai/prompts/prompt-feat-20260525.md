# Prompt: GITHUB_MODEL 配置开关合并 GitHub LFS batch 路径

**类型**: feat
**日期**: 2026-05-25

## 需求描述

此前 `/objects/batch` 走 Gitee/GitCode 的鉴权与元数据路径，GitHub 仓库使用单独的
`/github/{owner}/{repo}/objects/batch` 路由。希望通过一个配置开关在同一个 batch
入口内切换两种鉴权与元数据写入流程，简化客户端配置。

## 实现方案

1. `config.Config` 新增 `GithubModel bool` 字段（YAML key `GITHUB_MODEL`，默认 false）
2. `server/validate.go` 新增包级变量 `githubModel`，在 `Init()` 中从配置读入
3. `server/server.go`：
   - `handleBatch` 根据 `githubModel` 选择 `dealWithGithubAuthError` + `addGithubMetaData`
     或原有的 `CheckRepoOwner` + `dealWithAuthError` + `addMetaData`
   - 移除单独的 `/github/{owner}/{repo}/objects/batch` 路由
4. `config.example.yml` 补充 `GIT_CODE_SWITCH` 与 `GITHUB_MODEL` 示例

## 验收标准

- `go build ./...` 通过
- `go vet ./...` 通过
- `go test ./config/... ./server/...` 通过
- 默认配置（`GITHUB_MODEL: false`）行为与原来一致
