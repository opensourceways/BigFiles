# 提示词归档：GitHub LFS Batch 接口开发

**日期**：2026-03-23
**类型**：feat
**任务**：新增 `POST /github/{owner}/{repo}/objects/batch` 接口，支持 GitHub 平台用户使用 Git LFS 服务

## 需求描述

在现有支持 Gitee/GitCode 平台的 LFS 服务基础上，新增独立的 GitHub batch 接口：
- 路由：`POST /github/{owner}/{repo}/objects/batch`
- 鉴权：GitHub OIDC token（通过 Basic Auth password 字段传入，与 gitcode 模式完全一致）
- org 白名单校验：复用 `allowedRepos`，支持 fork parent 检查
- 权限验证：upload=admin/write，download=repo 可访问，delete=admin only
- 元数据写入：platform 字段固定为 "github"

## 相关文件

- 设计文档：`docs/superpowers/specs/2026-03-23-github-lfs-batch-design.md`
- 实现计划：`docs/superpowers/plans/2026-03-23-github-lfs-batch.md`

## GitHub API

- `GET https://api.github.com/repos/{owner}/{repo}` — org/fork 检查
- `GET https://api.github.com/repos/{owner}/{repo}/collaborators/{username}/permission` — 权限验证
- 认证：`Authorization: Bearer {token}` + `X-GitHub-Api-Version: 2022-11-28`
