# Prompt: allowedRepos 配置化

**类型**: feat
**日期**: 2026-04-15

## 需求描述

`allowedRepos` 目前硬编码为 `[]string{"openeuler", "src-openeuler", "lfs-org", "openeuler-test"}`，
每次变更需修改代码并重新部署，希望改为通过配置文件管理。

## 实现方案

1. `config.Config` 新增 `AllowedRepos []string` 字段，YAML key 为 `ALLOWED_REPOS`
2. `auth.Init()` 中：若 `cfg.AllowedRepos` 非空则使用，否则 fallback 到默认列表（向后兼容）
3. `config.example.yml` 补充示例

## 验收标准

- `go build ./...` 通过
- `go test ./auth/... ./config/...` 通过
- 配置文件中配置的值生效，未配置时行为与原来一致
