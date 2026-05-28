# BigFiles 项目架构文档

## 系统概述

BigFiles 是一个基于 Go 1.24.0 + chi 路由框架 的 Web 服务，主要提供 Git LFS (Large File Storage) 服务端实现，支持大文件通过华为云 OBS 对象存储进行上传、下载和管理，并集成用户认证功能。

### 核心价值
- **大文件存储**：为 Git 仓库提供透明的大文件存储能力，将二进制文件分离存储至 OBS
- **认证集成**：支持多种用户认证方式，保障文件访问安全
- **高可用性**：基于云端对象存储，支持高并发访问和可靠存储
- **LFS 协议兼容**：完全兼容 Git LFS 批量 API 协议

## 技术栈

### 后端框架
- **Go 1.24.0**：开发语言，高性能并发处理
- **go-chi/chi v4**：Web 层轻量级 HTTP 路由框架
- **GORM v1.31.1**：ORM 框架，数据库操作
- **logrus v1.9.3**：结构化日志记录

### 数据存储
- **MySQL**：主用户数据和元数据存储
- **华为云 OBS**：大文件对象存储

### 安全与认证
- **auth 模块**：自定义认证逻辑
- **config 模块**：配置文件加载与管理

### 工具库
- **bou.ke/monkey v1.0.2**：测试用 monkey patching
- **stretchr/testify v1.11.1**：测试断言框架
- **sigs.k8s.io/yaml v1.6.0**：YAML 配置解析

### 外部服务集成
- **华为云 OBS（对象存储服务）**：大文件存储后端
- **MySQL（关系型数据库）**：元数据持久化
- **Git LFS 协议（Large File Storage）**：Git 大文件存储标准协议

## 核心模块划分

### 1. 主入口 (main.go)
- **main** (`main.go`)：程序入口，解析命令行参数，初始化各模块并启动 HTTP 服务

### 2. 服务层 (server/)
- **HTTP 路由处理**：处理 Git LFS Batch API 请求
  - 上传操作（upload）处理
  - 下载操作（download）处理
  - 锁定操作（locks）处理

### 3. 认证层 (auth/)
- **用户认证**：验证访问凭证
  - 基本认证（Basic Auth）
  - Token 认证

### 4. 数据访问层 (db/)
- **数据库操作**：封装 MySQL 数据访问
  - 用户信息查询
  - 元数据存储

### 5. 配置模块 (config/)
- **配置加载**：YAML 配置文件解析
  - 服务器配置（端口、主机）
  - 数据库连接配置
  - OBS 配置（endpoint、bucket、credentials）

### 6. 批处理模块 (batch/)
- **批量操作**：处理 Git LFS 批量 API
  - 批量上传预签名 URL 生成
  - 批量下载预签名 URL 生成

### 7. 工具模块 (utils/)
- **辅助函数**：通用工具方法

## 目录结构

```
github.com/metalogical/BigFiles/
├── auth/           # 认证模块（用户身份验证）
├── batch/          # 批处理模块（批量文件操作 API）
├── config/         # 配置模块（配置加载与解析）
├── db/             # 数据库模块（MySQL 数据访问）
├── docs/           # 文档目录
├── scripts/        # 脚本目录
├── server/         # HTTP 服务器模块（路由与处理器）
├── utils/          # 工具模块（辅助函数）
├── main.go         # 程序入口
├── go.mod          # Go 模块依赖
├── go.sum          # 依赖校验
├── config.example.yml  # 配置示例
├── .golangci.yml   # golangci-lint 配置
├── DockerFile      # Docker 构建文件
└── typos.toml      # 拼写检查配置
```

## 分层架构规则

```
main.go
    ↓
server/ (HTTP 路由层)
    ↓
batch/ (业务处理层)
    ↓
auth/ + db/ (认证与数据访问层)
    ↓
华为云 OBS + MySQL (外部服务层)
```

### 严格约束
1. **server 层**：只做路由、参数解析和 HTTP 响应处理，不包含业务逻辑
2. **batch 层**：实现所有业务逻辑，协调 auth、db 与 OBS 操作
3. **db 层**：只封装数据库 API 调用，不含业务逻辑
4. **auth 层**：只负责身份验证，不含业务逻辑
5. **跨层调用禁止**：server 层不可直接访问 db 层或 OBS

## 数据流

```
Git 客户端请求
    ↓
HTTP Router (server/)
    ↓
Auth 验证 (auth/)
    ↓
Batch 处理 (batch/)
    ↓
DB 查询 (db/) + OBS 预签名 URL 生成
    ↓
JSON 响应返回
    ↓
Git 客户端
```

## 安全设计

- **认证**：HTTP Basic Auth + Token 认证
- **授权**：基于用户身份的访问控制
- **加密**：HTTPS 传输，OBS 访问密钥管理
- **配置安全**：敏感配置通过配置文件管理（config.yml 已加入 .gitignore）
- **审计**：使用 logrus 记录关键操作日志

## 外部服务集成

### 华为云 OBS（对象存储服务）
- **用途**：存储 Git LFS 大文件对象
- **集成方式**：使用 huaweicloud-sdk-go-obs SDK
- **认证方式**：AccessKey + SecretKey

### MySQL（关系型数据库）
- **用途**：存储用户信息和文件元数据
- **集成方式**：使用 GORM ORM 框架
- **连接方式**：DSN 配置字符串

## 部署结构

```
[Docker 容器]
    ├── BigFiles 服务 (Go binary)
    │   ├── 监听端口（默认 8080）
    │   └── 读取 config.yml
    ├── 外部依赖：
    │   ├── MySQL 数据库（外部/容器）
    │   └── 华为云 OBS（云端服务）
    └── Docker 镜像：DockerFile / DockerFileSSH
```

## 关键设计模式

- **配置驱动**：通过 YAML 配置文件管理所有运行时参数
- **依赖注入**：通过构造函数传递依赖（config、db、obs client）
- **预签名 URL**：利用 OBS 预签名 URL 实现客户端直传，避免代理大文件流量
- **LFS 批量 API**：遵循 Git LFS 批量 API 规范，支持 upload/download 操作
- **分离关注点**：认证、业务处理、数据访问各层职责清晰

---

**版本**：1.0.0
**最后更新**：2026-03-23
**维护团队**：项目开发组
