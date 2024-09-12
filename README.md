**BigFiles** is a (partial) Go implementation of a [Git-LFS
v2.12.0](https://github.com/git-lfs/git-lfs/tree/v2.12.0/docs/api) server.

- It can be configured to use any S3-API-compatible backend for LFS storage.
- It does not currently implent the locking API.
- See [the default entrypoint](BigFiles/main.go).


**TODO**:

1. 外部参数校验：username、password进行格式校验。
2. 添加配置文件，将AKSK等写入配置文件中。可参考merlin-server配置文件的格式与读取方式。
3. 添加测试用例。
4. 认证方式支持token。
5. 认证时校验用户在仓库内权限。
6. 支持ssh。
7. 仓库添加github 
