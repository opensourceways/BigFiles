# 快速开始

## 准备工作

请确保您在本地环境中已安装GIT LFS。详阅[安装指导](BasicGuide.md#安装)。

## 第三方LFS服务使用配置

- 创建.lfsconfig文件  

在仓库根目录下创建.lfsconfig文件以指定第三方LFS服务，文件内容如下：

```
[lfs]
    url = https://artifacts.openeuler.openatom.cn/{owner}/{repo}
```

- 或者通过命令行设置仓库中LFS远程地址：

```
$ git config --local lfs.url https://artifacts.openeuler.openatom.cn/{owner}/{repo}
```

> 当存在.lfsconfig文件时，使用命令行进行LFS远程地址设置的优先级将高于.lfsconfig文件。  
> url中{owner}/{repo}替换为实际的仓库路径，如：openeuler/lfs。由于Gitee默认会将仓库路径中的大写转化为小写，请确认仓库路径的大小写。  
> Artlfs服务在迁移到AtomGit平台后，需要使用账号-token的方式进行身份验证。

## 第三方LFS服务与Gitee的使用差异

关于GIT LFS的基本使用请详阅[基础教程](BasicGuide.md)。我们努力使第三方LFS服务与原生LFS服务的使用差异尽可能少，以下是现存的一些差异：

- 当您fork一个仓库：将fork仓库克隆到本地后，需手动使用如下命令修改本地仓库的lfs配置：

  ```
  $ git config --local lfs.url https://artifacts.openeuler.openatom.cn/{owner}/{repo}
  ```

- 当您使用ssh协议进行克隆或推送：克隆或推送大文件时仍需输入用户名和密码进行认证。

## 迁移Gitee中使用LFS服务的仓库中的大文件

1. 克隆仓库

    ```
    $ git clone <url>
    ```

2. 在克隆仓库之后，想要获取远端仓库的最新LFS对象

    ```
    $ git lfs fetch --all origin
    ```
    
    git lfs fetch命令会从远程仓库中获取所有缺失的Git LFS对象，但不会将这些对象应用到你的工作目录中。如果想将这些对象应用到工作目录中，需要使用git lfs checkout命令。  

3. 通过.lfsconfig文件来[配置lfs服务](QuickStart.md#第三方lfs服务使用配置)大文件的远程地址

    ```
    $ git add .
    $ git commit -m "modify .lfsconfig"
    ```

4. 推送大文件：

    ```
    $ git lfs push --all origin
    $ git push
    ```

5. 原仓库中的lfs文件成功存储于第三方lfs服务中

## 关闭第三方LFS功能

对于已经使用第三方LFS服务的仓库，如果想要关闭第三方LFS功能，需要删除.lfsconfig文件，并将改动提交到远程仓库中。

```
$ rm .lfsconfig
$ git add .
$ git commit -m "close lfs server"
$ git push
```

如果该仓库在之前通过命令行设置仓库中LFS远程地址，那么除了删除.lfsconfig文件之外，还需要通过命令行删除对LFS远程地址的设置。

```
$ git config lfs.url ""
```
