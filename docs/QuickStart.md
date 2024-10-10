# 快速开始

## 准备工作

[下载](BasicGuide.md#下载)  
[安装](BasicGuide.md#安装)  

## 第三方LFS服务使用配置

- 创建.lfsconfig文件  
  
通过.lfsconfig文件来配置lfs服务大文件的远程地址，使得将仓库中的大文件上传至BigFiles中。

```
# .lfsconfig文件的格式为  
[lfs]  
 　　url = https://lfs.test.osinfra.cn/{owner}/{repo}
```

或者通过命令行设置仓库中LFS远程地址：

```
$ git config --local lfs.url https://lfs.test.osinfra.cn/{owner}/{repo}
```

当存在.lfsconfig文件时，使用命令行进行LFS远程地址设置的优先级将高于.lfsconfig文件。

## 第三方LFS服务与Gitee的使用差异

- 在fork一个已经使用第三方LFS服务作为LFS远程服务的仓库后，需要手动修改新仓库中LFS远程地址中的{owner}以及{repo}，否则会出现权限校验问题，**错误代码401**。
- 在使用SSH对Gitee仓库进行克隆后，在使用第三方LFS服务作为LFS远程服务时，仍然需要输入账户和密码。

## 迁移Gitee中使用LFS服务的仓库

- 克隆仓库

```
$ git clone --bare <url>
```

- 在克隆仓库之后，想要获取远端仓库的最新LFS对象

```
$ git lfs fetch --all origin
```

git lfs fetch命令会从远程仓库中获取所有缺失的Git LFS对象，但不会将这些对象应用到你的工作目录中。如果想将这些对象应用到工作目录中，需要使用git lfs checkout命令。  

- 通过.lfsconfig文件来[配置lfs服务](QuickStart.md#第三方lfs服务使用配置)大文件的远程地址

```
$ git add .
$ git commit -m "modify .lfsconfig"
```

- 修改仓库远程地址

```
$ git remote add <新repo> <repo新地址>
```

- 执行：

```
$ git lfs push --all <新repo>
$ git push --all --force <新repo>
$ git push --tags --force <新repo>
```

- 原仓库中的lfs文件成功迁移至新仓库，并存储于第三方lfs服务中

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





