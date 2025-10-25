# 第三方LFS服务操作指南

***

## 介绍

第三方LFS服务是基于Git LFS插件，实现将Gitee仓库内的大文件上传至第三方LFS服务中的功能。目前该插件仅支持openeuler、src-openeuler组织下的仓库。

***

## 在已有仓库启用LFS

### 下载

安装依赖：Git >= 1.85

- linux Debian 和 RPM packages:[安装地址](https://packagecloud.io/github/git-lfs/install)
- Mac系统

```
brew install git-lfs
```

- Windows：目前已经集成在了[Git for Windows](https://gitforwindows.org/)中，直接下载和使用最新版本的Windows Git即可。
- 直接下载二进制包：<https://github.com/git-lfs/git-lfs/releases>
- 依据源码构建：<https://github.com/git-lfs/git-lfs>

### 安装

- 如果你选择使用二进制包下载后安装，直接执行解压后的./install.sh脚本即可，这个脚本会做两个事情：
  - 在$PATH中安装Git LFS的二进制可执行文件
  - 执行git lfs install命令，让当前环境支持全局的LFS配置
    - Tips:  
      这个命令会自动改变Git配置文件 .gitconfig，而且是全局性质的，会自动在配置文件中增加如下配置：  
      [filter "lfs"]
      clean = git-lfs clean -- %f  
      smudge = git-lfs smudge -- %f  
      process = git-lfs filter-process  
      required = true

```
让仓库支持LFS  
$ git lfs install  
Updated pre-push hook.  
Git LFS initialized.
```

### 配置

- 创建.lfsconfig文件  

通过.lfsconfig文件来配置lfs服务大文件的远程地址，使得将仓库中的大文件上传至第三方LFS服务中。

```
[lfs]
    url = https://artifacts.openeuler.openatom.cn/{owner}/{repo}
```

- 或者通过命令行设置仓库中LFS远程地址：

```
git config --local lfs.url https://artifacts.openeuler.openatom.cn/{owner}/{repo}
```

> - 当存在.lfsconfig文件时，使用命令行进行LFS远程地址设置的优先级将高于.lfsconfig文件。  
> - 在fork一个已经使用第三方LFS服务服务作为LFS远程服务的仓库后，需要需手动使用上述命令设置仓库中LFS远程地址，否则可能会出现权限校验问题，**错误代码401**。  
> - url中{owner}/{repo}替换为实际的仓库路径，注意仓库路径的大小写。
> - Artlfs服务在迁移到AtomGit平台后，需要使用账号-token的方式进行身份验证。

- 选择要用LFS追踪的文件

```
$ git lfs track "*.svg"  
# 或者具体到某个文件  
$ git lfs track "2.png"  
$ git lfs track "example.lfs"  
Tips:  
这个命令会更改仓库中的 .gitattributes配置文件(如果之前不存在这个文件，则会自动新建):  
查看如下：  
$ cat .gitattributes  
*.svg filter=lfs diff=lfs merge=lfs -text  
*.png filter=lfs diff=lfs merge=lfs -text
```

执行git lfs track(不带任何参数)，可以查看当前已跟踪的Git LFS File类型

```
$ git lfs track  
Listing tracked patterns  
　　　*.svg (.gitattributes)  
　　　*.png (.gitattributes)   
Listing excluded patterns  
```

- 查询自己追踪的文件

```
$ git lfs ls-files  
7b3c7dae41 * 1.png  
sw1cf5835a * 2.png  
398213f90f * 3.svg  
```

- 取消对某个文件的追踪

```
$ git lfs untrack "1.png"hclw
```

- 保存并提交配置

```
$ git add .gitattributes  
$ git commit -m "add .gitattributes"
```

- 新建一个.bigfile文件进行测试

在工作空间创造一个名为bigfiles.bigfile的文件，大小为1GB：

```
$ git lfs track "*.bigfile"  
Tracking "*.bigfile"  
# mac环境可以使用mkfile命令替换dd命令  
dd if=/dev/zero of=bigfiles.bigfile bs=1G count=1  
1+0 records in   
1+0 records out  
1073741824 bytes (1.1 GB) copied, 2.41392 s, 445 MB/s  
$du -sh bigfiles.bigfile  
1.1G    bigfiles.bigfile
```

将bigfiles.bigfile添加到暂存区：

```
$ git add bigfiles.bigfile
```

由于 bigfiles.bigfile 后缀命中了.gitattributes中设置的"*.bigfile"的文件格式，所以将做为 LFS 文件处理。  

推送文件到远端

```
$ git commit -m "Add a big file"  
[master 917c0d9] Add a big file  
1 file changed, 3 insertions(+)  
create mode 100644 bigfiles.bigfile
```

其中，“1 file changed, 3 insertions(+)”表示Pointer文件已经提交，可以执行git show HEAD查看提交详情：

```
$ git show HEAD  
commit 917c0d992443568052e8f928d24e622922350011 (HEAD -> master)  
Author: Zhou* <****@***.com>  
Date:   Wed Oct 9 09:52:17 2024 +0800
 
 　　　Add a big file
 
diff --git a/bigfiles.bigfile b/bigfiles.bigfile    
new file mode 100644    
index 0000000..6aafd1c    
--- /dev/null    
+++ b/bigfiles.bigfile    
@@ -0,0 +1,3 @@  
+version https://git-lfs.github.com/spec/v1  
+oid sha256:d29751f2649b32ff572b5e0a9f541ea660a50f94ff0beedfb0b692b924cc8025  
+size 1073741824  
```

将大文件提交到远端第三方LFS服务服务

```
$ git push
```

如果存在LFS文件需要上传，在推送过程中将会显示LFS上传进度。

***

## 克隆已经启用LFS的仓库

- 进行仓库克隆

```
git clone {仓库地址}
```

当仓库中存在LFS管理的文件时，Git 会自动检测 LFS 跟踪的文件并通过 HTTP 克隆它们。

- 如果已经clone了仓库，想要获取远端仓库的最新LFS对象

```
git lfs fetch origin main
```

git lfs fetch命令会从远程仓库中获取所有缺失的Git LFS对象，但不会将这些对象应用到你的工作目录中。如果想将这些对象应用到工作目录中，需要使用git lfs checkout命令。  
此时需要确保文件没有在 .gitignore 中列出，否则它们会被 Git 忽略并且不会被推送到远端仓库。

***

## 将历史文件转换为LFS管理

如果一个仓库中原来已经提交了一些大文件，此时即使运行 git lfs track也不会有效的。
为了将仓库中现存的大文件应用到LFS，需要用 git lfs migrate导入到LFS中：

```
$ git lfs migrate import --include-ref=master --include="picture.pug"
```

其中：

```
--include-ref 选项指定导入的分支  
如果向应用到所有分支，则使用--everything选项  
--include 选项指定要导入的文件。可以使用通配符，批量导入。
```

上述操作会改写提交历史，如果不想改写历史，则使用 --no-rewrite选项，并提供新的commit信息：

```
$ git lfs migrate import --no-rewrite -m "lfs import"
```

将本地历史提交中的文件纳入到LFS管理后，如果重改了历史，再次推送代码时，需要使用强制推送:

```
$ git push origin master --force
```

***

## 撤销LFS跟踪并使用Git管理

取消继续跟踪某类文件，并将其从cache中清理：

```
git lfs untrack "*.zip"  
git rm --cached "*.zip"
```

***

## Git LFS常用命令的使用

- 显示当前跟踪的文件列表

```
git lfs ls-files
```

- 配置追踪命令

```
git lfs track "*.png"
```

track命令实际上是修改了仓库中的.gitattributes文件，使用git add命令将该文件添加到暂存区。

```
git add .gitattributes
```

注意：.gitattributes与.git同级目录，否则会出现git push失败的情况。  

使用git commit提交至仓库，使配置追踪生效。

```
git commit -m "添加lfs配置"
```

使用git push推动至远程仓库，LFS跟踪的文件会以“Git LFS”的形式显示。

- 撤销追踪命令  

例如，撤销追踪zip文件

```
git lfs untrack "*.zip"
```

使用git rm -cached清理缓存

```
git rm --cached "*.zip"
```

- 提交推送

在设置完成Git LFS后，使用git命令进行提交和推送时，Git LFS将自动处理大文件的上传和下载。

```
git add .  
git commit -m "Add large files"  
git push origin master  
```

- 拉取  

在拉取更改或切换分支时，Git LFS会自动下载所需的大文件。

```
git pull origin master
git checkout test-branch
```

- git lfs fetch

git lfs fetch命令会从远程仓库中获取所有缺失的Git LFS对象，但不会将这些对象应用到你的工作目录中。如果你想将这些对象应用到你的工作目录中，你需要使用git lfs checkout命令。

- git lfs pull

git lfs pull命令会从远程仓库中获取所有缺失的Git LFS对象，并将这些对象应用到你的工作目录中。如果你的工作目录中已经存在了这些对象，那么git lfs pull命令会跳过这些对象。

- git lfs pull提速

使用 Git LFS 的批量下载功能，可以通过命令 git lfs fetch --all 来实现。

```
git lfs fetch --all
```

使用 Git LFS 的并发下载功能，可以通过命令 git config --global lfs.concurrenttransfers 10 来设置并发下载数。

```
git config --global lfs.concurrenttransfers 10 
```

- LFS文件过滤
  
此命令将自动过滤LFS文件，不会在git clone时下载lfs文件。

```
git config --global filter.lfs.smudge "git-lfs smudge --skip -- %f"  
git config --global filter.lfs.process "git-lfs filter-process --skip"
```

- LFS文件下载

该命令将自动下载LFS文件，在git clone时下载lfs文件。

```
git config --global filter.lfs.smudge "git-lfs smudge -- %f"  
git config --global filter.lfs.process "git-lfs filter-process"
```
