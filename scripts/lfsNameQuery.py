import os
import sys
import subprocess
import json
import shutil
from urllib.parse import quote_plus

# 平台配置映射
PLATFORM_CONFIGS = {
    "gitee": {
        "domain": "gitee.com",
        "auth_method": "token"  # 或 "username_password"
    },
    "gitcode": {
        "domain": "gitcode.com",
        "auth_method": "token"  # GitCode必须使用Token认证[6](@ref)
    }
}

def clone_repo_skip_lfs(platform, owner, repo, username=None, token=None, target_dir="temp_repo"):
    """克隆仓库并强制跳过LFS文件下载，支持多平台"""
    if platform not in PLATFORM_CONFIGS:
        raise ValueError(f"不支持的平台: {platform}，支持的平台: {list(PLATFORM_CONFIGS.keys())}")

    config = PLATFORM_CONFIGS[platform]
    domain = config["domain"]

    # 构建认证URL
    if username and token:
        encoded_username = quote_plus(username)
        encoded_token = quote_plus(token)
        repo_url = f"https://{encoded_username}:{encoded_token}@{domain}/{owner}/{repo}.git"
    elif token and config["auth_method"] == "token":
        # GitCode推荐方式：使用用户名+Token[6](@ref)
        encoded_token = quote_plus(token)
        # 假设username作为GitCode用户名
        username = username or "gitcode_user"
        repo_url = f"https://{username}:{encoded_token}@{domain}/{owner}/{repo}.git"
    else:
        repo_url = f"https://{domain}/{owner}/{repo}.git"

    force_remove(target_dir)

    try:
        env = os.environ.copy()
        env.update({
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CLONE_PROTECTION_ACTIVE": "false"
        })

        print(f"正在克隆 {platform} 仓库: {repo_url.replace(encoded_token, '***') if token else repo_url}")

        subprocess.run(
            ["git", "clone", repo_url, target_dir],
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return target_dir
    except subprocess.CalledProcessError as e:
        error_msg = f"{platform}克隆失败: "
        if username and token:
            error_msg += "认证失败或"
        error_msg += e.stderr.strip() if e.stderr else '未知错误'

        # 平台特定的错误提示
        if platform == "gitcode":
            error_msg += "\nGitCode提示: 请确认使用Token认证而非密码[6](@ref)"

        force_remove(target_dir)
        raise RuntimeError(error_msg)


def branch_has_lfsconfig(repo_dir, branch):
    """检查分支是否包含.lfsconfig文件"""
    try:
        result = subprocess.run(
            ["git", "ls-tree", "-r", branch, "--name-only"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding='utf-8'
        )
        return ".lfsconfig" in result.stdout.split('\n')
    except Exception:
        return False


def get_all_branches_lfs_mapping(repo_dir):
    """获取所有包含.lfsconfig的分支的LFS文件信息"""
    try:
        branches = subprocess.run(
            ["git", "branch", "-a"],
            cwd=repo_dir,
            capture_output=True,
            text=True,
            encoding='utf-8'
        ).stdout.split('\n')

        lfs_mapping = {}

        for branch in branches:
            branch = branch.strip().replace('*', '').strip()
            if not branch or 'HEAD' in branch:
                continue

            if not branch_has_lfsconfig(repo_dir, branch):
                print(f"跳过分支 {branch} (无.lfsconfig文件)")
                continue

            subprocess.run(
                ["git", "checkout", branch],
                cwd=repo_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )

            result = subprocess.run(
                ["git", "lfs", "ls-files", "--json"],
                cwd=repo_dir,
                capture_output=True,
                text=True,
                encoding='utf-8',
            )

            if result.returncode == 0:
                data = json.loads(result.stdout)
                if isinstance(data, dict) and "files" in data:
                    for f in data["files"]:
                        if isinstance(f, dict) and "oid" in f and "name" in f:
                            oid = f["oid"]
                            if oid not in lfs_mapping:
                                lfs_mapping[oid] = {
                                    "name": f["name"],
                                    "size": f.get("size", 0),
                                    "branches": []
                                }
                            lfs_mapping[oid]["branches"].append(branch)

        return lfs_mapping
    except Exception as e:
        raise RuntimeError(f"获取LFS映射失败: {str(e)}")


def force_remove(path):
    """跨平台强制删除文件/目录"""
    if not os.path.exists(path):
        return
    try:
        shutil.rmtree(path) if os.path.isdir(path) else os.remove(path)
    except:
        os.system(f'rm -rf "{path}"' if os.name != 'nt' else f'rd /s /q "{path}"')


def main(platform, owner, repo, output_file="lfs_mapping.json", username=None, token=None):
    """主函数，支持平台参数"""
    try:
        if platform == "gitcode" and not token:
            print("警告: GitCode强烈建议使用Token认证而非密码[6](@ref)")

        repo_dir = clone_repo_skip_lfs(platform, owner, repo, username, token)
        mapping = get_all_branches_lfs_mapping(repo_dir)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)

        print(f"{platform}平台结果已保存到 {output_file}")
        return True
    except Exception as e:
        print(f"错误: {str(e)}", file=sys.stderr)
        return False
    finally:
        if 'repo_dir' in locals():
            force_remove(repo_dir)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("用法: python lfsNameQuery.py <platform> <owner> <repo> [output_file] [username] [token]")
        print("平台支持: gitee, gitcode")
        sys.exit(1)

    args = {
        "platform": sys.argv[1],  # 新增平台参数
        "owner": sys.argv[2],
        "repo": sys.argv[3],
        "output_file": sys.argv[4] if len(sys.argv) > 4 else "lfs_mapping.json",
        "username": sys.argv[5] if len(sys.argv) > 5 else None,
        "token": sys.argv[6] if len(sys.argv) > 6 else None
    }

    sys.exit(0 if main(**args) else 1)
