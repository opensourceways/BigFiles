import os
import sys
import subprocess
import json
import shutil
from urllib.parse import quote_plus


def clone_repo_skip_lfs(gitee_owner, gitee_repo, username=None, token=None, target_dir="temp_repo"):
    """克隆仓库并强制跳过LFS文件下载"""
    if username and token:
        encoded_username = quote_plus(username)
        encoded_token = quote_plus(token)
        repo_url = f"https://{encoded_username}:{encoded_token}@gitee.com/{gitee_owner}/{gitee_repo}.git"
    else:
        repo_url = f"https://gitee.com/{gitee_owner}/{gitee_repo}.git"

    force_remove(target_dir)

    try:
        env = os.environ.copy()
        env.update({
            "GIT_LFS_SKIP_SMUDGE": "1",
            "GIT_CLONE_PROTECTION_ACTIVE": "false"
        })

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
        error_msg = "克隆失败: "
        if username and token:
            error_msg += "认证失败或"
        error_msg += e.stderr.strip() if e.stderr else '未知错误'
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


def main(owner, repo, output_file="lfs_mapping.json", username=None, token=None):
    try:
        repo_dir = clone_repo_skip_lfs(owner, repo, username, token)
        mapping = get_all_branches_lfs_mapping(repo_dir)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2, ensure_ascii=False)

        print(f"结果已保存到 {output_file}")
        return True
    except Exception as e:
        print(f"错误: {str(e)}", file=sys.stderr)
        return False
    finally:
        if 'repo_dir' in locals():
            force_remove(repo_dir)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法: python lfsNameQuery.py <owner> <repo> [output_file] [username] [token]")
        sys.exit(1)

    args = {
        "owner": sys.argv[1],
        "repo": sys.argv[2],
        "output_file": sys.argv[3] if len(sys.argv) > 3 else "lfs_mapping.json",
        "username": sys.argv[4] if len(sys.argv) > 4 else None,
        "token": sys.argv[5] if len(sys.argv) > 5 else None
    }

    sys.exit(0 if main( ** args) else 1)
