package auth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

type githubRepo struct {
	FullName string       `json:"full_name"`
	Fork     bool         `json:"fork"`
	Parent   githubParent `json:"parent"`
}

type githubParent struct {
	FullName string `json:"full_name"`
}

type githubCollaboratorPermission struct {
	Permission string `json:"permission"`
}

// GithubAuth 与 gitcode 模式完全一致：token 直接来自 password 字段
func GithubAuth() func(UserInRepo) error {
	return func(userInRepo UserInRepo) error {
		userInRepo.Token = userInRepo.Password

		if _, err := CheckGithubRepoOwner(userInRepo); err != nil {
			return err
		}
		return VerifyGithubUser(userInRepo)
	}
}

// CheckGithubRepoOwner 检查仓库是否属于允许的 org（含 fork parent 检查）
func CheckGithubRepoOwner(userInRepo UserInRepo) (githubRepo, error) {
	// Pre-check: if owner is not in allowedRepos, reject immediately without API call
	ownerAllowed := false
	for _, allowed := range allowedRepos {
		if userInRepo.Owner == allowed {
			ownerAllowed = true
			break
		}
	}
	if !ownerAllowed {
		msg := "forbidden: repo has no permission to use this lfs server"
		logrus.Error(fmt.Sprintf("CheckGithubRepoOwner | %s", msg))
		return githubRepo{}, errors.New(msg)
	}

	token := userInRepo.Token
	if token == "" {
		token = defaultGithubToken
	}

	path := fmt.Sprintf("https://api.github.com/repos/%s/%s",
		userInRepo.Owner, userInRepo.Repo)
	headers := http.Header{
		"Authorization":        []string{"Bearer " + token},
		"Accept":               []string{"application/vnd.github+json"},
		"X-GitHub-Api-Version": []string{"2022-11-28"},
	}

	repo := new(githubRepo)
	if err := getParsedResponse("GET", path, headers, nil, repo); err != nil {
		return *repo, errors.New(err.Error() + ": check github repo failed")
	}

	owner := strings.Split(repo.FullName, "/")[0]
	for _, allowed := range allowedRepos {
		if owner == allowed {
			return *repo, nil
		}
	}

	if repo.Fork && repo.Parent.FullName != "" {
		parentOwner := strings.Split(repo.Parent.FullName, "/")[0]
		for _, allowed := range allowedRepos {
			if parentOwner == allowed {
				return *repo, nil
			}
		}
	}

	msg := "forbidden: repo has no permission to use this lfs server"
	logrus.Error(fmt.Sprintf("CheckGithubRepoOwner | %s", msg))
	return *repo, errors.New(msg)
}

// VerifyGithubUser 按 operation 验证 GitHub 用户权限
func VerifyGithubUser(userInRepo UserInRepo) error {
	token := userInRepo.Token
	if token == "" {
		token = defaultGithubToken
	}
	headers := http.Header{
		"Authorization":        []string{"Bearer " + token},
		"Accept":               []string{"application/vnd.github+json"},
		"X-GitHub-Api-Version": []string{"2022-11-28"},
	}

	switch userInRepo.Operation {
	case "upload":
		return verifyGithubUpload(userInRepo, headers)
	case "download":
		return verifyGithubDownload(userInRepo, headers)
	case "delete":
		return verifyGithubDelete(userInRepo, headers)
	default:
		msg := "system_error: unknown operation"
		logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
		return errors.New(msg)
	}
}

func getGithubCollaboratorPermission(userInRepo UserInRepo, headers http.Header) (*githubCollaboratorPermission, error) {
	path := fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/collaborators/%s/permission",
		userInRepo.Owner, userInRepo.Repo, userInRepo.Username,
	)
	perm := new(githubCollaboratorPermission)
	if err := getParsedResponse("GET", path, headers, nil, perm); err != nil {
		return nil, err
	}
	return perm, nil
}

func verifyGithubUpload(userInRepo UserInRepo, headers http.Header) error {
	perm, err := getGithubCollaboratorPermission(userInRepo, headers)
	if err != nil {
		msg := err.Error() + ": verify github user permission failed"
		logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
		return errors.New(msg)
	}
	if perm.Permission == "admin" || perm.Permission == "write" {
		return nil
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to upload to %s/%s",
		userInRepo.Username, userInRepo.Owner, userInRepo.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}

func verifyGithubDownload(userInRepo UserInRepo, headers http.Header) error {
	perm, err := getGithubCollaboratorPermission(userInRepo, headers)
	if err != nil {
		// collaborator API requires write/maintain/admin; for public repos it returns 404
		// fall back to checking repo accessibility
		path := fmt.Sprintf("https://api.github.com/repos/%s/%s",
			userInRepo.Owner, userInRepo.Repo)
		repo := new(githubRepo)
		if repoErr := getParsedResponse("GET", path, headers, nil, repo); repoErr != nil {
			// propagate unauthorized as-is so dealWithGithubAuthError returns 401
			if strings.HasPrefix(repoErr.Error(), "unauthorized") {
				return repoErr
			}
			msg := fmt.Sprintf("forbidden: user %s has no permission to download", userInRepo.Username)
			logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
			return errors.New(msg)
		}
		return nil
	}
	if perm.Permission == "admin" || perm.Permission == "write" || perm.Permission == "read" {
		return nil
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to download from %s/%s",
		userInRepo.Username, userInRepo.Owner, userInRepo.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}

func verifyGithubDelete(userInRepo UserInRepo, headers http.Header) error {
	perm, err := getGithubCollaboratorPermission(userInRepo, headers)
	if err != nil {
		msg := err.Error() + ": unauthorized: github token is invalid or expired, please re-authenticate"
		return errors.New(msg)
	}
	if perm.Permission == "admin" {
		return nil
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to delete from %s/%s",
		userInRepo.Username, userInRepo.Owner, userInRepo.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}
