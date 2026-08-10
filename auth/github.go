package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

var (
	githubUploadPermissions   = []string{"admin", "maintain", "write"}
	githubDownloadPermissions = []string{"admin", "maintain", "write", "triage", "read"}
	githubDeletePermissions   = []string{"admin"}
)

type ghOrg struct {
	Login string `json:"login"`
}

// githubRepo mirrors the subset of the GitHub /repos/{owner}/{repo} response
// that BigFiles needs for ownership validation.
type githubRepo struct {
	FullName string `json:"full_name"`
	Owner    ghOrg  `json:"owner"`
	Parent   parent `json:"parent"`
}

// githubPermission mirrors the GitHub collaborator permission response.
type githubPermission struct {
	Permission string `json:"permission"`
}

const (
	githubAccept = "application/vnd.github+json"
)

// githubAPIBase is the GitHub REST API root. It is a var so unit tests can
// redirect it to an httptest server.
var githubAPIBase = "https://api.github.com"

// githubTokenFor returns the token to use for a GitHub API call: the user PAT
// when present, otherwise the server-side default bot token.
func githubTokenFor(u UserInRepo) string {
	if u.Token != "" {
		return u.Token
	}
	return githubDefaultToken
}

func githubHeaders(token string) http.Header {
	h := http.Header{
		contentType:   []string{headerContentType},
		accept:        []string{githubAccept},
		authorization: []string{"Bearer " + token},
	}
	return h
}

func GithubOrg(org string) func(string, string) error {
	return func(_, ghToken string) error {
		req, err := http.NewRequest("GET", "https://api.github.com/user/orgs", nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+ghToken)

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		var ghOrgs []ghOrg
		if err := json.NewDecoder(resp.Body).Decode(&ghOrgs); err != nil {
			return err
		}

		for _, ghOrg := range ghOrgs {
			if ghOrg.Login == org {
				return nil
			}
		}
		return fmt.Errorf("user must be member of Github organization %s", org)
	}
}

func Static(u, p string) func(string, string) error {
	return func(username, password string) error {
		if u != username || p != password {
			return errors.New("invalid credentials")
		}
		return nil
	}
}

// CheckGithubRepoOwner validates that {owner}/{repo} exists on GitHub and that
// the repository owner is an allowed GitHub organization.
func CheckGithubRepoOwner(u UserInRepo) (Repo, error) {
	token := githubTokenFor(u)
	path := fmt.Sprintf("%s/repos/%s/%s", githubAPIBase, u.Owner, u.Repo)
	repo := new(githubRepo)
	if err := getParsedResponse("GET", path, githubHeaders(token), nil, repo); err != nil {
		return Repo{}, err
	}
	for _, allowed := range githubAllowedOrgs {
		if repo.Owner.Login == allowed {
			return Repo{Fullname: repo.FullName, Parent: repo.Parent}, nil
		}
	}
	// a fork under an allowed organisation is also admissible
	if repo.Parent.Fullname != "" {
		parentOwner := strings.Split(repo.Parent.Fullname, "/")[0]
		for _, allowed := range githubAllowedOrgs {
			if parentOwner == allowed {
				return Repo{Fullname: repo.FullName, Parent: repo.Parent}, nil
			}
		}
	}
	msg := "forbidden: repo has no permission to use this lfs server"
	logrus.Error(fmt.Sprintf("CheckGithubRepoOwner | %s | owner:%s repo:%s", msg, u.Owner, u.Repo))
	return Repo{Fullname: repo.FullName, Parent: repo.Parent}, errors.New(msg)
}

// VerifyGithubUser checks the collaborator permission of username on the repo
// against the operation being performed.
func VerifyGithubUser(u UserInRepo) error {
	token := githubTokenFor(u)
	path := fmt.Sprintf("%s/repos/%s/%s/collaborators/%s/permission",
		githubAPIBase, u.Owner, u.Repo, u.Username)
	perm := new(githubPermission)
	if err := getParsedResponse("GET", path, githubHeaders(token), nil, perm); err != nil {
		msg := err.Error() + ": verify github user permission failed"
		logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
		return errors.New(msg)
	}

	switch u.Operation {
	case "upload":
		return verifyGithubUserUpload(perm, u)
	case "download":
		return verifyGithubUserDownload(perm, u)
	case "delete":
		return verifyGithubUserDelete(perm, u)
	default:
		msg := "system_error: unknown operation"
		logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
		return errors.New(msg)
	}
}

func verifyGithubUserUpload(perm *githubPermission, u UserInRepo) error {
	for _, p := range githubUploadPermissions {
		if perm.Permission == p {
			return nil
		}
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to upload to %s/%s",
		u.Username, u.Owner, u.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}

func verifyGithubUserDownload(perm *githubPermission, u UserInRepo) error {
	for _, p := range githubDownloadPermissions {
		if perm.Permission == p {
			return nil
		}
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to download from %s/%s",
		u.Username, u.Owner, u.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}

func verifyGithubUserDelete(perm *githubPermission, u UserInRepo) error {
	for _, p := range githubDeletePermissions {
		if perm.Permission == p {
			return nil
		}
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to delete in %s/%s",
		u.Username, u.Owner, u.Repo)
	logrus.Error(fmt.Sprintf(formatLogString, verifyLog, msg))
	return errors.New(msg)
}

// GithubAuth mirrors GiteeAuth: first validate repo ownership, then the user's
// collaborator permission. For GitHub the PAT is passed verbatim in Basic Auth
// (password field), no OAuth token exchange is performed.
func GithubAuth() func(UserInRepo) error {
	return func(userInRepo UserInRepo) error {
		userInRepo.Token = userInRepo.Password
		if _, err := CheckGithubRepoOwner(userInRepo); err != nil {
			return err
		}
		return VerifyGithubUser(userInRepo)
	}
}

// CheckRepoOwnerByPlatform dispatches repo-ownership validation to the
// platform-specific implementation.
func CheckRepoOwnerByPlatform(platform string, u UserInRepo) (Repo, error) {
	if platform == "github" {
		return CheckGithubRepoOwner(u)
	}
	return CheckRepoOwner(u)
}
