package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/metalogical/BigFiles/config"
	"github.com/sirupsen/logrus"
)

var (
	clientId     string
	clientSecret string
	defaultToken string
)

var (
	allowedRepos        = []string{"openeuler", "src-openeuler", "lfs-org"}
	uploadPermissions   = []string{"admin", "developer"}
	downloadPermissions = []string{"admin", "developer", "read"}
)

var contentType = "Content-Type"
var verifyLog = "verifyUser"
var appendPathAccessToken = "?access_token="

type giteeUser struct {
	Permission string `json:"permission"`
}

type UserInRepo struct {
	Repo      string
	Owner     string
	Token     string
	Username  string
	Password  string
	Operation string
}

type parent struct {
	Fullname string `json:"full_name"`
}

type Repo struct {
	Parent   parent `json:"parent"`
	Fullname string `json:"full_name"`
}

type AccessToken struct {
	Token string `json:"access_token"`
}

func Init(cfg *config.Config) error {
	clientId = cfg.ClientId
	if clientId == "" {
		clientId = os.Getenv("CLIENT_ID")
		if clientId == "" {
			return errors.New("client id required")
		}
	}
	clientSecret = cfg.ClientSecret
	if clientSecret == "" {
		clientSecret = os.Getenv("CLIENT_SECRET")
		if clientSecret == "" {
			return errors.New("client secret required")
		}
	}
	defaultToken = cfg.DefaultToken
	if defaultToken == "" {
		defaultToken = os.Getenv("DEFAULT_TOKEN")
		if defaultToken == "" {
			return errors.New("default token required")
		}
	}

	return nil
}

func GiteeAuth() func(UserInRepo) error {
	return func(userInRepo UserInRepo) error {
		if userInRepo.Password != "" {
			token, err := getToken(userInRepo.Username, userInRepo.Password)
			if err != nil {
				userInRepo.Token = userInRepo.Password
			} else {
				userInRepo.Token = token
			}
		}

		if err := CheckRepoOwner(userInRepo); err != nil {
			return err
		}

		return verifyUser(userInRepo)
	}
}

// CheckRepoOwner checks whether the owner of a repo is allowed to use lfs server
func CheckRepoOwner(userInRepo UserInRepo) error {
	path := fmt.Sprintf(
		"https://gitee.com/api/v5/repos/%s/%s",
		userInRepo.Owner,
		userInRepo.Repo,
	)
	if userInRepo.Token != "" {
		path += fmt.Sprintf(appendPathAccessToken + userInRepo.Token)
	} else {
		path += fmt.Sprintf(appendPathAccessToken + defaultToken)
	}
	headers := http.Header{contentType: []string{"application/json;charset=UTF-8"}}
	repo := new(Repo)
	err := getParsedResponse("GET", path, headers, nil, &repo)
	if err != nil {
		msg := err.Error() + ": check repo_id failed"
		return errors.New(msg)
	}
	for _, allowedRepo := range allowedRepos {
		if strings.Split(repo.Fullname, "/")[0] == allowedRepo {
			return nil
		}
	}

	if repo.Parent.Fullname != "" {
		for _, allowedRepo := range allowedRepos {
			if strings.Split(repo.Parent.Fullname, "/")[0] == allowedRepo {
				return nil
			}
		}
	}
	msg := "forbidden: repo has no permission to use this lfs server"
	logrus.Error(fmt.Sprintf("CheckRepoOwner | %s", msg))
	return errors.New(msg)
}

// getToken gets access_token by username and password
func getToken(username, password string) (string, error) {
	form := url.Values{}
	form.Add("scope", "user_info projects")
	form.Add("grant_type", "password")
	form.Add("username", username)
	form.Add("password", password)
	form.Add("client_id", clientId)
	form.Add("client_secret", clientSecret)

	path := "https://gitee.com/oauth/token"
	headers := http.Header{contentType: []string{"application/x-www-form-urlencoded"}}
	accessToken := new(AccessToken)
	err := getParsedResponse("POST", path, headers, strings.NewReader(form.Encode()), &accessToken)
	if err != nil {
		msg := err.Error() + ": get token failed. Or may be it is already a token"
		return "", errors.New(msg)
	}

	return accessToken.Token, nil
}

// verifyUser verifies user permission in repo by access_token and operation
func verifyUser(userInRepo UserInRepo) error {
	path := fmt.Sprintf(
		"https://gitee.com/api/v5/repos/%s/%s/collaborators/%s/permission",
		userInRepo.Owner,
		userInRepo.Repo,
		userInRepo.Username,
	)
	if userInRepo.Token != "" {
		path += fmt.Sprintf(appendPathAccessToken + userInRepo.Token)
	} else {
		path += fmt.Sprintf(appendPathAccessToken + defaultToken)
	}
	headers := http.Header{contentType: []string{"application/json;charset=UTF-8"}}
	giteeUser := new(giteeUser)
	err := getParsedResponse("GET", path, headers, nil, &giteeUser)
	if err != nil {
		msg := err.Error() + ": verify user permission failed"
		logrus.Error(fmt.Sprintf(verifyLog + " | " + msg))
		return errors.New(msg)
	}

	if userInRepo.Operation == "upload" {
		return verifyUserUpload(giteeUser, userInRepo)
	} else if userInRepo.Operation == "download" {
		return verifyUserDownload(giteeUser, userInRepo)
	} else {
		msg := "system_error: unknow operation"
		logrus.Error(fmt.Sprintf(verifyLog + " | " + msg))
		return errors.New(msg)
	}
}

func verifyUserUpload(giteeUser *giteeUser, userInRepo UserInRepo) error {
	for _, v := range uploadPermissions {
		if giteeUser.Permission == v {
			return nil
		}
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to upload to %s/%s",
		userInRepo.Username, userInRepo.Owner, userInRepo.Repo)
	remindMsg := " \n如果您正在向fork仓库上传大文件，请确认您已使用如下命令修改了本地仓库的配置：" +
		"\n`git config --local lfs.url https://artifacts.openeuler.openatom.cn/{owner}/{repo}`" +
		"，\n其中{owner}/{repo}请改为您fork之后的仓库的名称"
	logrus.Error(fmt.Sprintf(verifyLog + " | " + msg))
	return errors.New(msg + remindMsg)
}

func verifyUserDownload(giteeUser *giteeUser, userInRepo UserInRepo) error {
	for _, v := range downloadPermissions {
		if giteeUser.Permission == v {
			return nil
		}
	}
	msg := fmt.Sprintf("forbidden: user %s has no permission to download", userInRepo.Username)
	logrus.Error(fmt.Sprintf(verifyLog + " | " + msg))
	return errors.New(msg)
}
