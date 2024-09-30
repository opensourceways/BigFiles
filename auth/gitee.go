package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
)

var (
	allowedRepos        = []string{"wj00037", "openeuler", "src-openeuler"}
	uploadPermissions   = []string{"admin", "developer"}
	downloadPermissions = []string{"admin", "developer", "read"}
)

type giteeUser struct {
	Login      string `json:"login"`
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
		path += fmt.Sprintf("?access_token=%s", userInRepo.Token)
	}
	headers := http.Header{"Content-Type": []string{"application/json;charset=UTF-8"}}
	repo := new(Repo)
	err := getParsedResponse("GET", path, headers, nil, &repo)
	if err != nil {
		return err
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

	return errors.New("your repository does not appear to have permission to use this lfs service")
}

// getToken gets access_token by username and password
func getToken(username, password string) (string, error) {
	clientId := os.Getenv("CLIENT_ID")
	clientSecret := os.Getenv("CLIENT_SECRET")
	form := url.Values{}
	form.Add("scope", "user_info projects")
	form.Add("grant_type", "password")
	form.Add("username", username)
	form.Add("password", password)
	form.Add("client_id", clientId)
	form.Add("client_secret", clientSecret)

	path := "https://gitee.com/oauth/token"
	headers := http.Header{"Content-Type": []string{"application/x-www-form-urlencoded"}}
	accessToken := new(AccessToken)
	err := getParsedResponse("POST", path, headers, strings.NewReader(form.Encode()), &accessToken)
	if err != nil {
		return "", err
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
		path += fmt.Sprintf("?access_token=%s", userInRepo.Token)
	}
	headers := http.Header{"Content-Type": []string{"application/json;charset=UTF-8"}}
	giteeUser := new(giteeUser)
	err := getParsedResponse("GET", path, headers, nil, &giteeUser)
	if err != nil {
		return err
	}

	if giteeUser.Login != userInRepo.Username {
		return errors.New("username does not match")
	}
	if userInRepo.Operation == "upload" {
		for _, v := range uploadPermissions {
			if giteeUser.Permission == v {
				return nil
			}
		}
		return errors.New("user has no permission uploading to the repository")
	} else if userInRepo.Operation == "download" {
		for _, v := range downloadPermissions {
			if giteeUser.Permission == v {
				return nil
			}
		}
		return errors.New("user has no permission downloading in the repository")
	} else {
		return errors.New("unknow operation")
	}
}
