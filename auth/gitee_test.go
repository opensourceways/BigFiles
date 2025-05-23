package auth

import (
	"fmt"
	"github.com/metalogical/BigFiles/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SuiteGitee used for testing
type SuiteGitee struct {
	suite.Suite
	cfg      config.Config
	Repo     string
	Owner    string
	UserName string
	Password string
}

// SetupSuite used for testing
func (s *SuiteGitee) SetupSuite() {
	s.Repo = "software-package-server"
	s.Owner = "src-openeuler"
	s.UserName = "user"
	s.Password = "wrong_pwd"
	s.cfg = config.Config{
		ClientId:     "clientId",
		ClientSecret: "clientSecret",
		DefaultToken: "defaultToken",
		OpenEulerAccountConfig: config.OpenEulerAccountConfig{
			AppId:     "appId",
			UrlPath:   "urlPath",
			AppSecret: "appSecret",
		},
	}
}

func (s *SuiteGitee) TestInit() {
	//Init success
	err := Init(&s.cfg)
	assert.Nil(s.T(), err)
}

func (s *SuiteGitee) TestGiteeAuth() {
	// GiteeAuth fail
	userInRepo := UserInRepo{
		Repo:      s.Repo,
		Owner:     s.Owner,
		Username:  s.UserName,
		Password:  s.Password,
		Operation: "download",
	}
	giteeAuth := GiteeAuth()
	err := giteeAuth(userInRepo)
	assert.NotNil(s.T(), err)
}

func (s *SuiteGitee) TestGetToken() {
	// getToken fail
	token, err := getToken(s.UserName, s.Password)
	assert.Equal(s.T(), "", token)
	assert.NotNil(s.T(), err.Error())
}

func (s *SuiteGitee) TestCheckRepoOwner() {
	// CheckRepoOwner success
	userInRepo := UserInRepo{
		Repo:  s.Repo,
		Owner: s.Owner,
		Token: s.cfg.DefaultToken,
	}
	err := CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)

	// check no_exist repo
	userInRepo = UserInRepo{
		Repo:  "repo",
		Owner: "owner",
		Token: s.cfg.DefaultToken,
	}
	err = CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)
}

func (s *SuiteGitee) TestVerifyUser() {
	userInRepo := UserInRepo{
		Repo:      s.Repo,
		Owner:     s.Owner,
		Username:  s.UserName,
		Operation: "download",
		Token:     s.cfg.DefaultToken,
	}

	err := VerifyUser(userInRepo)
	assert.NotNil(s.T(), err)

	userInRepo.Operation = "upload"
	err = VerifyUser(userInRepo)
	assert.NotNil(s.T(), err)
}

func TestGitee(t *testing.T) {
	suite.Run(t, new(SuiteGitee))
}

func TestVerifySSHAuthToken(t *testing.T) {
	type args struct {
		auth       string
		userInRepo UserInRepo
	}
	tests := []struct {
		name    string
		args    args
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "verify ssh auth token failed",
			args: args{
				auth: "",
				userInRepo: UserInRepo{
					Repo:  "repo",
					Owner: "owner",
				},
			},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.wantErr(t, VerifySSHAuthToken(tt.args.auth, tt.args.userInRepo),
				fmt.Sprintf("VerifySSHAuthToken(%v, %v)", tt.args.auth, tt.args.userInRepo))
		})
	}
}
