package auth

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"bou.ke/monkey"
	"github.com/metalogical/BigFiles/batch"
	"github.com/metalogical/BigFiles/config"
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
		ClientId:            "clientId",
		ClientSecret:        "clientSecret",
		DefaultToken:        "defaultToken",
		DefaultGitCodeToken: "defaultGiteCode",
		DefaultGithubToken:  "defaultGithubToken",
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
	_, err := CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)

	// check no_exist repo
	userInRepo = UserInRepo{
		Repo:  "repo",
		Owner: "owner",
		Token: s.cfg.DefaultToken,
	}
	_, err = CheckRepoOwner(userInRepo)
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

func TestVerifyUserDelete(t *testing.T) {
	userInRepo := UserInRepo{Username: "testuser", Owner: "owner", Repo: "repo"}
	tests := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"admin can delete", "admin", false},
		{"developer cannot delete", "developer", true},
		{"read cannot delete", "read", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &giteeUser{Permission: tt.permission}
			err := verifyUserDelete(user, userInRepo)
			if tt.wantErr {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestVerifyUserUpload(t *testing.T) {
	userInRepo := UserInRepo{Username: "testuser", Owner: "owner", Repo: "repo"}
	tests := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"admin can upload", "admin", false},
		{"developer can upload", "developer", false},
		{"read cannot upload", "read", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &giteeUser{Permission: tt.permission}
			err := verifyUserUpload(user, userInRepo)
			if tt.wantErr {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestVerifyUserDownload(t *testing.T) {
	userInRepo := UserInRepo{Username: "testuser"}
	tests := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"admin can download", "admin", false},
		{"developer can download", "developer", false},
		{"read can download", "read", false},
		{"write cannot download", "write", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &giteeUser{Permission: tt.permission}
			err := verifyUserDownload(user, userInRepo)
			if tt.wantErr {
				assert.NotNil(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func TestResolveScriptPath(t *testing.T) {
	t.Run("returns provided path directly", func(t *testing.T) {
		path, err := resolveScriptPath("/custom/path/script.py")
		assert.Nil(t, err)
		assert.Equal(t, "/custom/path/script.py", path)
	})

	t.Run("returns error when no path and script not found in executable dir", func(t *testing.T) {
		_, err := resolveScriptPath()
		assert.NotNil(t, err)
	})
}

func TestCreateTempOutputFile(t *testing.T) {
	outputFile, cleanup, err := createTempOutputFile()
	assert.Nil(t, err)
	assert.NotEmpty(t, outputFile)
	assert.NotNil(t, cleanup)
	cleanup()
}

func TestParseOutputFile(t *testing.T) {
	t.Run("returns error for relative path outside /tmp", func(t *testing.T) {
		_, err := parseOutputFile("relative/path.json")
		assert.NotNil(t, err)
		assert.Contains(t, err.Error(), "access denied")
	})

	t.Run("returns error for absolute path outside /tmp", func(t *testing.T) {
		_, err := parseOutputFile("/var/other/file.json")
		assert.NotNil(t, err)
	})
}

func initTestOpenEulerCfg(t *testing.T) {
	t.Helper()
	cfg := &config.Config{
		OpenEulerAccountConfig: config.OpenEulerAccountConfig{
			AppId:     "test-app-id",
			UrlPath:   "http://test-url/%s",
			AppSecret: "test-secret",
		},
	}
	_ = Init(cfg)
}

func TestGetAccountManageToken(t *testing.T) {
	initTestOpenEulerCfg(t)

	t.Run("returns token when http call succeeds with status 200", func(t *testing.T) {
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				if out, ok := obj.(*batch.ManagerTokenOutput); ok {
					out.STATUS = 200
					out.Token = "test-manager-token"
				}
				return nil
			})
		defer unpatch.Unpatch()

		token, err := GetAccountManageToken()
		assert.Nil(t, err)
		assert.Equal(t, "test-manager-token", token)
	})

	t.Run("returns error when http call fails", func(t *testing.T) {
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				return errors.New("connection refused")
			})
		defer unpatch.Unpatch()

		_, err := GetAccountManageToken()
		assert.NotNil(t, err)
	})

	t.Run("returns error when response status is not 200", func(t *testing.T) {
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				if out, ok := obj.(*batch.ManagerTokenOutput); ok {
					out.STATUS = 401
				}
				return nil
			})
		defer unpatch.Unpatch()

		_, err := GetAccountManageToken()
		assert.NotNil(t, err)
	})
}

func TestGetOpenEulerUserInfo(t *testing.T) {
	initTestOpenEulerCfg(t)
	userInRepo := UserInRepo{Owner: "testowner", Repo: "testrepo"}

	t.Run("returns error when GetAccountManageToken fails", func(t *testing.T) {
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				return errors.New("token fetch error")
			})
		defer unpatch.Unpatch()

		_, err := GetOpenEulerUserInfo("ut", "yg", userInRepo)
		assert.NotNil(t, err)
	})

	t.Run("returns user info when all calls succeed", func(t *testing.T) {
		callCount := 0
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				callCount++
				if callCount == 1 {
					if out, ok := obj.(*batch.ManagerTokenOutput); ok {
						out.STATUS = 200
						out.Token = "manager-token"
					}
				} else {
					if out, ok := obj.(*batch.OpenEulerUserInfo); ok {
						out.Code = 200
						out.Data = batch.OpenEulerUserData{
							Identities: []batch.Identity{
								{AccessToken: "user-access-token", LoginName: "testlogin"},
							},
						}
					}
				}
				return nil
			})
		defer unpatch.Unpatch()

		result, err := GetOpenEulerUserInfo("ut", "yg", userInRepo)
		assert.Nil(t, err)
		assert.Equal(t, "user-access-token", result.Token)
		assert.Equal(t, "testlogin", result.Username)
	})

	t.Run("returns error when user info response code is not 200", func(t *testing.T) {
		callCount := 0
		unpatch := monkey.Patch(getParsedResponse,
			func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
				callCount++
				if callCount == 1 {
					if out, ok := obj.(*batch.ManagerTokenOutput); ok {
						out.STATUS = 200
						out.Token = "manager-token"
					}
				} else {
					if out, ok := obj.(*batch.OpenEulerUserInfo); ok {
						out.Code = 403
						out.Msg = "forbidden"
					}
				}
				return nil
			})
		defer unpatch.Unpatch()

		_, err := GetOpenEulerUserInfo("ut", "yg", userInRepo)
		assert.NotNil(t, err)
	})
}

func TestGetLFSMapping(t *testing.T) {
	userInRepo := UserInRepo{
		Owner:    "testowner",
		Repo:     "testrepo",
		Username: "testuser",
		Token:    "testtoken",
	}

	t.Run("returns error when python script not found in executable dir", func(t *testing.T) {
		_, err := GetLFSMapping(userInRepo)
		assert.NotNil(t, err)
	})
}
