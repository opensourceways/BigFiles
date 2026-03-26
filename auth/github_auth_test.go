package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SuiteGithubAuth struct {
	suite.Suite
}

func (s *SuiteGithubAuth) SetupSuite() {
	defaultGithubToken = "test-github-token"
	allowedRepos = []string{"openeuler", "src-openeuler", "lfs-org", "openeuler-test"}
}

// mockGithubServer 创建 mock GitHub API 服务
func mockGithubServer(repoOwner, repoName string, isFork bool, parentOwner string,
	collabPermission string, repoStatusCode int, collabStatusCode int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		repoPath := "/repos/" + repoOwner + "/" + repoName
		collabPath := repoPath + "/collaborators/"

		if r.URL.Path == repoPath {
			if repoStatusCode != http.StatusOK {
				w.WriteHeader(repoStatusCode)
				return
			}
			repo := githubRepo{
				FullName: repoOwner + "/" + repoName,
				Fork:     isFork,
			}
			if isFork {
				repo.Parent = githubParent{FullName: parentOwner + "/" + repoName}
			}
			json.NewEncoder(w).Encode(repo)
			return
		}

		if len(r.URL.Path) > len(collabPath) && r.URL.Path[:len(collabPath)] == collabPath {
			if collabStatusCode != http.StatusOK {
				w.WriteHeader(collabStatusCode)
				return
			}
			json.NewEncoder(w).Encode(githubCollaboratorPermission{Permission: collabPermission})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
}

// patchGithubAPI patches getParsedResponse to redirect https://api.github.com requests
// to the given mock server, then returns an unpatch func.
func patchGithubAPI(mockServer *httptest.Server) func() {
	patch := monkey.Patch(getParsedResponse,
		func(method, path string, header http.Header, body io.Reader, obj interface{}) error {
			mockPath := strings.Replace(path, "https://api.github.com", mockServer.URL, 1)
			client := &http.Client{}
			req, err := http.NewRequest(method, mockPath, body)
			if err != nil {
				return err
			}
			req.Header = header
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("请求执行失败: %w", err)
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusNotFound:
				return errors.New("not_found")
			case http.StatusUnauthorized:
				return errors.New("unauthorized")
			case http.StatusForbidden:
				return errors.New("forbidden")
			}
			if resp.StatusCode/100 != 2 {
				return fmt.Errorf("system_error: %v", resp.StatusCode)
			}
			return json.NewDecoder(resp.Body).Decode(obj)
		})
	return patch.Unpatch
}

// --- CheckGithubRepoOwner 测试 ---

func (s *SuiteGithubAuth) TestCheckGithubRepoOwner_AllowedOrg() {
	// Given: owner 在白名单中，repo API 返回正常数据
	mockServer := mockGithubServer("openeuler", "test-repo", false, "", "", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "test-repo", Token: "test-token"}

	// When
	repo, err := CheckGithubRepoOwner(userInRepo)

	// Then
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "openeuler/test-repo", repo.FullName)
}

func (s *SuiteGithubAuth) TestCheckGithubRepoOwner_ForbiddenOrg() {
	// Given: owner 不在白名单中，pre-check 直接拒绝，无需 API
	userInRepo := UserInRepo{Owner: "forbidden-org", Repo: "test-repo", Token: "test-token"}

	// When
	_, err := CheckGithubRepoOwner(userInRepo)

	// Then
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "forbidden")
}

func (s *SuiteGithubAuth) TestCheckGithubRepoOwner_ForkAllowedParent() {
	// Given: owner "openeuler" 通过预检，但 API 返回 full_name 的 owner 是
	// "external-fork-user"（不在白名单），该 repo 是 "openeuler/base-repo" 的 fork，
	// parent owner "openeuler" 在白名单中 → fork parent 分支被实际执行
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(githubRepo{
			FullName: "external-fork-user/test-repo", // owner 不在白名单
			Fork:     true,
			Parent:   githubParent{FullName: "openeuler/test-repo"}, // parent 在白名单
		})
	}))
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "test-repo", Token: "test-token"}

	// When
	repo, err := CheckGithubRepoOwner(userInRepo)

	// Then: full_name owner 不在白名单，但 fork parent "openeuler" 在白名单，通过
	assert.NoError(s.T(), err)
	assert.True(s.T(), repo.Fork)
	assert.Equal(s.T(), "openeuler/test-repo", repo.Parent.FullName)
}

// --- GithubAuth token 解析测试 ---

func (s *SuiteGithubAuth) TestGithubAuth_TokenFromPassword() {
	// Given: owner 在白名单，mock server 校验 Authorization 头包含 password 中的 token
	const expectedToken = "my-github-token"
	var capturedAuthHeader string

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		repoPath := "/repos/openeuler/test-repo"
		if r.URL.Path == repoPath {
			json.NewEncoder(w).Encode(githubRepo{FullName: "openeuler/test-repo"})
			return
		}
		// collaborator permission → write
		json.NewEncoder(w).Encode(githubCollaboratorPermission{Permission: "write"})
	}))
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{
		Owner:     "openeuler",
		Repo:      "test-repo",
		Username:  "testuser",
		Password:  expectedToken,
		Operation: "upload",
	}

	// When
	githubAuth := GithubAuth()
	err := githubAuth(userInRepo)

	// Then: 鉴权通过，且请求头中携带了来自 Password 字段的 token
	assert.NoError(s.T(), err)
	assert.Equal(s.T(), "Bearer "+expectedToken, capturedAuthHeader)
}

// --- VerifyGithubUser 测试 ---

func (s *SuiteGithubAuth) TestVerifyGithubUser_UnknownOperation() {
	userInRepo := UserInRepo{
		Owner: "openeuler", Repo: "repo", Username: "user",
		Token: "token", Operation: "unknown",
	}
	err := VerifyGithubUser(userInRepo)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "system_error")
}

func (s *SuiteGithubAuth) TestVerifyGithubUpload_AdminPass() {
	// Given: collaborator API 返回 admin 权限
	mockServer := mockGithubServer("openeuler", "repo", false, "", "admin", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "upload"}

	assert.NoError(s.T(), VerifyGithubUser(userInRepo))
}

func (s *SuiteGithubAuth) TestVerifyGithubUpload_WritePass() {
	// Given: collaborator API 返回 write 权限
	mockServer := mockGithubServer("openeuler", "repo", false, "", "write", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "upload"}

	assert.NoError(s.T(), VerifyGithubUser(userInRepo))
}

func (s *SuiteGithubAuth) TestVerifyGithubUpload_ReadFail() {
	// Given: collaborator API 返回 read 权限（不足以 upload）
	mockServer := mockGithubServer("openeuler", "repo", false, "", "read", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "upload"}

	err := VerifyGithubUser(userInRepo)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "forbidden")
}

func (s *SuiteGithubAuth) TestVerifyGithubDownload_ReadPass() {
	// Given: collaborator API 返回 read 权限（下载足够）
	mockServer := mockGithubServer("openeuler", "repo", false, "", "read", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "download"}

	assert.NoError(s.T(), VerifyGithubUser(userInRepo))
}

func (s *SuiteGithubAuth) TestVerifyGithubDownload_UnauthorizedFail() {
	// Given: collaborator API 返回 401（token 无效），repo API 也返回 401
	// 期望错误前缀为 unauthorized，确保 dealWithGithubAuthError 返回 401 而非 403
	mockServer := mockGithubServer("openeuler", "repo", false, "", "", http.StatusUnauthorized, http.StatusUnauthorized)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "download"}

	err := VerifyGithubUser(userInRepo)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "unauthorized")
}

func (s *SuiteGithubAuth) TestVerifyGithubDelete_AdminPass() {
	// Given: collaborator API 返回 admin 权限
	mockServer := mockGithubServer("openeuler", "repo", false, "", "admin", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "delete"}

	assert.NoError(s.T(), VerifyGithubUser(userInRepo))
}

func (s *SuiteGithubAuth) TestVerifyGithubDelete_WriteFail() {
	// Given: collaborator API 返回 write 权限（不足以 delete）
	mockServer := mockGithubServer("openeuler", "repo", false, "", "write", http.StatusOK, http.StatusOK)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "delete"}

	err := VerifyGithubUser(userInRepo)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "forbidden")
}

func (s *SuiteGithubAuth) TestVerifyGithubDelete_TokenExpiredReturns401Prefix() {
	// Given: collaborator API 返回 401（token 过期）
	mockServer := mockGithubServer("openeuler", "repo", false, "", "", http.StatusOK, http.StatusUnauthorized)
	defer mockServer.Close()
	unpatch := patchGithubAPI(mockServer)
	defer unpatch()

	userInRepo := UserInRepo{Owner: "openeuler", Repo: "repo", Username: "user", Token: "token", Operation: "delete"}

	err := VerifyGithubUser(userInRepo)
	assert.Error(s.T(), err)
	// 错误前缀应为 unauthorized，确保 dealWithGithubAuthError 能正确分类为 401
	assert.Contains(s.T(), err.Error(), "unauthorized")
}

func TestGithubAuth(t *testing.T) {
	suite.Run(t, new(SuiteGithubAuth))
}
