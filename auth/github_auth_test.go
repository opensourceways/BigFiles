package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

type SuiteGithubAuth struct {
	suite.Suite
	mockServer *httptest.Server
}

func (s *SuiteGithubAuth) SetupSuite() {
	defaultGithubToken = "test-github-token"
	allowedRepos = []string{"openeuler", "src-openeuler", "lfs-org", "openeuler-test"}
}

func (s *SuiteGithubAuth) TearDownSuite() {
	if s.mockServer != nil {
		s.mockServer.Close()
	}
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

// --- CheckGithubRepoOwner 测试 ---

func (s *SuiteGithubAuth) TestCheckGithubRepoOwner_AllowedOrg() {
	userInRepo := UserInRepo{Owner: "openeuler", Repo: "test-repo", Token: "test-token"}
	_, err := CheckGithubRepoOwner(userInRepo)
	// 使用无效 token 调用真实 GitHub API，预期会报错（API 失败）
	assert.Error(s.T(), err)
}

func (s *SuiteGithubAuth) TestCheckGithubRepoOwner_ForbiddenOrg() {
	userInRepo := UserInRepo{Owner: "forbidden-org", Repo: "test-repo", Token: "test-token"}
	_, err := CheckGithubRepoOwner(userInRepo)
	assert.Error(s.T(), err)
	assert.Contains(s.T(), err.Error(), "forbidden")
}

// --- GithubAuth token 解析测试 ---

func (s *SuiteGithubAuth) TestGithubAuth_TokenFromPassword() {
	userInRepo := UserInRepo{
		Owner:     "non-exist-org",
		Repo:      "non-exist-repo",
		Username:  "user",
		Password:  "my-github-token",
		Operation: "upload",
	}
	githubAuth := GithubAuth()
	err := githubAuth(userInRepo)
	assert.Error(s.T(), err)
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

func TestGithubAuth(t *testing.T) {
	suite.Run(t, new(SuiteGithubAuth))
}
