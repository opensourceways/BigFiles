package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/metalogical/BigFiles/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SuiteGithub used for testing
type SuiteGithub struct {
	suite.Suite
	Username string
	Password string
}

// SetupSuite used for testing
func (s *SuiteGithub) SetupSuite() {
	s.Username = "username"
	s.Password = "password"
}

func (s *SuiteGithub) TestStatic() {
	// Static success
	static := Static(s.Username, s.Password)
	err := static(s.Username, s.Password)
	assert.Nil(s.T(), err)

	// Static fail
	static = Static(s.Username, s.Password)
	err = static(s.Username, "wrong_pwd")
	assert.NotNil(s.T(), err)
}

func (s *SuiteGithub) TestGithubOrg() {
	githubAuth := GithubOrg("github_org")
	err := githubAuth("user", "token")
	assert.NotNil(s.T(), err)
}

func TestGithub(t *testing.T) {
	suite.Run(t, new(SuiteGithub))
}

// -------------------- GitHub platform auth tests (httptest) --------------------

// ghMockServer builds an httptest server that stubs the GitHub REST endpoints
// used by BigFiles. repoOwner is the login returned by /repos/{o}/{r};
// permission is returned by the collaborator endpoint. statusRepo/statusPerm
// override the HTTP status codes.
type ghMock struct {
	repoOwner   string
	repoParent  string
	permission  string
	statusRepo  int
	statusPerm  int
	repoCalled  bool
	permCalled  bool
	permToken   string
}

func newGHMockServer(m *ghMock) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", func(w http.ResponseWriter, r *http.Request) {
		if isCollaboratorPath(r.URL.Path) {
			m.permCalled = true
			m.permToken = r.Header.Get("Authorization")
			if m.statusPerm != 0 {
				w.WriteHeader(m.statusPerm)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"permission": m.permission})
			return
		}
		m.repoCalled = true
		if m.statusRepo != 0 {
			w.WriteHeader(m.statusRepo)
			return
		}
		owner := m.repoOwner
		if owner == "" {
			owner = "mindspore-ai"
		}
		resp := map[string]interface{}{
			"full_name": fmt.Sprintf("%s/%s", owner, "repo"),
			"owner":     map[string]string{"login": owner},
		}
		if m.repoParent != "" {
			resp["parent"] = map[string]string{"full_name": m.repoParent}
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	return httptest.NewServer(mux)
}

// isCollaboratorPath reports whether the path targets the collaborator
// permission endpoint rather than the repo metadata endpoint.
func isCollaboratorPath(path string) bool {
	return indexOf(path, "/collaborators/") >= 0 && indexOf(path, "/permission") >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestResolvePlatform(t *testing.T) {
	origMap := namespacePlatformMap
	origSwitch := gitCodeSwitch
	defer func() {
		namespacePlatformMap = origMap
		gitCodeSwitch = origSwitch
	}()

	namespacePlatformMap = map[string]string{
		"mindspore-ai": "github",
		"openeuler":    "gitee",
	}
	gitCodeSwitch = false

	assert.Equal(t, "github", ResolvePlatform("mindspore-ai"))
	assert.Equal(t, "gitee", ResolvePlatform("openeuler"))
	// unconfigured owner falls back to gitee
	assert.Equal(t, "gitee", ResolvePlatform("someone-else"))

	// with gitCodeSwitch on, unconfigured owner resolves to gitcode
	gitCodeSwitch = true
	assert.Equal(t, "gitcode", ResolvePlatform("someone-else"))
	// but configured github owner still wins
	assert.Equal(t, "github", ResolvePlatform("mindspore-ai"))
}

func TestPlatformForMetadata(t *testing.T) {
	assert.Equal(t, "github", PlatformForMetadata("github"))
	assert.Equal(t, "atomGit", PlatformForMetadata("gitcode"))
	assert.Equal(t, "gitee", PlatformForMetadata("gitee"))
	assert.Equal(t, "gitee", PlatformForMetadata("unknown"))
}

func TestIsSupportedPlatform(t *testing.T) {
	assert.True(t, isSupportedPlatform("gitee"))
	assert.True(t, isSupportedPlatform("gitcode"))
	assert.True(t, isSupportedPlatform("github"))
	assert.False(t, isSupportedPlatform("gitlab"))
	assert.False(t, isSupportedPlatform(""))
}

func TestBuildNamespacePlatformMap(t *testing.T) {
	origMap := namespacePlatformMap
	origRepos := allowedRepos
	defer func() {
		namespacePlatformMap = origMap
		allowedRepos = origRepos
	}()

	cfg := &config.Config{
		AllowedNamespaces: []config.NamespaceMapping{
			{Namespace: "mindspore-ai", Platform: "github"},
			{Namespace: "new-gitee-org", Platform: "gitee"},
			{Namespace: "bad-platform-org", Platform: "gitlab"}, // unsupported -> gitee
			{Namespace: "", Platform: "gitee"},                  // empty -> skipped
		},
	}
	buildNamespacePlatformMap(cfg)

	// configured github namespace
	assert.Equal(t, "github", namespacePlatformMap["mindspore-ai"])
	// configured gitee namespace
	assert.Equal(t, "gitee", namespacePlatformMap["new-gitee-org"])
	// default namespaces preserved
	assert.Equal(t, "gitee", namespacePlatformMap["openeuler"])
	assert.Equal(t, "gitee", namespacePlatformMap["src-openeuler"])
	// unsupported platform falls back to gitee
	assert.Equal(t, "gitee", namespacePlatformMap["bad-platform-org"])
	// gitee/gitcode namespaces are admissible in CheckRepoOwner (allowedRepos)
	assert.Contains(t, allowedRepos, "new-gitee-org")
	assert.Contains(t, allowedRepos, "bad-platform-org")
	// github namespace is NOT added to allowedRepos (handled by githubAllowedOrgs)
	for _, r := range allowedRepos {
		assert.NotEqual(t, "mindspore-ai", r)
	}
}

func TestCheckGithubRepoOwner(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{repoOwner: "mindspore-ai"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	u := UserInRepo{Owner: "mindspore-ai", Repo: "repo", Token: "pat"}
	repo, err := CheckGithubRepoOwner(u)
	assert.NoError(t, err)
	assert.Equal(t, "mindspore-ai/repo", repo.Fullname)
	assert.True(t, m.repoCalled)
}

func TestCheckGithubRepoOwner_DisallowedOrg(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{repoOwner: "evil-org"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	_, err := CheckGithubRepoOwner(UserInRepo{Owner: "evil-org", Repo: "repo"})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "forbidden")
}

func TestCheckGithubRepoOwner_ForkOfAllowedOrg(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{repoOwner: "personal-fork", repoParent: "mindspore-ai/repo"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	repo, err := CheckGithubRepoOwner(UserInRepo{Owner: "personal-fork", Repo: "repo"})
	assert.NoError(t, err)
	assert.NotEmpty(t, repo.Parent.Fullname)
}

func TestCheckGithubRepoOwner_NotFound(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{statusRepo: http.StatusNotFound}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	_, err := CheckGithubRepoOwner(UserInRepo{Owner: "mindspore-ai", Repo: "repo"})
	assert.Error(t, err)
}

func TestCheckGithubRepoOwner_UsesDefaultToken(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	origDefault := githubDefaultToken
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
		githubDefaultToken = origDefault
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}
	githubDefaultToken = "server-bot-token"

	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(githubRepo{
			FullName: "mindspore-ai/repo",
			Owner:    ghOrg{Login: "mindspore-ai"},
		})
	}))
	defer srv.Close()
	githubAPIBase = srv.URL

	// no user token -> server default token used
	_, err := CheckGithubRepoOwner(UserInRepo{Owner: "mindspore-ai", Repo: "repo"})
	assert.NoError(t, err)
	assert.Equal(t, "Bearer server-bot-token", gotAuth)
}

func TestVerifyGithubUser_Upload(t *testing.T) {
	origBase := githubAPIBase
	defer func() { githubAPIBase = origBase }()

	cases := []struct {
		name       string
		permission string
		op         string
		wantErr    bool
	}{
		{"write can upload", "write", "upload", false},
		{"maintain can upload", "maintain", "upload", false},
		{"admin can upload", "admin", "upload", false},
		{"read cannot upload", "read", "upload", true},
		{"triage cannot upload", "triage", "upload", true},
		{"none cannot upload", "none", "upload", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &ghMock{permission: c.permission}
			srv := newGHMockServer(m)
			defer srv.Close()
			githubAPIBase = srv.URL

			err := VerifyGithubUser(UserInRepo{
				Owner: "mindspore-ai", Repo: "repo",
				Username: "alice", Operation: c.op, Token: "pat",
			})
			if c.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyGithubUser_Download(t *testing.T) {
	origBase := githubAPIBase
	defer func() { githubAPIBase = origBase }()

	cases := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"read can download", "read", false},
		{"triage can download", "triage", false},
		{"write can download", "write", false},
		{"none cannot download", "none", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &ghMock{permission: c.permission}
			srv := newGHMockServer(m)
			defer srv.Close()
			githubAPIBase = srv.URL

			err := VerifyGithubUser(UserInRepo{
				Owner: "mindspore-ai", Repo: "repo",
				Username: "alice", Operation: "download", Token: "pat",
			})
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyGithubUser_Delete(t *testing.T) {
	origBase := githubAPIBase
	defer func() { githubAPIBase = origBase }()

	cases := []struct {
		name       string
		permission string
		wantErr    bool
	}{
		{"admin can delete", "admin", false},
		{"write cannot delete", "write", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := &ghMock{permission: c.permission}
			srv := newGHMockServer(m)
			defer srv.Close()
			githubAPIBase = srv.URL

			err := VerifyGithubUser(UserInRepo{
				Owner: "mindspore-ai", Repo: "repo",
				Username: "alice", Operation: "delete", Token: "pat",
			})
			if c.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyGithubUser_Unauthorized(t *testing.T) {
	origBase := githubAPIBase
	defer func() { githubAPIBase = origBase }()

	m := &ghMock{statusPerm: http.StatusUnauthorized}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	err := VerifyGithubUser(UserInRepo{
		Owner: "mindspore-ai", Repo: "repo",
		Username: "alice", Operation: "download", Token: "bad-pat",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unauthorized")
}

func TestVerifyGithubUser_UnknownOperation(t *testing.T) {
	origBase := githubAPIBase
	defer func() { githubAPIBase = origBase }()

	m := &ghMock{permission: "write"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	err := VerifyGithubUser(UserInRepo{
		Owner: "mindspore-ai", Repo: "repo",
		Username: "alice", Operation: "weird", Token: "pat",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unknown operation")
}

func TestGithubAuth_Success(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{repoOwner: "mindspore-ai", permission: "write"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	fn := GithubAuth()
	err := fn(UserInRepo{
		Owner: "mindspore-ai", Repo: "repo",
		Username: "alice", Password: "pat", Operation: "upload",
	})
	assert.NoError(t, err)
}

func TestGithubAuth_BadPAT(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}

	m := &ghMock{statusRepo: http.StatusUnauthorized}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	fn := GithubAuth()
	err := fn(UserInRepo{
		Owner: "mindspore-ai", Repo: "repo",
		Username: "alice", Password: "bad-pat", Operation: "download",
	})
	assert.Error(t, err)
}

func TestCheckRepoOwnerByPlatform_Dispatch(t *testing.T) {
	origBase := githubAPIBase
	origOrgs := githubAllowedOrgs
	origMap := namespacePlatformMap
	defer func() {
		githubAPIBase = origBase
		githubAllowedOrgs = origOrgs
		namespacePlatformMap = origMap
	}()
	githubAllowedOrgs = []string{"mindspore-ai"}
	namespacePlatformMap = map[string]string{"mindspore-ai": "github"}

	m := &ghMock{repoOwner: "mindspore-ai"}
	srv := newGHMockServer(m)
	defer srv.Close()
	githubAPIBase = srv.URL

	// github platform dispatches to CheckGithubRepoOwner
	_, err := CheckRepoOwnerByPlatform("github", UserInRepo{Owner: "mindspore-ai", Repo: "repo", Token: "pat"})
	assert.NoError(t, err)
	assert.True(t, m.repoCalled)
}
