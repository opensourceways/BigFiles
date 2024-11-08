package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SuiteUserInRepo used for testing
type SuiteUserInRepo struct {
	suite.Suite
	Repo      string
	Owner     string
	Token     string
	Username  string
	Password  string
	Operation string
	// userInRepo UserInRepo
}

// SetupSuite used for testing
func (s *SuiteUserInRepo) SetupSuite() {
	username := os.Getenv("GITEE_USER")
	token := os.Getenv("GITEE_TOKEN")
	s.Repo = "software-package-server"
	s.Owner = "src-openeuler"
	s.Username = username
	s.Token = token
}

// TearDownSuite used for testing
func (s *SuiteUserInRepo) TearDownSuite() {

}

func (s *SuiteUserInRepo) TestGetToken() {
	// getToken fail
	token, err := getToken(s.Username, "wrong_pwd")
	assert.Equal(s.T(), "", token)
	assert.NotNil(s.T(), err.Error())
}

func (s *SuiteUserInRepo) TestCheckRepoOwner() {
	// CheckRepoOwner success
	userInRepo := UserInRepo{
		Repo:  s.Repo,
		Owner: s.Owner,
	}
	err := CheckRepoOwner(userInRepo)
	assert.Nil(s.T(), err)

	// check no_exist repo
	userInRepo = UserInRepo{
		Repo:  "repo",
		Owner: "owner",
	}
	err = CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)
}

func (s *SuiteUserInRepo) TestVerifyUser() {
	userInRepo := UserInRepo{
		Repo:      s.Repo,
		Owner:     s.Owner,
		Token:     s.Token,
		Username:  s.Username,
		Operation: "download",
	}

	err := verifyUser(userInRepo)
	assert.Nil(s.T(), err)
}

func TestGitee(t *testing.T) {
	suite.Run(t, new(SuiteUserInRepo))
}
