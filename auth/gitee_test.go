package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SuiteGitee used for testing
type SuiteGitee struct {
	suite.Suite
	Repo  string
	Owner string
}

// SetupSuite used for testing
func (s *SuiteGitee) SetupSuite() {
	s.Repo = "software-package-server"
	s.Owner = "src-openeuler"
}

// TearDownSuite used for testing
func (s *SuiteGitee) TearDownSuite() {
}

func (s *SuiteGitee) TestGetToken() {
	// getToken fail
	token, err := getToken("user", "wrong_pwd")
	assert.Equal(s.T(), "", token)
	assert.NotNil(s.T(), err.Error())
}

func (s *SuiteGitee) TestCheckRepoOwner() {
	// CheckRepoOwner success
	userInRepo := UserInRepo{
		Repo:  s.Repo,
		Owner: s.Owner,
	}
	err := CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)

	// check no_exist repo
	userInRepo = UserInRepo{
		Repo:  "repo",
		Owner: "owner",
	}
	err = CheckRepoOwner(userInRepo)
	assert.NotNil(s.T(), err)
}

func (s *SuiteGitee) TestVerifyUser() {
	userInRepo := UserInRepo{
		Repo:      s.Repo,
		Owner:     s.Owner,
		Operation: "download",
	}

	err := verifyUser(userInRepo)
	assert.NotNil(s.T(), err)
}

func TestGitee(t *testing.T) {
	suite.Run(t, new(SuiteGitee))
}
