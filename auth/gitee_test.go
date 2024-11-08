package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

// SuiteUserInRepo used for testing
type SuiteUserInRepo struct {
	suite.Suite
	Repo  string
	Owner string
}

// SetupSuite used for testing
func (s *SuiteUserInRepo) SetupSuite() {
	s.Repo = "software-package-server"
	s.Owner = "src-openeuler"
}

// TearDownSuite used for testing
func (s *SuiteUserInRepo) TearDownSuite() {

}

func (s *SuiteUserInRepo) TestGetToken() {
	// getToken fail
	token, err := getToken("user", "wrong_pwd")
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
		Operation: "download",
	}

	err := verifyUser(userInRepo)
	assert.NotNil(s.T(), err)
}

func TestGitee(t *testing.T) {
	suite.Run(t, new(SuiteUserInRepo))
}
