package auth

import (
	"testing"

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

// TearDownSuite used for testing
func (s *SuiteGithub) TearDownSuite() {
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
