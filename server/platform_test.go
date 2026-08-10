package server

import (
	"errors"
	"testing"

	"github.com/metalogical/BigFiles/auth"
	"github.com/stretchr/testify/assert"
)

// TestTokenForPlatform covers all three branches of tokenForPlatform: the
// github/gitcode token dispatch and the default (gitee) fallback. These tokens
// back the OID->filename backfill task (TASK5) and must map each platform to
// the right server-side credential.
func TestTokenForPlatform(t *testing.T) {
	origGithub := githubDefaultToken
	origAtom := atomGiteDefaultToken
	origGitee := giteeDefaultToken
	defer func() {
		githubDefaultToken = origGithub
		atomGiteDefaultToken = origAtom
		giteeDefaultToken = origGitee
	}()
	githubDefaultToken = "gh-bot-token"
	atomGiteDefaultToken = "gitcode-bot-token"
	giteeDefaultToken = "gitee-bot-token"

	assert.Equal(t, "gh-bot-token", tokenForPlatform("github"))
	assert.Equal(t, "gitcode-bot-token", tokenForPlatform("gitcode"))
	// default branch: any unknown platform falls back to the gitee token
	assert.Equal(t, "gitee-bot-token", tokenForPlatform("gitee"))
	assert.Equal(t, "gitee-bot-token", tokenForPlatform("unknown-platform"))
}

// callAuthorized invokes the authorizer returned by authorizedFn and reports
// which sentinel it produced, so we can assert which branch was taken without
// comparing function values (Go forbids comparing funcs except to nil).
func callAuthorized(s *server, owner string) string {
	fn := s.authorizedFn(auth.UserInRepo{Owner: owner})
	err := fn(auth.UserInRepo{Owner: owner})
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestAuthorizedFn_FallbackNilMap pins the fallback path: when no
// platform-specific authorizer map is configured, the generic IsAuthorized must
// be used. This was the previously-uncovered branch (50% -> now covered).
func TestAuthorizedFn_FallbackNilMap(t *testing.T) {
	s := &server{
		isAuthorized:           func(auth.UserInRepo) error { return errors.New("fallback") },
		isAuthorizedByPlatform: nil,
	}
	assert.Equal(t, "fallback", callAuthorized(s, "openeuler"))
}

// TestAuthorizedFn_FallbackUnknownPlatform covers the case where the map is set
// but the resolved platform has no entry, so the generic authorizer is used.
func TestAuthorizedFn_FallbackUnknownPlatform(t *testing.T) {
	resolved := auth.ResolvePlatform("openeuler")
	s := &server{
		isAuthorized: func(auth.UserInRepo) error { return errors.New("fallback") },
		isAuthorizedByPlatform: map[string]func(auth.UserInRepo) error{
			"github": func(auth.UserInRepo) error { return errors.New("platform-gh") },
		},
	}
	// sanity: the resolved platform really is missing from the map
	_, present := s.isAuthorizedByPlatform[resolved]
	assert.False(t, present)
	assert.Equal(t, "fallback", callAuthorized(s, "openeuler"))
}

// TestAuthorizedFn_PlatformHit covers the happy path: the resolved platform has
// a registered authorizer, which must be returned instead of the generic one.
func TestAuthorizedFn_PlatformHit(t *testing.T) {
	resolved := auth.ResolvePlatform("openeuler")
	s := &server{
		isAuthorized: func(auth.UserInRepo) error { return errors.New("fallback") },
		isAuthorizedByPlatform: map[string]func(auth.UserInRepo) error{
			resolved: func(auth.UserInRepo) error { return errors.New("platform-hit") },
		},
	}
	assert.Equal(t, "platform-hit", callAuthorized(s, "openeuler"))
}
