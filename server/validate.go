package server

import (
	"fmt"
	"github.com/metalogical/BigFiles/config"
	"regexp"
)

type validateConfig struct {
	ownerRegexp    *regexp.Regexp
	reponameRegexp *regexp.Regexp
	usernameRegexp *regexp.Regexp
	passwordRegexp *regexp.Regexp
}

var validatecfg validateConfig
var Webhook_key string
var gitCodeSwitch bool
var defaultUsername string
var giteeDefaultToken string
var atomGiteDefaultToken string

func Init(cfg *config.Config) error {
	validateConfig := cfg.ValidateConfig
	gitCodeSwitch = cfg.GitCodeSwitch
	defaultUsername = cfg.DefaultUsername
	giteeDefaultToken = cfg.DefaultToken
	atomGiteDefaultToken = cfg.DefaultGitCodeToken
	var err error
	Webhook_key = validateConfig.WebhookKey

	validatecfg.ownerRegexp, err = regexp.Compile(validateConfig.OwnerRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile owner regexp: %w", err)
	}

	validatecfg.reponameRegexp, err = regexp.Compile(validateConfig.RepoNameRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile repo name regexp: %w", err)
	}

	validatecfg.usernameRegexp, err = regexp.Compile(validateConfig.UsernameRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile username regexp: %w", err)
	}

	validatecfg.passwordRegexp, err = regexp.Compile(validateConfig.PasswordRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile password regexp: %w", err)
	}

	return nil
}
