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

func Init(cfg config.ValidateConfig) error {
	var err error
	Webhook_key = cfg.WebhookKey

	validatecfg.ownerRegexp, err = regexp.Compile(cfg.OwnerRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile owner regexp: %w", err)
	}

	validatecfg.reponameRegexp, err = regexp.Compile(cfg.RepoNameRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile repo name regexp: %w", err)
	}

	validatecfg.usernameRegexp, err = regexp.Compile(cfg.UsernameRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile username regexp: %w", err)
	}

	validatecfg.passwordRegexp, err = regexp.Compile(cfg.PasswordRegexp)
	if err != nil {
		return fmt.Errorf("failed to compile password regexp: %w", err)
	}

	return nil
}
