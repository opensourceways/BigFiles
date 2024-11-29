package config

import (
	"os"

	"github.com/metalogical/BigFiles/utils"
)

type Config struct {
	Prefix             string         `json:"PATH_PREFIX"`
	LfsBucket          string         `json:"LFS_BUCKET"`
	ClientId           string         `json:"CLIENT_ID"`
	ClientSecret       string         `json:"CLIENT_SECRET"`
	CdnDomain          string         `json:"CDN_DOMAIN"`
	ObsRegion          string         `json:"OBS_REGION"`
	ObsAccessKeyId     string         `json:"OBS_ACCESS_KEY_ID"`
	ObsSecretAccessKey string         `json:"OBS_SECRET_ACCESS_KEY"`
	ValidateConfig     ValidateConfig `json:"VALIDATE_REGEXP"`
	DefaultToken       string         `json:"DEFAULT_TOKEN"`
}

type ValidateConfig struct {
	OwnerRegexp    string `json:"OWNER_REGEXP"         required:"true"`
	RepoNameRegexp string `json:"REPONAME_REGEXP"         required:"true"`
	UsernameRegexp string `json:"USERNAME_REGEXP"         required:"true"`
	PasswordRegexp string `json:"PASSWORD_REGEXP"         required:"true"`
}

// LoadConfig loads the configuration file from the specified path and deletes the file if needed
func LoadConfig(path string, cfg *Config, remove bool) error {
	if remove {
		defer os.Remove(path)
	}

	if err := utils.LoadFromYaml(path, cfg); err != nil {
		return err
	}
	return nil
}
