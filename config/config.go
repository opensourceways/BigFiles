package config

import (
	"fmt"
	"os"
	"time"

	"github.com/metalogical/BigFiles/utils"
)

type Config struct {
	Prefix                 string                 `json:"PATH_PREFIX"`
	LfsBucket              string                 `json:"LFS_BUCKET"`
	ClientId               string                 `json:"CLIENT_ID"`
	ClientSecret           string                 `json:"CLIENT_SECRET"`
	CdnDomain              string                 `json:"CDN_DOMAIN"`
	ObsRegion              string                 `json:"OBS_REGION"`
	DefaultToken           string                 `json:"DEFAULT_TOKEN"`
	DefaultUsername        string                 `json:"DEFAULT_USERNAME"`
	DefaultGitCodeToken    string                 `json:"DEFAULT_GIT_CODE_TOKEN"`
	ValidateConfig         ValidateConfig         `json:"VALIDATE_REGEXP"`
	ObsAccessKeyId         string                 `json:"OBS_ACCESS_KEY_ID"`
	ObsSecretAccessKey     string                 `json:"OBS_SECRET_ACCESS_KEY"`
	OpenEulerAccountConfig OpenEulerAccountConfig `json:"OPENEULER_ACCOUNT_PARAM"`
	DBConfig               DBConfig               `json:"DATABASE"`
	GitCodeSwitch          bool                   `json:"GIT_CODE_SWITCH" default:"false"`
}

type ValidateConfig struct {
	OwnerRegexp    string `json:"OWNER_REGEXP"         required:"true"`
	RepoNameRegexp string `json:"REPONAME_REGEXP"      required:"true"`
	UsernameRegexp string `json:"USERNAME_REGEXP"      required:"true"`
	PasswordRegexp string `json:"PASSWORD_REGEXP"      required:"true"`
	WebhookKey     string `json:"WEBHOOK_KEY"          required:"true"`
}

type DBConfig struct {
	DatabaseUserName string `json:"USERNAME"        required:"true"`
	DatabaseName     string `json:"NAME"         required:"true"`
	DatabasePassword string `json:"PASSWORD"         required:"true"`
	DatabasePort     string `json:"PORT"         required:"true"`
	DatabaseAddress  string `json:"ADDRESS"         required:"true"`
	Life             int    `json:"LIFE"     required:"true"`
	MaxIdle          int    `json:"MAXIDLE" required:"true"`
	MaxConn          int    `json:"MAXCONN" required:"true"`
}

type OpenEulerAccountConfig struct {
	AppId     string `json:"APP_ID"`
	UrlPath   string `json:"URL_PATH"`
	AppSecret string `json:"APP_SECRET"`
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

func (p *DBConfig) Dsn() string {

	return fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?charset=utf8&parseTime=True&loc=Local",
		p.DatabaseUserName, p.DatabasePassword, p.DatabaseAddress, p.DatabasePort, p.DatabaseName)

}

func (cfg *DBConfig) GetLifeDuration() time.Duration {
	return time.Minute * time.Duration(cfg.Life)
}
