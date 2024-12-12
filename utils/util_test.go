package utils

import (
	"testing"
)

func TestLoadFromYaml(t *testing.T) {
	type ValidateConfig struct {
		OwnerRegexp    string `json:"OWNER_REGEXP"         required:"true"`
		RepoNameRegexp string `json:"REPONAME_REGEXP"         required:"true"`
		UsernameRegexp string `json:"USERNAME_REGEXP"         required:"true"`
		PasswordRegexp string `json:"PASSWORD_REGEXP"         required:"true"`
	}
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
	type args struct {
		path string
		cfg  Config
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestLoadFromYaml success",
			args: args{
				path: "../config.example.yml",
			},
			wantErr: false,
		},
		{
			name: "TestLoadFromYaml fail",
			args: args{
				path: "../config.yml.example",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadFromYaml(tt.args.path, tt.args.cfg); (err != nil) != tt.wantErr {
				t.Errorf("LoadFromYaml() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
