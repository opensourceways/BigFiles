package server

import (
	"github.com/metalogical/BigFiles/config"
	"testing"
)

func TestInit(t *testing.T) {
	tests := []struct {
		name    string
		args    config.ValidateConfig
		wantErr bool
	}{
		{
			name: "compile owner regexp failed",
			args: config.ValidateConfig{
				OwnerRegexp: `^[\\-?]$`,
			},
			wantErr: true,
		},
		{
			name: "compile repo regexp failed",
			args: config.ValidateConfig{
				OwnerRegexp:    `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				RepoNameRegexp: `^[\\-?]$`,
			},
			wantErr: true,
		},
		{
			name: "compile username regexp failed",
			args: config.ValidateConfig{
				OwnerRegexp:    `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				RepoNameRegexp: `^[a-zA-Z0-9_.-]{1,189}[a-zA-Z0-9]$`,
				UsernameRegexp: `^[\\-?]$`,
			},
			wantErr: true,
		},
		{
			name: "compile password regexp failed",
			args: config.ValidateConfig{
				OwnerRegexp:    `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				RepoNameRegexp: `^[a-zA-Z0-9_.-]{1,189}[a-zA-Z0-9]$`,
				UsernameRegexp: `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				PasswordRegexp: `^[\\-?]$`,
			},
			wantErr: true,
		},
		{
			name: "compile regexp success",
			args: config.ValidateConfig{
				OwnerRegexp:    `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				RepoNameRegexp: `^[a-zA-Z0-9_.-]{1,189}[a-zA-Z0-9]$`,
				UsernameRegexp: `^[a-zA-Z]([-_.]?[a-zA-Z0-9]+)*$`,
				PasswordRegexp: `^[a-zA-Z0-9!@_#$%^&*()-=+,?.,]*$`,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := Init(tt.args); (err != nil) != tt.wantErr {
				t.Errorf("Init() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
