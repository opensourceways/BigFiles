package config

import "testing"

func TestLoadConfig(t *testing.T) {
	type args struct {
		path   string
		cfg    *Config
		remove bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "TestLoadConfig success",
			args: args{
				path:   "../config.example.yml",
				cfg:    &Config{},
				remove: false,
			},
			wantErr: false,
		},
		{
			name: "TestLoadConfig fail",
			args: args{
				path:   "../config.yml.example",
				cfg:    &Config{},
				remove: false,
			},
			wantErr: true,
		},
		{
			name: "TestLoadConfig fail and remove LocalFile",
			args: args{
				path:   "../config.yml.example",
				cfg:    &Config{},
				remove: true,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadConfig(tt.args.path, tt.args.cfg, tt.args.remove); (err != nil) != tt.wantErr {
				t.Errorf("LoadConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
