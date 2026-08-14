package main

import (
	"errors"
	"reflect"
	"testing"

	"bou.ke/monkey"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/config"
	"github.com/metalogical/BigFiles/db"
	"github.com/metalogical/BigFiles/server"
	"github.com/stretchr/testify/assert"
)

func Test_initConfig_serverInitError(t *testing.T) {
	monkey.Patch(server.Init, func(cfg *config.Config) error {
		return errors.New("server init failed")
	})
	defer monkey.UnpatchAll()

	cfg := &config.Config{}
	err := initConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load ValidateConfig")
}

func Test_initConfig_authInitError(t *testing.T) {
	monkey.Patch(server.Init, func(cfg *config.Config) error { return nil })
	monkey.Patch(auth.Init, func(cfg *config.Config) error {
		return errors.New("auth init failed")
	})
	defer monkey.UnpatchAll()

	cfg := &config.Config{}
	err := initConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load gitee config")
}

func Test_initConfig_dbInitError(t *testing.T) {
	monkey.Patch(server.Init, func(cfg *config.Config) error { return nil })
	monkey.Patch(auth.Init, func(cfg *config.Config) error { return nil })
	monkey.Patch(db.Init, func(cfg config.DBConfig) error {
		return errors.New("db init failed")
	})
	defer monkey.UnpatchAll()

	cfg := &config.Config{}
	err := initConfig(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "init database config")
}

func Test_initConfig_success(t *testing.T) {
	monkey.Patch(server.Init, func(cfg *config.Config) error { return nil })
	monkey.Patch(auth.Init, func(cfg *config.Config) error { return nil })
	monkey.Patch(db.Init, func(cfg config.DBConfig) error { return nil })
	defer monkey.UnpatchAll()

	cfg := &config.Config{}
	err := initConfig(cfg)
	assert.NoError(t, err)
}

func patchObsNew(fn func(ak, sk, endpoint string) (*obs.ObsClient, error)) {
	target := obs.New
	targetType := reflect.TypeOf(target)
	wrapper := reflect.MakeFunc(targetType, func(args []reflect.Value) []reflect.Value {
		ak := args[0].String()
		sk := args[1].String()
		endpoint := args[2].String()
		result, err := fn(ak, sk, endpoint)
		var errVal reflect.Value
		if err != nil {
			errVal = reflect.ValueOf(err)
		} else {
			errVal = reflect.Zero(reflect.TypeOf((*error)(nil)).Elem())
		}
		return []reflect.Value{reflect.ValueOf(result), errVal}
	})
	monkey.Patch(target, wrapper.Interface())
}

func Test_initObsClient_error(t *testing.T) {
	patchObsNew(func(ak, sk, endpoint string) (*obs.ObsClient, error) {
		return nil, errors.New("obs new failed")
	})
	defer monkey.UnpatchAll()

	cfg := &config.Config{
		ObsAccessKeyId:     "fake-ak",
		ObsSecretAccessKey: "fake-sk",
		ObsRegion:          "fake-region",
		LfsBucket:          "fake-bucket",
		Prefix:             "fake-prefix",
	}
	err := initObsClient(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to initialize OBS client")
}

func Test_initObsClient_success(t *testing.T) {
	patchObsNew(func(ak, sk, endpoint string) (*obs.ObsClient, error) {
		return &obs.ObsClient{}, nil
	})
	defer monkey.UnpatchAll()

	cfg := &config.Config{
		ObsAccessKeyId:     "fake-ak",
		ObsSecretAccessKey: "fake-sk",
		ObsRegion:          "fake-region",
		LfsBucket:          "test-bucket",
		Prefix:             "test-prefix",
	}
	err := initObsClient(cfg)
	assert.NoError(t, err)
	assert.NotNil(t, server.ObsClient)
	assert.Equal(t, "test-bucket", server.Bucket)
	assert.Equal(t, "test-prefix", server.Prefit)

	server.ObsClient = nil
	server.Bucket = ""
	server.Prefit = ""
}
