package main

import (
	"errors"
	"flag"
	"net"
	"net/http"
	"os"
	"reflect"
	"syscall"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/config"
	"github.com/metalogical/BigFiles/db"
	"github.com/metalogical/BigFiles/server"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func patchFatalf() {
	monkey.PatchInstanceMethod(reflect.TypeOf(logrus.StandardLogger()), "Fatalf",
		func(_ *logrus.Logger, format string, args ...interface{}) {
			panic(format)
		})
}

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

func TestServiceOptions_Validate_EmptyConfigFile(t *testing.T) {
	o := ServiceOptions{ConfigFile: ""}
	err := o.Validate()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "missing config-file")
}

func TestServiceOptions_Validate_ValidConfigFile(t *testing.T) {
	o := ServiceOptions{ConfigFile: "/some/path.yaml"}
	err := o.Validate()
	assert.NoError(t, err)
}

func TestOptions_Validate_DelegatesToServiceOptions(t *testing.T) {
	o := options{service: ServiceOptions{ConfigFile: ""}}
	err := o.Validate()
	assert.Error(t, err)

	o2 := options{service: ServiceOptions{ConfigFile: "/path/to/config"}}
	err2 := o2.Validate()
	assert.NoError(t, err2)
}

func TestServiceOptions_AddFlags(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	var o ServiceOptions
	o.AddFlags(fs)

	configFile := fs.Lookup("config-file")
	assert.NotNil(t, configFile, "config-file flag should be registered")

	rmCfg := fs.Lookup("rm-cfg")
	assert.NotNil(t, rmCfg, "rm-cfg flag should be registered")
}

func TestGatherOptions_Defaults(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o, err := gatherOptions(fs)
	assert.NoError(t, err)
	assert.False(t, o.enableDebug)
	assert.Equal(t, "", o.service.ConfigFile)
}

func TestGatherOptions_WithConfigFile(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o, err := gatherOptions(fs, "--config-file", "/etc/app/config.yaml")
	assert.NoError(t, err)
	assert.Equal(t, "/etc/app/config.yaml", o.service.ConfigFile)
}

func TestGatherOptions_EnableDebug(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o, err := gatherOptions(fs, "--enable_debug")
	assert.NoError(t, err)
	assert.True(t, o.enableDebug)
}

func TestGatherOptions_RmCfg(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	o, err := gatherOptions(fs, "--rm-cfg")
	assert.NoError(t, err)
	assert.True(t, o.service.RemoveCfg)
}

func TestReapZombies_ExitsOnChannelClose(t *testing.T) {
	sigChld := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		reapZombies(sigChld)
		close(done)
	}()
	close(sigChld)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reapZombies did not exit on channel close")
	}
}

func TestReapZombies_ProcessesSignal(t *testing.T) {
	sigChld := make(chan os.Signal, 1)
	done := make(chan struct{})
	go func() {
		reapZombies(sigChld)
		close(done)
	}()

	sigChld <- syscall.SIGCHLD
	close(sigChld)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("reapZombies did not exit")
	}
}

func TestSetupGracefulShutdown(t *testing.T) {
	srv := &http.Server{}
	quit := setupGracefulShutdown(srv)
	assert.NotNil(t, quit, "should return the quit channel")
}

func TestSetupGracefulShutdown_TriggersShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{}
	go srv.Serve(ln)
	time.Sleep(50 * time.Millisecond)

	setupGracefulShutdown(srv)

	syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	time.Sleep(300 * time.Millisecond)
}

func TestMain_GatherOptionsError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	defer resetWrappers()
	startSchedulerFn = func() {}
	startOidCheckerFn = func() {}

	monkey.Patch(gatherOptions, func(fs *flag.FlagSet, args ...string) (options, error) {
		return options{}, errors.New("flag error")
	})

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_ValidateError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	defer resetWrappers()
	startSchedulerFn = func() {}
	startOidCheckerFn = func() {}

	monkey.Patch(gatherOptions, func(fs *flag.FlagSet, args ...string) (options, error) {
		return options{}, nil
	})

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

// validOptions returns options that pass Validate() and enableDebug=true
// to cover the debug-level branch in main().
func validOptions() options {
	return options{
		service:     ServiceOptions{ConfigFile: "/fake/config.yaml"},
		enableDebug: true,
	}
}

// patchSuccessUpTo patches all init functions before the given checkpoint
// so that main() reaches the specified line.
type mainCheckpoint string

const (
	checkpointLoadConfig   mainCheckpoint = "loadConfig"
	checkpointInitObs      mainCheckpoint = "initObs"
	checkpointInitConfig   mainCheckpoint = "initConfig"
	checkpointRunMigration mainCheckpoint = "runMigration"
	checkpointNewServer    mainCheckpoint = "newServer"
	checkpointListenAndServe mainCheckpoint = "listenAndServe"
)

func resetWrappers() {
	runMigrationFn = db.RunMigration
	createServerFn = server.New
	serveFn = func(srv *http.Server) error {
		return srv.ListenAndServe()
	}
}

func patchSuccessUpTo(cp mainCheckpoint) {
	startSchedulerFn = func() {}
	startOidCheckerFn = func() {}

	monkey.Patch(gatherOptions, func(fs *flag.FlagSet, args ...string) (options, error) {
		return validOptions(), nil
	})

	if cp == checkpointLoadConfig {
		return
	}
	monkey.Patch(config.LoadConfig, func(path string, cfg *config.Config, remove bool) error {
		return nil
	})

	if cp == checkpointInitObs {
		return
	}
	monkey.Patch(initObsClient, func(cfg *config.Config) error {
		return nil
	})

	if cp == checkpointInitConfig {
		return
	}
	monkey.Patch(initConfig, func(cfg *config.Config) error {
		return nil
	})

	if cp == checkpointRunMigration {
		return
	}
	runMigrationFn = func() error { return nil }

	if cp == checkpointNewServer {
		return
	}
	createServerFn = func(o server.Options) (http.Handler, error) {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), nil
	}

	if cp == checkpointListenAndServe {
		return
	}
}

func TestMain_LoadConfigError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	patchSuccessUpTo(checkpointLoadConfig)

	monkey.Patch(config.LoadConfig, func(path string, cfg *config.Config, remove bool) error {
		return errors.New("load config failed")
	})

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_InitObsClientError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	patchSuccessUpTo(checkpointInitObs)

	monkey.Patch(initObsClient, func(cfg *config.Config) error {
		return errors.New("obs client failed")
	})

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_InitConfigError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	patchSuccessUpTo(checkpointInitConfig)

	monkey.Patch(initConfig, func(cfg *config.Config) error {
		return errors.New("init config failed")
	})

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_RunMigrationError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	defer resetWrappers()
	patchSuccessUpTo(checkpointRunMigration)

	runMigrationFn = func() error {
		return errors.New("migration failed")
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_NewServerError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	defer resetWrappers()
	patchSuccessUpTo(checkpointNewServer)

	createServerFn = func(o server.Options) (http.Handler, error) {
		return nil, errors.New("new server failed")
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}

func TestMain_ListenAndServeError(t *testing.T) {
	patchFatalf()
	defer monkey.UnpatchAll()
	defer resetWrappers()
	patchSuccessUpTo(checkpointListenAndServe)

	serveFn = func(srv *http.Server) error {
		return errors.New("listen and serve failed")
	}

	defer func() {
		r := recover()
		assert.NotNil(t, r, "should have panicked via logrus.Fatalf")
	}()

	main()
}
