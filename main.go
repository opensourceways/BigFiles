package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/sirupsen/logrus"

	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/config"
	"github.com/metalogical/BigFiles/db"
	"github.com/metalogical/BigFiles/server"
)

type options struct {
	service     ServiceOptions
	enableDebug bool
}

type ServiceOptions struct {
	ConfigFile string
	RemoveCfg  bool
}

// Validate checks if the ServiceOptions are valid.
// It returns an error if the config file is missing.
func (o *ServiceOptions) Validate() error {
	if o.ConfigFile == "" {
		return fmt.Errorf("missing config-file")
	}

	return nil
}

// AddFlags adds flags for ServiceOptions to the provided FlagSet.
func (o *ServiceOptions) AddFlags(fs *flag.FlagSet) {
	fs.StringVar(&o.ConfigFile, "config-file", "", "Path to config file.")
	fs.BoolVar(&o.RemoveCfg, "rm-cfg", false, "whether remove the cfg file after initialized .")
}

// Validate validates the options and returns an error if any validation fails.
func (o *options) Validate() error {
	return o.service.Validate()
}

func gatherOptions(fs *flag.FlagSet, args ...string) (options, error) {
	var o options
	o.service.AddFlags(fs)

	fs.BoolVar(
		&o.enableDebug, "enable_debug", false, "whether to enable debug model.",
	)

	err := fs.Parse(args)
	return o, err
}

func initConfig(cfg *config.Config) error {
	if err := server.Init(cfg); err != nil {
		return fmt.Errorf("load ValidateConfig: %w", err)
	}

	if err := auth.Init(cfg); err != nil {
		return fmt.Errorf("load gitee config: %w", err)
	}

	if err := db.Init(cfg.DBConfig); err != nil {
		return fmt.Errorf("init database config: %w", err)
	}

	return nil
}

func initObsClient(cfg *config.Config) error {
	var err error
	server.ObsClient, err = obs.New(cfg.ObsAccessKeyId, cfg.ObsSecretAccessKey,
		cfg.ObsRegion, obs.WithSignature(obs.SignatureObs))
	server.Bucket = cfg.LfsBucket
	server.Prefit = cfg.Prefix
	if err != nil {
		return fmt.Errorf("failed to initialize OBS client: %w", err)
	}
	return nil
}

var runMigrationFn = db.RunMigration

func runMigration() error {
	return runMigrationFn()
}

var createServerFn = server.New

func createServer(opts server.Options) (http.Handler, error) {
	return createServerFn(opts)
}

var startSchedulerFn = server.StartScheduledTask

func startScheduler() {
	startSchedulerFn()
}

var startOidCheckerFn = server.ScheduledCheckOidAndFileName

func startOidChecker() {
	startOidCheckerFn()
}

var serveFn = func(srv *http.Server) error {
	return srv.ListenAndServe()
}

func serve(srv *http.Server) error {
	return serveFn(srv)
}

func reapZombies(sigChld <-chan os.Signal) {
	for range sigChld {
		for {
			pid, _ := syscall.Wait4(-1, nil, syscall.WNOHANG, nil)
			if pid <= 0 {
				break
			}
		}
	}
}

func setupGracefulShutdown(srv *http.Server) <-chan os.Signal {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-quit
		log.Println("shutting down server...")
		if err := srv.Shutdown(nil); err != nil {
			logrus.Errorf("server shutdown error: %v", err)
		}
	}()
	return quit
}

func main() {
	o, err := gatherOptions(
		flag.NewFlagSet(os.Args[0], flag.ExitOnError),
		os.Args[1:]...,
	)
	if err != nil {
		logrus.Fatalf("new options failed, err:%s", err.Error())
	}

	if err := o.Validate(); err != nil {
		logrus.Fatalf("Invalid options, err:%s", err.Error())
	}

	if o.enableDebug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("debug enable.")
	}

	// Reap zombie child processes (e.g. git commands invoked by GetLFSMapping).
	// Without this, zombie [git] processes accumulate and exhaust the node PID
	// table, causing PIDPressure evictions.
	sigChld := make(chan os.Signal, 1)
	signal.Notify(sigChld, syscall.SIGCHLD)
	go reapZombies(sigChld)

	//cfg
	cfg := new(config.Config)

	if err := config.LoadConfig(o.service.ConfigFile, cfg, o.service.RemoveCfg); err != nil {
		logrus.Fatalf("load config, err:%s", err.Error())
	}

	if err := initObsClient(cfg); err != nil {
		logrus.Fatalf("init OBS client failed: %v", err)
	}

	if err := initConfig(cfg); err != nil {
		logrus.Fatalf("init config failed: %v", err)
	}

	// Run database schema migration once at startup instead of on every insert.
	if err := runMigration(); err != nil {
		logrus.Fatalf("run database migration failed: %v", err)
	}

	s, err := createServer(server.Options{
		Prefix:          cfg.Prefix,
		Bucket:          cfg.LfsBucket,
		Endpoint:        cfg.ObsRegion,
		CdnDomain:       cfg.CdnDomain,
		AccessKeyID:     cfg.ObsAccessKeyId,
		S3Accelerate:    true,
		IsAuthorized:       auth.GiteeAuth(),
		IsGithubAuthorized: auth.GithubAuth(),
		SecretAccessKey:    cfg.ObsSecretAccessKey,
	})
	if err != nil {
		logrus.Fatalf("create server failed: %v", err)
	}

	go startScheduler()
	go startOidChecker()

	srv := &http.Server{
		Addr:         "0.0.0.0:5000",
		Handler:      s,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Graceful shutdown: listen for SIGTERM/SIGINT and call srv.Shutdown()
	setupGracefulShutdown(srv)

	log.Println("serving on http://0.0.0.0:5000 ...")
	if err := serve(srv); err != nil && err != http.ErrServerClosed {
		logrus.Fatalf("server error: %v", err)
	}
}
