package main

import (
	"flag"
	"fmt"
	"github.com/metalogical/BigFiles/db"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/metalogical/BigFiles/auth"
	"github.com/metalogical/BigFiles/config"
	"github.com/metalogical/BigFiles/server"
	"github.com/sirupsen/logrus"
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

func main() {
	o, err := gatherOptions(
		flag.NewFlagSet(os.Args[0], flag.ExitOnError),
		os.Args[1:]...,
	)
	if err != nil {
		logrus.Errorf("new options failed, err:%s", err.Error())

		return
	}

	if err := o.Validate(); err != nil {
		logrus.Errorf("Invalid options, err:%s", err.Error())

		return
	}

	if o.enableDebug {
		logrus.SetLevel(logrus.DebugLevel)
		logrus.Debug("debug enable.")
	}

	//cfg
	cfg := new(config.Config)

	if err := config.LoadConfig(o.service.ConfigFile, cfg, o.service.RemoveCfg); err != nil {
		logrus.Errorf("load config, err:%s", err.Error())

		return
	}

	if err := server.Init(cfg.ValidateConfig); err != nil {
		logrus.Errorf("load ValidateConfig, err:%s", err.Error())

		return
	}

	if err := auth.Init(cfg); err != nil {
		logrus.Errorf("load gitee config, err:%s", err.Error())

		return
	}

	if err := db.Init(cfg.DBConfig); err != nil {
		logrus.Errorf("init database config, err:%s", err.Error())

		return
	}
	s, err := server.New(server.Options{
		Prefix:          cfg.Prefix,
		Bucket:          cfg.LfsBucket,
		Endpoint:        cfg.ObsRegion,
		CdnDomain:       cfg.CdnDomain,
		AccessKeyID:     cfg.ObsAccessKeyId,
		S3Accelerate:    true,
		IsAuthorized:    auth.GiteeAuth(),
		SecretAccessKey: cfg.ObsSecretAccessKey,
	})
	srv := &http.Server{
		Addr:         "0.0.0.0:5000",
		Handler:      s,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("serving on http://0.0.0.0:5000 ...")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalln(err)
	}
}
