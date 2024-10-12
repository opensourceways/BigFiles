package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/akrylysov/algnhsa"
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

	if err := auth.Init(cfg); err != nil {
		logrus.Errorf("load gitee config, err:%s", err.Error())

		return
	}

	bucket := cfg.LfsBucket
	if bucket == "" {
		bucket = os.Getenv("LFS_BUCKET")
		if bucket == "" {
			logrus.Errorf("LFS_BUCKET must be set")
		}
	}

	s, err := server.New(server.Options{
		Prefix:          cfg.Prefix,
		Bucket:          bucket,
		Endpoint:        cfg.AwsRegion,
		AccessKeyID:     cfg.AwsAccessKeyId,
		S3Accelerate:    true,
		IsAuthorized:    auth.GiteeAuth(),
		SecretAccessKey: cfg.AwsSecretAccessKey,
	})
	if err != nil {
		log.Fatalln(err)
	}

	if strings.HasPrefix(os.Getenv("AWS_EXECUTION_ENV"), "AWS_Lambda_") {
		algnhsa.ListenAndServe(s, nil)
	} else {
		log.Println("serving on http://0.0.0.0:5000 ...")
		if err := http.ListenAndServe("0.0.0.0:5000", s); err != nil {
			log.Fatalln(err)
		}
	}
}
