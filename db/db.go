package db

import (
	"log"

	"github.com/metalogical/BigFiles/config"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	db *gorm.DB
)

// Init initializes the database connection and configuration.
func Init(cfg config.DBConfig) error {
	dsn := cfg.Dsn()
	dbInstance, err := gorm.Open(
		mysql.Open(dsn),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Info),
		},
	)
	if err != nil {
		log.Fatal("Failed to connect to database", err)
		return err
	}

	sqlDb, err := dbInstance.DB()
	if err != nil {
		return err
	}

	sqlDb.SetConnMaxLifetime(cfg.GetLifeDuration())
	sqlDb.SetMaxOpenConns(cfg.MaxConn)
	sqlDb.SetMaxIdleConns(cfg.MaxIdle)

	db = dbInstance

	return nil
}

// DB returns the current database instance.
func DB() *gorm.DB {
	return db
}
