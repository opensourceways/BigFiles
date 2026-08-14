package db

import (
	"errors"
	"testing"

	"bou.ke/monkey"
	"github.com/metalogical/BigFiles/config"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestRunMigration_nilDb(t *testing.T) {
	origDb := Db
	Db = nil
	defer func() { Db = origDb }()

	assert.Panics(t, func() {
		RunMigration()
	})
}

func TestRunMigration_success(t *testing.T) {
	origDb := Db
	mockDb := &gorm.DB{}
	Db = mockDb
	defer func() { Db = origDb }()

	monkey.Patch((*gorm.DB).AutoMigrate, func(*gorm.DB, ...interface{}) error {
		return nil
	})
	defer monkey.UnpatchAll()

	err := RunMigration()
	assert.NoError(t, err)
}

func TestRunMigration_error(t *testing.T) {
	origDb := Db
	mockDb := &gorm.DB{}
	Db = mockDb
	defer func() { Db = origDb }()

	monkey.Patch((*gorm.DB).AutoMigrate, func(*gorm.DB, ...interface{}) error {
		return errors.New("migration failed")
	})
	defer monkey.UnpatchAll()

	err := RunMigration()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "migration failed")
}

func TestInit_gormOpenError(t *testing.T) {
	monkey.Patch(gorm.Open, func(gorm.Dialector, ...gorm.Option) (*gorm.DB, error) {
		return nil, errors.New("connection refused")
	})
	defer monkey.UnpatchAll()

	cfg := config.DBConfig{
		DatabaseUserName: "user",
		DatabasePassword: "pass",
		DatabaseAddress:  "localhost",
		DatabasePort:     "3306",
		DatabaseName:     "testdb",
	}
	err := Init(cfg)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to connect to database")
}
