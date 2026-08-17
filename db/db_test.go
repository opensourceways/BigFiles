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

func TestDB_ReturnsCurrentInstance(t *testing.T) {
	origDb := Db
	mockDb := &gorm.DB{}
	Db = mockDb
	defer func() { Db = origDb }()

	assert.Equal(t, mockDb, DB())
}

func setupDryRunDB(t *testing.T) {
	t.Helper()
	origDb := Db
	dryDb, err := gorm.Open(nil, &gorm.Config{DryRun: true})
	assert.Nil(t, err)
	assert.NotNil(t, dryDb)
	Db = dryDb
	t.Cleanup(func() { Db = origDb })
}

func TestInsertLFSObj_DryRun(t *testing.T) {
	setupDryRunDB(t)
	obj := LfsObj{Oid: "dryrun-oid", Repo: "repo", Owner: "owner", Size: 100}
	_ = InsertLFSObj(obj)
}

func TestDeleteLFSObj_DryRun(t *testing.T) {
	setupDryRunDB(t)
	obj := LfsObj{Oid: "dryrun-oid", Repo: "repo", Owner: "owner"}
	_ = DeleteLFSObj(obj)
}

func TestCountLFSObj_DryRun(t *testing.T) {
	setupDryRunDB(t)
	obj := LfsObj{Oid: "dryrun-oid"}
	_, _ = CountLFSObj(obj)
}

func TestGetUploadLfsObj_DryRun(t *testing.T) {
	setupDryRunDB(t)
	_, _ = GetUploadLfsObj()
}

func TestSelectLfsObjByOid_DryRun(t *testing.T) {
	setupDryRunDB(t)
	_, _ = SelectLfsObjByOid("dryrun-oid")
}

func TestUpdateLFSObjFileName_EmptyOID(t *testing.T) {
	err := UpdateLFSObjFileName("", "new.txt", "user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "OID")
}

func TestUpdateLFSObjFileName_EmptyFileName(t *testing.T) {
	err := UpdateLFSObjFileName("oid123", "", "user")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "文件名")
}

func TestUpdateLFSObjFileName_DryRun(t *testing.T) {
	setupDryRunDB(t)
	_ = UpdateLFSObjFileName("oid123", "new.txt", "user")
}

func TestUpdateLFSObjFileName_SameFileName(t *testing.T) {
	setupDryRunDB(t)

	monkey.Patch((*gorm.DB).Where, func(db *gorm.DB, query interface{}, args ...interface{}) *gorm.DB {
		return db
	})
	monkey.Patch((*gorm.DB).First, func(db *gorm.DB, dest interface{}, conds ...interface{}) *gorm.DB {
		if ptr, ok := dest.(*LfsObj); ok {
			ptr.FileName = "same.txt"
		}
		return &gorm.DB{}
	})
	defer monkey.UnpatchAll()

	err := UpdateLFSObjFileName("oid123", "same.txt", "user")
	assert.NoError(t, err, "same file name should skip update")
}
