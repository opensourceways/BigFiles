package server

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"bou.ke/monkey"
	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/db"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func setupDryRunDB(t *testing.T) {
	t.Helper()
	origDb := db.Db
	dryDb, err := gorm.Open(nil, &gorm.Config{DryRun: true})
	assert.Nil(t, err)
	assert.NotNil(t, dryDb)
	db.Db = dryDb
	t.Cleanup(func() { db.Db = origDb })
}

func Test_check_objectExists(t *testing.T) {
	monkey.Patch(getObsObjectMetadata, func(_ *obs.GetObjectMetadataInput) (*obs.GetObjectMetadataOutput, error) {
		return &obs.GetObjectMetadataOutput{}, nil
	})
	defer monkey.UnpatchAll()

	ObsClient = &obs.ObsClient{}
	Bucket = "test-bucket"
	Prefit = "prefix/"

	exists, err := check("abc123")
	assert.NoError(t, err)
	assert.True(t, exists)
}

func Test_check_noSuchKey(t *testing.T) {
	monkey.Patch(getObsObjectMetadata, func(_ *obs.GetObjectMetadataInput) (*obs.GetObjectMetadataOutput, error) {
		return nil, obs.ObsError{Code: "NoSuchKey"}
	})
	defer monkey.UnpatchAll()

	ObsClient = &obs.ObsClient{}
	Bucket = "test-bucket"
	Prefit = "prefix/"

	exists, err := check("nonexistent")
	assert.NoError(t, err)
	assert.False(t, exists)
}

func Test_check_otherObsError(t *testing.T) {
	monkey.Patch(getObsObjectMetadata, func(_ *obs.GetObjectMetadataInput) (*obs.GetObjectMetadataOutput, error) {
		return nil, obs.ObsError{Code: "AccessDenied"}
	})
	defer monkey.UnpatchAll()

	ObsClient = &obs.ObsClient{}
	Bucket = "test-bucket"
	Prefit = "prefix/"

	exists, err := check("denied-oid")
	assert.Error(t, err)
	assert.True(t, exists)
}

func Test_check_nonObsError(t *testing.T) {
	monkey.Patch(getObsObjectMetadata, func(_ *obs.GetObjectMetadataInput) (*obs.GetObjectMetadataOutput, error) {
		return nil, errors.New("network timeout")
	})
	defer monkey.UnpatchAll()

	ObsClient = &obs.ObsClient{}
	Bucket = "test-bucket"
	Prefit = "prefix/"

	exists, err := check("net-err-oid")
	assert.Error(t, err)
	assert.True(t, exists)
}

func Test_checkExist_objectExists(t *testing.T) {
	monkey.Patch(check, func(oid string) (bool, error) {
		return true, nil
	})
	setupDryRunDB(t)
	defer monkey.UnpatchAll()

	lfsObjs := []db.LfsObj{
		{Oid: "abc123", Owner: "owner", Repo: "repo", CreateTime: time.Now().Add(-2 * time.Hour)},
	}
	checkExist(lfsObjs)
}

func Test_checkExist_expiredObject(t *testing.T) {
	monkey.Patch(check, func(oid string) (bool, error) {
		return true, nil
	})
	setupDryRunDB(t)
	defer monkey.UnpatchAll()

	lfsObjs := []db.LfsObj{
		{Oid: "expired-oid", Owner: "owner", Repo: "repo", CreateTime: time.Now().Add(-48 * time.Hour)},
	}
	checkExist(lfsObjs)
}

func Test_checkExist_checkError(t *testing.T) {
	monkey.Patch(check, func(oid string) (bool, error) {
		return false, errors.New("network timeout")
	})
	defer monkey.UnpatchAll()

	lfsObjs := []db.LfsObj{
		{Oid: "err-oid", Owner: "owner", Repo: "repo", CreateTime: time.Now()},
	}
	checkExist(lfsObjs)
}

func Test_checkExist_objectNotExists(t *testing.T) {
	monkey.Patch(check, func(oid string) (bool, error) {
		return false, nil
	})
	setupDryRunDB(t)
	defer monkey.UnpatchAll()

	lfsObjs := []db.LfsObj{
		{Oid: "notexist-oid", Owner: "owner", Repo: "repo", CreateTime: time.Now().Add(-2 * time.Hour)},
	}
	checkExist(lfsObjs)
}

func TestScanUploadExistTask_nilObsClient(t *testing.T) {
	origObs := ObsClient
	defer func() { ObsClient = origObs }()

	ObsClient = nil

	monkey.Patch(db.GetUploadLfsObj, func() ([]db.LfsObj, error) {
		return []db.LfsObj{}, nil
	})
	defer monkey.UnpatchAll()

	ScanUploadExistTask()
}

func TestScanUploadExistTask_withObsClient(t *testing.T) {
	origObs := ObsClient
	defer func() { ObsClient = origObs }()

	ObsClient = &obs.ObsClient{}

	monkey.Patch(db.GetUploadLfsObj, func() ([]db.LfsObj, error) {
		return []db.LfsObj{{Oid: "abc", Owner: "owner", Repo: "repo", CreateTime: time.Now()}}, nil
	})
	monkey.Patch(check, func(oid string) (bool, error) {
		return true, nil
	})
	setupDryRunDB(t)
	defer monkey.UnpatchAll()

	ScanUploadExistTask()
}

func TestScanUploadExistTask_dbError(t *testing.T) {
	origObs := ObsClient
	defer func() { ObsClient = origObs }()

	ObsClient = nil

	monkey.Patch(db.GetUploadLfsObj, func() ([]db.LfsObj, error) {
		return nil, errors.New("db connection failed")
	})
	defer monkey.UnpatchAll()

	ScanUploadExistTask()
}

func Test_getObsObjectMetadata(t *testing.T) {
	ptr := reflect.ValueOf(getObsObjectMetadata)
	monkey.Patch(ptr.Interface(), func(_ *obs.GetObjectMetadataInput) (*obs.GetObjectMetadataOutput, error) {
		return &obs.GetObjectMetadataOutput{ContentLength: 42}, nil
	})
	defer monkey.UnpatchAll()

	ObsClient = &obs.ObsClient{}
	Bucket = "test-bucket"
	Prefit = "prefix/"

	out, err := getObsObjectMetadata(&obs.GetObjectMetadataInput{
		Bucket: Bucket,
		Key:    Prefit + "test-oid",
	})
	assert.NoError(t, err)
	assert.NotNil(t, out)
	assert.Equal(t, int64(42), out.ContentLength)
}
