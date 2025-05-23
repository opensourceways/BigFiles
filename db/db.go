package db

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/metalogical/BigFiles/config"
)

var (
	Db *gorm.DB
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

	Db = dbInstance

	return nil
}

// DB returns the current database instance.
func DB() *gorm.DB {
	return Db
}

type LfsObj struct {
	ID         int       `gorm:"primaryKey;autoIncrement;comment:'自增ID'"`
	Oid        string    `gorm:"size:511;not null;default:'';index:idx_oid;comment:'文件OID'"`
	Size       int       `gorm:"not null;comment:'文件大小'"`
	Platform   string    `gorm:"size:64;not null;default:'gitee';index:idx_platform;comment:'所属平台，默认为gitee'"`
	Owner      string    `gorm:"size:100;not null;index:idx_platform;comment:'仓库owner'"`
	Repo       string    `gorm:"size:100;not null;index:idx_platform;comment:'仓库名称'"`
	Operator   string    `gorm:"size:100;comment:'上一次操作人'"`
	Exist      int       `gorm:"not null;type:TINYINT;comment:'存在状态，1:存在，0:已删除'"`
	UpdateTime time.Time `gorm:"not null;type:timestamp;default:CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP;"`
	CreateTime time.Time `gorm:"not null;type:timestamp;default:CURRENT_TIMESTAMP;comment:'创建时间'"`
}

// InsertLFSObj 插入 LFS 元数据
func InsertLFSObj(obj LfsObj) error {
	err := Db.AutoMigrate(&LfsObj{})
	if err != nil {
		return err
	}

	var existingObj LfsObj
	if err := Db.Where("oid = ? AND repo = ? AND owner = ?", obj.Oid,
		obj.Repo, obj.Owner).First(&existingObj).Error; err == nil {
		return nil
	}

	result := Db.Create(&obj)
	if result.Error != nil {
		return fmt.Errorf("failed to insert LFS object: %w", result.Error)
	}
	return nil
}

// DeleteLFSObj 删除 LFS 元数据
func DeleteLFSObj(obj LfsObj) error {
	result := Db.Where("repo_name = ? AND oid = ? AND owner = ?",
		obj.Repo, obj.Oid, obj.Owner).Delete(&LfsObj{})
	if result.Error != nil {

		return fmt.Errorf("failed to delete LFS object: %w", result.Error)
	}
	return nil
}

// CountLFSObj 查找指定 OID 的 LFS 元数据数量
func CountLFSObj(obj LfsObj) (int64, error) {
	var count int64
	result := Db.Model(&LfsObj{}).Where("oid = ?", obj.Oid).Count(&count)
	if result.Error != nil {
		return 0, fmt.Errorf("failed to count LFS objects: %w", result.Error)
	}
	return count, nil
}

// GetUploadLfsObj 获取所有 Exist=2 的 LfsObj
func GetUploadLfsObj() ([]LfsObj, error) {
	var results []LfsObj
	// 查询所有 Exist=2 的记录
	if err := Db.Where("exist = ?", 2).Find(&results).Error; err != nil {
		return nil, fmt.Errorf("failed to get LfsObj: %w", err)
	}
	return results, nil
}

// SelectLfsObjByOid 通过OID查找指定了LFS数据
func SelectLfsObjByOid(oid string) ([]LfsObj, error) {
	var result []LfsObj
	if err := Db.Where("oid = ?", oid).Find(&result).Error; err != nil {
		return nil, fmt.Errorf("failed to get LfsObj: %w", err)
	}
	return result, nil
}
