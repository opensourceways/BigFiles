package server

import (
	"errors"
	"fmt"
	"time"

	"github.com/huaweicloud/huaweicloud-sdk-go-obs/obs"
	"github.com/metalogical/BigFiles/db"
)

var ObsClient *obs.ObsClient
var Bucket string
var Prefit string

func StartScheduledTask() {
	for {
		now := time.Now()
		nextRun := time.Date(now.Year(), now.Month(), now.Day(), 3, 0, 0, 0, now.Location())

		if now.After(nextRun) {
			nextRun = nextRun.Add(24 * time.Hour)
		}

		duration := nextRun.Sub(now)
		time.Sleep(duration)

		ScheduledTask()
	}
}

func ScheduledTask() {
	// 获取所有 LfsObj 记录
	lfsObjs, err := db.GetAll()
	if err != nil {
		fmt.Println("Error retrieving LfsObj records:", err)
		return
	}

	if ObsClient != nil {
		fmt.Println("Performing scheduled task with OBS client...")

		for _, obj := range lfsObjs {
			// 调用 check 函数检查每个 Oid
			exists, err := check(obj.Oid)
			if err != nil {
				fmt.Println("Error checking Oid:", err)
				continue // 继续处理下一个记录
			}

			if exists {
				// 如果 check 返回 true，更新 exist 字段为 1
				obj.Exist = 1
				if err := db.DB().Save(&obj).Error; err != nil {
					fmt.Println("Error updating LfsObj record:", err)
				}
			} else {
				// 如果 check 返回 false，删除该记录
				if err := db.DB().Delete(&obj).Error; err != nil {
					fmt.Println("Error deleting LfsObj record:", err)
				}
			}
		}
	} else {
		fmt.Println("Obs_Client is not initialized.")
	}
}

func check(oid string) (bool, error) {
	getObjectMetadataInput := obs.GetObjectMetadataInput{
		Bucket: Bucket,
		Key:    Prefit + oid,
	}

	_, err := ObsClient.GetObjectMetadata(&getObjectMetadataInput)
	if err != nil {
		var obsError obs.ObsError
		if errors.As(err, &obsError) {
			if obsError.Code == "NoSuchKey" {
				return false, nil
			}
		}
		// 其他错误
		return true, err
	}

	return true, nil
}
