package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"log"
)

type Metadata struct {
	OID   string `gorm:"column:oid"`
	Exist int    `gorm:"column:exist"`
}

var db *gorm.DB
var s3Client *s3.S3

// Initialize MySQL and OBS (S3) connections
func init() {
	var err error
	dsn := "your_user:your_password@tcp(your_host:3306)/your_database?charset=utf8mb4&parseTime=True&loc=Local"
	db, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String("your_region"),
		Credentials: credentials.NewStaticCredentials("your_access_key", "your_secret_key", ""),
	})
	if err != nil {
		log.Fatalf("failed to create session: %v", err)
	}

	s3Client = s3.New(sess)
}

// Check if object exists in S3
func checkObjectExists(bucket, oid string) (bool, error) {
	_, err := s3Client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(oid),
	})
	if err != nil {
		if err.(awserr.Error).Code() == s3.ErrCodeNoSuchKey {
			return false, nil // Object does not exist
		}
		return false, err // Other error
	}
	return true, nil // Object exists
}

// Periodic task to check and clean up metadata
func cleanupMetadata() {
	var metadataList []Metadata
	if err := db.Where("exist = ?", 1).Find(&metadataList).Error; err != nil {
		log.Printf("failed to query metadata: %v", err)
		return
	}

	for _, metadata := range metadataList {
		exists, err := checkObjectExists("your_bucket_name", metadata.OID)
		if err != nil {
			log.Printf("error checking existence for %s: %v", metadata.OID, err)
			continue
		}
		if !exists {
			// Delete the metadata if the object does not exist
			if err := db.Delete(&metadata).Error; err != nil {
				log.Printf("failed to delete metadata %s: %v", metadata.OID, err)
			} else {
				log.Printf("Deleted metadata with OID: %s", metadata.OID)
			}
		}
	}
}

func main() {
	c := cron.New()
	c.AddFunc("@every 10m", cleanupMetadata) // 每10分钟执行一次
	c.Start()

	// Keep the program running
	select {}
}
