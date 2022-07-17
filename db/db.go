package db

import (
	"crypto/x509/pkix"
	"errors"
	"sync/atomic"
	"time"

	"github.com/spf13/viper"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB
var serial int64

type SignedCertificate struct {
	ID int64 `gorm:"primaryKey"`

	NotBefore time.Time
	NotAfter  time.Time

	Issuer  pkix.Name `gorm:"serializer:json"`
	Subject pkix.Name `gorm:"serializer:json"`
}

func InitDB() error {
	dbPath := viper.GetString("storage.database")

	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	DB.AutoMigrate(&SignedCertificate{})
	serial, err = lastSerial()
	return err
}

func lastSerial() (int64, error) {
	var lastCert SignedCertificate
	if err := DB.Last(&lastCert).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, nil
		}

		return 0, err
	}

	return lastCert.ID, nil
}

func NextSerial() int64 {
	return atomic.AddInt64(&serial, 1)
}
