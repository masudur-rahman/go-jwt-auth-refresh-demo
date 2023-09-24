package models

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB

func InitDB() error {
	var err error
	db, err = gorm.Open(sqlite.Open("auth.demo"), &gorm.Config{})
	if err != nil {
		return err
	}
	return db.AutoMigrate(&User{}, &RefreshToken{})
}
