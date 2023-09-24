package models

import (
	"fmt"
	"gorm.io/gorm"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	gorm.Model
	Username     string `json:"username"`
	Email        string `json:"email"`
	Password     string `json:"-" gorm:"-"`
	Salt         string `json:"-"`
	PasswordHash string `json:"-"`

	LastLogin int64
}

func CreteUser(user *User) (*User, error) {
	if err := db.First(new(User), &User{Username: user.Username}).Error; err == nil {
		return nil, fmt.Errorf("user already exists")
	}

	user.GeneratePasswordSalt(16)
	if err := user.HashPassword(); err != nil {
		return nil, err
	}

	user.Password = ""
	if err := db.Create(user).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func GetUserByID(id uint) (*User, error) {
	user := &User{}
	if err := db.First(user, id).Error; err != nil {
		return nil, err
	}
	return user, nil
}

func LoginUser(username, password string) (*User, error) {
	user := &User{}
	if err := db.First(user, &User{Username: username}).Error; err != nil {
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password+user.Salt)); err != nil {
		return nil, err
	}

	user.LastLogin = time.Now().Unix()
	if err := db.Save(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

// GeneratePasswordSalt generates a random string of the specified length
func (u *User) GeneratePasswordSalt(n int) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	seed := rand.NewSource(time.Now().UnixNano())
	randSrc := rand.New(seed)

	b := make([]byte, n)
	for i := range b {
		b[i] = charset[randSrc.Intn(len(charset))]
	}

	u.Salt = string(b)
}

// HashPassword hashes a password with a given salt using bcrypt
func (u *User) HashPassword() error {
	if u.Password == "" || u.Salt == "" {
		return fmt.Errorf("password or salt can't be empty")
	}
	// Hash the password with the salt and a cost factor (work factor)
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Password+u.Salt), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.PasswordHash = string(hashedPassword)
	return nil
}
