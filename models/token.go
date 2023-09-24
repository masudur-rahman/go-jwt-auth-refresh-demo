package models

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RefreshToken represents a refresh token
type RefreshToken struct {
	gorm.Model
	ID        int64
	UserID    uint
	UUID      string
	ExpiresAt int64
}

// JWTSecret is the secret key for signing JWT tokens
var JWTSecret []byte

// RefreshSecret is the secret key for signing refresh tokens
var RefreshSecret []byte

// TokenExpireDuration is the duration for JWT token expiration
var TokenExpireDuration = time.Hour

// RefreshTokenExpireDuration is the duration for refresh token expiration
var RefreshTokenExpireDuration = time.Hour * 24

func GenerateAccessToken(userID uint) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   strconv.FormatInt(int64(userID), 10),
		Issuer:    "go-jwt-auth-refresh-demo",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return token.SignedString(JWTSecret)
}

func CreateRefreshToken(userID uint) (string, error) {
	uid := uuid.New().String()
	claims := jwt.StandardClaims{
		Id:        uid,
		Subject:   strconv.FormatInt(int64(userID), 10),
		Issuer:    "go-jwt-auth-refresh-demo",
		IssuedAt:  time.Now().Unix(),
		ExpiresAt: time.Now().Add(RefreshTokenExpireDuration).Unix(),
	}

	refreshToken := RefreshToken{
		UserID:    userID,
		UUID:      uid,
		ExpiresAt: claims.ExpiresAt,
	}

	if err := db.Create(&refreshToken).Error; err != nil {
		return "", err
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(RefreshSecret)
}

func VerifyRefreshToken(tokenString string) (*RefreshToken, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return RefreshSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	refreshToken := &RefreshToken{}
	if err = db.Take(refreshToken, RefreshToken{UUID: claims.Id}).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, err
		}
		uid, err := strconv.ParseUint(claims.Subject, 10, 64)
		if err != nil {
			return nil, err
		}

		if err = db.Delete(&RefreshToken{}, &RefreshToken{UserID: uint(uid)}).Error; err != nil {
			return nil, err
		}

		return nil, fmt.Errorf("refresh token already used or invalid")
	}

	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	if err = db.Delete(&RefreshToken{}, &RefreshToken{UUID: claims.Id}).Error; err != nil {
		return nil, err
	}

	return refreshToken, nil
}

func VerifyAccessToken(tokenString string) (*jwt.StandardClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}
	if claims.ExpiresAt < time.Now().Unix() {
		return nil, fmt.Errorf("token expired")
	}

	return claims, nil
}
