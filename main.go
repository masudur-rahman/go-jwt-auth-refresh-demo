package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/masudur-rahman/go-jwt-auth-refresh-demo/models"
)

func reqAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(ctx echo.Context) (err error) {
			var user *models.User
			username, passwd, ok := ctx.Request().BasicAuth()
			if ok {
				user, err = models.LoginUser(username, passwd)
				if err != nil {
					return ctx.String(http.StatusUnauthorized, "Login failed")
				}
			} else {
				token := strings.Fields(ctx.Request().Header.Get("Authorization"))
				if len(token) < 2 {
					return ctx.String(http.StatusUnauthorized, "Authorization token is required")
				}

				claims, err := models.VerifyAccessToken(token[1])
				if err != nil {
					return ctx.String(http.StatusUnauthorized, "Invalid token")
				}

				id, err := strconv.ParseUint(claims.Subject, 10, 64)
				if err != nil {
					return ctx.String(http.StatusUnauthorized, "userid parse error")
				}

				user, err = models.GetUserByID(uint(id))
				if err != nil {
					return ctx.String(http.StatusUnauthorized, "user not found")
				}
			}

			ctx.Set("user", user)

			return next(ctx)
		}
	}
}

func main() {
	models.JWTSecret = []byte("secret")
	models.RefreshSecret = []byte("refresh-secret")
	if err := models.InitDB(); err != nil {
		log.Fatalln(err)
	}

	e := echo.New()
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	e.GET("/", Hello)
	auth := e.Group("/auth")
	auth.POST("/register", Register)
	auth.POST("/login", Login)
	auth.POST("/refresh", RefreshToken)

	user := e.Group("/user")
	user.Use(reqAuth())
	user.GET("/me", Me)

	e.Logger.Fatal(e.Start(":1323"))
}

func Hello(ctx echo.Context) error {
	return ctx.String(http.StatusOK, "Hello, World!")
}

func Me(ctx echo.Context) error {
	user, ok := ctx.Get("user").(*models.User)
	if !ok {
		return ctx.String(http.StatusUnauthorized, "user not found")
	}

	return ctx.JSON(http.StatusOK, user)
}

type UserParams struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Register(ctx echo.Context) error {
	params := new(UserParams)
	if err := ctx.Bind(params); err != nil {
		return err
	}
	user := &models.User{
		Username: params.Username,
		Password: params.Password,
	}

	if _, err := models.CreteUser(user); err != nil {
		return err
	}

	ctx.Response().WriteHeader(http.StatusOK)
	return nil
}

type AccessToken struct {
	AccessToken  string `json:"accessToken,omitempty"`
	RefreshToken string `json:"refreshToken"`
}

func Login(ctx echo.Context) error {
	params := new(UserParams)
	if err := ctx.Bind(params); err != nil {
		return err
	}
	user, err := models.LoginUser(params.Username, params.Password)
	if err != nil {
		return ctx.String(http.StatusUnauthorized, "Login failed")
	}

	accessToken, err := models.GenerateAccessToken(user.ID)
	if err != nil {
		return err
	}

	refreshToken, err := models.CreateRefreshToken(user.ID)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, &AccessToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}

func RefreshToken(ctx echo.Context) error {
	t := new(AccessToken)
	if err := ctx.Bind(t); err != nil {
		return err
	}
	if t.RefreshToken == "" {
		return ctx.String(http.StatusBadRequest, "refreshToken is required")
	}

	token, err := models.VerifyRefreshToken(t.RefreshToken)
	if err != nil {
		return ctx.String(http.StatusBadRequest, "invalid refreshToken")
	}

	accessToken, err := models.GenerateAccessToken(token.UserID)
	if err != nil {
		return err
	}

	refreshToken, err := models.CreateRefreshToken(token.UserID)
	if err != nil {
		return err
	}

	return ctx.JSON(http.StatusOK, &AccessToken{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	})
}
