package krypto

import (
	"github.com/golang-jwt/jwt"
	"os"
)

type UserClaims struct {
	First string `json:"first"`
	Last  string `json:"last"`
	Token string `json:"token"`
	jwt.StandardClaims
}

func NewHs256AccessToken(claims UserClaims) (string, error) {
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return accessToken.SignedString([]byte(os.Getenv("JWT_HS256_KEY")))
}

func NewHs256RefreshToken(claims jwt.StandardClaims) (string, error) {
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return refreshToken.SignedString([]byte(os.Getenv("JWT_HS256_KEY")))
}

func ParseHs256AccessToken(accessToken string) (*UserClaims, error) {
	parsedAccessToken, err := jwt.ParseWithClaims(accessToken, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_HS256_KEY")), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := parsedAccessToken.Claims.(*UserClaims); ok && parsedAccessToken.Valid {
		return claims, nil
	} else {
		return nil, err
	}
}

func ParseHs256RefreshToken(refreshToken string) *jwt.StandardClaims {
	parsedRefreshToken, _ := jwt.ParseWithClaims(refreshToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_HS256_KEY")), nil
	})

	return parsedRefreshToken.Claims.(*jwt.StandardClaims)
}
