package auth

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	HASH_COST = 12
)

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), HASH_COST)
	if err != nil {
		return "", err
	}

	return string(hashed), nil
}

func CheckPasswordHash(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	if userID == uuid.Nil || tokenSecret == "" {
		return "", fmt.Errorf("error: uuid or secret not provided")
	}

	nowUTC := time.Now().UTC()

	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(nowUTC),
		ExpiresAt: jwt.NewNumericDate(nowUTC.Add(expiresIn * time.Second)),
		Subject:   userID.String()}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedString, err := token.SignedString([]byte(tokenSecret))
	if err != nil {
		return "", fmt.Errorf("error: %v", err)
	}

	return signedString, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure signing method is HS256
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(tokenSecret), nil
	})

	if err != nil {
		return uuid.Nil, fmt.Errorf("%v", err)
	}

	if claims, ok := token.Claims.(*jwt.RegisteredClaims); ok && token.Valid {
		uid, err := uuid.Parse(claims.Subject)
		if err != nil {
			return uuid.Nil, err
		}

		return uid, nil
	} else {
		return uuid.Nil, fmt.Errorf("error: invalid token")
	}
}

func GetBearerToken(headers http.Header) (string, error) {
	auth := headers.Get("Authorization")

	if auth != "" && strings.Contains(auth, " ") {
		tokenString := strings.Trim(strings.Split(auth, " ")[1], " ")

		return tokenString, nil
	}

	return "", fmt.Errorf("error: no authorization header")
}
