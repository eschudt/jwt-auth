package auth

import (
	"fmt"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

type LoginDetail struct {
	Username  string
	Password  string
	AccountID string
}

type Service struct {
	credentials []LoginDetail
}

func New(credentials []LoginDetail) *Service {
	return &Service{
		credentials: credentials,
	}
}

func (s *Service) Login(login, password string) string {
	for _, credential := range s.credentials {
		if login == credential.Username && password == credential.Password {
			// Create a new token object, specifying signing method and the claims
			// you would like it to contain.
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
				"accountID": credential.AccountID,
				"isService": false,
				"nbf":       time.Date(2015, 10, 10, 12, 0, 0, 0, time.UTC).Unix(),
			})

			// Sign and get the complete encoded token as a string using the secret
			hmacSampleSecret := []byte("hmacSampleSecret")
			tokenString, err := token.SignedString(hmacSampleSecret)
			if err != nil {
				fmt.Printf("err: %s", err.Error())
				fmt.Println()
			}

			fmt.Printf("Computed Token: %s", tokenString)
			fmt.Println()
			return tokenString
		}
	}

	return ""
}
