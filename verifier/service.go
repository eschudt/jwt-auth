package verifier

import (
	"fmt"
	jwt "github.com/dgrijalva/jwt-go"
)

type Service struct {

}

type RequesterDetails struct {
	AccountID string
	IsService bool
}

func New() *Service {
	return &Service{}
}

func (s *Service) Verify(tokenString string) RequesterDetails {
	// Parse takes the token string and a function for looking up the key. The latter is especially
	// useful if you use multiple keys for your application.  The standard is to use 'kid' in the
	// head of the token to identify which key to use, but the parsed token (head and claims) is provided
	// to the callback, providing flexibility.
	token, _ := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
	    // Don't forget to validate the alg is what you expect:
	    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
	        return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
	    }

	    // hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
			hmacSampleSecret := []byte("hmacSampleSecret")
	    return hmacSampleSecret, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		isService := claims["isService"].(bool)
		accountID := claims["accountID"].(string)
		return RequesterDetails{
			accountID,
			isService,
		}
	}

	return RequesterDetails{}
}
