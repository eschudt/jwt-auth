package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/eschudt/jwt-auth/auth"
	"github.com/eschudt/jwt-auth/verifier"
)

type JwtToken struct {
	Token string
}

var (
	logger        *log.Logger
	authService   *auth.Service
	verifyService *verifier.Service
	credentials   []auth.LoginDetail
)

func main() {
	listenPort := os.Getenv("NOMAD_PORT_http")
	logger = log.New(os.Stderr, "", 0)

	login1 := auth.LoginDetail{
		Username:  "user1",
		Password:  "password1",
		AccountID: "1",
	}
	login2 := auth.LoginDetail{
		Username:  "user2",
		Password:  "password2",
		AccountID: "2",
	}
	credentials = append(credentials, login1)
	credentials = append(credentials, login2)
	authService = auth.New(credentials)

	verifyService = verifier.New()

	mux := http.NewServeMux()
	mux.HandleFunc("/", helloHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/verify", verifyHandler)
	http.ListenAndServe(":"+listenPort, mux)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		logger.Fatal(err)
	}
	var t auth.LoginDetail
	err = json.Unmarshal(body, &t)
	if err != nil {
		logger.Fatal(err)
	}

	jwtToken := authService.Login(t.Username, t.Password)
	if jwtToken == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	data := JwtToken{jwtToken}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, err := json.Marshal(data)
	if err != nil {
		logger.Fatal(err)
	}
	w.Write(resp)
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	requesterDetails := verifyService.Verify(token)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	resp, err := json.Marshal(requesterDetails)
	if err != nil {
		logger.Fatal(err)
	}
	w.Write(resp)
}
