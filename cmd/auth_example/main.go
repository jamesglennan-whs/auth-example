package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

const (
	cookieKey  = "auth"
	userHeader = "User"
	passHeader = "Pass"
	authHeader = "Authorization"
	secretKey  = "mySecretKey"
)

var jwtKey = []byte(secretKey)

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

// Create a struct that will be encoded to a JWT.
// We add jwt.StandardClaims as an embedded type, to provide fields like expiry time
type Claims struct {
	Username string `json:"username"`
	Tenant   string `json:"tenant"`
	jwt.StandardClaims
}

func main() {

	fmt.Println("Starting Fake Auth Service")
	stopCh := make(chan struct{})
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt)

	go func() {
		<-signalCh
		close(stopCh)
		os.Exit(1)
	}()

	// /auth is our authentication endpoint
	http.HandleFunc("/auth", Auth)

	// start the server on port 3000
	log.Fatal(http.ListenAndServe(":3000", nil))

}

//Auth - super insecure authentication method, for demonstrating API gateway authentication
func Auth(w http.ResponseWriter, r *http.Request) {

	if a, ok := r.Header[http.CanonicalHeaderKey(authHeader)]; ok {
		auth := strings.Replace(a[0], "bearer ", "", -1)
		fmt.Println("Header Auth")
		if checkAuth(w, auth) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		}
		return
	} else if auth, err := r.Cookie(cookieKey); err == nil {
		fmt.Println("Cookie Auth")
		if checkAuth(w, auth.Value) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "OK")
		}
		return

	} else {

		if user, ok := r.Header[http.CanonicalHeaderKey(userHeader)]; ok {
			if pass, ok := r.Header[http.CanonicalHeaderKey(passHeader)]; ok {
				if users[user[0]] == pass[0] {
					token := getJWTToken(w, user[0])
					if len(token) > 0 {
						fmt.Fprintf(w, "Authentication via user/pass: %v", token)
						return
					}
				}
			}
		}
	}

	w.WriteHeader(http.StatusUnauthorized)
	fmt.Fprintln(w, "AUTH FAILED")

}

func getJWTToken(w http.ResponseWriter, user string) string {
	var tenant string
	if user == "user2" {
		tenant = "tenantB"
	} else {
		tenant = "tenantA"
	}

	// Declare the expiration time of the token
	// here, we have kept it as 5 minutes
	expirationTime := time.Now().Add(5 * time.Minute)
	tkn := setToken(w, user, tenant, expirationTime)
	return tkn

}

func setToken(w http.ResponseWriter, user, tenant string, expirationTime time.Time) string {
	// Create the JWT claims, which includes the username and expiry time
	claims := &Claims{
		Username: user,
		Tenant:   tenant,
		StandardClaims: jwt.StandardClaims{
			// In JWT, the expiry time is expressed as unix milliseconds
			ExpiresAt: expirationTime.Unix(),
		},
	}

	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		return ""
	}
	// Finally, we set the client cookie for "token" as the JWT we just generated
	// we also set an expiry time which is the same as the token itself
	http.SetCookie(w, &http.Cookie{
		Name:    cookieKey,
		Value:   tokenString,
		Expires: expirationTime,
	})

	w.Header().Add(authHeader, "bearer "+tokenString)
	w.WriteHeader(http.StatusAccepted)
	fmt.Println(tokenString)
	return tokenString
}

func checkAuth(w http.ResponseWriter, token string) bool {
	// Initialize a new instance of `Claims`
	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(token, claims, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	if err != nil {
		fmt.Print(err.Error())
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		w.WriteHeader(http.StatusBadRequest)
		return false
	}
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return false
	}

	return true

}
