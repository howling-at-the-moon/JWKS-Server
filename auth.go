package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type AuthHandler struct{ kms *KeyManager }

func (h AuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setJSON(w)
	if r.Method != http.MethodPost {
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return
	}
	useExpired := r.URL.Query().Has("expired")

	var kr KeyRecord
	var exp time.Time
	if useExpired {
		kr = h.kms.Expired()
		exp = time.Now().Add(-10 * time.Minute) // already expired
	} else {
		kr = h.kms.Active()
		exp = time.Now().Add(15 * time.Minute)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "fake-user-123",
		"iat": time.Now().Unix(),
		"exp": exp.Unix(),
		"iss": "http://localhost:8080",
		"aud": "jwks-demo",
	})
	token.Header["kid"] = kr.KID

	signed, err := token.SignedString(kr.Priv)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(`{"token":"` + signed + `"}`))
}
