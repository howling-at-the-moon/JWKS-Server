package main

import (
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

type JWKSHandler struct{ kms *KeyManager }

func toJWK(pub *rsa.PublicKey, kid string) (jwk.Key, error) {
	jk, err := jwk.FromRaw(pub)
	if err != nil {
		return nil, err
	}
	_ = jk.Set(jwk.KeyIDKey, kid)
	_ = jk.Set(jwk.KeyUsageKey, "sig")
	_ = jk.Set(jwk.AlgorithmKey, "RS256")
	return jk, nil
}

func (h JWKSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setJSON(w)

	set := jwk.NewSet()
	now := time.Now()

	// Only include unexpired keys.
	if h.kms.Active().ExpiresAt.After(now) {
		if jk, err := toJWK(&h.kms.Active().Priv.PublicKey, h.kms.Active().KID); err == nil {
			set.AddKey(jk)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// (Expired key intentionally not included.)

	if err := json.NewEncoder(w).Encode(set); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func setJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
}
