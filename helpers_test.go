package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func newServer(t *testing.T) (*httptest.Server, *KeyManager) {
	t.Helper()
	km, err := NewKeyManager()
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/jwks", JWKSHandler{kms: km})
	mux.Handle("/auth", AuthHandler{kms: km})
	return httptest.NewServer(mux), km
}
