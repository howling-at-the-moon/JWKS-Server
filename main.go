package main

import (
	"log"
	"net/http"
)

func main() {
	km, err := NewKeyManager()
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/jwks", JWKSHandler{kms: km})
	mux.Handle("/auth", AuthHandler{kms: km})

	log.Println("JWKS server listening on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
