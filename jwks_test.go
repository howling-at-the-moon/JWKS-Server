package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

func TestJWKSIncludesOnlyActive(t *testing.T) {
	srv, km := newServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var set jwk.Set
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		t.Fatal(err)
	}
	if set.Len() != 1 {
		t.Fatalf("expected 1 key, got %d", set.Len())
	}
	k := set.Keys()[0]
	if kid, _ := k.Get(jwk.KeyIDKey); kid != km.Active().KID {
		t.Fatalf("expected kid %s", km.Active().KID)
	}
}
