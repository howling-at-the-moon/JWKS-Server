package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func post(t *testing.T, endpoint string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, endpoint, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAuthIssuesValidTokenWithActiveKey(t *testing.T) {
	srv, km := newServer(t)
	defer srv.Close()

	out := post(t, srv.URL+"/auth")
	raw := out["token"].(string)

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if token.Header["kid"] != km.Active().KID {
		t.Fatalf("expected kid %s", km.Active().KID)
	}

	// Validate signature with active key
	token2, err := jwt.Parse(raw, func(tk *jwt.Token) (any, error) {
		return &km.Active().Priv.PublicKey, nil
	})
	if err != nil || !token2.Valid {
		t.Fatalf("expected valid token: %v", err)
	}
	claims := token2.Claims.(jwt.MapClaims)
	if float64(time.Now().Unix()) > claims["exp"].(float64) {
		t.Fatalf("token unexpectedly expired")
	}
}

func TestAuthIssuesExpiredTokenWhenRequested(t *testing.T) {
	srv, km := newServer(t)
	defer srv.Close()

	u, _ := url.Parse(srv.URL + "/auth")
	q := u.Query()
	q.Set("expired", "1")
	u.RawQuery = q.Encode()

	out := post(t, u.String())
	raw := out["token"].(string)

	// Header should carry expired kid
	parser := jwt.NewParser(jwt.WithValidMethods([]string{"RS256"}))
	token, _, err := parser.ParseUnverified(raw, jwt.MapClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if token.Header["kid"] != km.Expired().KID {
		t.Fatalf("expected expired kid %s", km.Expired().KID)
	}

	// Verify signature with expired key's public part (crypto still valid)
	_, err = jwt.Parse(raw, func(tk *jwt.Token) (any, error) {
		return &km.Expired().Priv.PublicKey, nil
	})
	if err == nil {
		// Signature may validate but we expect exp in the past; enforce standard validation:
		t.Fatal("expected validation error due to expiration")
	}
	if !strings.Contains(err.Error(), "token is expired") {
		t.Fatalf("expected expiration error, got: %v", err)
	}
}
