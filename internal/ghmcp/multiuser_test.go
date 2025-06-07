package ghmcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

type dummyRequest struct {
	Test string `json:"test"`
}

func TestMultiUserHTTPServer_TokenRequired(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractTokenFromRequest(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing GitHub token in Authorization header"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	ts := httptest.NewServer(h)
	defer ts.Close()

	// No Authorization header
	resp, err := http.Post(ts.URL, "application/json", bytes.NewBufferString(`{"test":"noauth"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", resp.StatusCode)
	}
}

func TestMultiUserHTTPServer_ValidToken(t *testing.T) {
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractTokenFromRequest(r)
		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"missing GitHub token in Authorization header"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true,"token":"` + token + `"}`))
	})

	ts := httptest.NewServer(h)
	defer ts.Close()

	// With Authorization header
	body, _ := json.Marshal(dummyRequest{Test: "authed"})
	req, _ := http.NewRequest("POST", ts.URL, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer testtoken123")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", resp.StatusCode)
	}
	data, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(data, []byte("testtoken123")) {
		t.Errorf("expected token in response, got %s", string(data))
	}
}
