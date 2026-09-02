package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsPrime(t *testing.T) {
	cases := map[int]bool{
		0: false, 1: false, 2: true, 3: true, 4: false, 17: true, 18: false,
	}
	for n, want := range cases {
		if got := IsPrime(n); got != want {
			t.Errorf("IsPrime(%d) = %v, want %v", n, got, want)
		}
	}
}

func TestReverse(t *testing.T) {
	if got := Reverse("hello"); got != "olleh" {
		t.Errorf("Reverse(hello) = %q, want %q", got, "olleh")
	}
	if got := Reverse(""); got != "" {
		t.Errorf("Reverse(\"\") = %q, want empty string", got)
	}
}

func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	healthHandler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}
	if got := rec.Body.String(); got != "{\"status\":\"ok\"}\n" {
		t.Errorf("unexpected body: %q", got)
	}
}
