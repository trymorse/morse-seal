package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestEachRouteCrossesPlainOrSealedAsTheListSays(t *testing.T) {
	for _, c := range []struct {
		method, path string
		sealed       bool
	}{
		{"GET", "/v1/models", false},
		{"GET", "/v1/attestation", false},
		{"GET", "/v1/receipts/rcpt_1", false},
		{"GET", "/v1/videos/video_1", false},
		{"GET", "/v1/videos/video_1/content", true},
		{"POST", "/v1/chat/completions", true},
		{"POST", "/v1/chat/compact", true},
		{"POST", "/v1/images/generations", true},
		{"POST", "/v1/videos", true},
		{"POST", "/v1/search", true},
		{"POST", "/v1/fetch", true},
		{"POST", "/v1/research", true},
		{"GET", "/v1/research/r_1", true},
		{"GET", "/v1/research/r_1/events", true},
		{"GET", "/v1/lookup/coingecko/simple/price", true},
		{"POST", "/v1/audio/transcriptions", true},
		{"POST", "/v1/models", true},
		{"GET", "/v1/receipts", true},
		{"POST", "/v1/anything/else", true},
	} {
		r, relayServer := newRelay(t)
		sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
		req, err := http.NewRequest(c.method, sidecar.URL+c.path, strings.NewReader(`{"model":"stub"}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		r.mu.Lock()
		sealed := len(r.opened) == 1
		r.mu.Unlock()
		if sealed != c.sealed {
			t.Errorf("%s %s: sealed %t, want %t", c.method, c.path, sealed, c.sealed)
		}
		if !c.sealed && r.attestations.Load() != 0 && c.path != "/v1/attestation" {
			t.Errorf("%s %s: a plain route fetched %d attestations", c.method, c.path, r.attestations.Load())
		}
	}
}
