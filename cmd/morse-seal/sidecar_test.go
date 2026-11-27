package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trymorse/morse-seal/verify"
	"github.com/trymorse/morse-seal/seal"
)

type relay struct {
	t            *testing.T
	mu           sync.Mutex
	identity     *seal.Identity
	environment  string
	attestations atomic.Int32
	plainContent atomic.Int32
	opened       []seal.Request
	refuseClear  int
	behind       time.Duration
	cut          bool
	veiled       string
}

func newRelay(t *testing.T) (*relay, *httptest.Server) {
	identity, err := seal.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	r := &relay{t: t, identity: identity, environment: "dev"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attestation", r.attestation)
	mux.HandleFunc("POST /v1/sealed", r.sealed)
	mux.HandleFunc("GET /v1/models", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Authorization") != "Bearer sk_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"object":"list","data":[{"id":"stub"}]}`)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		r.plainContent.Add(1)
		w.WriteHeader(http.StatusTeapot)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return r, server
}

func (r *relay) rotate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identity, _ = seal.NewIdentity()
}

func (r *relay) attestation(w http.ResponseWriter, req *http.Request) {
	r.attestations.Add(1)
	r.mu.Lock()
	now := time.Now().Add(-r.behind)
	document := verify.StandIn{Environment: r.environment, PublicKey: r.identity.PublicKey(), IssuedAt: now}.Document()
	r.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"object": "proxy_attestation", "environment": r.environment, "instances": []string{base64.StdEncoding.EncodeToString(document)}, "proxy_time": now.Unix()})
}

func (r *relay) sealed(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != "Bearer sk_test" || req.Header.Get("Content-Type") != seal.ContentType {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"code":"invalid_api_key"}}`)
		return
	}
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	opened, err := r.identity.Open(body)
	if err == nil {
		r.opened = append(r.opened, opened)
	}
	refuseClear, cut, veiled := r.refuseClear, r.cut, r.veiled
	r.mu.Unlock()
	if err == seal.ErrKeyUnknown {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMisdirectedRequest)
		io.WriteString(w, `{"error":{"code":"sealed_key_unknown"},"instances":[]}`)
		return
	}
	if err != nil {
		r.t.Errorf("open: %v", err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if refuseClear != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(refuseClear)
		io.WriteString(w, `{"error":{"code":"rate_limit_exceeded"}}`)
		return
	}
	w.Header().Set("Content-Type", seal.ContentType)
	w.Header().Set("X-Request-Id", "req_123")
	w.WriteHeader(http.StatusOK)
	g := &gate{w: w}
	flushed := make(chan struct{}, 8)
	stream, err := seal.NewStream(g, func() {
		g.flush()
		flushed <- struct{}{}
	}, opened.CEK)
	if err != nil {
		r.t.Fatal(err)
	}
	head := seal.ReplyHead{Status: 200, Headers: http.Header{"Content-Type": {"text/event-stream"}}}
	if veiled != "" {
		head.Headers.Set(headerPrivacyVeil, veiled)
	}
	stream.Begin(head)
	for _, line := range []string{`data: {"choices":[{"delta":{"content":"hel"}}]}`, `data: {"choices":[{"delta":{"content":"lo"}}]}`, "data: [DONE]"} {
		io.WriteString(stream, line+"\n\n")
		if cut {
			<-flushed
			<-flushed
			g.shut()
			return
		}
		time.Sleep(60 * time.Millisecond)
	}
	stream.Close()
}

type gate struct {
	mu     sync.Mutex
	w      http.ResponseWriter
	closed bool
}

func (g *gate) Write(p []byte) (int, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return len(p), nil
	}
	return g.w.Write(p)
}

func (g *gate) flush() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed {
		http.NewResponseController(g.w).Flush()
	}
}

func (g *gate) shut() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
}

func writePins(t *testing.T) string {
	path := filepath.Join(t.TempDir(), "pins.json")
	os.WriteFile(path, []byte(`[{"commit":"c0ffee","version":"v1","environment":"dev","pcr0":"`+strings.Repeat("a0", 48)+`","pcr1":"`+strings.Repeat("a1", 48)+`","pcr2":"`+strings.Repeat("a2", 48)+`","built_at":"2026-10-01T00:00:00Z","revoked":false}]`), 0o600)
	return path
}

func startSidecar(t *testing.T, upstream string, environment, floor string, dev bool) *httptest.Server {
	s, err := configure(options{upstream: upstream, key: "sk_test", pins: writePins(t), env: environment, floor: floor, dev: dev})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	return server
}

func post(t *testing.T, base, path, body string) (*http.Response, string) {
	resp, err := http.Post(base+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

const chat = `{"model":"stub","stream":true,"messages":[{"role":"user","content":"hi"}]}`

func TestAChatIsSealedWithTheFloorAndItsStreamedReplyOpened(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startSidecar(t, relayServer.URL, "dev", "tee", true)
	resp, body := post(t, sidecar.URL, "/v1/chat/completions?x=1", chat)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" || resp.Header.Get("X-Request-Id") != "req_123" {
		t.Fatalf("status %d, headers %v", resp.StatusCode, resp.Header)
	}
	if !strings.Contains(body, `"content":"hel"`) || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("body %q", body)
	}
	if len(r.opened) != 1 || r.plainContent.Load() != 0 {
		t.Fatalf("%d sealed requests opened, %d plain content requests", len(r.opened), r.plainContent.Load())
	}
	inner := r.opened[0]
	if inner.Method != "POST" || inner.Path != "/v1/chat/completions?x=1" || inner.Headers["Content-Type"] != "application/json" {
		t.Fatalf("inner head %+v", inner.Head)
	}
	var fields map[string]any
	json.Unmarshal(inner.Body, &fields)
	if provider, _ := fields["provider"].(map[string]any); provider["min_privacy"] != "tee" || fields["model"] != "stub" {
		t.Fatalf("inner body %s", inner.Body)
	}
	if skew := time.Now().Unix() - inner.TS; skew < -2 || skew > 2 {
		t.Fatalf("inner ts %d is %d s off", inner.TS, skew)
	}
}

func TestTheFloorHoldsAgainstALowerOneTheRequestSets(t *testing.T) {
	for name, c := range map[string]struct{ in, want string }{
		"lower":          {`{"model":"stub","provider":{"min_privacy":"anon"}}`, "tee"},
		"lower, private": {`{"model":"stub","provider":{"min_privacy":"private","zdr":true}}`, "tee"},
		"null":           {`{"model":"stub","provider":{"min_privacy":null}}`, "tee"},
		"no tier":        {`{"model":"stub","provider":{"min_privacy":"TEE "}}`, "tee"},
		"not a string":   {`{"model":"stub","provider":{"min_privacy":3}}`, "tee"},
		"same":           {`{"model":"stub","provider":{"min_privacy":"tee"}}`, "tee"},
		"higher":         {`{"model":"stub","provider":{"min_privacy":"e2ee"}}`, "e2ee"},
		"other provider": {`{"model":"stub","provider":{}}`, "tee"},
		"null provider":  {`{"model":"stub","provider":null}`, "tee"},
		"no provider":    {`{"model":"stub"}`, "tee"},
	} {
		out, err := withFloor([]byte(c.in), "tee")
		if err != nil {
			t.Fatal(err)
		}
		var fields struct {
			Model    string
			Provider map[string]any
		}
		json.Unmarshal(out, &fields)
		if fields.Model != "stub" || fields.Provider["min_privacy"] != c.want {
			t.Errorf("%s: %s", name, out)
		}
		if name == "lower, private" && fields.Provider["zdr"] != true {
			t.Errorf("%s lost the provider's other fields: %s", name, out)
		}
	}
	if out, _ := withFloor([]byte(`{"model":"stub","provider":{"min_privacy":"tee"}}`), "private"); !strings.Contains(string(out), `"min_privacy":"tee"`) {
		t.Errorf("a private floor lowered a tee request: %s", out)
	}
	if _, err := withFloor([]byte(`[1]`), "tee"); err == nil {
		t.Error("an array body took a floor")
	}
	if _, err := withFloor([]byte(`{"provider":"tee"}`), "tee"); err == nil {
		t.Error("a string provider took a floor")
	}
}

func TestRelayAloneRoutesPassThroughWithTheBearer(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	resp, err := http.Get(sidecar.URL + "/v1/models")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || !strings.Contains(string(body), `"id":"stub"`) {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if r.attestations.Load() != 0 || len(r.opened) != 0 {
		t.Fatalf("a relay-alone route fetched %d attestations and sealed %d requests", r.attestations.Load(), len(r.opened))
	}
}

func TestRefusesToSealWhenNoListedInstanceVerifies(t *testing.T) {
	for name, c := range map[string]struct {
		environment string
		dev         bool
		want        string
	}{
		"stand-in without --dev":  {"dev", false, "only with --dev"},
		"the proxy is dev":        {"prod", true, "the proxy is dev, not prod"},
		"stand-in without --dev2": {"prod", false, "the proxy is dev, not prod"},
	} {
		r, relayServer := newRelay(t)
		sidecar := startSidecar(t, relayServer.URL, c.environment, "", c.dev)
		resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
		var envelope struct {
			Error struct{ Code, Message string }
		}
		json.Unmarshal([]byte(body), &envelope)
		if resp.StatusCode != http.StatusBadGateway || envelope.Error.Code != "attestation_failed" || !strings.Contains(envelope.Error.Message, c.want) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
		if len(r.opened) != 0 || r.plainContent.Load() != 0 {
			t.Errorf("%s: %d sealed and %d plain requests reached the relay", name, len(r.opened), r.plainContent.Load())
		}
	}
}

func TestKeysAreCachedAndRefetchedWhenTheWorkerRestarts(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	for range 2 {
		if resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat); resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
	if r.attestations.Load() != 1 {
		t.Fatalf("%d attestation fetches for two chats", r.attestations.Load())
	}
	r.rotate()
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != 200 || !strings.Contains(body, "[DONE]") {
		t.Fatalf("after a restart: %d %s", resp.StatusCode, body)
	}
	if r.attestations.Load() != 2 || len(r.opened) != 3 {
		t.Fatalf("%d attestation fetches, %d opened", r.attestations.Load(), len(r.opened))
	}
}

func TestARelayRefusalInTheClearPassesThrough(t *testing.T) {
	r, relayServer := newRelay(t)
	r.refuseClear = http.StatusTooManyRequests
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != http.StatusTooManyRequests || !strings.Contains(body, "rate_limit_exceeded") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestConfigureRefusesBadFlags(t *testing.T) {
	pins := writePins(t)
	commit := strings.Repeat("ab", 20)
	for name, c := range map[string]struct {
		o    options
		want string
	}{
		"no key":                    {options{upstream: "https://x", pins: pins, env: "prod"}, "an API key is required"},
		"bad env":                   {options{upstream: "https://x", key: "sk", pins: pins, env: "staging"}, "--env"},
		"bad floor":                 {options{upstream: "https://x", key: "sk", pins: pins, env: "prod", floor: "secret"}, "--floor"},
		"e2ee floor":                {options{upstream: "https://x", key: "sk", pins: pins, env: "prod", floor: "e2ee"}, "--floor"},
		"no upstream":               {options{upstream: "x", key: "sk", pins: pins, env: "prod"}, "--upstream"},
		"no pins":                   {options{upstream: "https://x", key: "sk", pins: filepath.Join(t.TempDir(), "missing.json"), env: "prod"}, "no such file"},
		"pins and a pins commit":    {options{upstream: "https://x", key: "sk", pins: pins, pinsCommit: commit, env: "prod"}, "--pins reads a local file and --pins-commit a morse-pins commit; pass one"},
		"a pins URL":                {options{upstream: "https://x", key: "sk", pins: "https://raw.githubusercontent.com/trymorse/morse-pins/main/enclave_pins.json", env: "prod"}, "is a URL"},
		"a pins commit that is not": {options{upstream: "https://x", key: "sk", pinsCommit: "main", env: "prod"}, "not a 40-character"},
	} {
		if _, err := configure(c.o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	u, _ := url.Parse(defaultUpstream)
	s, err := configure(options{upstream: u.String(), key: "sk", pins: pins, env: "prod", floor: "tee"})
	if err != nil || s.floor != "tee" || s.trust.standIns {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestAStreamedReplyOutlastsTheShortCallsTimeout(t *testing.T) {
	_, relayServer := newRelay(t)
	s, err := configure(options{upstream: relayServer.URL, key: "sk_test", pins: writePins(t), env: "dev", dev: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.keys(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.client.Timeout = 50 * time.Millisecond
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != 200 || !strings.HasSuffix(body, "data: [DONE]\n\n") {
		t.Fatalf("a reply streamed over 180ms through a 50ms short-call timeout: %d %q, want it whole", resp.StatusCode, body)
	}
}

func TestADocumentStaleByThisClockIsRefusedWhateverTheRelaysClockSays(t *testing.T) {
	r, relayServer := newRelay(t)
	r.behind = 6 * time.Hour
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "attestation_failed") || !strings.Contains(body, "minutes old") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if len(r.opened) != 0 {
		t.Fatalf("%d requests sealed to a 6-hour-old document", len(r.opened))
	}
}

func TestAReplyCutBeforeItsFinalFrameBreaksTheConnection(t *testing.T) {
	r, relayServer := newRelay(t)
	r.cut = true
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	resp, err := http.Post(sidecar.URL+"/v1/chat/completions", "application/json", strings.NewReader(chat))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, err := io.ReadAll(resp.Body); err == nil {
		t.Fatalf("a reply cut after its first frame ended cleanly: %d %q", resp.StatusCode, body)
	}
}

func TestAnUnsealedSuccessFromTheRelayIsRefused(t *testing.T) {
	r, relayServer := newRelay(t)
	r.refuseClear = http.StatusOK
	sidecar := startSidecar(t, relayServer.URL, "dev", "", true)
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "sealed_reply_missing") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
}

func TestARelayAloneRouteIsNeverForwardedToAnotherPath(t *testing.T) {
	r, relayServer := newRelay(t)
	for _, floor := range []string{"", "tee"} {
		sidecar := startSidecar(t, relayServer.URL, "dev", floor, true)
		for _, id := range []string{"..%2F..%2Fv1%2Flookup%2Fsvc%2Fpath", "%2E%2E", "a%2Fb", "..%5C..%5Cv1%5Csearch"} {
			resp, err := http.Get(sidecar.URL + "/v1/receipts/" + id)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(body), "invalid_path") {
				t.Errorf("floor %q, id %s: %d %s", floor, id, resp.StatusCode, body)
			}
		}
	}
	if n := r.plainContent.Load(); n != 0 {
		t.Fatalf("%d refused requests reached the relay", n)
	}
	resp, err := http.Get(startSidecar(t, relayServer.URL, "dev", "", true).URL + "/v1/receipts/rcpt_abc")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot || r.plainContent.Load() != 1 {
		t.Fatalf("a plain receipt id: %d, relay saw %d", resp.StatusCode, r.plainContent.Load())
	}
}

func TestARequestFromAWebPageOrAForeignHostIsRefused(t *testing.T) {
	r, relayServer := newRelay(t)
	s, err := configure(options{upstream: relayServer.URL, key: "sk_test", pins: writePins(t), env: "dev", dev: true, listen: "box.lan:4141"})
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	send := func(route, host, origin string) (int, string) {
		method, path, _ := strings.Cut(route, " ")
		req, _ := http.NewRequest(method, sidecar.URL+path, strings.NewReader(chat))
		req.Header.Set("Content-Type", "text/plain")
		if host != "" {
			req.Host = host
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	for name, c := range map[string]struct{ route, host, origin, want string }{
		"a page's origin":          {"POST /v1/chat/completions", "", "http://attacker.example", "origin_refused"},
		"a loopback page":          {"POST /v1/chat/completions", "", "http://127.0.0.1:8000", "origin_refused"},
		"a rebound host":           {"POST /v1/chat/completions", "attacker.example:4141", "", "host_refused"},
		"a bare foreign host":      {"POST /v1/chat/completions", "evil.example", "", "host_refused"},
		"the listen host off-port": {"POST /v1/chat/completions", "box.lan:80", "", "host_refused"},
		"a relay-alone route":      {"GET /v1/models", "evil.example", "", "host_refused"},
	} {
		if status, body := send(c.route, c.host, c.origin); status != http.StatusForbidden || !strings.Contains(body, c.want) {
			t.Errorf("%s: %d %s", name, status, body)
		}
	}
	if r.attestations.Load() != 0 || len(r.opened) != 0 {
		t.Fatalf("refused requests fetched %d attestations and sealed %d", r.attestations.Load(), len(r.opened))
	}
	for _, host := range []string{"", "localhost:4141", "localhost", "[::1]:4141", "box.lan:4141"} {
		if status, body := send("POST /v1/chat/completions", host, ""); status != http.StatusOK {
			t.Errorf("host %q: %d %s", host, status, body)
		}
	}
}

func TestTheFloorRefusesRoutesItCannotCover(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startSidecar(t, relayServer.URL, "dev", "tee", true)
	for _, path := range []string{"/v1/images/generations", "/v1/search", "/v1/responses"} {
		resp, body := post(t, sidecar.URL, path, `{"model":"stub","prompt":"secret"}`)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "floor_unsupported_route") {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	if len(r.opened) != 0 {
		t.Fatalf("%d unfloored requests were sealed", len(r.opened))
	}
}

func TestTheFloorLeavesAnE2EEBodyUntouched(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startSidecar(t, relayServer.URL, "dev", "tee", true)
	e2ee := `{"model":"stub","messages":[{"role":"user","content":"ab12"}],"provider":{"zdr":true}}`
	req, _ := http.NewRequest(http.MethodPost, sidecar.URL+"/v1/chat/completions", strings.NewReader(e2ee))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-E2EE-Version", "2")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(r.opened) != 1 {
		t.Fatalf("%d opened", len(r.opened))
	}
	if inner := string(r.opened[0].Body); inner != e2ee {
		t.Fatalf("inner body %s, want %s", inner, e2ee)
	}
}

func startVeilSidecar(t *testing.T, upstream string, force bool) *httptest.Server {
	s, err := configure(options{upstream: upstream, key: "sk_test", pins: writePins(t), env: "dev", dev: true, privacyVeil: force})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(s)
	t.Cleanup(server.Close)
	return server
}

func TestAChatsVeilAskGoesInTheSealsHeadAndNeverInItsBody(t *testing.T) {
	r, relayServer := newRelay(t)
	r.veiled = "applied"
	sidecar := startVeilSidecar(t, relayServer.URL, false)
	asked := `{"model":"stub","privacy_veil":{"report": true},"messages":[{"role":"user","content":"Call Jane Doe"}]}`
	if ask, body, err := withVeil([]byte(`{"model":"stub","privacy_veil":null}`), false); err != nil || ask != nil || string(body) != `{"model":"stub"}` {
		t.Fatalf("a null ask became %s in the head and %s in the body", ask, body)
	}
	for _, body := range []string{asked, asked, chat} {
		if resp, out := post(t, sidecar.URL, "/v1/chat/completions", body); resp.StatusCode != 200 || resp.Header.Get(headerPrivacyVeil) != "applied" {
			t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, out)
		}
	}
	first, second, plain := r.opened[0], r.opened[1], r.opened[2]
	if string(first.PrivacyVeil) != `{"report":true}` || strings.Contains(string(first.Body), "privacy_veil") || !strings.Contains(string(first.Body), "Call Jane Doe") {
		t.Fatalf("head ask %s, body %s", first.PrivacyVeil, first.Body)
	}
	if partition, err := base64.RawURLEncoding.DecodeString(first.PrivacyVeilPartition); err != nil || len(partition) != 16 || second.PrivacyVeilPartition != first.PrivacyVeilPartition {
		t.Fatalf("partitions %q and %q", first.PrivacyVeilPartition, second.PrivacyVeilPartition)
	}
	if plain.PrivacyVeil != nil || plain.PrivacyVeilPartition != "" || string(plain.Body) != chat {
		t.Fatalf("a chat that asked for nothing was sealed with %s %q, body %s", plain.PrivacyVeil, plain.PrivacyVeilPartition, plain.Body)
	}
}

func TestThePrivacyVeilFlagAsksOnEveryChatAndRefusesWhatItCannotVeil(t *testing.T) {
	r, relayServer := newRelay(t)
	r.veiled = `applied; unveiled="image_url"`
	sidecar := startVeilSidecar(t, relayServer.URL, true)
	for _, body := range []string{chat, `{"model":"stub","privacy_veil":null}`, `not json`} {
		if resp, out := post(t, sidecar.URL, "/v1/chat/compact", body); resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", body, resp.StatusCode, out)
		}
	}
	for _, opened := range r.opened {
		if string(opened.PrivacyVeil) != "true" || opened.PrivacyVeilPartition == "" {
			t.Fatalf("a chat under the flag was sealed with %s %q", opened.PrivacyVeil, opened.PrivacyVeilPartition)
		}
	}
	if string(r.opened[2].Body) != "not json" {
		t.Fatalf("a body that is not JSON was rewritten to %q", r.opened[2].Body)
	}
	refused := map[string]struct{ path, body, header, want string }{
		"false":       {"/v1/chat/completions", `{"model":"stub","privacy_veil":false}`, "", "privacy_veil_required"},
		"images":      {"/v1/images/generations", `{"model":"stub","prompt":"Jane Doe"}`, "", "privacy_veil_not_applicable"},
		"e2ee":        {"/v1/chat/completions", `{"model":"stub","messages":[{"role":"user","content":"ab12"}]}`, "X-E2EE-Version", "privacy_veil_not_applicable"},
		"ehbp":        {"/v1/chat/completions", "sealed", "Ehbp-Encapsulated-Key", "privacy_veil_not_applicable"},
		"lookup":      {"/v1/lookup/coingecko/simple/price", "", "", "privacy_veil_not_applicable"},
		"transcribed": {"/v1/audio/transcriptions", "audio", "", "privacy_veil_not_applicable"},
	}
	for name, c := range refused {
		req, _ := http.NewRequest(http.MethodPost, sidecar.URL+c.path, strings.NewReader(c.body))
		req.Header.Set("Content-Type", "application/json")
		if c.header != "" {
			req.Header.Set(c.header, "2")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		out, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(out), c.want) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, out)
		}
	}
	if len(r.opened) != 3 {
		t.Fatalf("%d requests were sealed, want the 3 the flag let through", len(r.opened))
	}
}

func TestAReplyTheEnclaveDidNotVeilIsWithheld(t *testing.T) {
	r, relayServer := newRelay(t)
	sidecar := startVeilSidecar(t, relayServer.URL, true)
	for _, veiled := range []string{"", "skipped", "appliedish"} {
		r.mu.Lock()
		r.veiled = veiled
		r.mu.Unlock()
		resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
		if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "privacy_veil_missing") || strings.Contains(body, "hel") {
			t.Errorf("header %q: %d %s", veiled, resp.StatusCode, body)
		}
	}
	plain := startSidecar(t, relayServer.URL, "dev", "", true)
	if resp, body := post(t, plain.URL, "/v1/chat/completions", chat); resp.StatusCode != 200 {
		t.Fatalf("a chat that asked for no Veil: %d %s", resp.StatusCode, body)
	}
}

func TestTheDefaultUpstreamIsTheInferenceDoor(t *testing.T) {
	if defaultUpstream != "https://inference.trymorse.ai" {
		t.Errorf("--upstream defaults to %q, but prod refuses sk_ keys anywhere but https://inference.trymorse.ai", defaultUpstream)
	}
}

func TestTheKeyFlagNeverPrintsItsValueInHelp(t *testing.T) {
	key := "sk_morse_from_the_environment"
	var help strings.Builder
	fs := flag.NewFlagSet("morse-seal", flag.ContinueOnError)
	fs.SetOutput(&help)
	fs.Var(unprinted{&key}, "key", "sk_ API key, or MORSE_API_KEY")
	if err := fs.Parse([]string{"-no-such-flag"}); err == nil || !strings.Contains(help.String(), "-key") || strings.Contains(help.String(), "sk_morse") {
		t.Errorf("err %v, help %q; want the usage text without the key", err, help.String())
	}
	if err := fs.Parse([]string{"-key", "sk_morse_from_the_flag"}); err != nil || key != "sk_morse_from_the_flag" {
		t.Errorf("-key: key %q, err %v; want the flag's", key, err)
	}
}
