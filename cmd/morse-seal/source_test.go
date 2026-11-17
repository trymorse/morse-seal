package main

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/trymorse/morse-seal/verify"
)

const (
	realPCR0 = "1dab5ad4c661f95a9e7e3f57bcd83efd9fced7f749ac21ea85a1853131bb5e43b41eb58615efef998d478ce485fcff53"
	realPCR1 = "3b4a7e1b5f13c5a1000b3ed32ef8995ee13e9876329f9bc72650b918329ef9cf4e2e4d1e1e37375dab0ba56ba0974d03"
	realPCR2 = "f9d2c68436810c46556535a583870e2913ec1f05ecca361b4e78eaa00d0b365dee6570e7699c4f34165fbf635bf35c6a"
	mainSHA  = "1111111111111111111111111111111111111111"
	olderSHA = "2222222222222222222222222222222222222222"
	forkSHA  = "3333333333333333333333333333333333333333"
)

var realIssuedAt = time.UnixMilli(1792280904626)

type github struct {
	mu          sync.Mutex
	pins        map[string]string
	tags        map[string]string
	objects     map[string][]byte
	rawPaths    []string
	pinsRefs    atomic.Int32
	commitsSent atomic.Int32
	down        bool
	apiDown     bool
}

func newGitHub(t *testing.T) (*github, *httptest.Server) {
	g := &github{pins: map[string]string{}, tags: map[string]string{}, objects: map[string][]byte{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /pins/info/refs", func(w http.ResponseWriter, r *http.Request) {
		g.pinsRefs.Add(1)
		advertise(w, map[string]string{"refs/heads/main": mainSHA})
	})
	mux.HandleFunc("GET /raw/{commit}/enclave_pins.json", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.rawPaths = append(g.rawPaths, r.URL.Path)
		pins, ok := g.pins[r.PathValue("commit")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, pins)
	})
	mux.HandleFunc("GET /api/compare/{spec}", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.apiDown {
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"message":"API rate limit exceeded"}`)
			return
		}
		base, _ := strings.CutSuffix(r.PathValue("spec"), "...main")
		status, ok := map[string]string{mainSHA: "identical", olderSHA: "ahead", forkSHA: "behind"}[base]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": status, "files": []string{}})
	})
	mux.HandleFunc("GET /enclave/info/refs", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.down {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		refs := map[string]string{"refs/heads/main": strings.Repeat("9", 40)}
		for tag, sha := range g.tags {
			refs["refs/tags/"+tag] = sha
		}
		advertise(w, refs)
	})
	mux.HandleFunc("POST /enclave/git-upload-pack", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		want := regexp.MustCompile(`want ([0-9a-f]{40}) `).FindSubmatch(body)
		g.mu.Lock()
		object, ok := g.objects[string(want[1])]
		g.mu.Unlock()
		if !ok {
			io.WriteString(w, pkt("ERR upload-pack: not our ref\n"))
			return
		}
		g.commitsSent.Add(1)
		io.WriteString(w, pkt("shallow "+string(want[1])+"\n")+"0000"+pkt("NAK\n"))
		w.Write(pack(object))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return g, server
}

func (g *github) publish(tag, message string) {
	object := []byte("tree " + strings.Repeat("4", 40) + "\nauthor morse <m@x> 0 +0000\ncommitter morse <m@x> 0 +0000\n\n" + message)
	sum := sha1.Sum(append(fmt.Appendf(nil, "commit %d\x00", len(object)), object...))
	sha := hex.EncodeToString(sum[:])
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tags[tag], g.objects[sha] = sha, object
}

func (g *github) pinAt(commit, tag string) {
	pins, _ := json.Marshal([]map[string]any{{"tag": tag, "environment": "dev", "pcr0": realPCR0, "pcr1": realPCR1, "pcr2": realPCR2, "built_at": "2026-10-01T00:00:00Z", "revoked": false}})
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pins[commit] = string(pins)
}

func releaseMessage(tag, pcr0 string) string {
	return tag + "\n\nPCR0 " + pcr0 + "\nPCR1 " + realPCR1 + "\nPCR2 " + realPCR2 + "\nrootfs sha256 " + strings.Repeat("5", 64) + "\n"
}

func pkt(line string) string { return fmt.Sprintf("%04x%s", len(line)+4, line) }

func advertise(w http.ResponseWriter, refs map[string]string) {
	io.WriteString(w, pkt("# service=git-upload-pack\n")+"0000")
	first := true
	for name, sha := range refs {
		line := sha + " " + name
		if first {
			line += "\x00multi_ack shallow filter"
			first = false
		}
		io.WriteString(w, pkt(line+"\n"))
	}
	io.WriteString(w, "0000")
}

func pack(object []byte) []byte {
	var out bytes.Buffer
	out.WriteString("PACK")
	binary.Write(&out, binary.BigEndian, [2]uint32{2, 1})
	size := len(object)
	header := byte(packCommit<<4) | byte(size&15)
	for size >>= 4; size > 0; size >>= 7 {
		out.WriteByte(header | 0x80)
		header = byte(size & 0x7f)
	}
	out.WriteByte(header)
	z := zlib.NewWriter(&out)
	z.Write(object)
	z.Close()
	out.Write(make([]byte, 20))
	return out.Bytes()
}

type enclaveRelay struct {
	attestations atomic.Int32
	sealed       atomic.Int32
	misdirect    atomic.Bool
}

func newEnclaveRelay(t *testing.T) (*enclaveRelay, *httptest.Server) {
	encoded, err := os.ReadFile("testdata/nitro_document.b64")
	if err != nil {
		t.Fatal(err)
	}
	r := &enclaveRelay{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/attestation", func(w http.ResponseWriter, req *http.Request) {
		r.attestations.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"environment": "dev", "instances": []string{strings.TrimSpace(string(encoded))}, "proxy_time": realIssuedAt.Add(time.Minute).Unix()})
	})
	mux.HandleFunc("POST /v1/sealed", func(w http.ResponseWriter, req *http.Request) {
		r.sealed.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.misdirect.CompareAndSwap(true, false) {
			w.WriteHeader(http.StatusMisdirectedRequest)
			io.WriteString(w, `{"error":{"code":"sealed_key_unknown"}}`)
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"error":{"code":"invalid_api_key"}}`)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return r, server
}

func captureLog(t *testing.T) *bytes.Buffer {
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return &out
}

func sealTo(relay, git, pinsCommit string) (*sidecar, error) {
	s, err := configure(options{upstream: relay, key: "sk_test", env: "dev", pinsCommit: pinsCommit, pinsRepo: git + "/pins", pinsRaw: git + "/raw", pinsAPI: git + "/api", source: git + "/enclave"})
	if err == nil {
		s.now = func() time.Time { return realIssuedAt.Add(time.Minute) }
	}
	return s, err
}

func TestAnImageIsTrustedOnceItsTagPublishesItsMeasurementsAndIsLoggedWithThePinsCommit(t *testing.T) {
	out := captureLog(t)
	g, git := newGitHub(t)
	g.pinAt(mainSHA, "v2026.10.1")
	g.publish("v2026.10.1", releaseMessage("v2026.10.1", realPCR0))
	r, relay := newEnclaveRelay(t)
	r.misdirect.Store(true)
	s, err := sealTo(relay.URL, git.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "invalid_api_key") {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	if r.attestations.Load() != 2 || r.sealed.Load() != 2 || g.commitsSent.Load() != 1 {
		t.Fatalf("%d attestations, %d sealed, %d source commits fetched", r.attestations.Load(), r.sealed.Load(), g.commitsSent.Load())
	}
	want := "trusting image v2026.10.1 pcr0 1dab5ad4c661f95a… pinned by " + git.URL + "/pins@" + mainSHA + ", source commit " + g.tags["v2026.10.1"]
	if strings.Count(out.String(), "trusting image") != 1 || !strings.Contains(out.String(), want) {
		t.Fatalf("log %q lacks %q once", out, want)
	}
}

func TestAnImageWhoseSourceIsNotConfirmedIsRefused(t *testing.T) {
	for name, c := range map[string]struct {
		pinTag, publishedTag, message string
		down                          bool
		want                          string
	}{
		"its tag is missing":         {"v2026.10.1", "v2026.10.2", releaseMessage("v2026.10.2", realPCR0), false, "has no tag v2026.10.1"},
		"its measurements differ":    {"v2026.10.1", "v2026.10.1", releaseMessage("v2026.10.1", strings.Repeat("ab", 48)), false, "publishes PCR0 abababababababab…, not the pinned 1dab5ad4c661f95a…"},
		"its tag is another release": {"v2026.10.1", "v2026.10.1", releaseMessage("v2026.10.0", realPCR0), false, "is the release of v2026.10.0"},
		"its tag is not a release":   {"v2026.10.1", "v2026.10.1", "v2026.10.1\n\nsome change\n", false, "does not read as a release"},
		"GitHub is unreachable":      {"v2026.10.1", "v2026.10.1", releaseMessage("v2026.10.1", realPCR0), true, "cannot be confirmed"},
	} {
		g, git := newGitHub(t)
		g.pinAt(mainSHA, c.pinTag)
		g.publish(c.publishedTag, c.message)
		g.mu.Lock()
		g.down = c.down
		g.mu.Unlock()
		r, relay := newEnclaveRelay(t)
		s, err := sealTo(relay.URL, git.URL, "")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sidecar := httptest.NewServer(s)
		resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
		sidecar.Close()
		var envelope struct {
			Error struct{ Code, Message string }
		}
		json.Unmarshal([]byte(body), &envelope)
		if resp.StatusCode != http.StatusBadGateway || envelope.Error.Code != "attestation_failed" || !strings.Contains(envelope.Error.Message, c.want) {
			t.Errorf("%s: %d %s", name, resp.StatusCode, body)
		}
		if r.sealed.Load() != 0 {
			t.Errorf("%s: %d sealed requests reached the relay", name, r.sealed.Load())
		}
	}
}

func TestPinsCommitReadsThePinsAtThatCommitAndNeverMain(t *testing.T) {
	out := captureLog(t)
	g, git := newGitHub(t)
	g.pinAt(mainSHA, "v2026.10.2")
	g.pinAt(olderSHA, "v2026.10.1")
	g.publish("v2026.10.1", releaseMessage("v2026.10.1", realPCR0))
	_, relay := newEnclaveRelay(t)
	s, err := sealTo(relay.URL, git.URL, olderSHA)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	if resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	for _, path := range g.rawPaths {
		if path != "/raw/"+olderSHA+"/enclave_pins.json" || g.pinsRefs.Load() != 0 {
			t.Fatalf("read pins at %v and main's refs %d times", g.rawPaths, g.pinsRefs.Load())
		}
	}
	if !strings.Contains(out.String(), "trusting image v2026.10.1 pcr0 1dab5ad4c661f95a… pinned by "+git.URL+"/pins@"+olderSHA) {
		t.Fatalf("log %q", out)
	}
}

func TestAPinsCommitOffMainIsRefusedAtStartup(t *testing.T) {
	for name, c := range map[string]struct {
		commit  string
		apiDown bool
		want    string
	}{
		"a fork commit":           {forkSHA, false, `is not in the history of main of %s/pins; GitHub compares it as "behind", and a commit off main can come from a fork`},
		"no commit of morse-pins": {strings.Repeat("4", 40), false, "is not a commit of %s/pins"},
		"the API refuses":         {olderSHA, true, "cannot be confirmed on main of %s/pins: the GitHub API answered 403 API rate limit exceeded"},
	} {
		g, git := newGitHub(t)
		g.pinAt(c.commit, "v2026.10.1")
		g.apiDown = c.apiDown
		_, relay := newEnclaveRelay(t)
		_, err := sealTo(relay.URL, git.URL, c.commit)
		if want := "--pins-commit " + c.commit + " " + fmt.Sprintf(c.want, git.URL); err == nil || err.Error() != want {
			t.Errorf("%s: %v, want %q", name, err, want)
		}
		if len(g.rawPaths) != 0 {
			t.Errorf("%s: read pins at %v", name, g.rawPaths)
		}
	}
}

func TestParseReleaseReadsThePublishedMessageStrictly(t *testing.T) {
	commit := strings.Repeat("6", 40)
	object := func(message string) []byte {
		return []byte("tree " + strings.Repeat("4", 40) + "\nparent " + strings.Repeat("3", 40) + "\nauthor b <b@x> 0 +0000\ncommitter b <b@x> 0 +0000\n\n" + message)
	}
	withoutRootfs := "v2026.11.0\n\nPCR0 " + realPCR0 + "\nPCR1 " + realPCR1 + "\nPCR2 " + realPCR2 + "\n"
	for _, message := range []string{withoutRootfs, releaseMessage("v2026.11.0", realPCR0)} {
		r, err := parseRelease(commit, object(message))
		if err != nil || r != (release{tag: "v2026.11.0", commit: commit, pcr0: realPCR0, pcr1: realPCR1, pcr2: realPCR2}) {
			t.Fatalf("%q: %+v %v", message, r, err)
		}
	}
	for name, message := range map[string]string{
		"an extra line":     withoutRootfs + "PCR3 " + realPCR0 + "\n",
		"uppercase hex":     strings.Replace(withoutRootfs, realPCR0, strings.ToUpper(realPCR0), 1),
		"a short PCR":       strings.Replace(withoutRootfs, realPCR2, realPCR2[:94], 1),
		"PCRs out of order": "v2026.11.0\n\nPCR1 " + realPCR1 + "\nPCR0 " + realPCR0 + "\nPCR2 " + realPCR2 + "\n",
		"no subject":        "\n\nPCR0 " + realPCR0 + "\nPCR1 " + realPCR1 + "\nPCR2 " + realPCR2 + "\n",
	} {
		if _, err := parseRelease(commit, object(message)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
}

func TestAPinWithoutATagIsRefused(t *testing.T) {
	_, err := sourceCheck{}.confirm(t.Context(), verify.Pin{Image: verify.Built("c0ffee", "v1"), Environment: "dev", PCR0: realPCR0, PCR1: realPCR1, PCR2: realPCR2})
	if err == nil || !strings.Contains(err.Error(), "the pin for v1 names no tag") {
		t.Fatalf("%v", err)
	}
}

func TestARefusedImageIsNotCheckedAgainForAMinute(t *testing.T) {
	g, git := newGitHub(t)
	g.pinAt(mainSHA, "v2026.10.1")
	g.publish("v2026.10.1", releaseMessage("v2026.10.1", strings.Repeat("ab", 48)))
	_, relay := newEnclaveRelay(t)
	s, err := sealTo(relay.URL, git.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	for range 3 {
		if resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "not the pinned") {
			t.Fatalf("%d %s", resp.StatusCode, body)
		}
	}
	if g.commitsSent.Load() != 1 {
		t.Fatalf("%d source commits fetched for one refused image, want 1", g.commitsSent.Load())
	}
}

func TestARevokedImageIsRefusedOnceTheKeysAreRefetched(t *testing.T) {
	g, git := newGitHub(t)
	g.pinAt(mainSHA, "v2026.10.1")
	g.publish("v2026.10.1", releaseMessage("v2026.10.1", realPCR0))
	r, relay := newEnclaveRelay(t)
	s, err := sealTo(relay.URL, git.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	if resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("%d %s", resp.StatusCode, body)
	}
	g.mu.Lock()
	g.pins[mainSHA] = strings.Replace(g.pins[mainSHA], `"revoked":false`, `"revoked":true`, 1)
	g.mu.Unlock()
	r.misdirect.Store(true)
	resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat)
	if resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "is revoked") || r.sealed.Load() != 2 {
		t.Fatalf("after revocation: %d %s, %d sealed", resp.StatusCode, body, r.sealed.Load())
	}
}

func TestAPinsReloadThatFailsKeepsThePinsItHad(t *testing.T) {
	out := captureLog(t)
	g, git := newGitHub(t)
	g.pinAt(mainSHA, "v2026.10.1")
	g.publish("v2026.10.1", releaseMessage("v2026.10.1", realPCR0))
	r, relay := newEnclaveRelay(t)
	s, err := sealTo(relay.URL, git.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	sidecar := httptest.NewServer(s)
	defer sidecar.Close()
	g.mu.Lock()
	delete(g.pins, mainSHA)
	g.mu.Unlock()
	if resp, body := post(t, sidecar.URL, "/v1/chat/completions", chat); resp.StatusCode != http.StatusUnauthorized || r.sealed.Load() != 1 {
		t.Fatalf("%d %s, %d sealed", resp.StatusCode, body, r.sealed.Load())
	}
	if !strings.Contains(out.String(), "enclave_pins.json answered 404") {
		t.Fatalf("log %q", out)
	}
}
