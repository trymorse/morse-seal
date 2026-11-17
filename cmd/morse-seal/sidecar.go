package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/trymorse/morse-seal/seal"
)

var sealedMethod, sealedPath, _ = strings.Cut(seal.Endpoint, " ")

var e2eeHeaders = []string{"X-E2EE-Version", "X-E2EE-Nonce", "X-E2EE-Timestamp", "X-Client-Pub-Key", "X-Model-Pub-Key", "X-Signing-Algo", "X-Encryption-Version", "X-Encrypt-All-Fields", "Ehbp-Encapsulated-Key", "X-Tinfoil-Model", "X-Tinfoil-Max-Output-Tokens"}

var contentHeaders = append([]string{"Content-Type"}, e2eeHeaders...)

var floorRoutes = []string{"/v1/chat/completions", "/v1/chat/compact"}

// headerPrivacyVeil is the reply header in which the enclave says it veiled a chat.
const headerPrivacyVeil = "X-Privacy-Veil"

type sidecar struct {
	upstream    *url.URL
	key         string
	floor       string
	privacyVeil bool
	// partition names this process's chats to the enclave's Privacy Veil, which may answer a scan of text one of them
	// sent before from its cache. It is drawn at start, so it links only the chats of one run.
	partition string
	listen    string
	trust     *trust
	client    *http.Client
	relay     *http.Client
	now       func() time.Time
	mux       *http.ServeMux
	mu        sync.Mutex
	cached    keySet
}

var loopbackHosts = []string{"127.0.0.1", "::1", "localhost"}

func newSidecar(upstream *url.URL, key, floor, listen string, t *trust) *sidecar {
	partition := make([]byte, 16)
	rand.Read(partition)
	s := &sidecar{upstream: upstream, key: key, floor: floor, partition: base64.RawURLEncoding.EncodeToString(partition), listen: listen, trust: t, client: t.client, relay: streaming(), now: time.Now, mux: http.NewServeMux()}
	for _, rt := range seal.Routes {
		if !rt.Sealed {
			s.mux.HandleFunc(rt.Pattern, s.forward)
		}
	}
	s.mux.HandleFunc("/", s.sealed)
	return s
}

func (s *sidecar) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if len(r.Header.Values("Origin")) > 0 {
		refuse(w, http.StatusForbidden, "origin_refused", "morse-seal refuses a request that carries an Origin header, as a web page's does, so no page can spend the sidecar's key")
		return
	}
	if !s.servesHost(r.Host) {
		refuse(w, http.StatusForbidden, "host_refused", fmt.Sprintf("morse-seal answers only Host 127.0.0.1, ::1, localhost, or %s, not %q", s.listen, r.Host))
		return
	}
	s.mux.ServeHTTP(w, r)
}

func (s *sidecar) servesHost(host string) bool {
	if host == s.listen {
		return true
	}
	name, _, err := net.SplitHostPort(host)
	if err != nil {
		name = host
	}
	return slices.Contains(loopbackHosts, name)
}

func refuse(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"message": message, "type": code, "code": code}})
}

func (s *sidecar) outer(ctx context.Context, method, target string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.upstream.JoinPath(target).String(), body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+s.key)
	return req, nil
}

func (s *sidecar) forward(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawPath != "" || strings.Contains(r.URL.Path, `\`) || path.Clean(r.URL.Path) != r.URL.Path {
		refuse(w, http.StatusBadRequest, "invalid_path", fmt.Sprintf("morse-seal forwards a relay-alone route only by the exact path it matched, not %q", r.URL.EscapedPath()))
		return
	}
	req, err := s.outer(r.Context(), r.Method, r.URL.Path, http.MaxBytesReader(w, r.Body, seal.MaxBody))
	if err != nil {
		refuse(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		return
	}
	req.URL.RawQuery = r.URL.RawQuery
	for _, name := range []string{"Content-Type", "Accept"} {
		if value := r.Header.Get(name); value != "" {
			req.Header.Set(name, value)
		}
	}
	resp, err := s.relay.Do(req)
	if err != nil {
		refuse(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		return
	}
	defer resp.Body.Close()
	log.Printf("%s %s -> %d plain", r.Method, r.URL.Path, resp.StatusCode)
	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	stream(w, resp.Body)
}

func (s *sidecar) sealed(w http.ResponseWriter, r *http.Request) {
	chat := r.Method == http.MethodPost && slices.Contains(floorRoutes, r.URL.Path)
	if s.floor != "" && !chat {
		refuse(w, http.StatusBadRequest, "floor_unsupported_route", fmt.Sprintf("--floor sets provider.min_privacy only on POST %s, so morse-seal refuses %s %s rather than send it without the floor; run a sidecar without --floor for it", strings.Join(floorRoutes, " and "), r.Method, r.URL.Path))
		return
	}
	if s.privacyVeil && !chat {
		refuse(w, http.StatusBadRequest, "privacy_veil_not_applicable", fmt.Sprintf("--privacy-veil asks for the Privacy Veil only on POST %s, so morse-seal refuses %s %s rather than send it unveiled; run a sidecar without --privacy-veil for it", strings.Join(floorRoutes, " and "), r.Method, r.URL.Path))
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, seal.MaxBody))
	if err != nil {
		refuse(w, http.StatusRequestEntityTooLarge, "request_too_large", err.Error())
		return
	}
	e2ee := slices.ContainsFunc(e2eeHeaders, func(name string) bool { return r.Header.Get(name) != "" })
	if s.privacyVeil && e2ee {
		refuse(w, http.StatusBadRequest, "privacy_veil_not_applicable", "the Privacy Veil reads only chats the enclave can read, so under --privacy-veil morse-seal refuses a chat sealed to the vendor rather than send it unveiled; run a sidecar without --privacy-veil for it")
		return
	}
	if s.floor != "" && !e2ee {
		if body, err = withFloor(body, s.floor); err != nil {
			refuse(w, http.StatusBadRequest, "invalid_json", "the request body is not a JSON object: "+err.Error())
			return
		}
	}
	head := seal.Head{Method: r.Method, Path: r.URL.RequestURI(), Headers: map[string]string{}}
	if chat && !e2ee {
		if head.PrivacyVeil, body, err = withVeil(body, s.privacyVeil); err != nil {
			refuse(w, http.StatusBadRequest, "privacy_veil_required", "--privacy-veil asks for the Privacy Veil on every chat, so morse-seal refuses one that says privacy_veil false; run a sidecar without --privacy-veil for it")
			return
		}
		if veilOn(head.PrivacyVeil) {
			head.PrivacyVeilPartition = s.partition
		}
	}
	for _, name := range contentHeaders {
		if value := r.Header.Get(name); value != "" {
			head.Headers[name] = value
		}
	}
	resp, cek, err := s.sendSealed(r.Context(), head, body, true)
	if err != nil {
		if errors.As(err, new(unattested)) {
			refuse(w, http.StatusBadGateway, "attestation_failed", err.Error())
		} else {
			refuse(w, http.StatusBadGateway, "upstream_unreachable", err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != seal.ContentType {
		if resp.StatusCode < http.StatusBadRequest {
			log.Printf("%s %s -> %d unsealed, refused", r.Method, r.URL.Path, resp.StatusCode)
			refuse(w, http.StatusBadGateway, "sealed_reply_missing", fmt.Sprintf("the proxy answered %d without sealing its reply, so morse-seal cannot tell it came from the enclave", resp.StatusCode))
			return
		}
		log.Printf("%s %s -> %d refused in the clear", r.Method, r.URL.Path, resp.StatusCode)
		copyHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		stream(w, resp.Body)
		return
	}
	reply, err := seal.OpenReply(resp.Body, cek)
	if err != nil {
		refuse(w, http.StatusBadGateway, "sealed_reply_invalid", "the proxy's sealed reply does not open: "+err.Error())
		return
	}
	if veilOn(head.PrivacyVeil) && reply.Head.Status < http.StatusMultipleChoices && !veilApplied(reply.Head.Headers.Get(headerPrivacyVeil)) {
		log.Printf("%s %s -> %d sealed without the Privacy Veil, refused", r.Method, r.URL.Path, reply.Head.Status)
		refuse(w, http.StatusBadGateway, "privacy_veil_missing", "the enclave answered a chat that asked for the Privacy Veil without "+headerPrivacyVeil+": applied, so morse-seal withholds its reply; the vendor may have read the chat as written")
		return
	}
	log.Printf("%s %s -> %d sealed", r.Method, r.URL.Path, reply.Head.Status)
	copyHeaders(w.Header(), reply.Head.Headers)
	for _, name := range []string{"X-Request-Id", "X-Funding", "X-Output-Limited"} {
		if value := resp.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(reply.Head.Status)
	stream(w, reply)
}

func (s *sidecar) sendSealed(ctx context.Context, head seal.Head, body []byte, mayRetry bool) (*http.Response, [32]byte, error) {
	keys, err := s.keys(ctx)
	if err != nil {
		return nil, [32]byte{}, err
	}
	s.mu.Lock()
	head.TS = s.now().Add(s.cached.offset).Unix()
	s.mu.Unlock()
	sealed, cek, err := seal.Seal(keys, head, body)
	if err != nil {
		return nil, cek, err
	}
	req, err := s.outer(ctx, sealedMethod, sealedPath, bytes.NewReader(sealed))
	if err != nil {
		return nil, cek, err
	}
	req.Header.Set("Content-Type", seal.ContentType)
	resp, err := s.relay.Do(req)
	if err != nil {
		return nil, cek, fmt.Errorf("POST /v1/sealed: %w", err)
	}
	if resp.StatusCode == http.StatusMisdirectedRequest && mayRetry {
		resp.Body.Close()
		s.forgetKeys()
		return s.sendSealed(ctx, head, body, false)
	}
	return resp, cek, nil
}

func withFloor(body []byte, floor string) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return nil, err
	}
	provider := map[string]json.RawMessage{}
	if raw, ok := fields["provider"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &provider); err != nil {
			return nil, fmt.Errorf("provider: %w", err)
		}
	}
	if _, set := provider["min_privacy"]; set {
		return body, nil
	}
	provider["min_privacy"], _ = json.Marshal(floor)
	fields["provider"], _ = json.Marshal(provider)
	return json.Marshal(fields)
}

var errVeilRequired = errors.New("privacy_veil is false")

// withVeil moves a chat body's privacy_veil into the seal's head, where the worker reads a sealed chat's ask and the
// relay can't drop it; a sealed body that names it is refused. With force it asks for the Veil on a chat that does not
// say, and refuses one that says false. A body that is not a JSON object goes as it came, for the worker to refuse.
func withVeil(body []byte, force bool) (json.RawMessage, []byte, error) {
	var ask json.RawMessage
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) == nil {
		if raw, ok := fields["privacy_veil"]; ok {
			delete(fields, "privacy_veil")
			body, _ = json.Marshal(fields)
			ask = raw
		}
	}
	switch string(bytes.TrimSpace(ask)) {
	case "false":
		if force {
			return nil, nil, errVeilRequired
		}
	case "", "null":
		ask = nil
		if force {
			ask = json.RawMessage("true")
		}
	}
	return ask, body, nil
}

// veilOn is whether an ask turns the Veil on: true, or an object of options.
func veilOn(ask json.RawMessage) bool {
	trimmed := bytes.TrimSpace(ask)
	return string(trimmed) == "true" || len(trimmed) > 0 && trimmed[0] == '{'
}

func veilApplied(header string) bool {
	return header == "applied" || strings.HasPrefix(header, "applied;")
}

func copyHeaders(to, from http.Header) {
	for name, values := range from {
		if name == "Content-Length" || name == "Transfer-Encoding" || name == "Connection" {
			continue
		}
		to[name] = values
	}
}

func stream(w http.ResponseWriter, r io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			rc.Flush()
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("reply ended early: %v", err)
				panic(http.ErrAbortHandler)
			}
			return
		}
	}
}

func streaming() *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
	}}
}
