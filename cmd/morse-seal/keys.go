package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/trymorse/morse-seal/verify"
	"github.com/trymorse/morse-seal/seal"
)

type trustedImage struct {
	pin    verify.Pin
	pins   string
	source release
}

func (i trustedImage) String() string {
	return fmt.Sprintf("%s pcr0 %s… pinned by %s, source commit %s", i.pin.Name(), i.pin.PCR0[:16], i.pins, i.source.commit)
}

type trust struct {
	client      *http.Client
	environment string
	standIns    bool
	pinsSource  pinsSource
	source      sourceCheck
	mu          sync.Mutex
	snapshot    snapshot
	trusted     map[verify.Pin]trustedImage
	refused     map[verify.Pin]refusal
}

type refusal struct {
	err error
	at  time.Time
}

const refusalHeld = time.Minute

func newTrust(client *http.Client, environment string, pins pinsSource, source sourceCheck, standIns bool) (*trust, error) {
	t := &trust{client: client, environment: environment, standIns: standIns, pinsSource: pins, source: source, trusted: map[verify.Pin]trustedImage{}, refused: map[verify.Pin]refusal{}}
	if err := t.reloadPins(context.Background()); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *trust) reloadPins(ctx context.Context) error {
	snap, err := t.pinsSource.load(ctx)
	if err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.snapshot = snap
	return nil
}

func (t *trust) current() snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshot
}

func (t *trust) verify(ctx context.Context, document []byte, now time.Time) (verify.Key, error) {
	if len(document) > 0 && document[0] == '{' {
		return t.verifyStandIn(document, now)
	}
	snap := t.current()
	key, err := verify.Document(document, verify.Expectation{Environment: t.environment, Pins: snap.pins, Root: verify.Root, Now: now})
	if err != nil {
		return verify.Key{}, err
	}
	if err := t.trustImage(ctx, key.Pin, snap.origin, now); err != nil {
		return verify.Key{}, err
	}
	return key, nil
}

func (t *trust) trustImage(ctx context.Context, pin verify.Pin, pins string, now time.Time) error {
	t.mu.Lock()
	_, ok := t.trusted[pin]
	held, refused := t.refused[pin]
	t.mu.Unlock()
	if ok {
		return nil
	}
	if refused && now.Sub(held.at) < refusalHeld {
		return held.err
	}
	source, err := t.source.confirm(ctx, pin)
	if err != nil {
		t.mu.Lock()
		t.refused[pin] = refusal{err: err, at: now}
		t.mu.Unlock()
		return err
	}
	image := trustedImage{pin: pin, pins: pins, source: source}
	t.mu.Lock()
	t.trusted[pin] = image
	t.mu.Unlock()
	log.Printf("morse-seal: trusting image %s", image)
	return nil
}

func (t *trust) verifyStandIn(document []byte, now time.Time) (verify.Key, error) {
	standIn, err := verify.ParseStandIn(document)
	if err != nil {
		return verify.Key{}, err
	}
	if !t.standIns {
		return verify.Key{}, errors.New("the proxy runs outside an enclave and lists a stand-in document, which morse-seal accepts only with --dev")
	}
	if standIn.Environment != t.environment {
		return verify.Key{}, fmt.Errorf("the stand-in is for %s, not %s", standIn.Environment, t.environment)
	}
	if err := verify.Fresh(standIn.IssuedAt, now); err != nil {
		return verify.Key{}, err
	}
	return verify.Key{PublicKey: standIn.PublicKey, IssuedAt: standIn.IssuedAt}, nil
}

type attestation struct {
	Environment string   `json:"environment"`
	Instances   []string `json:"instances"`
	ProxyTime   int64    `json:"proxy_time"`
}

type keySet struct {
	keys    [][]byte
	expires time.Time
	offset  time.Duration
}

type unattested struct {
	refusals []string
}

func (u unattested) Error() string {
	if len(u.refusals) == 0 {
		return "the proxy lists no attested instance"
	}
	return "no proxy instance is attested: " + strings.Join(u.refusals, "; ")
}

func (s *sidecar) keys(ctx context.Context) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cached.keys) > 0 && s.now().Before(s.cached.expires) {
		return s.cached.keys, nil
	}
	set, err := s.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	s.cached = set
	return set.keys, nil
}

func (s *sidecar) forgetKeys() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cached = keySet{}
}

func (s *sidecar) fetchKeys(ctx context.Context) (keySet, error) {
	if err := s.trust.reloadPins(ctx); err != nil {
		log.Printf("morse-seal: keeping the pins from %s: %v", s.trust.current().origin, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.upstream.JoinPath("/v1/attestation").String(), nil)
	if err != nil {
		return keySet{}, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return keySet{}, fmt.Errorf("GET /v1/attestation: %w", err)
	}
	defer resp.Body.Close()
	var a attestation
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&a); err != nil || resp.StatusCode != http.StatusOK {
		return keySet{}, fmt.Errorf("GET /v1/attestation answered %d", resp.StatusCode)
	}
	if a.Environment != s.trust.environment {
		return keySet{}, unattested{[]string{fmt.Sprintf("the proxy is %s, not %s", a.Environment, s.trust.environment)}}
	}
	now, offset := s.now(), time.Duration(0)
	if a.ProxyTime != 0 {
		offset = time.Unix(a.ProxyTime, 0).Sub(now)
	}
	var refusals []string
	byID := map[seal.KeyID]verify.Key{}
	for i, encoded := range a.Instances {
		document, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			refusals = append(refusals, fmt.Sprintf("instance %d is not base64", i+1))
			continue
		}
		key, err := s.trust.verify(ctx, document, now)
		if err != nil {
			refusals = append(refusals, fmt.Sprintf("instance %d: %v", i+1, err))
			continue
		}
		id := seal.KeyIDOf(key.PublicKey)
		if known, ok := byID[id]; !ok || known.IssuedAt.Before(key.IssuedAt) {
			byID[id] = key
		}
	}
	if len(byID) == 0 {
		return keySet{}, unattested{refusals}
	}
	accepted := slices.SortedFunc(maps.Values(byID), func(a, b verify.Key) int { return b.IssuedAt.Compare(a.IssuedAt) })
	accepted = accepted[:min(len(accepted), seal.MaxKeys)]
	set := keySet{offset: offset, expires: accepted[len(accepted)-1].IssuedAt.Add(verify.MaxAge)}
	for _, key := range accepted {
		set.keys = append(set.keys, key.PublicKey)
	}
	return set, nil
}
