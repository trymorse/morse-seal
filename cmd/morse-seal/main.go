// Command morse-seal is a local sidecar for the Morse developer API. It listens on loopback, speaks the OpenAI API,
// and sends every content request to the proxy as POST /v1/sealed, sealed to the HPKE keys of the enclaves whose
// AWS Nitro attestation it has verified against the pinned root and morse-pins, and whose image morse-enclave
// publishes the source of. Point an OpenAI SDK at it and set the SDK's key to anything; the sidecar's own key rides
// on the outer request.
//
//	MORSE_API_KEY=sk_... morse-seal --floor tee --privacy-veil
//	OPENAI_BASE_URL=http://127.0.0.1:4141/v1 python ...
//
// It never falls back to an unsealed request: when no listed enclave verifies, a content request gets 502.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

const (
	defaultUpstream = "https://inference.trymorse.ai"
	defaultPinsRepo = "https://github.com/trymorse/morse-pins"
	defaultPinsRaw  = "https://raw.githubusercontent.com/trymorse/morse-pins"
	defaultPinsAPI  = "https://api.github.com/repos/trymorse/morse-pins"
	defaultSource   = "https://github.com/trymorse/morse-enclave"
	defaultListen   = "127.0.0.1:4141"
)

var (
	tiers        = []string{"anon", "private", "tee"}
	requestTiers = append(slices.Clone(tiers), "e2ee")
)

type options struct {
	upstream, key, env, floor, listen string
	dev, privacyVeil                  bool
	pins, pinsCommit                  string
	pinsRepo, pinsRaw, pinsAPI        string
	source                            string
}

// why: flag prints each flag's default, read from its Value's String, in -h and after an unknown flag, so a
// StringVar whose default is os.Getenv of a key prints the key. internal/cli holds the same type for e2eechat.
type unprinted struct{ value *string }

func (unprinted) String() string { return "" }

func (u unprinted) Set(v string) error {
	*u.value = v
	return nil
}

func main() {
	o := options{pinsRepo: defaultPinsRepo, pinsRaw: defaultPinsRaw, pinsAPI: defaultPinsAPI}
	flag.StringVar(&o.listen, "listen", defaultListen, "address to serve the OpenAI API on")
	flag.StringVar(&o.upstream, "upstream", defaultUpstream, "the Morse proxy")
	o.key = os.Getenv("MORSE_API_KEY")
	flag.Var(unprinted{&o.key}, "key", "sk_ API key, or MORSE_API_KEY")
	flag.StringVar(&o.pins, "pins", "", "a local enclave_pins.json to trust in place of morse-pins")
	flag.StringVar(&o.pinsCommit, "pins-commit", "", "the morse-pins commit to trust, in place of main")
	flag.StringVar(&o.source, "source", defaultSource, "the public repository whose tags publish each pinned image's source")
	flag.StringVar(&o.env, "env", "prod", "the proxy's environment, prod or dev")
	flag.StringVar(&o.floor, "floor", "", "the lowest provider.min_privacy a chat may use, set on a chat that names none or a lower one, refusing every other content route: "+strings.Join(tiers, ", "))
	flag.BoolVar(&o.privacyVeil, "privacy-veil", false, "ask for the Privacy Veil inside the seal on every chat, refusing every other content route, a chat that says privacy_veil false, and a reply the enclave did not veil")
	flag.BoolVar(&o.dev, "dev", false, "accept a proxy off an enclave by its stand-in document")
	flag.Parse()
	s, err := configure(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "morse-seal:", err)
		os.Exit(2)
	}
	pins := s.trust.current()
	log.Printf("morse-seal: sealing to %s (%s) from http://%s/v1, %d pinned images from %s, sources at %s, floor %q, privacy veil %t, stand-ins %t", s.upstream, s.trust.environment, o.listen, len(pins.pins), pins.origin, s.trust.source.repo, s.floor, s.privacyVeil, s.trust.standIns)
	log.Fatal(http.ListenAndServe(o.listen, s))
}

func configure(o options) (*sidecar, error) {
	base, err := url.Parse(o.upstream)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("--upstream %q is not a URL", o.upstream)
	}
	if o.key == "" {
		return nil, fmt.Errorf("an API key is required: --key or MORSE_API_KEY")
	}
	if o.env != "prod" && o.env != "dev" {
		return nil, fmt.Errorf("--env %q is not prod or dev", o.env)
	}
	if o.floor != "" && !slices.Contains(tiers, o.floor) {
		return nil, fmt.Errorf("--floor %q is not one of %s", o.floor, strings.Join(tiers, ", "))
	}
	client := &http.Client{Timeout: 30 * time.Second}
	var pins pinsSource
	switch {
	case o.pins != "" && o.pinsCommit != "":
		return nil, fmt.Errorf("--pins reads a local file and --pins-commit a morse-pins commit; pass one")
	case strings.HasPrefix(o.pins, "http://") || strings.HasPrefix(o.pins, "https://"):
		return nil, fmt.Errorf("--pins %q is a URL; it takes a local path, and --pins-commit freezes morse-pins at a commit", o.pins)
	case o.pins != "":
		pins = pinsFile(o.pins)
	case o.pinsCommit != "" && !shaPattern.MatchString(o.pinsCommit):
		return nil, fmt.Errorf("--pins-commit %q is not a 40-character lowercase hex commit", o.pinsCommit)
	default:
		repo := pinsRepo{repo: gitRemote{client: client, url: o.pinsRepo}, raw: o.pinsRaw, api: o.pinsAPI, frozen: o.pinsCommit}
		if repo.frozen != "" {
			if err := repo.frozenOnMain(context.Background()); err != nil {
				return nil, err
			}
		}
		pins = repo
	}
	source := sourceCheck{repo: gitRemote{client: client, url: strings.TrimSuffix(o.source, "/")}}
	trust, err := newTrust(client, o.env, pins, source, o.dev)
	if err != nil {
		return nil, err
	}
	s := newSidecar(base, o.key, o.floor, o.listen, trust)
	s.privacyVeil = o.privacyVeil
	return s, nil
}
