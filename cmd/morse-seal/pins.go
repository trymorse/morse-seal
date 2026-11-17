package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/trymorse/morse-seal/verify"
)

type snapshot struct {
	origin string
	pins   []verify.Pin
}

type pinsSource interface {
	load(ctx context.Context) (snapshot, error)
}

type pinsFile string

func (p pinsFile) load(context.Context) (snapshot, error) {
	data, err := os.ReadFile(string(p))
	if err != nil {
		return snapshot{}, fmt.Errorf("pins: %w", err)
	}
	pins, err := verify.ParsePins(data)
	return snapshot{origin: "file " + string(p), pins: pins}, err
}

type pinsRepo struct {
	repo   gitRemote
	raw    string
	api    string
	frozen string
}

func (p pinsRepo) frozenOnMain(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.api+"/compare/"+p.frozen+"...main", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := p.repo.client.Do(req)
	if err != nil {
		return fmt.Errorf("--pins-commit %s cannot be confirmed on main of %s: %w", p.frozen, p.repo, err)
	}
	defer resp.Body.Close()
	var compare struct{ Status, Message string }
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&compare)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("--pins-commit %s is not a commit of %s", p.frozen, p.repo)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("--pins-commit %s cannot be confirmed on main of %s: the GitHub API answered %d %s", p.frozen, p.repo, resp.StatusCode, compare.Message)
	case decodeErr != nil:
		return fmt.Errorf("--pins-commit %s cannot be confirmed on main of %s: %w", p.frozen, p.repo, decodeErr)
	case compare.Status != "ahead" && compare.Status != "identical":
		return fmt.Errorf("--pins-commit %s is not in the history of main of %s; GitHub compares it as %q, and a commit off main can come from a fork", p.frozen, p.repo, compare.Status)
	}
	return nil
}

func (p pinsRepo) load(ctx context.Context) (snapshot, error) {
	commit := p.frozen
	if commit == "" {
		refs, err := p.repo.refs(ctx)
		if err != nil {
			return snapshot{}, fmt.Errorf("pins: %w", err)
		}
		if commit = refs["refs/heads/main"]; commit == "" {
			return snapshot{}, fmt.Errorf("pins: %s has no main branch", p.repo)
		}
	}
	origin := p.repo.String() + "@" + commit
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.raw+"/"+commit+"/enclave_pins.json", nil)
	if err != nil {
		return snapshot{}, err
	}
	resp, err := p.repo.client.Do(req)
	if err != nil {
		return snapshot{}, fmt.Errorf("pins %s: %w", origin, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return snapshot{}, fmt.Errorf("pins %s: enclave_pins.json answered %d", origin, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return snapshot{}, fmt.Errorf("pins %s: %w", origin, err)
	}
	pins, err := verify.ParsePins(data)
	if err != nil {
		return snapshot{}, fmt.Errorf("pins %s: %w", origin, err)
	}
	return snapshot{origin: origin, pins: pins}, nil
}
