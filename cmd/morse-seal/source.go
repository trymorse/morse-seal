package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/trymorse/morse-seal/verify"
)

type gitRemote struct {
	client *http.Client
	url    string
}

func (g gitRemote) String() string {
	return strings.TrimPrefix(strings.TrimPrefix(g.url, "https://"), "github.com/")
}

func (g gitRemote) refs(ctx context.Context) (map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.url+"/info/refs?service=git-upload-pack", nil)
	if err != nil {
		return nil, err
	}
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", g, resp.StatusCode)
	}
	lines := bufio.NewReader(io.LimitReader(resp.Body, 4<<20))
	if first, err := readPkt(lines); err != nil || string(first) != "# service=git-upload-pack\n" {
		return nil, fmt.Errorf("%s does not speak git smart HTTP", g)
	}
	if _, err := readPkt(lines); err != nil {
		return nil, err
	}
	refs := map[string]string{}
	for {
		line, err := readPkt(lines)
		if err != nil {
			return nil, fmt.Errorf("%s: refs: %w", g, err)
		}
		if line == nil {
			return refs, nil
		}
		line, _, _ = bytes.Cut(bytes.TrimSuffix(line, []byte("\n")), []byte{0})
		sha, name, ok := strings.Cut(string(line), " ")
		if !ok || !shaPattern.MatchString(sha) {
			return nil, fmt.Errorf("%s: a ref line reads %q", g, line)
		}
		if peeled, annotated := strings.CutSuffix(name, "^{}"); annotated {
			name = peeled
		}
		refs[name] = sha
	}
}

func (g gitRemote) commit(ctx context.Context, sha string) ([]byte, error) {
	var body bytes.Buffer
	for _, line := range []string{"want " + sha + " no-progress shallow filter agent=morse-seal\n", "deepen 1\n", "filter tree:0\n", "", "done\n"} {
		writePkt(&body, line)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.url+"/git-upload-pack", &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d for commit %s", g, resp.StatusCode, sha)
	}
	reply := bufio.NewReader(io.LimitReader(resp.Body, 1<<20))
	for {
		line, err := readPkt(reply)
		if err != nil {
			return nil, fmt.Errorf("%s: commit %s: %w", g, sha, err)
		}
		if text := string(line); text == "NAK\n" {
			break
		} else if strings.HasPrefix(text, "ERR ") {
			return nil, fmt.Errorf("%s: commit %s: %s", g, sha, strings.TrimSpace(text))
		}
	}
	object, err := firstPackObject(reply)
	if err != nil {
		return nil, fmt.Errorf("%s: commit %s: %w", g, sha, err)
	}
	sum := sha1.Sum(append(fmt.Appendf(nil, "commit %d\x00", len(object)), object...))
	if hex.EncodeToString(sum[:]) != sha {
		return nil, fmt.Errorf("%s sent an object that is not commit %s", g, sha)
	}
	return object, nil
}

func readPkt(r *bufio.Reader) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(string(size[:]), 16, 16)
	if err != nil || n == 1 || n == 2 || n == 3 {
		return nil, fmt.Errorf("a pkt-line length reads %q", size)
	}
	if n == 0 {
		return nil, nil
	}
	line := make([]byte, n-4)
	_, err = io.ReadFull(r, line)
	return line, err
}

func writePkt(w *bytes.Buffer, line string) {
	if line == "" {
		w.WriteString("0000")
		return
	}
	fmt.Fprintf(w, "%04x%s", len(line)+4, line)
}

const packCommit = 1

func firstPackObject(r *bufio.Reader) ([]byte, error) {
	var header [12]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("pack: %w", err)
	}
	if string(header[:4]) != "PACK" || header[7] != 2 || bytes.Equal(header[8:], []byte{0, 0, 0, 0}) {
		return nil, errors.New("the reply is not a pack that holds an object")
	}
	c, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	kind, size, shift := (c>>4)&7, uint64(c&15), 4
	for c&0x80 != 0 && shift < 32 {
		if c, err = r.ReadByte(); err != nil {
			return nil, err
		}
		size |= uint64(c&0x7f) << shift
		shift += 7
	}
	if kind != packCommit || size > 64<<10 {
		return nil, fmt.Errorf("the pack's first object is type %d of %d bytes, not a commit", kind, size)
	}
	inflated, err := zlib.NewReader(r)
	if err != nil {
		return nil, err
	}
	object := make([]byte, size)
	if _, err := io.ReadFull(inflated, object); err != nil {
		return nil, fmt.Errorf("the commit does not inflate: %w", err)
	}
	return object, nil
}

var (
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	releasePattern = regexp.MustCompile(`^(\S+)\n\nPCR0 ([0-9a-f]{96})\nPCR1 ([0-9a-f]{96})\nPCR2 ([0-9a-f]{96})\n(?:rootfs sha256 [0-9a-f]{64}\n)?$`)
)

type release struct {
	tag, commit      string
	pcr0, pcr1, pcr2 string
}

func parseRelease(commit string, object []byte) (release, error) {
	_, message, ok := bytes.Cut(object, []byte("\n\n"))
	m := releasePattern.FindSubmatch(message)
	if !ok || m == nil {
		return release{}, fmt.Errorf("commit %s does not read as a release: its message is not the tag and PCR0, PCR1, and PCR2 lines", commit)
	}
	return release{tag: string(m[1]), commit: commit, pcr0: string(m[2]), pcr1: string(m[3]), pcr2: string(m[4])}, nil
}

type sourceCheck struct {
	repo gitRemote
}

func (s sourceCheck) confirm(ctx context.Context, pin verify.Pin) (release, error) {
	tag, tagged := pin.Image.Tag()
	if !tagged {
		return release{}, fmt.Errorf("the pin for %s names no tag in %s, so its source is not published", pin.Name(), s.repo)
	}
	refs, err := s.repo.refs(ctx)
	if err != nil {
		return release{}, fmt.Errorf("the source of %s cannot be confirmed: %w", tag, err)
	}
	commit, ok := refs["refs/tags/"+tag]
	if !ok {
		return release{}, fmt.Errorf("%s has no tag %s, so the source of that image is not published", s.repo, tag)
	}
	object, err := s.repo.commit(ctx, commit)
	if err != nil {
		return release{}, fmt.Errorf("the source of %s cannot be confirmed: %w", tag, err)
	}
	r, err := parseRelease(commit, object)
	if err != nil {
		return release{}, fmt.Errorf("%s tag %s: %w", s.repo, tag, err)
	}
	if r.tag != tag {
		return release{}, fmt.Errorf("%s tag %s is the release of %s", s.repo, tag, r.tag)
	}
	for _, pcr := range [][3]string{{"PCR0", r.pcr0, pin.PCR0}, {"PCR1", r.pcr1, pin.PCR1}, {"PCR2", r.pcr2, pin.PCR2}} {
		if pcr[1] != pcr[2] {
			return release{}, fmt.Errorf("%s tag %s publishes %s %s…, not the pinned %s…", s.repo, tag, pcr[0], pcr[1][:16], pcr[2][:16])
		}
	}
	return r, nil
}
