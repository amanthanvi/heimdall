// X4 Linux spike (Go): store, read, delete a secret via freedesktop Secret
// Service (D-Bus) and the kernel keyring. Disposable G02 round-4 evidence code.
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// result is the only thing ever printed. It never contains the secret.
type result struct {
	Backend string `json:"backend"`
	Lang    string `json:"lang"`
	Store   string `json:"store"`
	Read    string `json:"read"`
	Match   bool   `json:"match"`
	Delete  string `json:"delete"`
	Gone    bool   `json:"gone"`
	Err     string `json:"err,omitempty"`
}

// backend: store(secret) -> read() -> delete() -> gone().
type backend interface {
	store(name string, secret []byte) error
	read(name string) ([]byte, error)
	del(name string) error
	gone(name string) (bool, error)
}

func run(b backend, label string) result {
	r := result{Backend: label, Lang: "go", Store: "skip", Read: "skip", Delete: "skip"}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		r.Err = "rand: " + err.Error()
		return r
	}
	secret := []byte(hex.EncodeToString(raw))
	sum := sha256.Sum256(raw)
	name := "hm-x4-" + hex.EncodeToString(sum[:4])
	step := func(s *string, err error) bool {
		if err != nil {
			*s = "fail"
			r.Err = err.Error()
			return false
		}
		*s = "ok"
		return true
	}
	if !step(&r.Store, b.store(name, secret)) {
		return r
	}
	got, err := b.read(name)
	if step(&r.Read, err) {
		r.Match = subtle.ConstantTimeCompare(got, secret) == 1
	}
	derr := b.del(name)
	step(&r.Delete, derr)
	if derr == nil {
		g, err := b.gone(name)
		r.Gone = g
		if err != nil {
			r.Err = err.Error()
		}
	}
	return r
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: spike secret-service|keyctl|keyctl-user")
		os.Exit(2)
	}
	// Watchdog: a locked collection can make Secret Service block on a prompt.
	time.AfterFunc(20*time.Second, func() {
		fmt.Fprintln(os.Stderr, "timeout")
		os.Exit(124)
	})
	b, label := pick(os.Args[1])
	if b == nil {
		fmt.Fprintln(os.Stderr, "unknown or unavailable backend")
		os.Exit(2)
	}
	r := run(b, label)
	_ = json.NewEncoder(os.Stdout).Encode(r)
	if r.Store != "ok" || r.Read != "ok" || !r.Match || r.Delete != "ok" || !r.Gone {
		os.Exit(1)
	}
}
