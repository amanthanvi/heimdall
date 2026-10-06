//go:build !nobackends

package main

import (
	"errors"

	keyring "github.com/zalando/go-keyring"
	"golang.org/x/sys/unix"
)

func pick(name string) (backend, string) {
	switch name {
	case "secret-service":
		return ssBackend{}, "secret-service"
	case "keyctl":
		return kcBackend{}, "keyctl-session"
	case "keyctl-user":
		return kcBackend{user: true}, "keyctl-user"
	}
	return nil, ""
}

// Secret Service via zalando/go-keyring (pure Go, godbus underneath).
const svc = "heimdall-x4"

type ssBackend struct{}

func (ssBackend) store(n string, s []byte) error { return keyring.Set(svc, n, string(s)) }
func (ssBackend) read(n string) ([]byte, error) {
	v, err := keyring.Get(svc, n)
	return []byte(v), err
}
func (ssBackend) del(n string) error { return keyring.Delete(svc, n) }
func (ssBackend) gone(n string) (bool, error) {
	_, err := keyring.Get(svc, n)
	return errors.Is(err, keyring.ErrNotFound), nil
}

// Kernel keyring via golang.org/x/sys/unix (raw keyctl syscalls, no cgo).
// scope "session": the process session keyring (keys die with the session).
// scope "user": the per-UID user keyring, linked into the session keyring so the
// process POSSESSES it. Without possession a default-permission key (POS_ALL |
// USR_VIEW) is not readable by its own owner; inside runc the anonymous session
// keyring does not link the user keyring. The session keyring is never joined
// here: joining is per-thread credential state and unsafe from Go's runtime
// without LockOSThread.
type kcBackend struct{ user bool }

func (k kcBackend) ring() (int, error) {
	if !k.user {
		return unix.KEY_SPEC_SESSION_KEYRING, nil
	}
	u, err := unix.KeyctlGetKeyringID(unix.KEY_SPEC_USER_KEYRING, true)
	if err != nil {
		return 0, err
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_LINK, u, unix.KEY_SPEC_SESSION_KEYRING, 0, 0); err != nil {
		return 0, err
	}
	return u, nil
}

func (k kcBackend) store(n string, s []byte) error {
	r, err := k.ring()
	if err != nil {
		return err
	}
	_, err = unix.AddKey("user", n, s, r)
	return err
}
func (k kcBackend) find(n string) (int, int, error) {
	r, err := k.ring()
	if err != nil {
		return 0, 0, err
	}
	id, err := unix.KeyctlSearch(r, "user", n, 0)
	return id, r, err
}
func (k kcBackend) read(n string) ([]byte, error) {
	id, _, err := k.find(n)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	m, err := unix.KeyctlBuffer(unix.KEYCTL_READ, id, buf, 0)
	if err != nil {
		return nil, err
	}
	if m > len(buf) {
		return nil, errors.New("payload larger than buffer")
	}
	return buf[:m], nil
}
func (k kcBackend) del(n string) error {
	id, r, err := k.find(n)
	if err != nil {
		return err
	}
	if _, err := unix.KeyctlInt(unix.KEYCTL_REVOKE, id, 0, 0, 0); err != nil {
		return err
	}
	_, err = unix.KeyctlInt(unix.KEYCTL_UNLINK, id, r, 0, 0)
	return err
}
func (k kcBackend) gone(n string) (bool, error) {
	_, _, err := k.find(n)
	return errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.EKEYREVOKED), nil
}
