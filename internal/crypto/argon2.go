package crypto

import (
	"errors"
	"fmt"
	"runtime"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultArgon2MemoryKiB  uint32 = 256 * 1024
	DefaultArgon2Iterations uint32 = 3
	DefaultArgon2SaltLen           = 32
	DefaultArgon2KeyLen     uint32 = 32
	MinArgon2MemoryKiB      uint32 = 32 * 1024
)

var ErrInvalidArgon2Params = errors.New("invalid argon2 parameters")

type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     int
	KeyLen      uint32
}

func DefaultArgon2Params() Argon2Params {
	parallelism := runtime.NumCPU()
	if parallelism > 4 {
		parallelism = 4
	}
	if parallelism < 1 {
		parallelism = 1
	}

	return Argon2Params{
		Memory:      DefaultArgon2MemoryKiB,
		Iterations:  DefaultArgon2Iterations,
		Parallelism: uint8(parallelism),
		SaltLen:     DefaultArgon2SaltLen,
		KeyLen:      DefaultArgon2KeyLen,
	}
}

func (p Argon2Params) Validate() error {
	switch {
	case p.Memory < MinArgon2MemoryKiB:
		return fmt.Errorf("%w: memory must be >= %d KiB", ErrInvalidArgon2Params, MinArgon2MemoryKiB)
	case p.Iterations == 0:
		return fmt.Errorf("%w: iterations must be > 0", ErrInvalidArgon2Params)
	case p.Parallelism == 0:
		return fmt.Errorf("%w: parallelism must be > 0", ErrInvalidArgon2Params)
	case p.SaltLen < 16:
		return fmt.Errorf("%w: salt length must be >= 16", ErrInvalidArgon2Params)
	case p.KeyLen == 0:
		return fmt.Errorf("%w: key length must be > 0", ErrInvalidArgon2Params)
	default:
		return nil
	}
}

func DeriveKEKFromPassphrase(passphrase []byte, salt []byte, params Argon2Params) ([]byte, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("%w: passphrase must not be empty", ErrInvalidArgon2Params)
	}
	if len(salt) < params.SaltLen {
		return nil, fmt.Errorf("%w: salt must be at least %d bytes", ErrInvalidArgon2Params, params.SaltLen)
	}

	key := argon2.IDKey(passphrase, salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLen)
	return key, nil
}
