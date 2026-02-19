//go:build fido2

package fido2

/*
#cgo CFLAGS: -D_FORTIFY_SOURCE=2
#cgo pkg-config: libfido2
#include <stdlib.h>
#include <fido.h>
*/
import "C"

import (
	"fmt"
	"sync"
	"unsafe"
)

type cgoAuthenticator struct {
	mu  sync.Mutex
	dev *C.fido_dev_t
}

func NewAuthenticator(devicePath string) (Authenticator, error) {
	if devicePath == "" {
		return nil, fmt.Errorf("open fido2 device: device path is required")
	}

	C.fido_init(0)
	dev := C.fido_dev_new()
	if dev == nil {
		return nil, fmt.Errorf("open fido2 device: allocation failed")
	}

	cPath := C.CString(devicePath)
	defer C.free(unsafe.Pointer(cPath))

	rc := C.fido_dev_open(dev, cPath)
	if rc != C.FIDO_OK {
		C.fido_dev_free(&dev)
		return nil, fmt.Errorf("open fido2 device: %s", C.GoString(C.fido_strerr(rc)))
	}

	return &cgoAuthenticator{dev: dev}, nil
}

func (a *cgoAuthenticator) MakeCredential(opts MakeCredentialOpts) (*Credential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev == nil {
		return nil, fmt.Errorf("make credential: device is closed")
	}
	if opts.RPID == "" {
		opts.RPID = defaultRPID
	}
	if len(opts.UserHandle) == 0 {
		buf, err := randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("make credential: generate user handle: %w", err)
		}
		opts.UserHandle = buf
	}
	if opts.UserName == "" {
		opts.UserName = "heimdall"
	}

	cred := C.fido_cred_new()
	if cred == nil {
		return nil, fmt.Errorf("make credential: allocation failed")
	}
	defer C.fido_cred_free(&cred)

	rpid := C.CString(opts.RPID)
	defer C.free(unsafe.Pointer(rpid))
	username := C.CString(opts.UserName)
	defer C.free(unsafe.Pointer(username))

	rc := C.fido_cred_set_rp(cred, rpid, rpid)
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: set rp: %s", C.GoString(C.fido_strerr(rc)))
	}

	rc = C.fido_cred_set_user(
		cred,
		(*C.uchar)(unsafe.Pointer(&opts.UserHandle[0])),
		C.size_t(len(opts.UserHandle)),
		username,
		username,
		nil,
	)
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: set user: %s", C.GoString(C.fido_strerr(rc)))
	}

	alg := opts.Algorithm
	if alg == 0 {
		alg = -7
	}
	rc = C.fido_cred_set_type(cred, C.int(alg))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: set algorithm: %s", C.GoString(C.fido_strerr(rc)))
	}

	clientDataHash, err := randomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("make credential: generate client data hash: %w", err)
	}
	rc = C.fido_cred_set_clientdata_hash(cred, (*C.uchar)(unsafe.Pointer(&clientDataHash[0])), C.size_t(len(clientDataHash)))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: set client data hash: %s", C.GoString(C.fido_strerr(rc)))
	}

	if opts.RequireHMACSecret {
		rc = C.fido_cred_set_extensions(cred, C.FIDO_EXT_HMAC_SECRET)
		if rc != C.FIDO_OK {
			return nil, fmt.Errorf("make credential: set extension: %s", C.GoString(C.fido_strerr(rc)))
		}
	}

	rc = C.fido_cred_set_uv(cred, uvPolicyToC(opts.UVPolicy))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: set uv policy: %s", C.GoString(C.fido_strerr(rc)))
	}

	var cPIN *C.char
	if len(opts.PIN) > 0 {
		cPIN = C.CString(string(opts.PIN))
		defer C.free(unsafe.Pointer(cPIN))
	}

	rc = C.fido_dev_make_cred(a.dev, cred, cPIN)
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("make credential: device call failed: %s", C.GoString(C.fido_strerr(rc)))
	}

	idPtr := C.fido_cred_id_ptr(cred)
	idLen := C.fido_cred_id_len(cred)
	pubPtr := C.fido_cred_pubkey_ptr(cred)
	pubLen := C.fido_cred_pubkey_len(cred)
	aaguidPtr := C.fido_cred_aaguid_ptr(cred)

	credential := &Credential{
		CredentialID:       cBytes(idPtr, idLen),
		PublicKeyCOSE:      cBytes(pubPtr, pubLen),
		AAGUID:             cBytes(aaguidPtr, 16),
		SupportsHMACSecret: opts.RequireHMACSecret,
	}
	return credential, nil
}

func (a *cgoAuthenticator) GetAssertion(opts GetAssertionOpts) (*Assertion, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev == nil {
		return nil, fmt.Errorf("get assertion: device is closed")
	}
	if opts.RPID == "" {
		opts.RPID = defaultRPID
	}
	if len(opts.CredentialID) == 0 {
		return nil, fmt.Errorf("get assertion: credential id is required")
	}
	if len(opts.ClientDataHash) == 0 {
		buf, err := randomBytes(32)
		if err != nil {
			return nil, fmt.Errorf("get assertion: generate client data hash: %w", err)
		}
		opts.ClientDataHash = buf
	}

	assertion := C.fido_assert_new()
	if assertion == nil {
		return nil, fmt.Errorf("get assertion: allocation failed")
	}
	defer C.fido_assert_free(&assertion)

	rpid := C.CString(opts.RPID)
	defer C.free(unsafe.Pointer(rpid))

	rc := C.fido_assert_set_rp(assertion, rpid)
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("get assertion: set rp: %s", C.GoString(C.fido_strerr(rc)))
	}

	rc = C.fido_assert_set_clientdata_hash(assertion, (*C.uchar)(unsafe.Pointer(&opts.ClientDataHash[0])), C.size_t(len(opts.ClientDataHash)))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("get assertion: set client data hash: %s", C.GoString(C.fido_strerr(rc)))
	}

	rc = C.fido_assert_allow_cred(assertion, (*C.uchar)(unsafe.Pointer(&opts.CredentialID[0])), C.size_t(len(opts.CredentialID)))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("get assertion: set allow credential: %s", C.GoString(C.fido_strerr(rc)))
	}

	if opts.RequireHMACSecret {
		rc = C.fido_assert_set_extensions(assertion, C.FIDO_EXT_HMAC_SECRET)
		if rc != C.FIDO_OK {
			return nil, fmt.Errorf("get assertion: set extension: %s", C.GoString(C.fido_strerr(rc)))
		}
		if len(opts.HMACSecretSalt) > 0 {
			rc = C.fido_assert_set_hmac_salt(assertion, (*C.uchar)(unsafe.Pointer(&opts.HMACSecretSalt[0])), C.size_t(len(opts.HMACSecretSalt)))
			if rc != C.FIDO_OK {
				return nil, fmt.Errorf("get assertion: set hmac salt: %s", C.GoString(C.fido_strerr(rc)))
			}
		}
	}

	rc = C.fido_assert_set_uv(assertion, uvPolicyToC(opts.UVPolicy))
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("get assertion: set uv policy: %s", C.GoString(C.fido_strerr(rc)))
	}

	var cPIN *C.char
	if len(opts.PIN) > 0 {
		cPIN = C.CString(string(opts.PIN))
		defer C.free(unsafe.Pointer(cPIN))
	}

	rc = C.fido_dev_get_assert(a.dev, assertion, cPIN)
	if rc != C.FIDO_OK {
		return nil, fmt.Errorf("get assertion: device call failed: %s", C.GoString(C.fido_strerr(rc)))
	}

	if C.fido_assert_count(assertion) == 0 {
		return nil, fmt.Errorf("get assertion: empty assertion result")
	}

	authData := cBytes(C.fido_assert_authdata_ptr(assertion, 0), C.fido_assert_authdata_len(assertion, 0))
	signature := cBytes(C.fido_assert_sig_ptr(assertion, 0), C.fido_assert_sig_len(assertion, 0))
	hmacOutput := cBytes(C.fido_assert_hmac_secret_ptr(assertion, 0), C.fido_assert_hmac_secret_len(assertion, 0))

	return &Assertion{
		AuthData:         authData,
		Signature:        signature,
		HMACSecretOutput: hmacOutput,
	}, nil
}

func (a *cgoAuthenticator) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.dev == nil {
		return nil
	}
	C.fido_dev_close(a.dev)
	C.fido_dev_free(&a.dev)
	return nil
}

func uvPolicyToC(policy string) C.fido_opt_t {
	switch policy {
	case "required":
		return C.FIDO_OPT_TRUE
	case "discouraged":
		return C.FIDO_OPT_FALSE
	default:
		return C.FIDO_OPT_OMIT
	}
}

func cBytes(ptr *C.uchar, length C.size_t) []byte {
	if ptr == nil || length == 0 {
		return nil
	}
	return C.GoBytes(unsafe.Pointer(ptr), C.int(length))
}
