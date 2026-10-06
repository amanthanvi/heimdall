//go:build windows

package main

import (
	"bytes"
	"unsafe"

	"golang.org/x/sys/windows"
)

// protect wraps CryptProtectData (user scope, UI forbidden). entropy may be nil.
func protect(plain, entropy []byte) ([]byte, error) {
	in := blob(plain)
	var out windows.DataBlob
	err := windows.CryptProtectData(&in, windows.StringToUTF16Ptr("heimdall-x4"), optBlob(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:errcheck
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func unprotect(ct, entropy []byte) ([]byte, error) {
	in := blob(ct)
	var out windows.DataBlob
	var desc *uint16
	err := windows.CryptUnprotectData(&in, &desc, optBlob(entropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data))) //nolint:errcheck
	if desc != nil {
		defer windows.LocalFree(windows.Handle(unsafe.Pointer(desc))) //nolint:errcheck
	}
	return bytes.Clone(unsafe.Slice(out.Data, out.Size)), nil
}

func blob(b []byte) windows.DataBlob {
	if len(b) == 0 {
		return windows.DataBlob{}
	}
	return windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func optBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return nil
	}
	d := blob(b)
	return &d
}

// runDPAPI: round trip, tamper detection and entropy mismatch rejection. The plaintext is a fixed
// non-secret marker; nothing sensitive is printed.
func runDPAPI() map[string]any {
	plain := []byte("heimdall-x4-dpapi-roundtrip-marker")
	entropy := []byte("heimdall-x4-entropy")
	res := map[string]any{"op": "dpapi", "scope": "current-user"}
	ct, err := protect(plain, entropy)
	if err != nil {
		res["ok"], res["error"] = false, err.Error()
		return res
	}
	res["ciphertext_len"] = len(ct)
	res["ciphertext_differs"] = !bytes.Contains(ct, plain)
	back, err := unprotect(ct, entropy)
	res["roundtrip_ok"] = err == nil && bytes.Equal(back, plain)
	_, err = unprotect(ct, []byte("wrong-entropy"))
	res["wrong_entropy_rejected"] = err != nil
	bad := bytes.Clone(ct)
	bad[len(bad)/2] ^= 0xff
	_, err = unprotect(bad, entropy)
	res["tamper_rejected"] = err != nil
	res["ok"] = res["roundtrip_ok"] == true && res["wrong_entropy_rejected"] == true && res["tamper_rejected"] == true
	return res
}
