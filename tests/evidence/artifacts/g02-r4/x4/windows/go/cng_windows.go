//go:build windows

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// golang.org/x/sys/windows has no NCrypt bindings, so the spike binds ncrypt.dll lazily by hand.
// That is plain syscall + unsafe.Pointer (no cgo).
var (
	ncrypt          = windows.NewLazySystemDLL("ncrypt.dll")
	pOpenProvider   = ncrypt.NewProc("NCryptOpenStorageProvider")
	pCreateKey      = ncrypt.NewProc("NCryptCreatePersistedKey")
	pSetProperty    = ncrypt.NewProc("NCryptSetProperty")
	pFinalizeKey    = ncrypt.NewProc("NCryptFinalizeKey")
	pOpenKey        = ncrypt.NewProc("NCryptOpenKey")
	pSignHash       = ncrypt.NewProc("NCryptSignHash")
	pVerifySig      = ncrypt.NewProc("NCryptVerifySignature")
	pExportKey      = ncrypt.NewProc("NCryptExportKey")
	pDeleteKey      = ncrypt.NewProc("NCryptDeleteKey")
	pFreeObject     = ncrypt.NewProc("NCryptFreeObject")
	softwareKSP     = "Microsoft Software Key Storage Provider"
	platformKSP     = "Microsoft Platform Crypto Provider" // TPM-backed; needs a TPM, may reject ECDSA_P256 on old TPMs
	ncryptSilent    = uintptr(0x40)                        // NCRYPT_SILENT_FLAG
	ntBadKeyset     = uint32(0x80090016)
	eccPublicMagic  = uint32(0x31534345) // BCRYPT_ECDSA_PUBLIC_P256_MAGIC "ECS1"
	exportPolicyKey = "Export Policy"
)

type secErr struct {
	fn   string
	code uint32
}

func (e *secErr) Error() string { return fmt.Sprintf("%s: SECURITY_STATUS 0x%08X", e.fn, e.code) }

func st(fn string, r uintptr) error {
	if r != 0 {
		return &secErr{fn, uint32(r)}
	}
	return nil
}

func u16(s string) *uint16 { p, _ := windows.UTF16PtrFromString(s); return p }

func openProvider(name string) (uintptr, error) {
	var h uintptr
	r, _, _ := pOpenProvider.Call(uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(u16(name))), 0)
	return h, st("NCryptOpenStorageProvider", r)
}

func free(h uintptr) { pFreeObject.Call(h) }

func createKey(prov uintptr, name string) (uintptr, error) {
	var k uintptr
	// No NCRYPT_OVERWRITE_KEY_FLAG: an existing key of the same name must fail with NTE_EXISTS.
	r, _, _ := pCreateKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16("ECDSA_P256"))), uintptr(unsafe.Pointer(u16(name))), 0, ncryptSilent)
	if err := st("NCryptCreatePersistedKey", r); err != nil {
		return 0, err
	}
	// Explicit non-exportable policy (DWORD 0). Non-fatal on providers that reject the property.
	var pol uint32
	pSetProperty.Call(k, uintptr(unsafe.Pointer(u16(exportPolicyKey))), uintptr(unsafe.Pointer(&pol)), 4, ncryptSilent)
	r, _, _ = pFinalizeKey.Call(k, ncryptSilent)
	if err := st("NCryptFinalizeKey", r); err != nil {
		free(k)
		return 0, err
	}
	return k, nil
}

func openKey(prov uintptr, name string) (uintptr, error) {
	var k uintptr
	r, _, _ := pOpenKey.Call(prov, uintptr(unsafe.Pointer(&k)), uintptr(unsafe.Pointer(u16(name))), 0, ncryptSilent)
	return k, st("NCryptOpenKey", r)
}

func exportPublic(k uintptr) ([]byte, error) {
	var n uint32
	typ := u16("ECCPUBLICBLOB")
	r, _, _ := pExportKey.Call(k, 0, uintptr(unsafe.Pointer(typ)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err := st("NCryptExportKey(size)", r); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	r, _, _ = pExportKey.Call(k, 0, uintptr(unsafe.Pointer(typ)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	return buf[:n], st("NCryptExportKey", r)
}

func signVerify(k uintptr) (sigLen int, verified bool, err error) {
	h := sha256.Sum256([]byte("heimdall-x4-cng-sign-marker"))
	var n uint32
	r, _, _ := pSignHash.Call(k, 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	if err = st("NCryptSignHash(size)", r); err != nil {
		return
	}
	sig := make([]byte, n)
	r, _, _ = pSignHash.Call(k, 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), uintptr(unsafe.Pointer(&sig[0])), uintptr(n), uintptr(unsafe.Pointer(&n)), 0)
	if err = st("NCryptSignHash", r); err != nil {
		return
	}
	sigLen = int(n)
	r, _, _ = pVerifySig.Call(k, 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), uintptr(unsafe.Pointer(&sig[0])), uintptr(n), 0)
	verified = r == 0
	sig[0] ^= 0xff // tampered signature must NOT verify
	r2, _, _ := pVerifySig.Call(k, 0, uintptr(unsafe.Pointer(&h[0])), uintptr(len(h)), uintptr(unsafe.Pointer(&sig[0])), uintptr(n), 0)
	if r2 == 0 {
		verified = false
	}
	return
}

func deleteKey(k uintptr) error {
	r, _, _ := pDeleteKey.Call(k, ncryptSilent) // also releases the handle on success
	return st("NCryptDeleteKey", r)
}

// runCNG executes op = probe|create|sign|delete|all against the named KSP. Each op is a separate
// process invocation when driven by the run script, so persistence across processes is exercised.
func runCNG(op, provider, keyName string) map[string]any {
	res := map[string]any{"op": "cng-" + op, "provider": provider, "key_name": keyName}
	fail := func(err error) map[string]any {
		res["ok"], res["error"] = false, err.Error()
		if e, ok := err.(*secErr); ok {
			res["status_hex"] = fmt.Sprintf("0x%08X", e.code)
		}
		return res
	}
	name := softwareKSP
	if provider == "platform" {
		name = platformKSP
	}
	if op == "probe" {
		for _, p := range []struct{ id, n string }{{"software", softwareKSP}, {"platform", platformKSP}} {
			h, err := openProvider(p.n)
			res[p.id+"_provider_open"] = err == nil
			if err != nil {
				res[p.id+"_provider_error"] = err.Error()
			} else {
				free(h)
			}
		}
		res["ok"] = true
		return res
	}
	prov, err := openProvider(name)
	if err != nil {
		return fail(err)
	}
	defer free(prov)
	do := func(step string) error {
		switch step {
		case "create":
			k, err := createKey(prov, keyName)
			if err != nil {
				return err
			}
			defer free(k)
			pub, err := exportPublic(k)
			if err != nil {
				return err
			}
			res["created"] = true
			res["pub_blob_len"] = len(pub)
			res["pub_magic_ok"] = len(pub) >= 8 && binary.LittleEndian.Uint32(pub) == eccPublicMagic && binary.LittleEndian.Uint32(pub[4:]) == 32
		case "sign":
			k, err := openKey(prov, keyName)
			if err != nil {
				return err
			}
			defer free(k)
			n, ok, err := signVerify(k)
			if err != nil {
				return err
			}
			res["sig_len"], res["verify_ok_and_tamper_rejected"] = n, ok
		case "delete":
			k, err := openKey(prov, keyName)
			if err != nil {
				return err
			}
			if err := deleteKey(k); err != nil {
				return err
			}
			res["deleted"] = true
			if _, err := openKey(prov, keyName); err != nil {
				e, _ := err.(*secErr)
				res["open_after_delete_is_bad_keyset"] = e != nil && e.code == ntBadKeyset
			} else {
				res["open_after_delete_is_bad_keyset"] = false
			}
		}
		return nil
	}
	steps := []string{op}
	if op == "all" {
		steps = []string{"create", "sign", "delete"}
	}
	for _, s := range steps {
		if err := do(s); err != nil {
			return fail(err)
		}
	}
	res["ok"] = true
	return res
}
