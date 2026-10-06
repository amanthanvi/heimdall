//go:build darwin

// hm-x4-go-purego: same three probes as hm-x4-go, but calling Security.framework through
// github.com/ebitengine/purego (dlopen/dlsym, no cgo), so it builds with CGO_ENABLED=0.
// Disposable G02 round-4 X4 evidence, not production code. Secrets are never printed.
//
//	hm-x4-go-purego keychain <file-keychain-path> | se | dpprobe
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"github.com/ebitengine/purego"
)

type ref = uintptr // any CF/Sec object reference

var (
	cfRelease            func(ref)
	cfDictionaryCreate   func(alloc ref, keys, values *ref, n int, kcb, vcb uintptr) ref
	cfDictionaryGetValue func(d, k ref) ref
	cfEqual              func(a, b ref) bool
	cfNumberCreate       func(alloc ref, typ int, v *int32) ref
	cfDataCreate         func(alloc ref, b *byte, n int) ref
	cfDataGetLength      func(d ref) int
	cfStringCreate       func(alloc ref, s string, enc uint32) ref
	cfErrorGetCode       func(e ref) int

	secKeychainOpen                func(path string, kc *ref) int32
	secKeychainAddGenericPassword  func(kc ref, sl uint32, s string, al uint32, a string, pl uint32, p *byte, item *ref) int32
	secKeychainFindGenericPassword func(kc ref, sl uint32, s string, al uint32, a string, pl *uint32, p *unsafe.Pointer, item *ref) int32
	secKeychainItemFreeContent     func(attrs ref, data unsafe.Pointer) int32
	secKeychainItemDelete          func(item ref) int32
	secItemCopyMatching            func(q ref, out *ref) int32
	secAccessControlCreate         func(alloc, prot ref, flags uint64, err *ref) ref
	secKeyCreateRandomKey          func(attrs ref, err *ref) ref
	secKeyCopyAttributes           func(k ref) ref
	secKeyCopyExternalRep          func(k ref, err *ref) ref
	secKeyCopyPublicKey            func(k ref) ref
	secKeyCreateSignature          func(k, alg, data ref, err *ref) ref
	secKeyVerifySignature          func(k, alg, data, sig ref, err *ref) bool
)

var cf, sec uintptr

// constant reads the value of an exported `const CFStringRef`/`CFBooleanRef` symbol.
func constant(lib uintptr, name string) ref {
	p, err := purego.Dlsym(lib, name)
	if err != nil {
		panic(err)
	}
	return **(**ref)(unsafe.Pointer(&p))
}

// symbol returns the address of an exported data symbol (e.g. dictionary callback structs).
func symbol(lib uintptr, name string) uintptr {
	p, err := purego.Dlsym(lib, name)
	if err != nil {
		panic(err)
	}
	return p
}

func load() {
	var err error
	if cf, err = purego.Dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
		panic(err)
	}
	if sec, err = purego.Dlopen("/System/Library/Frameworks/Security.framework/Security", purego.RTLD_NOW|purego.RTLD_GLOBAL); err != nil {
		panic(err)
	}
	for name, fp := range map[string]any{
		"CFRelease": &cfRelease, "CFDictionaryCreate": &cfDictionaryCreate, "CFDictionaryGetValue": &cfDictionaryGetValue,
		"CFEqual": &cfEqual, "CFNumberCreate": &cfNumberCreate, "CFDataCreate": &cfDataCreate,
		"CFDataGetLength": &cfDataGetLength, "CFStringCreateWithCString": &cfStringCreate, "CFErrorGetCode": &cfErrorGetCode,
	} {
		purego.RegisterLibFunc(fp, cf, name)
	}
	for name, fp := range map[string]any{
		"SecKeychainOpen": &secKeychainOpen, "SecKeychainAddGenericPassword": &secKeychainAddGenericPassword,
		"SecKeychainFindGenericPassword": &secKeychainFindGenericPassword, "SecKeychainItemFreeContent": &secKeychainItemFreeContent,
		"SecKeychainItemDelete": &secKeychainItemDelete, "SecItemCopyMatching": &secItemCopyMatching,
		"SecAccessControlCreateWithFlags": &secAccessControlCreate, "SecKeyCreateRandomKey": &secKeyCreateRandomKey,
		"SecKeyCopyAttributes": &secKeyCopyAttributes, "SecKeyCopyExternalRepresentation": &secKeyCopyExternalRep,
		"SecKeyCopyPublicKey": &secKeyCopyPublicKey, "SecKeyCreateSignature": &secKeyCreateSignature,
		"SecKeyVerifySignature": &secKeyVerifySignature,
	} {
		purego.RegisterLibFunc(fp, sec, name)
	}
}

func dict(kv ...ref) ref {
	var k, v []ref
	for i := 0; i < len(kv); i += 2 {
		k, v = append(k, kv[i]), append(v, kv[i+1])
	}
	return cfDictionaryCreate(0, &k[0], &v[0], len(k),
		symbol(cf, "kCFTypeDictionaryKeyCallBacks"), symbol(cf, "kCFTypeDictionaryValueCallBacks"))
}

func cferr(e ref) int {
	if e == 0 {
		return -1
	}
	defer cfRelease(e)
	return cfErrorGetCode(e)
}

func rnd(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func keychain(path string) bool {
	svc, acct := "hm-x4-svc", "hm-x4-acct"
	secret := []byte("hm-x4-not-a-canary-" + rnd(16))
	var kc ref
	st := secKeychainOpen(path, &kc)
	fmt.Printf("keychain open osstatus=%d\n", st)
	if st != 0 {
		return false
	}
	defer cfRelease(kc)
	add := secKeychainAddGenericPassword(kc, uint32(len(svc)), svc, uint32(len(acct)), acct, uint32(len(secret)), &secret[0], nil)
	fmt.Printf("keychain add osstatus=%d\n", add)
	var n uint32
	var data unsafe.Pointer
	read := secKeychainFindGenericPassword(kc, uint32(len(svc)), svc, uint32(len(acct)), acct, &n, &data, nil)
	fmt.Printf("keychain read osstatus=%d\n", read)
	match := false
	if read == 0 {
		match = bytes.Equal(unsafe.Slice((*byte)(data), n), secret)
		secKeychainItemFreeContent(0, data)
		fmt.Printf("keychain read_mismatch osstatus=%d\n", map[bool]int{true: 0, false: 1}[match])
	}
	var item ref
	del := secKeychainFindGenericPassword(kc, uint32(len(svc)), svc, uint32(len(acct)), acct, nil, nil, &item)
	if del == 0 {
		del = secKeychainItemDelete(item)
		cfRelease(item)
	}
	fmt.Printf("keychain delete osstatus=%d\n", del)
	after := secKeychainFindGenericPassword(kc, uint32(len(svc)), svc, uint32(len(acct)), acct, nil, nil, nil)
	fmt.Printf("keychain read_after_delete osstatus=%d\n", after)
	return add == 0 && match && del == 0 && after == -25300
}

func se() bool {
	var e ref
	ac := secAccessControlCreate(0, constant(sec, "kSecAttrAccessibleWhenUnlockedThisDeviceOnly"), 1<<30 /* kSecAccessControlPrivateKeyUsage */, &e)
	if ac == 0 {
		fmt.Printf("se access_control_cferror=%d\n", cferr(e))
		return false
	}
	bits := int32(256)
	nbits := cfNumberCreate(0, 3 /* kCFNumberSInt32Type */, &bits)
	priv := dict(constant(sec, "kSecAttrIsPermanent"), constant(cf, "kCFBooleanFalse"), constant(sec, "kSecAttrAccessControl"), ac)
	tokSE := constant(sec, "kSecAttrTokenIDSecureEnclave")
	attrs := dict(constant(sec, "kSecAttrKeyType"), constant(sec, "kSecAttrKeyTypeECSECPrimeRandom"),
		constant(sec, "kSecAttrKeySizeInBits"), nbits, constant(sec, "kSecAttrTokenID"), tokSE, constant(sec, "kSecPrivateKeyAttrs"), priv)
	key := secKeyCreateRandomKey(attrs, &e)
	cfRelease(attrs)
	cfRelease(priv)
	cfRelease(nbits)
	cfRelease(ac)
	if key == 0 {
		fmt.Printf("se create_cferror=%d\n", cferr(e))
		return false
	}
	defer cfRelease(key)
	ka := secKeyCopyAttributes(key)
	isSE := cfEqual(cfDictionaryGetValue(ka, constant(sec, "kSecAttrTokenID")), tokSE)
	cfRelease(ka)
	privExportable := false
	if r := secKeyCopyExternalRep(key, &e); r != 0 {
		privExportable = true
		cfRelease(r)
	} else {
		cferr(e)
	}
	pub := secKeyCopyPublicKey(key)
	defer cfRelease(pub)
	pubLen := 0
	if r := secKeyCopyExternalRep(pub, nil); r != 0 {
		pubLen = cfDataGetLength(r)
		cfRelease(r)
	}
	fmt.Printf("se create_cferror=0 is_secure_enclave_token=%t private_exportable=%t public_len=%d\n", isSE, privExportable, pubLen)
	alg := constant(sec, "kSecKeyAlgorithmECDSASignatureMessageX962SHA256")
	msg := []byte("heimdall g02 r4 x4 message " + rnd(8))
	m := cfDataCreate(0, &msg[0], len(msg))
	defer cfRelease(m)
	sig := secKeyCreateSignature(key, alg, m, &e)
	if sig == 0 {
		fmt.Printf("se sign_cferror=%d\n", cferr(e))
		return false
	}
	defer cfRelease(sig)
	ok := secKeyVerifySignature(pub, alg, m, sig, nil)
	t := append([]byte(nil), msg...)
	t[0] ^= 1
	tm := cfDataCreate(0, &t[0], len(t))
	defer cfRelease(tm)
	tampered := secKeyVerifySignature(pub, alg, tm, sig, nil)
	fmt.Printf("se sign_cferror=0 sig_der_len=%d verify=%t verify_tampered=%t\n", cfDataGetLength(sig), ok, tampered)
	return isSE && !privExportable && pubLen == 65 && ok && !tampered
}

const dpGroup = "XXXXXXXXXX.dev.heimdall.x4" // placeholder team prefix

func dpProbe(group string) int32 {
	s := cfStringCreate(0, "hm-x4-dp-probe-"+rnd(8), 0x08000100 /* UTF-8 */)
	defer cfRelease(s)
	kv := []ref{constant(sec, "kSecClass"), constant(sec, "kSecClassGenericPassword"), constant(sec, "kSecAttrService"), s,
		constant(sec, "kSecUseDataProtectionKeychain"), constant(cf, "kCFBooleanTrue"), constant(sec, "kSecMatchLimit"), constant(sec, "kSecMatchLimitOne")}
	if group != "" {
		g := cfStringCreate(0, group, 0x08000100)
		defer cfRelease(g)
		kv = append(kv, constant(sec, "kSecAttrAccessGroup"), g)
	}
	q := dict(kv...)
	defer cfRelease(q)
	return secItemCopyMatching(q, nil)
}

func main() {
	load()
	ok := false
	switch {
	case len(os.Args) == 3 && os.Args[1] == "keychain":
		ok = keychain(os.Args[2])
	case len(os.Args) == 2 && os.Args[1] == "se":
		ok = se()
	case len(os.Args) == 2 && os.Args[1] == "dpprobe":
		a, b := dpProbe(""), dpProbe(dpGroup)
		fmt.Printf("dpprobe no_access_group osstatus=%d\n", a)
		fmt.Printf("dpprobe access_group=%s osstatus=%d\n", dpGroup, b)
		ok = a == -25300 && b == -25300
	default:
		fmt.Fprintln(os.Stderr, "usage: hm-x4-go-purego keychain <path> | se | dpprobe")
		os.Exit(2)
	}
	if !ok {
		os.Exit(1)
	}
}
