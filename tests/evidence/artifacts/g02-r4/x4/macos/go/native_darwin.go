//go:build darwin

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// --- (1) file-based keychain: add / read / delete one generic password ---
static OSStatus kc_open(const char *path, SecKeychainRef *kc) {
	return SecKeychainOpen(path, kc);
}
static OSStatus kc_add(SecKeychainRef kc, const char *svc, const char *acct, const void *pw, UInt32 n) {
	return SecKeychainAddGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, n, pw, NULL);
}
// Reads the item; copies at most cap bytes into out; returns length in *n.
static OSStatus kc_read(SecKeychainRef kc, const char *svc, const char *acct, void *out, UInt32 cap, UInt32 *n) {
	void *data = NULL;
	OSStatus st = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, n, &data, NULL);
	if (st == errSecSuccess) {
		memcpy(out, data, *n < cap ? *n : cap);
		SecKeychainItemFreeContent(NULL, data);
	}
	return st;
}
static OSStatus kc_delete(SecKeychainRef kc, const char *svc, const char *acct) {
	SecKeychainItemRef item = NULL;
	OSStatus st = SecKeychainFindGenericPassword(kc, (UInt32)strlen(svc), svc, (UInt32)strlen(acct), acct, NULL, NULL, &item);
	if (st != errSecSuccess) return st;
	st = SecKeychainItemDelete(item);
	CFRelease(item);
	return st;
}

// --- data-protection keychain: read-only probe (never writes) ---
// group == NULL: no kSecAttrAccessGroup; otherwise query that (unentitled) access group.
static OSStatus dp_probe(const char *svc, const char *group) {
	CFStringRef s = CFStringCreateWithCString(NULL, svc, kCFStringEncodingUTF8);
	CFStringRef g = group ? CFStringCreateWithCString(NULL, group, kCFStringEncodingUTF8) : NULL;
	const void *k[] = {kSecClass, kSecAttrService, kSecUseDataProtectionKeychain, kSecMatchLimit, kSecAttrAccessGroup};
	const void *v[] = {kSecClassGenericPassword, s, kCFBooleanTrue, kSecMatchLimitOne, g};
	CFDictionaryRef q = CFDictionaryCreate(NULL, k, v, g ? 5 : 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	OSStatus st = SecItemCopyMatching(q, NULL);
	CFRelease(q); CFRelease(s); if (g) CFRelease(g);
	return st;
}

// --- (2) ephemeral Secure Enclave P-256 key: sign / verify ---
typedef struct {
	long create_err;      // CFError code from SecKeyCreateRandomKey (0 = ok)
	int  is_se_token;     // kSecAttrTokenID == kSecAttrTokenIDSecureEnclave
	int  priv_exportable; // SecKeyCopyExternalRepresentation(priv) succeeded
	int  pub_len;         // external representation length of the public key
	long sign_err;
	int  sig_len;
	int  verify_ok;
	int  verify_tampered_ok;
} se_result;

static long cferr(CFErrorRef e) { long c = e ? (long)CFErrorGetCode(e) : 0; if (e) CFRelease(e); return c; }

static void se_run(const UInt8 *msg, CFIndex n, se_result *r) {
	memset(r, 0, sizeof *r);
	CFErrorRef err = NULL;
	SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
		kSecAttrAccessibleWhenUnlockedThisDeviceOnly, kSecAccessControlPrivateKeyUsage, &err);
	if (!ac) { r->create_err = cferr(err); return; }
	int bits = 256;
	CFNumberRef nbits = CFNumberCreate(NULL, kCFNumberIntType, &bits);
	const void *pk[] = {kSecAttrIsPermanent, kSecAttrAccessControl};
	const void *pv[] = {kCFBooleanFalse, ac};
	CFDictionaryRef priv = CFDictionaryCreate(NULL, pk, pv, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	const void *k[] = {kSecAttrKeyType, kSecAttrKeySizeInBits, kSecAttrTokenID, kSecPrivateKeyAttrs};
	const void *v[] = {kSecAttrKeyTypeECSECPrimeRandom, nbits, kSecAttrTokenIDSecureEnclave, priv};
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, k, v, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecKeyRef key = SecKeyCreateRandomKey(attrs, &err);
	CFRelease(attrs); CFRelease(priv); CFRelease(nbits); CFRelease(ac);
	if (!key) { r->create_err = cferr(err); if (!r->create_err) r->create_err = -1; return; }

	CFDictionaryRef ka = SecKeyCopyAttributes(key);
	if (ka) {
		CFTypeRef tok = CFDictionaryGetValue(ka, kSecAttrTokenID);
		r->is_se_token = tok && CFEqual(tok, kSecAttrTokenIDSecureEnclave);
		CFRelease(ka);
	}
	CFDataRef privRep = SecKeyCopyExternalRepresentation(key, &err);
	if (privRep) { r->priv_exportable = 1; CFRelease(privRep); } else { cferr(err); err = NULL; }

	SecKeyRef pub = SecKeyCopyPublicKey(key);
	CFDataRef pubRep = pub ? SecKeyCopyExternalRepresentation(pub, NULL) : NULL;
	if (pubRep) { r->pub_len = (int)CFDataGetLength(pubRep); CFRelease(pubRep); }

	CFDataRef m = CFDataCreate(NULL, msg, n);
	SecKeyAlgorithm alg = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
	CFDataRef sig = SecKeyCreateSignature(key, alg, m, &err);
	if (!sig) { r->sign_err = cferr(err); if (!r->sign_err) r->sign_err = -1; }
	else {
		r->sig_len = (int)CFDataGetLength(sig);
		if (pub) {
			r->verify_ok = SecKeyVerifySignature(pub, alg, m, sig, NULL) ? 1 : 0;
			UInt8 *t = malloc(n); memcpy(t, msg, n); t[0] ^= 1;
			CFDataRef tm = CFDataCreate(NULL, t, n); free(t);
			r->verify_tampered_ok = SecKeyVerifySignature(pub, alg, tm, sig, NULL) ? 1 : 0;
			CFRelease(tm);
		}
		CFRelease(sig);
	}
	CFRelease(m);
	if (pub) CFRelease(pub);
	CFRelease(key);
}
*/
import "C"

import (
	"bytes"
	"unsafe"
)

func kcRoundTrip(path, svc, acct string, secret []byte) (st map[string]int) {
	st = map[string]int{}
	cp, cs, ca := C.CString(path), C.CString(svc), C.CString(acct)
	defer C.free(unsafe.Pointer(cp))
	defer C.free(unsafe.Pointer(cs))
	defer C.free(unsafe.Pointer(ca))
	var kc C.SecKeychainRef
	st["open"] = int(C.kc_open(cp, &kc))
	if st["open"] != 0 {
		return
	}
	defer C.CFRelease(C.CFTypeRef(kc))
	st["add"] = int(C.kc_add(kc, cs, ca, unsafe.Pointer(&secret[0]), C.UInt32(len(secret))))
	buf := make([]byte, 256)
	var n C.UInt32
	st["read"] = int(C.kc_read(kc, cs, ca, unsafe.Pointer(&buf[0]), C.UInt32(len(buf)), &n))
	if st["read"] == 0 && !bytes.Equal(buf[:n], secret) {
		st["read_mismatch"] = 1
	}
	st["delete"] = int(C.kc_delete(kc, cs, ca))
	st["read_after_delete"] = int(C.kc_read(kc, cs, ca, unsafe.Pointer(&buf[0]), C.UInt32(len(buf)), &n))
	return
}

func dpProbe(svc, group string) int {
	cs := C.CString(svc)
	defer C.free(unsafe.Pointer(cs))
	var cg *C.char
	if group != "" {
		cg = C.CString(group)
		defer C.free(unsafe.Pointer(cg))
	}
	return int(C.dp_probe(cs, cg))
}

type seResult struct {
	CreateErr, SignErr                               int64
	IsSE, PrivExportable, VerifyOK, VerifyTamperedOK bool
	PubLen, SigLen                                   int
}

func seRun(msg []byte) seResult {
	var r C.se_result
	C.se_run((*C.UInt8)(unsafe.Pointer(&msg[0])), C.CFIndex(len(msg)), &r)
	return seResult{
		CreateErr: int64(r.create_err), SignErr: int64(r.sign_err),
		IsSE: r.is_se_token != 0, PrivExportable: r.priv_exportable != 0,
		VerifyOK: r.verify_ok != 0, VerifyTamperedOK: r.verify_tampered_ok != 0,
		PubLen: int(r.pub_len), SigLen: int(r.sig_len),
	}
}
