// hm-x4-go: G02 round-4 X4 macOS spike (disposable evidence, not production code).
//
//	hm-x4-go keychain <file-keychain-path>   add/read/delete one generic password
//	hm-x4-go se                              ephemeral Secure Enclave P-256 sign/verify
//	hm-x4-go dpprobe                         read-only data-protection keychain probe
//
// Secrets are generated in-process and never printed. Exit 0 = step succeeded.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

// Placeholder team prefix: no Apple team ID exists for this spike.
const dpGroup = "XXXXXXXXXX.dev.heimdall.x4"

func rnd(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: hm-x4-go keychain <path> | se | dpprobe")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keychain":
		if len(os.Args) != 3 {
			os.Exit(2)
		}
		secret := []byte("hm-x4-not-a-canary-" + rnd(16))
		st := kcRoundTrip(os.Args[2], "hm-x4-svc", "hm-x4-acct", secret)
		for _, k := range []string{"open", "add", "read", "read_mismatch", "delete", "read_after_delete"} {
			if v, ok := st[k]; ok {
				fmt.Printf("keychain %s osstatus=%d\n", k, v)
			}
		}
		// errSecItemNotFound = -25300 is the expected status after delete.
		if st["open"] != 0 || st["add"] != 0 || st["read"] != 0 || st["read_mismatch"] != 0 ||
			st["delete"] != 0 || st["read_after_delete"] != -25300 {
			os.Exit(1)
		}
	case "se":
		r := seRun([]byte("heimdall g02 r4 x4 message " + rnd(8)))
		fmt.Printf("se create_cferror=%d is_secure_enclave_token=%t private_exportable=%t public_len=%d\n",
			r.CreateErr, r.IsSE, r.PrivExportable, r.PubLen)
		fmt.Printf("se sign_cferror=%d sig_der_len=%d verify=%t verify_tampered=%t\n",
			r.SignErr, r.SigLen, r.VerifyOK, r.VerifyTamperedOK)
		if r.CreateErr != 0 || r.SignErr != 0 || !r.IsSE || r.PrivExportable || !r.VerifyOK || r.VerifyTamperedOK || r.PubLen != 65 {
			os.Exit(1)
		}
	case "dpprobe":
		// Read-only. -25300 = errSecItemNotFound; -34018 = errSecMissingEntitlement.
		// Exit 0 only if both queries are allowed (i.e. the process holds the group entitlement).
		a := dpProbe("hm-x4-dp-probe-"+rnd(8), "")
		b := dpProbe("hm-x4-dp-probe-"+rnd(8), dpGroup)
		fmt.Printf("dpprobe no_access_group osstatus=%d\n", a)
		fmt.Printf("dpprobe access_group=%s osstatus=%d\n", dpGroup, b)
		if a != -25300 || b != -25300 {
			os.Exit(1)
		}
	default:
		os.Exit(2)
	}
}
