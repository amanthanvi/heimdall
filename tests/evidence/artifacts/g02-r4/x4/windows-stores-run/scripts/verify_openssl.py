"""M00-T04-x4-stores: independent verification of the Rust spike's CNG signatures with OpenSSL.

Reads the runner's per-process JSON lines (<out>/rust-cng-<sw|tpm>-create.out.txt and -sign.out.txt),
converts the exported ECCPUBLICBLOB (magic ECS1, cbKey 32, X, Y) to a P-256 SubjectPublicKeyInfo PEM and
the raw r||s signature to DER, then runs `openssl dgst -sha256 -verify` over the signed message. A
tampered signature (first byte of r flipped) is the negative control and must fail. Only public data
is handled. Stdlib only; run with python -I.
usage: verify_openssl.py <out-dir> <work-dir> [openssl]
"""
import base64
import hashlib
import json
import os
import subprocess
import sys

SPKI_P256_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


def last_json(path):
    with open(path, encoding="utf-8-sig") as f:
        lines = [l for l in f.read().splitlines() if l.strip().startswith("{")]
    return json.loads(lines[-1])


def der_int(b):
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + bytes([len(b)]) + b


def der_sig(raw):
    body = der_int(raw[:32]) + der_int(raw[32:])
    return b"\x30" + bytes([len(body)]) + body


def main():
    out, work = sys.argv[1], sys.argv[2]
    openssl = sys.argv[3] if len(sys.argv) > 3 else "openssl"
    ver = subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.strip()
    results = {"openssl": ver, "cases": {}}
    ok_all = True
    for tag in ("sw", "tpm"):
        c = last_json(os.path.join(out, "rust-cng-%s-create.out.txt" % tag))
        s = last_json(os.path.join(out, "rust-cng-%s-sign.out.txt" % tag))
        blob = bytes.fromhex(c["pub_blob_hex"])
        magic, cb = int.from_bytes(blob[0:4], "little"), int.from_bytes(blob[4:8], "little")
        assert magic == 0x31534345 and cb == 32 and len(blob) == 72, "unexpected ECCPUBLICBLOB"
        point = b"\x04" + blob[8:72]
        pem = "-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----\n" % base64.b64encode(
            SPKI_P256_PREFIX + point).decode()
        msg = s["msg"].encode()
        digest_ok = hashlib.sha256(msg).hexdigest() == s["digest_hex"]
        raw = bytes.fromhex(s["sig_hex"])
        bad = bytes([raw[0] ^ 0xFF]) + raw[1:]
        p = {k: os.path.join(work, "%s-%s" % (tag, k)) for k in ("pub.pem", "msg.bin", "sig.der", "bad.der")}
        open(p["pub.pem"], "w").write(pem)
        open(p["msg.bin"], "wb").write(msg)
        open(p["sig.der"], "wb").write(der_sig(raw))
        open(p["bad.der"], "wb").write(der_sig(bad))

        def run(sig):
            r = subprocess.run([openssl, "dgst", "-sha256", "-verify", p["pub.pem"], "-signature", sig, p["msg.bin"]],
                               capture_output=True, text=True)
            return r.returncode, (r.stdout + r.stderr).strip().splitlines()[:1]

        g_rc, g_out = run(p["sig.der"])
        b_rc, b_out = run(p["bad.der"])
        case = {
            "key_name": c["key_name"], "provider": c["provider"], "message": s["msg"],
            "digest_matches_sha256_of_message": digest_ok, "pub_blob_hex": c["pub_blob_hex"], "sig_hex": s["sig_hex"],
            "spki_sha256": hashlib.sha256(SPKI_P256_PREFIX + point).hexdigest(),
            "verify_exit": g_rc, "verify_output": g_out, "tampered_exit": b_rc, "tampered_output": b_out,
            "pass": digest_ok and g_rc == 0 and b_rc != 0,
        }
        ok_all &= case["pass"]
        results["cases"][tag] = case
    results["pass"] = ok_all
    print(json.dumps(results, indent=1))
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
