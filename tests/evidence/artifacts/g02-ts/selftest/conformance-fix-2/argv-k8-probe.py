import subprocess, sys
code = "for (const a of process.argv.slice(1)) console.log(Buffer.from(a,'utf8').toString('hex')); for (const a of Bun.argv.slice(1)) console.log('B', Buffer.from(a,'utf8').toString('hex'))"
r = subprocess.run([b"bun", b"-e", code.encode(), b"a\xffb", b"caf\xe9", b"valid \xc3\xbc"], capture_output=True)
print("rc", r.returncode); print(r.stdout.decode()); print(r.stderr.decode()[:500])
