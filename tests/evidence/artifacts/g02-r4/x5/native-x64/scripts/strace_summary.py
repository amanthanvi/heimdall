"""Summarise strace -ff -yy -e trace=%network output files (argv[1:]).

Prints: socket() calls by family/type/protocol; every bind/connect/listen/accept call
(pid stripped); and for send*/recv* calls a count per (syscall, fd kind, local IP of the
fd, IP named in msg_name / sendto destination). Netlink payloads (route/address dumps
from the kernel) are counted but their decoded contents are not printed.
Ports are stripped from addresses. Output still needs redact.sh before storing.
"""
import collections, re, sys

FD = re.compile(r'^(\w+)\((\d+)<([A-Za-z0-9]+):\[([^\]]*)\]>')
NAME4 = re.compile(r'msg_name=\{sa_family=AF_INET, sin_port=htons\(\d+\), sin_addr=inet_addr\("([0-9.]+)"\)\}')
NAME6 = re.compile(r'msg_name=\{sa_family=AF_INET6, sin6_port=htons\(\d+\), sin6_flowinfo=[^,]*, inet_pton\(AF_INET6, "([0-9a-f:.]+)"')
SENDTO4 = re.compile(r'\}, \d+, [^,]*, \{sa_family=AF_INET, sin_port=htons\(\d+\), sin_addr=inet_addr\("([0-9.]+)"\)\}')
SOCK = re.compile(r'^socket\((AF_\w+), ([A-Z_|]+), (\w+)\)')
CTL = ('bind', 'connect', 'listen', 'accept', 'accept4')
IO = ('sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg')

socks = collections.Counter(); io = collections.Counter(); ctl = []
for path in sys.argv[1:]:
    for line in open(path, errors='replace'):
        line = line.rstrip('\n')
        m = SOCK.match(line)
        if m:
            socks[' '.join(m.groups())] += 1
            continue
        sc = line.split('(', 1)[0]
        if sc in CTL:
            ctl.append(line[:260])
            continue
        if sc not in IO:
            continue
        f = FD.match(line)
        kind, local = (f.group(3), f.group(4)) if f else ('?', '?')
        if kind == 'NETLINK':
            io[(sc, 'NETLINK', '-', '-')] += 1
            continue
        lip = re.sub(r':\d+(->.*)?$', '', local).strip('[]')
        peers = NAME4.findall(line) + NAME6.findall(line) + SENDTO4.findall(line)
        if not peers:
            peers = ['(no msg_name)']
        for p in peers:
            io[(sc, kind, lip, p)] += 1

print('-- socket() calls (family type protocol: count)')
for k, v in sorted(socks.items()):
    print(f'  {v:4d}  {k}')
print('-- bind/connect/listen/accept calls, in file order (fd annotation shows type and address)')
for l in ctl:
    print('  ' + l)
print('-- send*/recv* (syscall, fd kind, fd local IP, msg_name/destination IP: count)')
for k, v in sorted(io.items()):
    print(f'  {v:4d}  ' + ' '.join(k))
