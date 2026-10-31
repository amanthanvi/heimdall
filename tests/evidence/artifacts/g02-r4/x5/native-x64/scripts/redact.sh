#!/bin/sh
# Redact non-loopback IPs, MACs, home paths, user and host names from stdin (GNU sed).
# 127.x.x.x and ::1 are kept; the IPv4/IPv6 unspecified addresses and netdev's fixed
# probe addresses get named placeholders; any other address becomes <nonloop4>/<nonloop6>.
U=$(id -un); HN=$(hostname)
sed -E \
 -e "s#$HOME#<wslhome>#g" -e "s#/home/$U#<wslhome>#g" -e "s#/mnt/c/Users/[^/ \"]+#<winhome>#g" \
 -e "s#\\b$U\\b#<wsluser>#g" -e "s#\\b$HN\\b#<winhost>#g" \
 -e 's#\b10\.254\.254\.254\b#<netdev-probe4>#g' \
 -e 's#\b0\.0\.0\.0\b#<any4>#g' \
 -e 's#\b(12[0-6]|1[01][0-9]|12[89]|1[3-9][0-9]|2[0-5][0-9]|[1-9]?[0-9])\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b#<nonloop4>#g' \
 -e 's#fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff#<netdev-probe6>#g' \
 -e 's#inet_pton\(AF_INET6, "::"#inet_pton(AF_INET6, "<any6>"#g' \
 -e 's#inet_pton\(AF_INET6, "([0-9a-fA-F:.]*[0-9a-fA-F.][0-9a-fA-F:.]*)"#inet_pton(AF_INET6, "@@\1@@"#g' \
 -e 's#"@@::1@@"#"::1"#g' -e 's#"@@[^@]*@@"#"<nonloop6>"#g' \
 -e 's#\[::\]#[<any6>]#g' -e 's#\[::1\]#[@L6@]#g' -e 's#\[[0-9a-fA-F]*:[0-9a-fA-F:.]*\]#[<nonloop6>]#g' -e 's#\[@L6@\]#[::1]#g' \
 -e 's#\b00000000000000000000000001000000\b#@L6HEX@#g' -e 's#\b0000000000000000FFFF0000([0-9A-F]{6})7F\b#@V4M@\1#g' -e 's#\b0{32}\b#<any6-hex>#g' -e 's#\b[0-9A-F]{32}\b#<nonloop6-hex>#g' -e 's#@L6HEX@#00000000000000000000000001000000#g' -e 's#@V4M@([0-9A-F]{6})#0000000000000000FFFF0000\17F#g' \
 -e 's#\b([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b#<mac>#g'
