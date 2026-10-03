#!/bin/bash
# E7 phase 5 (preliminary G09): pre-accepted mux control connections vs ssh -O stop / -O exit.
# Thin wrapper so run_all.sh can run the Python experiment; see e7_mux_preconnected.py for the
# design, hypotheses and safety rules. Exit code is the experiment's (0 / 1 / 3).
unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE DISPLAY
exec /usr/bin/python3 "$(cd "$(dirname "$0")" && pwd)/e7_mux_preconnected.py" "$@"
