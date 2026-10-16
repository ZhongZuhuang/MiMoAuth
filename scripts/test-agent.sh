#!/usr/bin/env bash
# Test stand-in for the GUI agent (used by automated e2e tests).
# Submits a fixed wrong password; cancels the request when PAM rejects it.
id=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --auth-id) id="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$id" ]] || exit 2
sleep 0.3
reply=$(gdbus call --session --dest org.mimoauth.Auth1 \
    --object-path /org/mimoauth/Auth1 \
    --method org.mimoauth.Auth1.SubmitPassword "$id" "definitely-wrong-password-123" 2>&1)
case "$reply" in
    *true*) exit 0 ;;
esac
gdbus call --session --dest org.mimoauth.Auth1 \
    --object-path /org/mimoauth/Auth1 \
    --method org.mimoauth.Auth1.CancelAuth "$id" >/dev/null 2>&1
exit 1
