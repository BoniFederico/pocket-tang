#!/usr/bin/env bash
# Clevis / upstream-tang interoperability tests for Pocket Tang.
#
#   tools/interop.sh [--host-bin PATH] [--url URL] [--skip-luks]
#
# Without --url the script starts tangd-host (our core) and upstream tangd (via socat) on
# localhost and runs the full suite, including rotation and an upstream cross-check using the
# same key files. With --url it tests an already running Pocket Tang (e.g. the ESP32 board):
# clevis round-trips, sss, and a status-code comparison against a local upstream tangd.
#
# Requirements: clevis, clevis-luks (optional), tang (tangd, tangd-keygen), jose, jq, curl,
# socat, cryptsetup (optional, root, dm-crypt).
set -euo pipefail

HOST_BIN=${HOST_BIN:-build/host/host/tangd-host}
URL=""
SKIP_LUKS=0
while [ $# -gt 0 ]; do
    case "$1" in
    --host-bin) HOST_BIN=$2; shift 2 ;;
    --url) URL=$2; shift 2 ;;
    --skip-luks) SKIP_LUKS=1; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
    esac
done

TANGD=${TANGD:-$(command -v tangd || echo /usr/libexec/tangd)}
KEYGEN=${KEYGEN:-$(command -v tangd-keygen || echo /usr/libexec/tangd-keygen)}
OURS_PORT=${OURS_PORT:-18080}
UP_PORT=${UP_PORT:-18081}
WORK=$(mktemp -d)
PIDS=()
PASS=0
FAIL=0

cleanup() {
    for p in "${PIDS[@]:-}"; do [ -n "$p" ] && kill "$p" 2>/dev/null || true; done
    if [ -n "${LOOPDEV:-}" ]; then cryptsetup close pt-interop 2>/dev/null || true; losetup -d "$LOOPDEV" 2>/dev/null || true; fi
    rm -rf "$WORK"
}
trap cleanup EXIT

ok() { PASS=$((PASS + 1)); echo "  PASS  $*"; }
ko() { FAIL=$((FAIL + 1)); echo "  FAIL  $*"; }
check() { local desc=$1; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else ko "$desc"; fi; }
wait_port() { for _ in $(seq 100); do curl -sf -o /dev/null "http://127.0.0.1:$1/adv" && return 0; sleep 0.1; done; echo "server on port $1 did not come up" >&2; return 1; }

start_ours() { # args: extra tangd-host options
    "$HOST_BIN" -l 127.0.0.1 -p "$OURS_PORT" "$@" >/dev/null 2>>"$WORK/ours.log" &
    OURS_PID=$!
    PIDS+=("$OURS_PID")
    wait_port "$OURS_PORT"
}
stop_ours() { kill "$OURS_PID" 2>/dev/null || true; wait "$OURS_PID" 2>/dev/null || true; }
start_upstream() { # arg: keydir
    socat "TCP-LISTEN:$UP_PORT,reuseaddr,fork" EXEC:"$TANGD $1" >/dev/null 2>>"$WORK/up.log" &
    UP_PID=$!
    PIDS+=("$UP_PID")
    wait_port "$UP_PORT"
}
stop_upstream() { kill "$UP_PID" 2>/dev/null || true; wait "$UP_PID" 2>/dev/null || true; }

# Signing-key thumbprint (S256) of the server's advertisement, verified by jose.
adv_sig_thp() {
    local adv
    adv=$(curl -sf "$1/adv")
    echo "$adv" | jose fmt -j- -g payload -y -o- | jose jwk use -i- -r -u verify -o- |
        jose jwk thp -i- -a S256 | head -1
}
adv_exc_thp() {
    curl -sf "$1/adv" | jose fmt -j- -g payload -y -o- | jose jwk use -i- -r -u deriveKey -o- |
        jose jwk thp -i- -a "${2:-S256}" | head -1
}

roundtrip() { # url thp label
    local secret="pocket-tang-$RANDOM-$RANDOM"
    local cfg
    cfg=$(jq -cn --arg u "$1" --arg t "$2" '{url:$u,thp:$t}')
    if echo -n "$secret" | clevis encrypt tang "$cfg" >"$WORK/rt.jwe" 2>"$WORK/rt.err" &&
        [ "$(clevis decrypt <"$WORK/rt.jwe" 2>>"$WORK/rt.err")" = "$secret" ]; then
        ok "clevis round-trip ($3)"
    else
        ko "clevis round-trip ($3): $(tail -2 "$WORK/rt.err" | tr '\n' ' ')"
    fi
}

# Status code matrix: prints "label code" lines for a server.
status_matrix() { # url
    local u=$1 exc sig exc1
    exc=$(adv_exc_thp "$u")
    exc1=$(adv_exc_thp "$u" S1)
    sig=$(adv_sig_thp "$u")
    local client
    client=$(jose jwk gen -i '{"alg":"ECMR","crv":"P-521"}' | jose jwk pub -i-)
    local c="curl -s -o /dev/null -w %{http_code}"
    echo "adv $($c "$u/adv")"
    echo "adv-slash $($c "$u/adv/")"
    echo "adv-dslash $($c --path-as-is "$u//adv//")"
    echo "adv-query $($c "$u/adv?x=1")"
    echo "adv-sig $($c "$u/adv/$sig")"
    echo "adv-exc $($c "$u/adv/$exc")"
    echo "adv-unknown $($c "$u/adv/AAAA")"
    echo "adv-post $($c -X POST "$u/adv")"
    echo "adv-head $($c -I "$u/adv")"
    echo "unknown $($c "$u/nothing")"
    echo "rec-get $($c "$u/rec/$exc")"
    echo "rec-ok $($c -X POST --data-binary "$client" "$u/rec/$exc")"
    echo "rec-s1 $($c -X POST --data-binary "$client" "$u/rec/$exc1")"
    echo "rec-sigkid $($c -X POST --data-binary "$client" "$u/rec/$sig")"
    echo "rec-unknown $($c -X POST --data-binary "$client" "$u/rec/AAAA")"
    echo "rec-badjson $($c -X POST --data-binary '{' "$u/rec/$exc")"
    echo "rec-array $($c -X POST --data-binary '[]' "$u/rec/$exc")"
    echo "rec-empty $($c -X POST --data-binary '' "$u/rec/$exc")"
    echo "rec-oct $($c -X POST --data-binary '{"kty":"oct","k":"AA"}' "$u/rec/$exc")"
    echo "rec-alg-es512 $($c -X POST --data-binary "$(echo "$client" | jq -c '.alg="ES512"')" "$u/rec/$exc")"
    echo "rec-noalg $($c -X POST --data-binary "$(echo "$client" | jq -c 'del(.alg)')" "$u/rec/$exc")"
    echo "rec-ops-sign $($c -X POST --data-binary "$(echo "$client" | jq -c '.key_ops=["sign"]')" "$u/rec/$exc")"
    echo "rec-ops-derive $($c -X POST --data-binary "$(echo "$client" | jq -c '.key_ops=["deriveKey"]')" "$u/rec/$exc")"
    echo "rec-use-sig $($c -X POST --data-binary "$(echo "$client" | jq -c '.use="sig"')" "$u/rec/$exc")"
    echo "rec-use-enc $($c -X POST --data-binary "$(echo "$client" | jq -c '.use="enc"')" "$u/rec/$exc")"
    echo "rec-crv $($c -X POST --data-binary "$(echo "$client" | jq -c '.crv="P-256"')" "$u/rec/$exc")"
    echo "rec-offcurve $($c -X POST --data-binary "$(echo "$client" | jq -c '.y=.x')" "$u/rec/$exc")"
    echo "rec-private $($c -X POST --data-binary "$(jose jwk gen -i '{"alg":"ECMR","crv":"P-521"}')" "$u/rec/$exc")"
}

# Intentional deviations from upstream (see docs/adr/0003-deviations-from-upstream-tang.md):
#   rec-private: upstream accepts a client JWK that carries a private scalar and ignores it;
#                Pocket Tang rejects private key material in requests with 400.
declare -A DEVIATION=([rec-private]="400")

compare_matrix() { # ours_url upstream_url
    status_matrix "$1" >"$WORK/m_ours"
    status_matrix "$2" >"$WORK/m_up"
    while read -r label code; do
        local up
        up=$(grep "^$label " "$WORK/m_up" | cut -d' ' -f2)
        if [ "$code" = "$up" ]; then
            ok "status $label = $code (upstream $up)"
        elif [ "${DEVIATION[$label]:-}" = "$code" ]; then
            ok "status $label = $code (documented deviation, upstream $up)"
        else
            ko "status $label = $code, upstream $up"
        fi
    done <"$WORK/m_ours"
}

echo "== Pocket Tang interop (clevis $(dpkg-query -W -f='${Version}' clevis 2>/dev/null || echo '?'), tang $(dpkg-query -W -f='${Version}' tang 2>/dev/null || echo '?'))"

if [ -n "$URL" ]; then
    # ---- External server mode (board) -------------------------------------------------------
    THP=$(adv_sig_thp "$URL")
    echo "-- target $URL, signing key $THP"
    check "adv signature verifies with jose" bash -c "curl -sf '$URL/adv' > '$WORK/adv.jws' && jose jws ver -i '$WORK/adv.jws' -k- -a < <(jose fmt -j '$WORK/adv.jws' -g payload -y -o- | jose jwk use -i- -r -u verify -o-)"
    roundtrip "$URL" "$THP" "external"
    mkdir -p "$WORK/updb" && "$KEYGEN" "$WORK/updb" >/dev/null
    start_upstream "$WORK/updb"
    UP="http://127.0.0.1:$UP_PORT"
    cfg=$(jq -cn --arg a "$URL" --arg b "$UP" --arg ta "$THP" --arg tb "$(adv_sig_thp "$UP")" \
        '{t:2,pins:{tang:[{url:$a,thp:$ta},{url:$b,thp:$tb}]}}')
    check "sss t=2 across device + upstream" bash -c "echo -n sss-secret | clevis encrypt sss '$cfg' > '$WORK/sss.jwe' && [ \"\$(clevis decrypt < '$WORK/sss.jwe')\" = sss-secret ]"
    compare_matrix "$URL" "$UP"
    echo "== $PASS passed, $FAIL failed"
    [ "$FAIL" -eq 0 ]
    exit $?
fi

[ -x "$HOST_BIN" ] || { echo "tangd-host not found at $HOST_BIN" >&2; exit 2; }
OURS="http://127.0.0.1:$OURS_PORT"
UP="http://127.0.0.1:$UP_PORT"

# ---- 1. fresh state, both /rec reply variants --------------------------------------------
echo "-- 1. fresh keys, clevis round-trips"
start_ours -s "$WORK/state.bin"
THP1=$(adv_sig_thp "$OURS")
check "--thp matches advertised key" test "$("$HOST_BIN" -s "$WORK/state.bin" --thp)" = "$THP1"
roundtrip "$OURS" "$THP1" "with tang_pub"
check "adv signature verifies with jose" bash -c "curl -sf '$OURS/adv' > '$WORK/adv.jws' && jose jws ver -i '$WORK/adv.jws' -k- -a < <(jose fmt -j '$WORK/adv.jws' -g payload -y -o- | jose jwk use -i- -r -u verify -o-)"
check "adv/{kid} verifies with jose" bash -c "curl -sf '$OURS/adv/$THP1' > '$WORK/advk.jws' && jose jws ver -i '$WORK/advk.jws' -k- -a < <(jose fmt -j '$WORK/advk.jws' -g payload -y -o- | jose jwk use -i- -r -u verify -o-)"
# encrypt with an adv file instead of thp
curl -sf "$OURS/adv" >"$WORK/adv.json"
check "clevis encrypt with adv file" bash -c "echo -n advfile | clevis encrypt tang '{\"url\":\"$OURS\",\"adv\":\"$WORK/adv.json\"}' > '$WORK/a.jwe' && [ \"\$(clevis decrypt < '$WORK/a.jwe')\" = advfile ]"
stop_ours
start_ours -s "$WORK/state.bin" --no-tang-pub
roundtrip "$OURS" "$THP1" "without tang_pub"
check "old JWE decrypts after restart" bash -c "[ \"\$(clevis decrypt < '$WORK/a.jwe')\" = advfile ]"
stop_ours
start_ours -s "$WORK/state.bin" --lock
check "lock: decrypt refused" bash -c "! clevis decrypt < '$WORK/a.jwe'"
stop_ours

# ---- 2. rotation ---------------------------------------------------------------------------
echo "-- 2. rotation"
"$HOST_BIN" -s "$WORK/state.bin" --rotate 2>/dev/null
start_ours -s "$WORK/state.bin"
THP2=$(adv_sig_thp "$OURS")
check "rotation changes the signing key" test "$THP1" != "$THP2"
check "rotated keys are not advertised" bash -c "! curl -sf '$OURS/adv' | jose fmt -j- -g payload -y -o- | grep -q \"\$(jose fmt -j '$WORK/adv.json' -g payload -y -o- | jq -r '.keys[0].x')\""
check "binding made before rotation still decrypts" bash -c "[ \"\$(clevis decrypt < '$WORK/a.jwe')\" = advfile ]"
check "rotated signing key still served at /adv/{old kid}" test "$(curl -s -o /dev/null -w '%{http_code}' "$OURS/adv/$THP1")" = 200
roundtrip "$OURS" "$THP2" "after rotation"
stop_ours

# ---- 3. cross-check with upstream tangd on identical keys ----------------------------------
echo "-- 3. upstream cross-check (same key directory)"
mkdir -p "$WORK/db"
"$KEYGEN" "$WORK/db" >/dev/null
start_ours -d "$WORK/db"
start_upstream "$WORK/db"
norm() { curl -sf "$1/adv" | jose fmt -j- -g payload -y -o- | jq -S -c '.keys|sort_by(.alg)'; }
check "advertised key sets are identical" test "$(norm "$OURS")" = "$(norm "$UP")"
EXC=$(adv_exc_thp "$UP")
CLIENT=$(jose jwk gen -i '{"alg":"ECMR","crv":"P-521"}' | jose jwk pub -i-)
r_ours=$(curl -sf -X POST --data-binary "$CLIENT" "$OURS/rec/$EXC" | jq -c '{x,y}')
r_up=$(curl -sf -X POST --data-binary "$CLIENT" "$UP/rec/$EXC" | jq -c '{x,y}')
check "/rec results identical (x,y)" test "$r_ours" = "$r_up"
SIG=$(adv_sig_thp "$UP")
echo -n cross1 | clevis encrypt tang "{\"url\":\"$UP\",\"thp\":\"$SIG\"}" >"$WORK/up.jwe"
echo -n cross2 | clevis encrypt tang "{\"url\":\"$OURS\",\"thp\":\"$SIG\"}" >"$WORK/ours.jwe"
stop_upstream
# The JWE bound against upstream must decrypt with ours: point its URL at ours via a proxy port.
socat "TCP-LISTEN:$UP_PORT,reuseaddr,fork" "TCP:127.0.0.1:$OURS_PORT" 2>/dev/null &
PIDS+=($!)
sleep 0.3
check "JWE bound to upstream decrypts with Pocket Tang" bash -c "[ \"\$(clevis decrypt < '$WORK/up.jwe')\" = cross1 ]"
kill "${PIDS[-1]}" 2>/dev/null || true
sleep 0.2
stop_ours
start_upstream "$WORK/db"
socat "TCP-LISTEN:$OURS_PORT,reuseaddr,fork" "TCP:127.0.0.1:$UP_PORT" 2>/dev/null &
PIDS+=($!)
sleep 0.3
check "JWE bound to Pocket Tang decrypts with upstream" bash -c "[ \"\$(clevis decrypt < '$WORK/ours.jwe')\" = cross2 ]"
kill "${PIDS[-1]}" 2>/dev/null || true
sleep 0.2
# rotated key files (dot-prefixed) behave the same in both
for f in "$WORK"/db/*.jwk; do mv "$f" "$WORK/db/.$(basename "$f")"; done
"$KEYGEN" "$WORK/db" >/dev/null
stop_upstream
start_upstream "$WORK/db"
start_ours -d "$WORK/db"
check "after rotation advertised key sets are identical" test "$(norm "$OURS")" = "$(norm "$UP")"
r_ours=$(curl -sf -X POST --data-binary "$CLIENT" "$OURS/rec/$EXC" | jq -c '{x,y}')
r_up=$(curl -sf -X POST --data-binary "$CLIENT" "$UP/rec/$EXC" | jq -c '{x,y}')
check "rotated exchange key: /rec identical" test "$r_ours" = "$r_up"
check "rotated signing key: /adv/{kid} served by both" test "$(curl -s -o /dev/null -w '%{http_code}' "$OURS/adv/$SIG")/$(curl -s -o /dev/null -w '%{http_code}' "$UP/adv/$SIG")" = "200/200"
compare_matrix "$OURS" "$UP"

# ---- 4. Shamir secret sharing across both servers ----------------------------------------
echo "-- 4. sss"
cfg=$(jq -cn --arg a "$OURS" --arg b "$UP" --arg ta "$(adv_sig_thp "$OURS")" --arg tb "$(adv_sig_thp "$UP")" \
    '{t:2,pins:{tang:[{url:$a,thp:$ta},{url:$b,thp:$tb}]}}')
check "sss t=2 decrypts with both servers" bash -c "echo -n sss2 | clevis encrypt sss '$cfg' > '$WORK/s2.jwe' && [ \"\$(clevis decrypt < '$WORK/s2.jwe')\" = sss2 ]"
cfg1=$(echo "$cfg" | jq -c '.t=1')
echo -n sss1 | clevis encrypt sss "$cfg1" >"$WORK/s1.jwe"
stop_upstream
check "sss t=1 decrypts with only Pocket Tang" bash -c "[ \"\$(clevis decrypt < '$WORK/s1.jwe')\" = sss1 ]"
check "sss t=2 fails with one server down" bash -c "! clevis decrypt < '$WORK/s2.jwe'"

# ---- 5. LUKS binding (optional) ------------------------------------------------------------
if [ "$SKIP_LUKS" = 0 ] && [ "$(id -u)" = 0 ] && command -v cryptsetup >/dev/null &&
    command -v clevis-luks-bind >/dev/null && modprobe dm_crypt 2>/dev/null; then
    echo "-- 5. LUKS2 bind/unlock"
    truncate -s 32M "$WORK/disk.img"
    echo -n "pt-test-passphrase" >"$WORK/pass"
    cryptsetup luksFormat --type luks2 --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
        "$WORK/disk.img" "$WORK/pass" >/dev/null
    LOOPDEV=$(losetup --show -f "$WORK/disk.img")
    THPL=$(adv_sig_thp "$OURS")
    check "clevis luks bind" clevis luks bind -y -k "$WORK/pass" -d "$LOOPDEV" tang "{\"url\":\"$OURS\",\"thp\":\"$THPL\"}"
    check "clevis luks unlock" clevis luks unlock -d "$LOOPDEV" -n pt-interop
    cryptsetup close pt-interop 2>/dev/null || true
    stop_ours
    check "luks unlock fails without Tang" bash -c "! clevis luks unlock -d '$LOOPDEV' -n pt-interop"
else
    echo "-- 5. LUKS2 bind/unlock: skipped (needs root, cryptsetup, clevis-luks, dm_crypt)"
fi

echo "== $PASS passed, $FAIL failed"
if [ "$FAIL" -ne 0 ]; then
    echo "--- tangd-host log (tail)"; tail -20 "$WORK/ours.log" || true
fi
[ "$FAIL" -eq 0 ]
