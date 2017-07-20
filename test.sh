#!/bin/bash

set -e

LOCAL_ORIGIN=localhost:8000
INJECTOR_TCP_PORT=8005
CLIENT_TCP_PORT=8006

HTTP_OK=200
HTTP_MOVED=301
HTTP_FOUND=302
HTTP_BAD_GATEWAY=502

trap cleanup SIGINT SIGTERM EXIT

all_jobs=()
function cleanup {
    kill -SIGINT ${all_jobs[*]} 2>/dev/null || true
}

function element_in {
    local e
    for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 0; done
    return 1
}

function seconds_since_epoch {
    date +'%s'
}

function now {
    date +'%M:%S'
}

# XXX Find a stdbuf replacement on OSX
if `which stdbuf >/dev/null`; then unbuf='stdbuf -i0 -o0 -e0'; fi

function prepend {
    while read line; do echo "$(now) $1| $line"; done
}

function do_curl {
    local proxy=""
    [ -n "$1" ] && proxy="-x localhost:$1"
    local host=$2
    local code=$(curl $proxy $host -o /dev/null -w "%{http_code}" --silent --show-error)
    if ! element_in $code "${@:3}"; then
        echo "Expected HTTP response one of (${@:3}) but received $code"
        return 1
    fi
    return 0
}

function test_n {
    local n=$1
    local host=$2
    local pids=()
    local i
    
    for ((i=0;i<$n;i++)); do
        do_curl $CLIENT_TCP_PORT $host "${@:3}" &
        pids+=("$!")
    done
    
    for p in "${pids[@]}"; do
        if ! wait $p; then
            kill "${pids[@]}" 2>/dev/null || true
            return 1
        fi
    done

    return 0
}

#-------------------------------------------------------------------------------
python -m SimpleHTTPServer &
server_pid=$!
all_jobs+=("$server_pid")

echo "$(now) Starting injector."
$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
injector_pid=$!
all_jobs+=("$injector_pid")

# Make sure injector starts properly.
sleep 2

#-------------------------------------------------------------------------------
echo "$(now) Testing curl directly to the server."
do_curl "" $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to injector."
do_curl $INJECTOR_TCP_PORT $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Starting client."
$unbuf ./client 2> >(prepend "Ce") > >(prepend "Co") &
all_jobs+=("$!")

# Wait for the client to perform a test on the injector nedpoint.
sleep 2

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to client."
for i in 1 8 16; do
    test_n $i $LOCAL_ORIGIN $HTTP_OK || exit 1
done

#-------------------------------------------------------------------------------
echo "$(now) Testing HTTPS forwarding."
do_curl $CLIENT_TCP_PORT https://google.com $HTTP_OK $HTTP_FOUND $HTTP_MOVED || exit 2

#-------------------------------------------------------------------------------
echo "$(now) Testing fast failure response."
# Kill the origin and try to connect to it. It shouldn't take long for the
# injector and proxy to find out the origin is unreachable.
kill -SIGINT $server_pid

start_time=$(seconds_since_epoch)
test_n 2 $LOCAL_ORIGIN $HTTP_BAD_GATEWAY
end_time=$(seconds_since_epoch)
[ $((end_time - start_time)) -lt 5 ] || exit 3

#-------------------------------------------------------------------------------
echo "$(now) Testing response if injector is down."
kill -SIGINT $injector_pid 2>/dev/null
do_curl $CLIENT_TCP_PORT $LOCAL_ORIGIN $HTTP_BAD_GATEWAY

#-------------------------------------------------------------------------------
echo "$(now) DONE"

exit $r

