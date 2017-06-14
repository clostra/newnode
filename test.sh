#!/bin/bash

set -e

if [ -z "$ASAN_OPTIONS" ]; then
    # https://github.com/clostra/dcdn/issues/27
    export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
fi

if [ -z "$LSAN_OPTIONS" ]; then
    # https://github.com/clostra/dcdn/issues/50
    export LSAN_OPTIONS=suppressions=.lsan.supp
fi

LOCAL_ORIGIN=localhost:8080
INJECTOR_TCP_PORT=8005
INJECTOR_UDP_PORT=7000
HELPER_TCP_PORT=5678

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
    while read line; do echo "$(now) |$1| $line"; done
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
        do_curl $HELPER_TCP_PORT $host "${@:3}" &
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

function countdown {
    local i
    for ((i=$1;i>0;i--)); do
        echo -en "countdown $i   \r"
        # '|| exit' because sleep catches the SIGINT signal.
        sleep 1 || exit
    done
    echo "             "
}

# Return a random alpha numeric string of size 32.
function rnd {
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1
}

# Determine our WAN IP address.
function wanip {
    dig +short myip.opendns.com @resolver1.opendns.com
}

# Determine whether we can receive UDP packets sent by us to our WAN IP
# address.
function can_ping_self {
    local myip=$(wanip)
    local port=$INJECTOR_UDP_PORT
    local msg=$(rnd)
    ( echo "$msg" | nc -u $myip $port -w0) &
    local n=$!
    while read line; do
        [ "$msg" == "$line" ] && return 0
    done < <(timeout 3 nc -lu 0.0.0.0 $port)
    return 1
}

#-------------------------------------------------------------------------------
USE_DHT=$(can_ping_self && echo "1" || echo "0")

if [ "$USE_DHT" == "1" ]; then
    SWARM_SALT=$(rnd)
    echo "Using DHT with SWARM_SALT=$SWARM_SALT"
    ADD_SWARM_SALT="-a $SWARM_SALT"
else
    echo "Warning: Not using DHT in tests because this PC can't communicate"
    echo "         with itself through its WAN IP address. Consider opening"
    echo "         port $INJECTOR_UDP_PORT on your router."

    countdown 5

    ADD_INJECTOR_EP="-i 127.0.0.1:$INJECTOR_UDP_PORT"
fi

#-------------------------------------------------------------------------------
./test_server &
server_pid=$!
all_jobs+=("$server_pid")

echo "$(now) Starting injector."
$unbuf ./injector -p $INJECTOR_UDP_PORT $ADD_SWARM_SALT 1> >(prepend "I") 2>&1 &
injector_pid=$!
all_jobs+=("$injector_pid")

# Make sure injector starts properly (if using DHT, allow time to register in
# its swarm).
# XXX Instead of countdown it'd be better to wait for an output from injector.
[ "$USE_DHT" == "1" ] && countdown 30 || countdown 2

#-------------------------------------------------------------------------------
echo "$(now) Testing curl directly to the server."
do_curl "" $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to injector."
do_curl $INJECTOR_TCP_PORT $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Starting injector helper."
$unbuf ./injector_helper $ADD_INJECTOR_EP $ADD_SWARM_SALT 1> >(prepend "H") 2>&1 &
all_jobs+=("$!")

# Wait for the injector helper to perform a test on the injector endpoint.
[ "$USE_DHT" == "1" ] && countdown 10 || countdown 2

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to injector_helper."
for i in 1 8 16; do
    test_n $i $LOCAL_ORIGIN $HTTP_OK || exit 1
done

#-------------------------------------------------------------------------------
echo "$(now) Testing HTTPS forwarding."
do_curl $HELPER_TCP_PORT https://google.com $HTTP_OK $HTTP_FOUND $HTTP_MOVED || exit 2

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
do_curl $HELPER_TCP_PORT $LOCAL_ORIGIN $HTTP_BAD_GATEWAY

#-------------------------------------------------------------------------------
echo "$(now) DONE"

exit $r

