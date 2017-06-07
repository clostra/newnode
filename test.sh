#!/bin/bash

set -e

if [ -z "$ASAN_OPTIONS" ]; then
    export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
fi

origin_addr=localhost
origin_port=8080
injector_tcp_port=8005
proxy_tcp_port=5678
GOOGLE=172.217.7.142
HTTP_OK=200
HTTP_BAD_GATEWAY=502

trap cleanup SIGINT SIGTERM EXIT

all_jobs=()
function cleanup {
    kill -SIGINT ${all_jobs[*]} 2>/dev/null || true
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
    proxy=localhost:$1
    host=$2
    expect=$3

    code=$(curl -x $proxy $host -o /dev/null -w "%{http_code}" --silent --show-error)
    
    if [ "$code" != "$expect" ]; then
        echo "$(now) $1 HTTP error code: $code (expected $expect)"
        return 1
    fi
}

function test_n {
    n=$1
    host=$2
    expect=$3
    echo "$(now) Testing with $n jobs"

    pids=()
    
    for ((i=0;i<$n;i++)); do
        do_curl $proxy_tcp_port $host $expect &
        pids+=("$!")
    done
    
    r=0
    for p in "${pids[@]}"; do
        if [ "$r" == "0" ]; then
            wait $p || r=1
        else
            kill $p 2>/dev/null
        fi
    done

    return $r
}

if [ "$origin_addr" == "localhost" ]; then
    ./test_server & # listens on origin_port
    server_pid=$!
    all_jobs+=("$server_pid")
fi

echo "$(now) Starting injector."
$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
all_jobs+=("$!")

# Make sure injector starts properly.
sleep 2

echo "$(now) Testing curl directly to the server."
do_curl $origin_port $origin_addr:$origin_port $HTTP_OK

echo "$(now) Testing curl to injector."
do_curl $injector_tcp_port $origin_addr:$origin_port $HTTP_OK

echo "$(now) Starting injector helper."
$unbuf ./injector_helper -i 127.0.0.1:7000 2> >(prepend "He") > >(prepend "Ho") &
all_jobs+=("$!")

# Wait for the injector helper to perform a test on the injector nedpoint.
sleep 2

echo "$(now) Testing curl to injector_helper."
r=0
for i in 1 8 16; do
    if ! test_n $i $origin_addr:$origin_port $HTTP_OK; then
        r=1; break;
    fi
done

if [ "$r" == "0" ]; then
    echo "$(now) Testing HTTPS forwarding."
    if ! do_curl $proxy_tcp_port $GOOGLE $HTTP_OK; then
        r=2
    fi
fi

if [ "$r" == "0" -a -n "$server_pid" ]; then
    echo "$(now) Testing fast failure response."
    # Kill the origin and try to connect to it. It shouldn't take long for the
    # injector and proxy to find out the origin is unreachable.
    kill -SIGINT $server_pid

    start_time=$(seconds_since_epoch)
    test_n 2 $origin_addr:$origin_port $HTTP_BAD_GATEWAY
    end_time=$(seconds_since_epoch)

    if [ $(($end_time - $start_time)) -ge 5 ]; then
        r=2
    fi
fi

echo "$(now) DONE"

exit $r

