#!/bin/bash

set -e

origin_addr=localhost
origin_port=8080
injector_tcp_port=8005
proxy_tcp_port=5678
HTTP_OK=200
HTTP_BAD_GATEWAY=502

function now {
    date +'%M:%S'
}

# XXX Find a stdbuf replacement on OSX
if `which stdbuf >/dev/null`; then unbuf='stdbuf -i0 -o0 -e0'; fi

function prepend {
    while read line; do echo "$(now) $1| $line"; done
}

function do_curl {
    port=$1
    expect=$2
    host="$origin_addr:$origin_port"

    code=$(curl -x localhost:$port $host -o /dev/null -w "%{http_code}" --silent --show-error)
    
    if [ "$code" != "$expect" ]; then
        echo "$(now) $1 HTTP error code: $code (expected $expect)"
        return 1
    fi
}

function test_n {
    n=$1
    expect=$2
    echo "$(now) Testing with $n jobs"

    pids=()
    
    for ((i=0;i<$n;i++)); do
        do_curl $proxy_tcp_port $expect &
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
fi

echo "$(now) Starting injector."
$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
i_pid=$!

# Make sure injector starts properly.
sleep 2

echo "$(now) Testing curl directly to the server."
do_curl $origin_port $HTTP_OK

echo "$(now) Testing curl to injector."
do_curl $injector_tcp_port $HTTP_OK

echo "$(now) Starting injector helper."
$unbuf ./injector_helper -i 127.0.0.1:7000 2> >(prepend "He") > >(prepend "Ho") &
h_pid=$!

# Wait for the injector helper to perform a test on the injector nedpoint.
sleep 2

echo "$(now) Testing curl to injector_helper."
r=0
for i in 1 8 16; do
    if ! test_n $i $HTTP_OK; then
        r=1; break;
    fi
done

kill -SIGINT $server_pid

test_n 2 $HTTP_BAD_GATEWAY

kill -SIGINT $i_pid $h_pid 2>/dev/null || true

echo "$(now) DONE"

exit $r

