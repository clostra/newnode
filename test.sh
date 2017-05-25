#!/bin/bash

set -e

origin_addr=localhost
origin_port=8080
injector_tcp_port=8005
proxy_tcp_port=5678

# XXX Find a stdbuf replacement on OSX
if `which stdbuf >/dev/null`; then unbuf='stdbuf -i0 -o0 -e0'; fi

function prepend {
    while read line; do echo "$1 `date +'%M:%S'`| $line"; done
}

function do_curl {
    port=$1
    host="$origin_addr:$origin_port"

    code=$(curl -x localhost:$port $host -o /dev/null -w "%{http_code}" --silent --show-error)
    
    if [ "$code" != "200" ]; then
        echo "$1 HTTP error code: $code"
        return 1
    fi
}

function test_n {
    n=$1
    echo "Testing with $n jobs"

    pids=()
    
    for ((i=0;i<$n;i++)); do
        do_curl $proxy_tcp_port $i &
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
fi

$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
i_pid=$!

# Make sure injector starts properly.
sleep 2

echo "Testing curl directly to the server."
do_curl $origin_port

echo "Testing curl to injector."
do_curl $injector_tcp_port

echo "Starting injector."
$unbuf ./injector_helper -i 127.0.0.1:7000 2> >(prepend "He") > >(prepend "Ho") &
h_pid=$!

# Wait for the injector helper to perform a test on the injector nedpoint.
sleep 2

echo "Testing curl to injector_helper."
r=0
for i in 1 8 16; do
    if ! test_n $i; then
        r=1; break;
    fi
done

kill -SIGINT $i_pid $h_pid 2>/dev/null || true

echo DONE

exit $r

