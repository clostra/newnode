#!/bin/bash

set -e

test_host=localhost
test_port=8080

unbuf='stdbuf -i0 -o0 -e0'

function prepend {
    while read line; do echo "$1 `date +'%M:%S'`| $line"; done
}

function do_curl {
    host="$test_host:$test_port"

    code=$(curl -x localhost:5678 $host -o /dev/null -w "%{http_code}" --silent --show-error)
    
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
        do_curl $i &
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

if [ "$test_host" == "localhost" ]; then
    python -m SimpleHTTPServer $test_port  &
fi

$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
i_pid=$!

$unbuf ./injector_helper -i 127.0.0.1:7000 -d 2> >(prepend "He") > >(prepend "Ho") &
h_pid=$!

# Wait for the injector helper to perform a test on the injector nedpoint.
sleep 5

r=0
for i in 8 16 32 64; do
    if ! test_n $i; then
        echo "break"
        r=1
        break;
    fi
done

kill $i_pid $h_pid 2>/dev/null || true

echo DONE

exit $r

