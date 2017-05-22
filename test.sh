#!/bin/bash

set -e

test_host=localhost
test_port=8080

unbuf='stdbuf -i0 -o0 -e0'

function run_http_server {
python << END
import SimpleHTTPServer
import SocketServer
PORT = 8080

class H(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write('It works')

httpd = SocketServer.TCPServer(("", PORT), H)
httpd.serve_forever()
END
}

function prepend {
    while read line; do echo "$1 `date +'%M:%S'`| $line"; done
}

function do_curl {
    port=$1
    host="$test_host:$test_port"

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
        do_curl 5678 $i &
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
    run_http_server &
fi

$unbuf ./injector -p 7000 2> >(prepend "Ie") 1> >(prepend "Io") &
i_pid=$!

# Make sure injector starts properly.
sleep 2

echo "Testing curl directly to the server."
do_curl 8080

echo "Testing curl to injector."
do_curl 8005

echo "Starting injector."
$unbuf ./injector_helper -i 127.0.0.1:7000 2> >(prepend "He") > >(prepend "Ho") &
h_pid=$!

# Wait for the injector helper to perform a test on the injector nedpoint.
sleep 5

echo "Testing curl to injector_helper."
r=0
for i in 1 8 32 64; do
    if ! test_n $i; then
        r=1; break;
    fi
done

kill $i_pid $h_pid 2>/dev/null || true

echo DONE

exit $r

