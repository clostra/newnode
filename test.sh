#!/bin/bash

set -e

LOCAL_ORIGIN=localhost:8000
INJECTOR_TCP_PORT=8005
INJECTOR_UTP_PORT=7000
CLIENT_TCP_PORT=8006

HTTP_OK=200
HTTP_MOVED=301
HTTP_FOUND=302
HTTP_BAD_GATEWAY=502

trap 'kill -SIGTERM $(jobs -pr) || true; exit' HUP INT TERM EXIT

function now {
    date +'%M:%S'
}

# XXX Find a stdbuf replacement on OSX
if `which stdbuf >/dev/null`; then unbuf='stdbuf -i0 -o0 -e0'; fi

function prepend {
    while read line; do echo "$(now) $1| $line"; done
}

function do_curl {
    local code=$(curl $1 -o /dev/null -w "%{http_code}" --silent --show-error "${@:3}")
    if [ $code != $2 ]; then
        echo "Expected HTTP response $2 but received $code"
        return 1
    fi
    return 0
}

#-------------------------------------------------------------------------------
python -m SimpleHTTPServer &
server_pid=$!

echo "$(now) Starting injector."
$unbuf ./injector -p $INJECTOR_UTP_PORT 2> >(prepend "inject_err") 1> >(prepend "inject_out") &
injector_pid=$!

# Wait for the injector to start
sleep 1

#-------------------------------------------------------------------------------
echo "$(now) Testing curl directly to the server."
do_curl $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to injector."
http_proxy=localhost:$INJECTOR_TCP_PORT do_curl $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Starting client."
$unbuf ./client -i 2> >(prepend "client_err") > >(prepend "client_out") &

# Wait for the client to start
sleep 1

#-------------------------------------------------------------------------------
echo "$(now) Testing curl to client."
http_proxy=localhost:$CLIENT_TCP_PORT do_curl $LOCAL_ORIGIN $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Testing HTTPS forwarding."
http_proxy=localhost:$CLIENT_TCP_PORT do_curl https://www.google.com $HTTP_OK

#-------------------------------------------------------------------------------
echo "$(now) Test indirect."
http_proxy=localhost:$CLIENT_TCP_PORT do_curl $LOCAL_ORIGIN $HTTP_OK -H "X-Peer: 127.0.0.1:$INJECTOR_UTP_PORT"

#-------------------------------------------------------------------------------
echo "$(now) Test cache."
http_proxy=localhost:$CLIENT_TCP_PORT do_curl $LOCAL_ORIGIN $HTTP_OK -H "X-Peer: 0.0.0.0:1"

#-------------------------------------------------------------------------------
echo "$(now) DONE"

exit $r

