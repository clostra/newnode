FROM debian:stretch

RUN apt update && apt install -y build-essential automake libtool clang git ca-certificates

ADD ./ /opt/newnode
WORKDIR /opt/newnode
RUN git submodule init && git submodule update
RUN ./build.sh
